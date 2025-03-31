from __future__ import annotations

import asyncio
import time
import enum
import logging
from typing import Dict, Optional, AsyncIterator

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.logger import QuicFileLogger
from aioquic.quic.packet import QuicProtocolVersion
from aioquic.tls import CipherSuite, SessionTicket

from .._backends.base import AsyncNetworkStream
from .._exceptions import (
    ConnectionNotAvailable,
    LocalProtocolError,
    RemoteProtocolError,
)
from .._models import Origin, Request, Response
from .._synchronization import AsyncLock, AsyncSemaphore, AsyncShieldCancellation
from .._trace import Trace
from .interfaces import AsyncConnectionInterface

logger = logging.getLogger("httpcore.http3")


class HTTPConnectionState(enum.IntEnum):
    ACTIVE = 1
    IDLE = 2
    CLOSED = 3


class HTTP3ResponseHandler:
    def __init__(self, connection: "ConnectionProtocol", stream_id: int):
        self._connection = connection
        self._stream_id = stream_id

        self._status: int | None = None
        self._headers: Dict[bytes, bytes] = {}
        self._queue: "asyncio.Queue[bytes]" = asyncio.Queue()
        self._no_content = False
        self._ready = asyncio.Event()
        self._closed = False

    def http_event_received(self, event: DataReceived | HeadersReceived) -> None:
        if isinstance(event, HeadersReceived):
            logger.info("H3 headers: %s", event.headers)
            for k, v in event.headers:
                if k == b":status":
                    self._status = int(v)
                if not k.startswith(b":"):
                    self._headers[k] = v

            self._ready.set()
            if event.stream_ended:
                self._no_content = True

        elif isinstance(event, DataReceived):
            self._queue.put_nowait(event.data)
            if event.stream_ended:
                self._queue.put_nowait(b"")

    async def build(self) -> Response:
        await self._ready.wait()
        assert self._status is not None
        return Response(
            status=self._status,
            headers=self._headers,
            content=None if self._no_content else self,
            extensions={
                b"http_version": b"HTTP/3",
                b"stream_id": self._stream_id,
            },
        )

    # ByteStream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while True:
            data = await self._queue.get()
            self._queue.task_done()
            if not data:
                break
            yield data

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            self._connection._responses.pop(self._stream_id)


class ConnectionProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._http = H3Connection(self._quic)

        self._responses: Dict[int, HTTP3ResponseHandler] = {}
        # self._websockets: Dict[int, WebSocket] = {}

    def has_streams(self) -> bool:
        return bool(self._responses)

    def http_event_received(self, event: H3Event) -> None:
        # logger.info("h3 event %s", event)

        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._responses:
                response = self._responses[stream_id]
                response.http_event_received(event)

            # elif stream_id in self._websockets:
            #     # websocket
            #     # websocket = self._websockets[stream_id]
            #     # websocket.http_event_received(event)
            #     # TODO: WebSockets
            #     pass

    def quic_event_received(self, event: QuicEvent) -> None:
        # logger.info("quic event %s", event)

        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def handle_async_request(self, request: Request) -> Response:
        stream_id = self._quic.get_next_available_stream_id()

        # Only async client is supported.
        # assert isinstance(request.stream, AsyncIterable[bytes])

        response = HTTP3ResponseHandler(self, stream_id)
        self._responses[stream_id] = response

        content_iter = request.stream.__aiter__()
        try:
            next_data_chunk: bytes | None = await content_iter.__anext__()
        except StopAsyncIteration:
            next_data_chunk = None

        # In HTTP/3 the ':authority' pseudo-header is used instead of 'Host'.
        # In order to gracefully handle HTTP/1.1 and HTTP/3 we always require
        # HTTP/1.1 style headers, and map them appropriately if we end up on
        # an HTTP/3 connection.
        # https://datatracker.ietf.org/doc/html/rfc9114#name-request-pseudo-header-field
        authority = [v for k, v in request.headers if k.lower() == b"host"][0]

        # Send headers
        headers = [
            (b":method", request.method),
            (b":scheme", request.url.scheme),
            (b":authority", authority),
            (b":path", request.url.target),
            *(
                (k.lower(), v)
                for k, v in request.headers
                if k.lower()
                not in (
                    b"host",
                    b"transfer-encoding",
                )
            ),
        ]

        logger.info("request headers: %s", headers)
        self._http.send_headers(
            stream_id=stream_id,
            headers=headers,
            end_stream=next_data_chunk is None,
        )
        self.transmit()

        # Stream data
        while next_data_chunk:
            data_chunk = next_data_chunk
            next_data_chunk = await content_iter.__anext__()
            self._http.send_data(
                stream_id=stream_id, data=data_chunk, end_stream=next_data_chunk is None
            )
            self.transmit()

        return await response.build()


class AsyncHTTP3Connection(AsyncConnectionInterface):
    def __init__(
        self,
        origin: Origin,
        stream: AsyncNetworkStream,
        keepalive_expiry: float | None = None,
    ):
        self._origin = origin
        self._network_stream = stream
        self._keepalive_expiry: float | None = keepalive_expiry
        self._state = HTTPConnectionState.IDLE
        self._expire_at: float | None = None
        self._request_count = 0

        self._protocol: ConnectionProtocol | None = None

        self._quic_conifuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
            congestion_control_algorithm="reno",
            original_version=QuicProtocolVersion.VERSION_1,
            supported_versions=[
                QuicProtocolVersion.VERSION_1,
                QuicProtocolVersion.VERSION_2,
            ],
            # idle_timeout=60,
            # quic_logger=QuicFileLogger("./"),
        )

        self._responses: Dict[int, HTTP3ResponseHandler] = {}

    async def handle_async_request(self, request: Request) -> Response:
        if self._protocol is None:
            self._connection_context = connect(
                self._network_stream[0],
                self._network_stream[1],
                configuration=self._quic_conifuration,
                create_protocol=ConnectionProtocol,
            )
            self._protocol = await self._connection_context.__aenter__()

        return await self._protocol.handle_async_request(request)

    async def aclose(self) -> None:
        if self._protocol is not None:
            await self._connection_context.__aexit__(None, None, None)

    def info(self) -> str:
        origin = str(self._origin)
        return (
            f"{origin!r}, HTTP/3, {self._state.name}, "
            f"Request Count: {self._request_count}"
        )

    def can_handle_request(self, origin: Origin) -> bool:
        return origin == self._origin

    def is_available(self) -> bool:
        return True

    def has_expired(self) -> bool:
        now = time.monotonic()
        return self._expire_at is not None and now > self._expire_at

    def is_idle(self) -> bool:
        self._protocol is None or self._protocol.has_streams()

    def is_closed(self) -> bool:
        return False

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        origin = str(self._origin)
        return (
            f"<{class_name} [{origin!r}, {self._state.name}, "
            f"Request Count: {self._request_count}]>"
        )
