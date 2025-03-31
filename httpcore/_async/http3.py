from __future__ import annotations

import time
import enum
import logging
from collections import deque, defaultdict
from typing import Dict, AsyncIterator, Deque, Tuple

from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection, QuicErrorCode
from aioquic.quic.events import QuicEvent
from aioquic.quic import events as quic_events
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
from .._synchronization import (
    AsyncLock,
    AsyncSemaphore,
    AsyncShieldCancellation,
    AsyncStream,
    AsyncEvent,
)
from .._trace import Trace
from .interfaces import AsyncConnectionInterface

logger = logging.getLogger("httpcore.http3")


class HTTPConnectionState(enum.IntEnum):
    ACTIVE = 1
    IDLE = 2
    CLOSED = 3


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

        self._connect_lock = AsyncLock()
        self._read_lock = AsyncLock()
        self._write_lock = AsyncLock()

        self._addr: str = ""
        self._quic_configuration = QuicConfiguration(
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
        self._quic: QuicConnection | None = None
        self._h3: H3Connection | None = None
        self._events: Dict[int, Deque[H3Event]] = defaultdict(deque)
        self._handshake_completed = False

    # data flow

    async def _flush(self) -> None:
        if self._quic is None:
            return

        async with self._write_lock:
            for data, addr in self._quic.datagrams_to_send(now=time.monotonic()):
                await self._network_stream.write(data)

        # TODO: handle quic timer

    async def _read_quic_event(self) -> None:
        """Read exactly one incoming quic event."""
        if self._quic is None:
            return

        async with self._read_lock:
            while True:
                if event := self._quic.next_event():
                    if isinstance(event, quic_events.HandshakeCompleted):
                        self._handshake_completed = True
                    else:
                        for h3_event in self._h3.handle_event(event):
                            if isinstance(h3_event, (HeadersReceived, DataReceived)):
                                self._events[h3_event.stream_id].append(h3_event)
                    break

                data = await self._network_stream.read(0)
                self._quic.receive_datagram(data, self._addr, now=time.monotonic())
                await self._flush()

    async def _receive_stream_h3_event(self, stream_id: int) -> H3Event:
        """Get next H3 event for the stream, read quic events until one is received."""
        while not self._events.get(stream_id):
            await self._read_quic_event()
        return self._events[stream_id].popleft()

    # send request

    async def _write_headers(self, stream_id: int, request: Request) -> None:
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
        end_stream = any(
            k.lower() == b"content-length" or k.lower() == b"transfer-encoding"
            for k, v in request.headers
        )
        self._h3.send_headers(stream_id, headers, end_stream=end_stream)

        await self._flush()

    async def _write_body(self, stream_id: int, request: Request) -> None:
        content_iter = request.stream.__aiter__()
        try:
            next_data_chunk: bytes | None = await content_iter.__anext__()
        except StopAsyncIteration:
            return

        while next_data_chunk:
            data_chunk = next_data_chunk
            next_data_chunk = await content_iter.__anext__()
            self._h3.send_data(
                stream_id=stream_id, data=data_chunk, end_stream=next_data_chunk is None
            )
            await self._flush()

    # receive response

    async def _read_headers(self, stream_id: int) -> Tuple[int, Dict[bytes, bytes]]:
        while True:
            event = await self._receive_stream_h3_event(stream_id)
            if isinstance(event, HeadersReceived):
                break

        status = 200
        headers = {}
        for k, v in event.headers:
            if k == b":status":
                status = int(v)
            if not k.startswith(b":"):
                headers[k] = v

        return (status, headers)

    async def _async_iter_body(self, stream_id: int) -> AsyncIterator[bytes]:
        while True:
            event = await self._receive_stream_h3_event(stream_id)
            if isinstance(event, DataReceived):
                yield event.data
            if event.stream_ended:
                break

    # AsyncConnectionInterface

    async def handle_async_request(self, request: Request) -> Response:
        async with self._connect_lock:
            if self._quic is None:
                self._quic = QuicConnection(configuration=self._quic_configuration)
                self._h3 = H3Connection(self._quic)
                # TODO: connection addr
                self._addr = request.url.host
                self._quic.connect(self._addr, now=time.monotonic())
                # TODO: Figure out how to do 0-RTT, we might not want to flush just now.
                await self._flush()
                while not self._handshake_completed:
                    await self._read_quic_event()

        stream_id = self._quic.get_next_available_stream_id()
        await self._write_headers(stream_id, request)
        await self._write_body(stream_id, request)
        status, headers = await self._read_headers(stream_id)

        # TODO: if stream ended after headers then do `content = None`
        content = self._async_iter_body(stream_id)

        return Response(
            status=status,
            headers=headers,
            content=content,
            extensions={
                "http_version": "HTTP/3",
                "stream_id": stream_id,
            },
        )

    async def aclose(self) -> None:
        if self._quic is not None:
            self._quic.close()
            await self._flush()

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
        try:
            return not self._read_lock._anyio_lock.locked()
        except AttributeError:
            return True

    def is_closed(self) -> bool:
        return False

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        origin = str(self._origin)
        return (
            f"<{class_name} [{origin!r}, {self._state.name}, "
            f"Request Count: {self._request_count}]>"
        )
