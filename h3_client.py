import argparse
import asyncio
import logging
import time

import aioquic

from httpcore import AsyncConnectionPool, Request, Response


logging.basicConfig(level=logging.INFO)
logging.getLogger("aioquic").setLevel(logging.DEBUG)
logging.getLogger("httpcore").setLevel(logging.DEBUG)
logging.getLogger("quic").setLevel(logging.DEBUG)


USER_AGENT = f"httcore; aioquic/{aioquic.__version__}"


async def show_response(response: Response) -> None:
    print("Status")
    print(f"  {response.status}")

    # print("Headers")
    # for k, v in response.headers:
    #     print(f"  {k}: {v}")

    # print("Extensions")
    # for k, v in response.extensions.items():
    #     print(f"  {k}: {v}")

    # content = await response.aread()
    # print("Content")
    # print(f"  {len(content)} bytes of data")
    # print(content.decode("utf8"))


async def main():
    async with AsyncConnectionPool(http2=True, http3=True) as pool:
        request = Request(
            "GET",
            "https://www.google.com/",
            headers={
                b"host": b"www.google.com",
                b"accept": b"text/html",
                b"user-agent": USER_AGENT.encode("ascii"),
            },
        )

        # First request will use HTTP/2
        response = await pool.handle_async_request(request)
        await show_response(response)

        # The rest is going to use HTTP/3
        responses: list[Response] = []

        async def request_and_show():
            response = await pool.handle_async_request(request)
            await response.aread()
            responses.append(response)

        t0 = time.monotonic()
        async with asyncio.TaskGroup() as tg:
            for _ in range(4):
                tg.create_task(request_and_show())
        t_elapsed = time.monotonic() - t0

        total_bytes = 0
        for response in responses:
            print("\n")
            await show_response(response)
            total_bytes += len(response._content)

        print("\n")
        print(
            f"downloaded >{total_bytes/1024:.2f} kbytes in {t_elapsed:.3f} seconds (avg >{total_bytes/t_elapsed * 8 / 1024 / 1024:.3f} Mbps)"
        )

if __name__ == "__main__":
    asyncio.run(main())
