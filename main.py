#!/usr/bin/env python3

import attr
import asyncio

from aiohttp import web, ClientSession
from nio import AsyncClient, LoginResponse

HOMESERVER = "https://localhost:8448"


@attr.s
class ProxyDaemon:
    homeserver = attr.ib()
    proxy = attr.ib(default=None)
    ssl = attr.ib(default=None)

    client_sessions = attr.ib(init=False, default=attr.Factory(dict))
    default_session = attr.ib(init=False, default=None)

    async def router(self, request):
        path = request.path
        method = request.method
        data = await request.text()

        print(method, path, data)

        if not self.default_session:
            self.default_session = ClientSession()

        async with self.default_session.request(
            method,
            HOMESERVER + path,
            data=data,
            proxy=self.proxy,
            ssl=False
        ) as resp:
            return(web.Response(text=await resp.text()))

    async def login(self, request):
        json = await request.json()

        user = json.get("user", "")
        password = json.get("password", "")
        device_id = json.get("device_id", "")
        device_name = json.get("initial_device_display_name", "")

        client = AsyncClient(
            HOMESERVER,
            user,
            device_id,
            ssl=self.ssl,
            proxy=self.proxy
        )

        print("Logging in")

        response = await client.login(password, device_name)

        if isinstance(response, LoginResponse):
            self.client_sessions[response.access_token] = client

        return web.Response(
            status=response.transport_response.status,
            text=await response.transport_response.text()
        )

    async def sync(self, request):
        return web.Response(
            status=405,
            text="Not implemented"
        )


async def init():
    """Initialize the proxy and the http server."""
    proxy = ProxyDaemon(HOMESERVER, proxy="http://localhost:8080", ssl=False)
    app = web.Application()
    app.add_routes([
        web.post("/_matrix/client/r0/login", proxy.login),
        web.get("/_matrix/client/r0/sync", proxy.sync),
    ])
    app.router.add_route('*', "/" + '{proxyPath:.*}', proxy.router)
    return proxy, app


def main():
    loop = asyncio.get_event_loop()
    proxy, app = loop.run_until_complete(init())

    web.run_app(app, host="127.0.0.1", port=8081)


if __name__ == "__main__":
    main()
