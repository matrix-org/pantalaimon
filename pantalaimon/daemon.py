#!/usr/bin/env python3

import attr
import asyncio
import aiohttp
import os
import json
import logbook

import click
from ipaddress import ip_address
from urllib.parse import urlparse
from logbook import StderrHandler

from aiohttp import web, ClientSession
from nio import (
    LoginResponse,
    KeysQueryResponse,
    GroupEncryptionError,
    SyncResponse
)
from appdirs import user_data_dir
from json import JSONDecodeError
from multidict import CIMultiDict

from pantalaimon.client import PantaClient
from pantalaimon.log import logger


@attr.s
class Client:
    user_id = attr.ib(type=str)
    access_token = attr.ib(type=str)


@attr.s
class ProxyDaemon:
    homeserver = attr.ib()
    data_dir = attr.ib()
    proxy = attr.ib(default=None)
    ssl = attr.ib(default=None)

    panta_clients = attr.ib(init=False, default=attr.Factory(dict))
    client_info = attr.ib(
        init=False,
        default=attr.Factory(dict),
        type=dict
    )
    default_session = attr.ib(init=False, default=None)

    def get_access_token(self, request):
        # type: (aiohttp.BaseRequest) -> str
        """Extract the access token from the request.

        This method extracts the access token either from the query string or
        from the Authorization header of the request.

        Returns the access token if it was found.
        """
        access_token = request.query.get("access_token", "")

        if not access_token:
            access_token = request.headers.get(
                "Authorization",
                ""
            ).strip("Bearer ")

        return access_token

    async def forward_request(
        self,
        request,
        params=None,
        session=None
    ):
        # type: (aiohttp.BaseRequest, aiohttp.ClientSession) -> str
        """Forward the given request to our configured homeserver.

        Args:
            request (aiohttp.BaseRequest): The request that should be
                forwarded.
            session (aiohttp.ClientSession): The client session that should be
                used to forward the request.
        """

        if not session:
            if not self.default_session:
                self.default_session = ClientSession()
            session = self.default_session

        path = request.path
        method = request.method

        headers = CIMultiDict(request.headers)
        headers.pop("Host", None)

        params = params or request.query

        data = await request.text()

        return await session.request(
            method,
            self.homeserver + path,
            data=data,
            params=params,
            headers=headers,
            proxy=self.proxy,
            ssl=self.ssl
        )

    async def router(self, request):
        """Catchall request router."""
        resp = await self.forward_request(request)

        return(
            await self.to_web_response(resp)
        )

    def _get_login_user(self, body):
        identifier = body.get("identifier", None)

        if identifier:
            user = identifier.get("user", None)

            if not user:
                user = body.get("user", "")
        else:
            user = body.get("user", "")

        return user

    async def start_panta_client(self, access_token, user, user_id, password):
        client = Client(user_id, access_token)
        self.client_info[access_token] = client

        if user_id in self.panta_clients:
            logger.info(f"Background sync client already exists for {user_id},"
                        f" not starting new one")
            return

        panta_client = PantaClient(
            self.homeserver,
            user,
            store_path=self.data_dir,
            ssl=self.ssl,
            proxy=self.proxy
        )
        response = await panta_client.login(password, "pantalaimon")

        if not isinstance(response, LoginResponse):
            await panta_client.close()
            return

        logger.info(f"Succesfully started new background sync client for "
                    f"{user_id}")

        self.panta_clients[user_id] = panta_client

        loop = asyncio.get_event_loop()
        loop.create_task(panta_client.loop())

    async def login(self, request):
        try:
            body = await request.json()
        except JSONDecodeError:
            # After a long debugging session the culprit ended up being aiohttp
            # and a similar bug to
            # https://github.com/aio-libs/aiohttp/issues/2277 but in the server
            # part of aiohttp. The bug is fixed in the latest master of
            # aiohttp.
            # Return 500 here for now since quaternion doesn't work otherwise.
            # After aiohttp 4.0 gets replace this with a 400 M_NOT_JSON
            # response.
            return web.Response(
                status=500,
                text=json.dumps({
                    "errcode": "M_NOT_JSON",
                    "error": "Request did not contain valid JSON."
                })
            )

        user = self._get_login_user(body)
        password = body.get("password", "")

        logger.info(f"New user logging in: {user}")

        response = await self.forward_request(request)

        try:
            json_response = await response.json()
        except JSONDecodeError:
            json_response = None
            pass

        if response.status == 200 and json_response:
            user_id = json_response.get("user_id", None)
            access_token = json_response.get("access_token", None)

            if user_id and access_token:
                logger.info(f"User: {user} succesfully logged in, starting "
                            f"a background sync client.")
                await self.start_panta_client(access_token, user, user_id,
                                              password)

        return web.Response(
            status=response.status,
            text=await response.text()
        )

    @property
    def _missing_token(self):
        return web.Response(
            status=401,
            text=json.dumps({
                "errcode": "M_MISSING_TOKEN",
                "error": "Missing access token."
            })
        )

    @property
    def _unknown_token(self):
        return web.Response(
                status=401,
                text=json.dumps({
                    "errcode": "M_UNKNOWN_TOKEN",
                    "error": "Unrecognised access token."
                })
        )

    @property
    def _not_json(self):
        return web.Response(
            status=400,
            text=json.dumps({
                "errcode": "M_NOT_JSON",
                "error": "Request did not contain valid JSON."
            })
        )

    async def sync(self, request):
        access_token = self.get_access_token(request)

        if not access_token:
            return self._missing_token

        try:
            client_info = self.client_info[access_token]
            client = self.panta_clients[client_info.user_id]
        except KeyError:
            return self._unknown_token

        sync_filter = request.query.get("filter", None)
        timeout = request.query.get("timeout", None)

        try:
            sync_filter = json.loads(sync_filter)
        except (JSONDecodeError, TypeError):
            pass

        if isinstance(sync_filter, int):
            sync_filter = None

        # TODO edit the sync filter to not filter encrypted messages
        # TODO do the same with an uploaded filter

        # room_filter = sync_filter.get("room", None)

        # if room_filter:
        #     timeline_filter = room_filter.get("timeline", None)
        #     if timeline_filter:
        #         types_filter = timeline_filter.get("types", None)

        query = CIMultiDict(request.query)
        query.pop("filter", None)

        response = await self.forward_request(request, query)

        if response.status == 200:
            json_response = await response.json()
            json_response = client.decrypt_sync_body(json_response)

            return web.Response(
                status=response.status,
                text=json.dumps(json_response)
            )
        else:
            return web.Response(
                status=response.status,
                text=await response.text()
            )

    async def to_web_response(self, response):
        return web.Response(status=response.status, text=await response.text())

    async def send_message(self, request):
        access_token = self.get_access_token(request)

        if not access_token:
            return self._missing_token

        try:
            client_info = self.client_info[access_token]
            client = self.panta_clients[client_info.user_id]
        except KeyError:
            return self._unknown_token

        room_id = request.match_info["room_id"]

        try:
            encrypt = client.rooms[room_id].encrypted
        except KeyError:
            return await self.to_web_response(
                await self.forward_request(request)
            )

        if not encrypt:
            return await self.to_web_response(
                await self.forward_request(request)
            )

        msgtype = request.match_info["event_type"]
        txnid = request.match_info["txnid"]

        try:
            content = await request.json()
        except JSONDecodeError:
            return self._not_json

        try:
            response = await client.room_send(room_id, msgtype, content, txnid)
        except GroupEncryptionError:
            await client.share_group_session(room_id)
            response = await client.room_send(room_id, msgtype, content, txnid)

        return web.Response(
            status=response.transport_response.status,
            text=await response.transport_response.text()
        )

    async def shutdown(self, app):
        """Shut the daemon down closing all the client sessions it has.

        This method is called when we shut the whole app down
        """
        for client in self.panta_clients.values():
            await client.loop_stop()
            await client.close()

        if self.default_session:
            await self.default_session.close()
            self.default_session = None


async def init(homeserver, http_proxy, ssl):
    """Initialize the proxy and the http server."""
    data_dir = user_data_dir("pantalaimon", "")

    try:
        os.makedirs(data_dir)
    except OSError:
        pass

    proxy = ProxyDaemon(homeserver, data_dir, proxy=http_proxy, ssl=ssl)

    app = web.Application()
    app.add_routes([
        web.post("/_matrix/client/r0/login", proxy.login),
        web.get("/_matrix/client/r0/sync", proxy.sync),
        web.put(
            r"/_matrix/client/r0/rooms/{room_id}/send/{event_type}/{txnid}",
            proxy.send_message
        ),
    ])
    app.router.add_route("*", "/" + "{proxyPath:.*}", proxy.router)
    app.on_shutdown.append(proxy.shutdown)
    return proxy, app


class URL(click.ParamType):
    name = 'url'

    def convert(self, value, param, ctx):
        try:
            value = urlparse(value)

            if value.scheme not in ('http', 'https'):
                self.fail(f"Invalid URL scheme {value.scheme}. Only HTTP(s) "
                          "URLs are allowed")
            value.port
        except ValueError as e:
            self.fail(f"Error parsing URL: {e}")

        return value


class ipaddress(click.ParamType):
    name = "ipaddress"

    def convert(self, value, param, ctx):
        try:
            value = ip_address(value)
        except ValueError as e:
            self.fail(f"Error parsing ip address: {e}")

        return value


@click.command(
    help=("pantalaimon is a reverse proxy for matrix homeservers that "
          "transparently encrypts and decrypts messages for clients that "
          "connect to pantalaimon.\n\n"
          "HOMESERVER - the homeserver that the daemon should connect to.")
)
@click.option(
    "--proxy",
    type=URL(),
    default=None,
    help="A proxy that will be used to connect to the homeserver."
)
@click.option(
    "-k",
    "--ssl-insecure/--no-ssl-insecure",
    default=False,
    help="Disable SSL verification for the homeserver connection."
)
@click.option(
    "-l",
    "--listen-address",
    type=ipaddress(),
    default=ip_address("127.0.0.1"),
    help=("The listening address for incoming client connections "
          "(default: 127.0.0.1)")
)
@click.option(
    "-p",
    "--listen-port",
    type=int,
    default=8009,
    help="The listening port for incoming client connections (default: 8009)"
)
@click.option("--log-level", type=click.Choice([
    "error",
    "warning",
    "info",
    "debug"
]), default="error")
@click.argument(
    "homeserver",
    type=URL(),
)
def main(
    proxy,
    ssl_insecure,
    listen_address,
    listen_port,
    log_level,
    homeserver
):
    ssl = None if ssl_insecure is False else False

    StderrHandler(level=log_level.upper()).push_application()

    if log_level == "info":
        logger.level = logbook.INFO
    elif log_level == "warning":
        logger.level = logbook.WARNING
    elif log_level == "error":
        logger.level = logbook.ERROR
    elif log_level == "debug":
        logger.level = logbook.DEBUG

    loop = asyncio.get_event_loop()
    proxy, app = loop.run_until_complete(init(
        homeserver.geturl(),
        proxy.geturl() if proxy else None,
        ssl
    ))

    web.run_app(app, host=str(listen_address), port=listen_port)


if __name__ == "__main__":
    main()
