#!/usr/bin/env python3

import attr
import asyncio
import aiohttp
import os
import json

from aiohttp import web, ClientSession
from nio import (
    AsyncClient,
    LoginResponse,
    RoomEncryptedEvent,
    MegolmEvent,
    EncryptionError
)
from appdirs import user_data_dir
from json import JSONDecodeError

HOMESERVER = "https://localhost:8448"


@attr.s
class ProxyDaemon:
    homeserver = attr.ib()
    proxy = attr.ib(default=None)
    ssl = attr.ib(default=None)

    client_sessions = attr.ib(init=False, default=attr.Factory(dict))
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

    async def router(self, request):
        path = request.path
        method = request.method
        data = await request.text()
        headers = request.headers
        params = request.query

        print(method, path, data)

        session = None

        token = self.get_access_token(request)
        client = self.client_sessions.get(token, None)

        if client:
            session = client.client_session

        if not session:
            if not self.default_session:
                self.default_session = ClientSession()
            session = self.default_session

        async with session.request(
            method,
            HOMESERVER + path,
            data=data,
            params=params,
            headers=headers,
            proxy=self.proxy,
            ssl=False
        ) as resp:
            print("Returning resp {}".format(resp))
            return(web.Response(text=await resp.text()))

    async def login(self, request):
        try:
            body = await request.json()
        except JSONDecodeError:
            # TODO what to do here, quaternion retries the login if we raise an
            # exception here, throws an error if we send out an 400 and hangs
            # if we forward it to the router() method.
            print("JSON ERROR IN LOGIN")
            raise
            # return web.Response(
            #     status=400,
            #     text=json.dumps({
            #         "errcode": "M_NOT_JSON",
            #         "error": "Request did not contain valid JSON."
            #     })
            # )

        print("Login request")

        identifier = body.get("identifier", None)

        if identifier:
            user = identifier.get("user", None)

            if not user:
                user = body.get("user", "")
        else:
            user = body.get("user", "")

        password = body.get("password", "")
        device_id = body.get("device_id", "")
        device_name = body.get("initial_device_display_name", "")

        store_path = user_data_dir("pantalaimon", "")

        try:
            os.makedirs(store_path)
        except OSError:
            pass

        client = AsyncClient(
            HOMESERVER,
            user,
            device_id,
            store_path=store_path,
            ssl=self.ssl,
            proxy=self.proxy
        )

        print("Logging in")

        response = await client.login(password, device_name)

        if isinstance(response, LoginResponse):
            self.client_sessions[response.access_token] = client
        else:
            await client.close()

        return web.Response(
            status=response.transport_response.status,
            text=await response.transport_response.text()
        )

    async def sync(self, request):
        access_token = self.get_access_token(request)

        if not access_token:
            return web.Response(
                status=401,
                text=json.dumps({
                    "errcode": "M_MISSING_TOKEN",
                    "error": "Missing access token."
                })
            )

        try:
            client = self.client_sessions[access_token]
        except KeyError:
            return web.Response(
                status=401,
                text=json.dumps({
                    "errcode": "M_UNKNOWN_TOKEN",
                    "error": "Unrecognised access token."
                })
            )

        sync_filter = request.query.get("filter", None)
        timeout = request.query.get("timeout", None)

        try:
            sync_filter = json.loads(sync_filter)
        except (JSONDecodeError, TypeError):
            pass

        # TODO edit the sync filter to not filter encrypted messages
        # TODO do the same with an uploaded filter

        # room_filter = sync_filter.get("room", None)

        # if room_filter:
        #     timeline_filter = room_filter.get("timeline", None)
        #     if timeline_filter:
        #         types_filter = timeline_filter.get("types", None)

        response = await client.sync(timeout, sync_filter)

        if client.should_upload_keys:
            await client.keys_upload()

        if client.should_query_keys:
            await client.keys_query()

        json_response = await response.transport_response.json()

        for room_id, room_dict in json_response["rooms"]["join"].items():
            if not client.rooms[room_id].encrypted:
                print("Room {} not encrypted skipping...".format(
                    client.rooms[room_id].display_name
                ))
                continue

            for event in room_dict["timeline"]["events"]:
                if event["type"] != "m.room.encrypted":
                    print("Event not encrypted skipping...")
                    continue

                parsed_event = RoomEncryptedEvent.parse_event(event)
                parsed_event.room_id = room_id

                if not isinstance(parsed_event, MegolmEvent):
                    print("Not a megolm event.")
                    continue

                try:
                    decrypted_event = client.decrypt_event(parsed_event)
                    print("Decrypted event: {}".format(decrypted_event))
                    event["type"] = "m.room.message"

                    # TODO support other event types
                    event["content"] = {
                        "msgtype": "m.text",
                        "body": decrypted_event.body
                    }

                    if decrypted_event.formatted_body:
                        event["content"]["formatted_body"] = (
                            decrypted_event.formatted_body)
                        event["content"]["format"] = decrypted_event.format

                    event["decrypted"] = True
                    event["verified"] = decrypted_event.verified

                except EncryptionError as e:
                    print("ERROR decrypting {}".format(e))
                    continue

        return web.Response(
            status=response.transport_response.status,
            text=json.dumps(json_response)
        )

    async def shutdown(self, app):
        """Shut the daemon down closing all the client sessions it has.

        This method is called when we shut the whole app down
        """
        for client in self.client_sessions.values():
            await client.close()

        if self.default_session:
            await self.default_session.close()
            self.default_session = None


async def init():
    """Initialize the proxy and the http server."""
    proxy = ProxyDaemon(HOMESERVER, proxy="http://localhost:8080", ssl=False)
    app = web.Application()
    app.add_routes([
        web.post("/_matrix/client/r0/login", proxy.login),
        web.get("/_matrix/client/r0/sync", proxy.sync),
    ])
    app.router.add_route('*', "/" + '{proxyPath:.*}', proxy.router)
    app.on_shutdown.append(proxy.shutdown)
    return proxy, app


def main():
    loop = asyncio.get_event_loop()
    proxy, app = loop.run_until_complete(init())

    web.run_app(app, host="127.0.0.1", port=8081)


if __name__ == "__main__":
    main()
