import asyncio
from aiohttp import web

from conftest import faker


class TestClass(object):

    @property
    def login_response(self):
        return {
            "access_token": "abc123",
            "device_id": "GHTYAJCE",
            "home_server": "example.org",
            "user_id": "@example:example.org"
        }

    async def test_daemon_start(self, pan_proxy_server, aiohttp_client, aioresponse):
        server, daemon = pan_proxy_server

        client = await aiohttp_client(server)

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response,
            repeat=True
        )

        assert not daemon.pan_clients

        resp = await client.post(
            "/_matrix/client/r0/login",
            json={
                "type": "m.login.password",
                "user": "example",
                "password": "wordpass",
            }
        )

        assert resp.status == 200

        assert len(daemon.pan_clients) == 1

        pan_client = list(daemon.pan_clients.values())[0]

        # Check if our pan client is logged in
        assert pan_client.logged_in
        # Check if our pan client has a sync loop started
        assert pan_client.task
