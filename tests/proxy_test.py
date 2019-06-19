import asyncio
import re
import json

from aiohttp import web

from conftest import faker


class TestClass(object):
    @staticmethod
    def _load_response(filename):
        with open(filename) as f:
            return json.loads(f.read(), encoding="utf-8")

    @property
    def login_response(self):
        return {
            "access_token": "abc123",
            "device_id": "GHTYAJCE",
            "home_server": "example.org",
            "user_id": "@example:example.org"
        }

    @property
    def sync_response(self):
        return self._load_response("tests/data/sync.json")

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

    async def test_pan_client_sync(self, pan_proxy_server, aiohttp_client, aioresponse):
        server, daemon = pan_proxy_server

        client = await aiohttp_client(server)

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response,
            repeat=True
        )

        sync_url = re.compile(
            r'^https://example\.org/_matrix/client/r0/sync\?access_token=.*'
        )

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_response,
        )

        await client.post(
            "/_matrix/client/r0/login",
            json={
                "type": "m.login.password",
                "user": "example",
                "password": "wordpass",
            }
        )

        # Check that the pan client started to sync after logging in.
        pan_client = list(daemon.pan_clients.values())[0]
        assert len(pan_client.rooms) == 1
