import asyncio
import shutil
import tempfile
from random import choices
from string import ascii_letters, ascii_uppercase, digits
from urllib.parse import urlparse

import janus
import pytest
from aiohttp import web
from aioresponses import aioresponses
from faker import Faker
from faker.providers import BaseProvider
from nio.crypto import OlmAccount
from nio.store import SqliteStore

from pantalaimon.config import ServerConfig
from pantalaimon.daemon import ProxyDaemon
from pantalaimon.store import ClientInfo, PanStore

faker = Faker()


class Provider(BaseProvider):
    def mx_id(self):
        return "@{}:{}".format(faker.user_name(), faker.hostname())

    def device_id(self):
        return "".join(choices(ascii_uppercase, k=10))

    def access_token(self):
        return "MDA" + "".join(choices(digits + ascii_letters, k=272))

    def client(self):
        return ClientInfo(faker.mx_id(), faker.access_token())


faker.add_provider(Provider)


@pytest.fixture
def access_token():
    return faker.access_token()


@pytest.fixture
def client():
    return faker.client()


@pytest.fixture
def tempdir():
    newpath = tempfile.mkdtemp()
    yield newpath
    shutil.rmtree(newpath)


@pytest.fixture
def panstore(tempdir):
    for _ in range(10):
        store = SqliteStore(
            faker.mx_id(),
            faker.device_id(),
            tempdir,
            "",
            "pan.db"
        )
        account = OlmAccount()
        store.save_account(account)

    store = PanStore(tempdir, "pan.db")
    return store


@pytest.fixture
def panstore_with_users(panstore):
    accounts = panstore.load_all_users()
    user_id, device_id = accounts[0]
    server = "example"

    panstore.save_server_user(server, user_id)

    server2 = "localhost"
    user_id2, device_id2 = accounts[1]
    panstore.save_server_user(server2, user_id2)

    return panstore


@pytest.fixture
async def pan_proxy_server(tempdir, aiohttp_server):
    loop = asyncio.get_event_loop()
    app = web.Application()

    server_name = faker.hostname()

    config = ServerConfig(server_name, urlparse("https://example.org"))

    pan_queue = janus.Queue(loop=loop)
    ui_queue = janus.Queue(loop=loop)

    proxy = ProxyDaemon(
        config.name,
        config.homeserver,
        config,
        tempdir,
        send_queue=pan_queue.async_q,
        recv_queue=ui_queue.async_q,
        proxy=None,
        ssl=False
    )

    app.add_routes([
        web.post("/_matrix/client/r0/login", proxy.login),
        web.get("/_matrix/client/r0/sync", proxy.sync),
        web.get("/_matrix/client/r0/rooms/{room_id}/messages", proxy.messages),
        web.put(
            r"/_matrix/client/r0/rooms/{room_id}/send/{event_type}/{txnid}",
            proxy.send_message
        ),
        web.post("/_matrix/client/r0/user/{user_id}/filter", proxy.filter),
        web.post("/_matrix/client/r0/search", proxy.search),
        web.options("/_matrix/client/r0/search", proxy.search_opts),
    ])

    server = await aiohttp_server(app)

    yield server, proxy

    await proxy.shutdown(app)


@pytest.fixture
def aioresponse():
    with aioresponses(passthrough=["http://127.0.0.1"]) as m:
        yield m
