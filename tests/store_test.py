import pdb
import shutil
import tempfile
from random import choices
from string import ascii_letters, ascii_uppercase, digits

import pytest
from faker import Faker
from faker.providers import BaseProvider
from nio.crypto import OlmAccount
from nio.store import SqliteStore

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


class TestClass(object):
    def test_account_loading(self, panstore):
        accounts = panstore.load_all_users()
        # pdb.set_trace()
        assert len(accounts) == 10

    def test_token_saving(self, panstore, access_token):
        accounts = panstore.load_all_users()
        user_id = accounts[0][0]
        device_id = accounts[0][1]

        panstore.save_access_token(user_id, device_id, access_token)

        token = panstore.load_access_token(user_id, device_id)
        access_token == token

    def test_child_clinets_storing(self, panstore, client):
        server = faker.hostname()
        clients = panstore.load_clients(server)
        assert not clients

        panstore.save_client(server, client)

        clients = panstore.load_clients(server)
        assert clients

        client2 = faker.client()
        panstore.save_client(server, client2)
        clients = panstore.load_clients(server)
        assert len(clients) == 2

    def test_server_account_storing(self, panstore):
        accounts = panstore.load_all_users()

        user_id, device_id = accounts[0]
        server = faker.hostname()

        panstore.save_server_user(server, user_id)

        server2 = faker.hostname()
        user_id2, device_id2 = accounts[1]
        panstore.save_server_user(server2, user_id2)

        server_users = panstore.load_users(server)
        assert (user_id, device_id) in server_users
        assert (user_id2, device_id2) not in server_users
