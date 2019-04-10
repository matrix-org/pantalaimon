import pdb
import pytest
import tempfile
import shutil

from nio.crypto import OlmAccount
from nio.store import SqliteStore
from pantalaimon.store import PanStore

from faker import Faker
from faker.providers import BaseProvider

from random import choices
from string import digits, ascii_letters, ascii_uppercase


faker = Faker()


class Provider(BaseProvider):
    def mx_id(self):
        return "@{}:{}".format(faker.user_name(), faker.hostname())

    def device_id(self):
        return "".join(choices(ascii_uppercase, k=10))

    def access_token(self):
        return "MDA" + "".join(choices(digits + ascii_letters, k=272))


faker.add_provider(Provider)


@pytest.fixture
def access_token():
    return faker.access_token()


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
        accounts = panstore.get_users()
        # pdb.set_trace()
        assert len(accounts) == 10

    def test_token_saving(self, panstore, access_token):
        accounts = panstore.get_users()
        user_id = accounts[0][0]
        device_id = accounts[0][1]

        panstore.save_access_token(user_id, device_id, access_token)

        token = panstore.load_access_token(user_id, device_id)
        access_token == token
