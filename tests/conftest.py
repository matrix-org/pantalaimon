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
