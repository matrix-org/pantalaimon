import pytest
from janus import Queue

from conftest import faker
from pantalaimon.ui import Control, Devices, IdCounter


class TestClass(object):
    def test_server_account_storing(self):
        users = [(faker.mx_id(), faker.device_id())]

        queue = Queue()
        counter = IdCounter()
        control = Control(queue.sync_q, users, counter)

        assert control.ListUsers() == users
