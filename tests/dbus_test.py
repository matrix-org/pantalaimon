import pytest
from janus import Queue

from conftest import faker
from pantalaimon.ui import Control, IdCounter
from pantalaimon.config import ServerConfig


class TestClass(object):
    def test_server_account_storing(self, panstore):
        domain = faker.domain_name()

        server_list = [
            ServerConfig(
                domain,
                faker.url("http"),
                faker.ipv4(),
                8080,
            )
        ]

        queue = Queue()
        counter = IdCounter()
        control = Control(queue.sync_q, panstore, server_list, counter)

        assert control.ListServers() == {domain: []}
