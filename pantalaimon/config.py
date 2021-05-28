# Copyright 2019 The Matrix.org Foundation CIC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import configparser
import os
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Union
from urllib.parse import ParseResult, urlparse

import attr
import logbook


class PanConfigParser(configparser.ConfigParser):
    def __init__(self):
        super().__init__(
            default_section="Default",
            defaults={
                "SSL": "True",
                "IgnoreVerification": "False",
                "ListenAddress": "localhost",
                "ListenPort": "8009",
                "LogLevel": "warnig",
                "Notifications": "on",
                "UseKeyring": "yes",
                "SearchRequests": "off",
                "IndexEncryptedOnly": "True",
                "IndexingBatchSize": "100",
                "HistoryFetchDelay": "3000",
                "DebugEncryption": "False",
                "DropOldKeys": "False",
            },
            converters={
                "address": parse_address,
                "url": parse_url,
                "loglevel": parse_log_level,
            },
        )


def parse_address(value):
    # type: (str) -> Union[IPv4Address, IPv6Address]
    if value == "localhost":
        return ip_address("127.0.0.1")

    return ip_address(value)


def parse_url(v):
    # type: (str) -> ParseResult
    value = urlparse(v)

    if value.scheme not in ("http", "https"):
        raise ValueError(
            f"Invalid URL scheme {value.scheme}. " f"Only HTTP(s) URLs are allowed"
        )
    value.port

    return value


def parse_log_level(value):
    # type: (str) -> logbook
    value = value.lower()

    if value == "info":
        return logbook.INFO
    elif value == "warning":
        return logbook.WARNING
    elif value == "error":
        return logbook.ERROR
    elif value == "debug":
        return logbook.DEBUG

    return logbook.WARNING


class PanConfigError(Exception):
    """Pantalaimon configuration error."""

    pass


@attr.s
class ServerConfig:
    """Server configuration.

    Args:
        name (str): A unique user chosen name that identifies the server.
        homeserver (ParseResult): The URL of the Matrix homeserver that we want
            to forward requests to.
        listen_address (str): The local address where pantalaimon will listen
            for connections.
        listen_port (int): The port where pantalaimon will listen for
            connections.
        proxy (ParseResult):
            A proxy that the daemon should use when making connections to the
            homeserver.
        ssl (bool): Enable or disable SSL for the connection between
            pantalaimon and the homeserver.
        ignore_verification (bool): Enable or disable device verification for
            E2E encrypted messages.
        keyring (bool): Enable or disable the OS keyring for the storage of
            access tokens.
        search_requests (bool): Enable or disable aditional Homeserver requests
            for the search API endpoint.
        index_encrypted_only (bool): Enable or disable message indexing fro
            non-encrypted rooms.
        indexing_batch_size (int): The number of messages that should be
            requested from the Homeserver when we fetch and index messages from
            the room history.
        history_fetch_delay (int): The delay between room history fetching
            requests in seconds.
        drop_old_keys (bool): Should Pantalaimon only keep the most recent
            decryption key around.
    """

    name = attr.ib(type=str)
    homeserver = attr.ib(type=ParseResult)
    listen_address = attr.ib(
        type=Union[IPv4Address, IPv6Address], default=ip_address("127.0.0.1")
    )
    listen_port = attr.ib(type=int, default=8009)
    proxy = attr.ib(type=str, default="")
    ssl = attr.ib(type=bool, default=True)
    ignore_verification = attr.ib(type=bool, default=False)
    keyring = attr.ib(type=bool, default=True)
    search_requests = attr.ib(type=bool, default=False)
    index_encrypted_only = attr.ib(type=bool, default=True)
    indexing_batch_size = attr.ib(type=int, default=100)
    history_fetch_delay = attr.ib(type=int, default=3)
    drop_old_keys = attr.ib(type=bool, default=False)


@attr.s
class PanConfig:
    """Pantalaimon configuration.

    Args:
        config_path (str): The path where we should search for a configuration
            file.
        filename (str): The name of the file that we should read.
        debug_encryption (bool): Should debug logs be enabled for the Matrix
            encryption support.
    """

    config_file = attr.ib()

    log_level = attr.ib(default=None)
    debug_encryption = attr.ib(type=bool, default=None)
    notifications = attr.ib(default=None)
    servers = attr.ib(init=False, default=attr.Factory(dict))

    def read(self):
        """Read the configuration file.

        Raises OSError if the file can't be read or PanConfigError if there is
        a syntax error with the config file.
        """
        config = PanConfigParser()
        try:
            config.read(os.path.abspath(self.config_file))
        except configparser.Error as e:
            raise PanConfigError(e)

        if self.log_level is None:
            self.log_level = config["Default"].getloglevel("LogLevel")

        if self.notifications is None:
            self.notifications = config["Default"].getboolean("Notifications")

        self.debug_encryption = config["Default"].getboolean("DebugEncryption")

        listen_set = set()

        try:
            for section_name, section in config.items():

                if section_name == "Default":
                    continue

                homeserver = section.geturl("Homeserver")

                if not homeserver:
                    raise PanConfigError(
                        f"Homserver is not set for " f"section {section_name}"
                    )

                listen_address = section.getaddress("ListenAddress")
                listen_port = section.getint("ListenPort")
                ssl = section.getboolean("SSL")
                ignore_verification = section.getboolean("IgnoreVerification")
                keyring = section.getboolean("UseKeyring")
                proxy = section.geturl("Proxy")
                search_requests = section.getboolean("SearchRequests")
                index_encrypted_only = section.getboolean("IndexEncryptedOnly")

                indexing_batch_size = section.getint("IndexingBatchSize")

                if not 1 < indexing_batch_size <= 1000:
                    raise PanConfigError(
                        "The indexing batch size needs to be "
                        "a positive integer between 1 and "
                        "1000"
                    )

                history_fetch_delay = section.getint("HistoryFetchDelay")

                if not 100 < history_fetch_delay <= 10000:
                    raise PanConfigError(
                        "The history fetch delay needs to be "
                        "a positive integer between 100 and "
                        "10000"
                    )

                listen_tuple = (listen_address, listen_port)

                if listen_tuple in listen_set:
                    raise PanConfigError(
                        f"The listen address/port combination"
                        f" for section {section_name} was "
                        f"already defined before."
                    )
                listen_set.add(listen_tuple)
                drop_old_keys = section.getboolean("DropOldKeys")

                server_conf = ServerConfig(
                    section_name,
                    homeserver,
                    listen_address,
                    listen_port,
                    proxy,
                    ssl,
                    ignore_verification,
                    keyring,
                    search_requests,
                    index_encrypted_only,
                    indexing_batch_size,
                    history_fetch_delay / 1000,
                    drop_old_keys,
                )

                self.servers[section_name] = server_conf

        except ValueError as e:
            raise PanConfigError(e)
