import os
import re

import janus
import pytest
from nio import (
    LoginResponse,
    KeysQueryResponse,
    KeysUploadResponse,
    SyncResponse,
)
from nio.crypto import Olm, OlmDevice
from nio.store import SqliteMemoryStore
from nio.store import SqliteStore

from pantalaimon.client import PanClient
from pantalaimon.config import ServerConfig
from pantalaimon.store import PanStore
from pantalaimon.index import INDEXING_ENABLED

TEST_ROOM_ID = "!SVkFJHzfwvuaIEawgC:localhost"
TEST_ROOM2 = "!testroom:localhost"

ALICE_ID = "@alice:example.org"


@pytest.fixture
async def client(tmpdir, loop):
    store = PanStore(tmpdir)
    queue = janus.Queue()
    conf = ServerConfig("example", "https://exapmle.org")
    conf.history_fetch_delay = 0.1

    store.save_server_user("example", "@example:example.org")

    pan_client = PanClient(
        "example",
        store,
        conf,
        "https://example.org",
        queue.async_q,
        "@example:example.org",
        "DEVICEID",
        tmpdir,
        store_class=SqliteStore,
    )

    yield pan_client

    await pan_client.close()


class TestClass(object):
    @property
    def login_response(self):
        return LoginResponse.from_dict(
            {
                "access_token": "abc123",
                "device_id": "DEVICEID",
                "home_server": "example.org",
                "user_id": "@example:example.org",
            }
        )

    @property
    def initial_sync_response(self):
        return {
            "device_one_time_keys_count": {},
            "next_batch": "s526_47314_0_7_1_1_1_11444_1",
            "device_lists": {"changed": ["@example:example.org"], "left": []},
            "rooms": {
                "invite": {},
                "join": {
                    "!SVkFJHzfwvuaIEawgC:localhost": {
                        "account_data": {"events": []},
                        "ephemeral": {"events": []},
                        "state": {
                            "events": [
                                {
                                    "content": {
                                        "avatar_url": None,
                                        "displayname": "example",
                                        "membership": "join",
                                    },
                                    "event_id": "$151800140517rfvjc:localhost",
                                    "membership": "join",
                                    "origin_server_ts": 1518001405556,
                                    "sender": "@example:localhost",
                                    "state_key": "@example:localhost",
                                    "type": "m.room.member",
                                    "unsigned": {
                                        "age": 2970366338,
                                        "replaces_state": "$151800111315tsynI:localhost",
                                    },
                                },
                                {
                                    "content": {"history_visibility": "shared"},
                                    "event_id": "$15139375515VaJEY:localhost",
                                    "origin_server_ts": 1513937551613,
                                    "sender": "@example:localhost",
                                    "state_key": "",
                                    "type": "m.room.history_visibility",
                                    "unsigned": {"age": 7034220281},
                                },
                                {
                                    "content": {"creator": "@example:localhost"},
                                    "event_id": "$15139375510KUZHi:localhost",
                                    "origin_server_ts": 1513937551203,
                                    "sender": "@example:localhost",
                                    "state_key": "",
                                    "type": "m.room.create",
                                    "unsigned": {"age": 7034220691},
                                },
                                {
                                    "content": {"aliases": ["#tutorial:localhost"]},
                                    "event_id": "$15139375516NUgtD:localhost",
                                    "origin_server_ts": 1513937551720,
                                    "sender": "@example:localhost",
                                    "state_key": "localhost",
                                    "type": "m.room.aliases",
                                    "unsigned": {"age": 7034220174},
                                },
                                {
                                    "content": {"topic": "\ud83d\ude00"},
                                    "event_id": "$151957878228ssqrJ:localhost",
                                    "origin_server_ts": 1519578782185,
                                    "sender": "@example:localhost",
                                    "state_key": "",
                                    "type": "m.room.topic",
                                    "unsigned": {
                                        "age": 1392989709,
                                        "prev_content": {"topic": "test"},
                                        "prev_sender": "@example:localhost",
                                        "replaces_state": "$151957069225EVYKm:localhost",
                                    },
                                },
                                {
                                    "content": {
                                        "ban": 50,
                                        "events": {
                                            "m.room.avatar": 50,
                                            "m.room.canonical_alias": 50,
                                            "m.room.history_visibility": 100,
                                            "m.room.name": 50,
                                            "m.room.power_levels": 100,
                                        },
                                        "events_default": 0,
                                        "invite": 0,
                                        "kick": 50,
                                        "redact": 50,
                                        "state_default": 50,
                                        "users": {"@example:localhost": 100},
                                        "users_default": 0,
                                    },
                                    "event_id": "$15139375512JaHAW:localhost",
                                    "origin_server_ts": 1513937551359,
                                    "sender": "@example:localhost",
                                    "state_key": "",
                                    "type": "m.room.power_levels",
                                    "unsigned": {"age": 7034220535},
                                },
                                {
                                    "content": {"alias": "#tutorial:localhost"},
                                    "event_id": "$15139375513VdeRF:localhost",
                                    "origin_server_ts": 1513937551461,
                                    "sender": "@example:localhost",
                                    "state_key": "",
                                    "type": "m.room.canonical_alias",
                                    "unsigned": {"age": 7034220433},
                                },
                                {
                                    "content": {
                                        "avatar_url": None,
                                        "displayname": "example2",
                                        "membership": "join",
                                    },
                                    "event_id": "$152034824468gOeNB:localhost",
                                    "membership": "join",
                                    "origin_server_ts": 1520348244605,
                                    "sender": "@example2:localhost",
                                    "state_key": "@example2:localhost",
                                    "type": "m.room.member",
                                    "unsigned": {
                                        "age": 623527289,
                                        "prev_content": {"membership": "leave"},
                                        "prev_sender": "@example:localhost",
                                        "replaces_state": "$152034819067QWJxM:localhost",
                                    },
                                },
                                {
                                    "content": {
                                        "algorithm": "m.megolm.v1.aes-sha2",
                                        "rotation_period_ms": 604800000,
                                        "rotation_period_msgs": 100,
                                    },
                                    "event_id": "$143273582443PhrSn:example.org",
                                    "origin_server_ts": 1432735824653,
                                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                                    "sender": "@example:example.org",
                                    "state_key": "",
                                    "type": "m.room.encryption",
                                    "unsigned": {"age": 1234},
                                },
                            ]
                        },
                        "timeline": {
                            "events": [
                                {
                                    "content": {
                                        "body": "baba",
                                        "format": "org.matrix.custom.html",
                                        "formatted_body": "<strong>baba</strong>",
                                        "msgtype": "m.text",
                                    },
                                    "event_id": "$152037280074GZeOm:localhost",
                                    "origin_server_ts": 1520372800469,
                                    "sender": "@example:localhost",
                                    "type": "m.room.message",
                                    "unsigned": {"age": 598971425},
                                }
                            ],
                            "limited": True,
                            "prev_batch": "t392-516_47314_0_7_1_1_1_11444_1",
                        },
                        "unread_notifications": {
                            "highlight_count": 0,
                            "notification_count": 11,
                        },
                    }
                },
                "leave": {},
            },
            "to_device": {"events": []},
        }

    @property
    def keys_upload_response(self):
        return {"one_time_key_counts": {"curve25519": 10, "signed_curve25519": 20}}

    @property
    def keys_query_response(self):
        return {
            "device_keys": {
                "@alice:example.org": {
                    "JLAFKJWSCS": {
                        "algorithms": [
                            "m.olm.v1.curve25519-aes-sha2",
                            "m.megolm.v1.aes-sha2",
                        ],
                        "device_id": "JLAFKJWSCS",
                        "user_id": "@alice:example.org",
                        "keys": {
                            "curve25519:JLAFKJWSCS": "wjLpTLRqbqBzLs63aYaEv2Boi6cFEbbM/sSRQ2oAKk4",
                            "ed25519:JLAFKJWSCS": "nE6W2fCblxDcOFmeEtCHNl8/l8bXcu7GKyAswA4r3mM",
                        },
                        "signatures": {
                            "@alice:example.org": {
                                "ed25519:JLAFKJWSCS": "m53Wkbh2HXkc3vFApZvCrfXcX3AI51GsDHustMhKwlv3TuOJMj4wistcOTM8q2+e/Ro7rWFUb9ZfnNbwptSUBA"
                            }
                        },
                    }
                }
            },
            "failures": {},
        }

    @property
    def empty_sync(self):
        return {
            "account_data": {"events": []},
            "device_lists": {"changed": [], "left": []},
            "device_one_time_keys_count": {"signed_curve25519": 50},
            "groups": {"invite": {}, "join": {}, "leave": {}},
            "next_batch": "s1059_133339_44_763_246_1_586_12411_1",
            "presence": {"events": []},
            "rooms": {"invite": {}, "join": {}, "leave": {}},
            "to_device": {"events": []},
        }

    @property
    def messages_response(self):
        return {
            "chunk": [
                {
                    "age": 1042,
                    "content": {"body": "hello world", "msgtype": "m.text"},
                    "event_id": "$1444812213350496Caaaa:example.com",
                    "origin_server_ts": 1444812213737,
                    "room_id": "!Xq3620DUiqCaoxq:example.com",
                    "sender": "@alice:example.com",
                    "type": "m.room.message",
                },
                {
                    "age": 20123,
                    "content": {"body": "the world is big", "msgtype": "m.text"},
                    "event_id": "$1444812213350496Cbbbb:example.com",
                    "origin_server_ts": 1444812194656,
                    "room_id": "!Xq3620DUiqCaoxq:example.com",
                    "sender": "@alice:example.com",
                    "type": "m.room.message",
                },
                {
                    "age": 50789,
                    "content": {"name": "New room name"},
                    "event_id": "$1444812213350496Ccccc:example.com",
                    "origin_server_ts": 1444812163990,
                    "prev_content": {"name": "Old room name"},
                    "room_id": "!Xq3620DUiqCaoxq:example.com",
                    "sender": "@alice:example.com",
                    "state_key": "",
                    "type": "m.room.name",
                },
            ],
            "end": "t47409-4357353_219380_26003_2265",
            "start": "t47429-4392820_219380_26003_2265",
        }

    @property
    def empty_messages(self):
        return {
            "chunk": [],
            "end": "t47429-4392820_219380_26003_2277",
            "start": "t47409-4357353_219380_26003_2265",
        }

    async def test_login(self, client):
        await client.receive_response(self.login_response)
        assert client.logged_in

    async def test_start_loop(self, client, aioresponse):
        sync_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/sync\?access_token=.*"
        )

        aioresponse.get(
            sync_url, status=200, payload=self.initial_sync_response, repeat=True
        )

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/upload?access_token=abc123",
            status=200,
            payload=self.keys_upload_response,
            repeat=True,
        )

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/query?access_token=abc123",
            status=200,
            payload=self.keys_query_response,
            repeat=True,
        )

        await client.receive_response(self.login_response)

        # Set a big history fetch delay so it doesn't consume the fetch tasks.
        client.pan_conf.history_fetch_delay = 10
        client.start_loop(100)

        # Sync tasks are done after we get a sync event so wait for two of them
        await client.synced.wait()
        await client.synced.wait()

        # Make sure that we have only a single history fetch task for the
        # single room we have
        assert not client.history_fetch_queue.empty()
        assert client.history_fetch_queue.qsize() == 1

        # Do another round to be sure we don't get more tasks than necessary.
        await client.synced.wait()
        assert client.history_fetch_queue.qsize() == 1

        await client.loop_stop()

    async def test_history_fetching_tasks(self, client, aioresponse, loop):
        if not INDEXING_ENABLED:
            pytest.skip("Indexing needs to be enabled to test this")

        sync_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/sync\?access_token=.*"
        )

        aioresponse.get(
            sync_url, status=200, payload=self.initial_sync_response,
        )

        aioresponse.get(sync_url, status=200, payload=self.empty_sync, repeat=True)

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/upload?access_token=abc123",
            status=200,
            payload=self.keys_upload_response,
            repeat=True,
        )

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/query?access_token=abc123",
            status=200,
            payload=self.keys_query_response,
            repeat=True,
        )

        messages_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/rooms/{}/messages\?.*".format(
                TEST_ROOM_ID
            )
        )

        aioresponse.get(messages_url, status=200, payload=self.messages_response)

        aioresponse.get(
            messages_url, status=200, payload=self.empty_messages, repeat=True
        )

        await client.receive_response(self.login_response)

        client.start_loop(100)

        await client.new_fetch_task.wait()

        # Load the currently waiting task
        tasks = client.pan_store.load_fetcher_tasks(client.server_name, client.user_id)
        assert len(tasks) == 1

        # Check that the task is our prev_batch from the sync resposne
        assert tasks[0].room_id == TEST_ROOM_ID
        assert tasks[0].token == "t392-516_47314_0_7_1_1_1_11444_1"

        # Let's wait for the next fetch task
        await client.new_fetch_task.wait()

        tasks = client.pan_store.load_fetcher_tasks(client.server_name, client.user_id)
        assert len(tasks) == 1

        # Check that the task is our end token from the messages resposne
        assert tasks[0].room_id == TEST_ROOM_ID
        assert tasks[0].token == "t47409-4357353_219380_26003_2265"

        # Wait for the next fetch loop iteration.
        await client.fetch_loop_event.wait()

        tasks = client.pan_store.load_fetcher_tasks(client.server_name, client.user_id)
        # Check that there are no more tasks since we reached the start of the
        # room timeline.
        assert not tasks

        await client.loop_stop()

    async def test_history_fetching_resume(self, client, aioresponse, loop):
        if not INDEXING_ENABLED:
            pytest.skip("Indexing needs to be enabled to test this")

        sync_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/sync\?access_token=.*"
        )

        aioresponse.get(
            sync_url, status=200, payload=self.initial_sync_response,
        )

        aioresponse.get(sync_url, status=200, payload=self.empty_sync, repeat=True)

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/upload?access_token=abc123",
            status=200,
            payload=self.keys_upload_response,
            repeat=True,
        )

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/query?access_token=abc123",
            status=200,
            payload=self.keys_query_response,
            repeat=True,
        )

        messages_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/rooms/{}/messages\?.*".format(
                TEST_ROOM_ID
            )
        )

        aioresponse.get(messages_url, status=200, payload=self.messages_response)

        aioresponse.get(
            messages_url, status=200, payload=self.empty_messages, repeat=True
        )

        await client.receive_response(self.login_response)

        client.start_loop(100)

        await client.new_fetch_task.wait()
        await client.new_fetch_task.wait()

        await client.loop_stop()

        index_path = os.path.join(client.store_path, client.server_name, client.user_id)

        # Remove the lock file since the GC won't do it for us
        writer_lock = os.path.join(index_path, ".tantivy-writer.lock")
        os.remove(writer_lock)

        # Create a new client
        client2 = PanClient(
            client.server_name,
            client.pan_store,
            client.pan_conf,
            client.homeserver,
            client.queue,
            client.user_id,
            client.device_id,
            client.store_path,
        )
        client2.user_id = client.user_id
        client2.access_token = client.access_token

        tasks = client2.pan_store.load_fetcher_tasks(
            client2.server_name, client2.user_id
        )
        assert len(tasks) == 1

        # Check that the task is our end token from the messages resposne
        assert tasks[0].room_id == TEST_ROOM_ID
        assert tasks[0].token == "t47409-4357353_219380_26003_2265"

        client2.start_loop(100)

        # We wait for two events here because the event gets fired at the start
        # of the loop
        await client2.fetch_loop_event.wait()
        await client2.fetch_loop_event.wait()

        tasks = client2.pan_store.load_fetcher_tasks(
            client2.server_name, client2.user_id
        )
        # Check that there are no more tasks since we reached the start of the
        # room timeline.
        assert not tasks

        await client2.loop_stop()

    async def test_room_key_on_client_sync_stream(self, client):
        await client.receive_response(self.login_response)
        await client.receive_response(
            SyncResponse.from_dict(self.initial_sync_response)
        )
        await client.receive_response(
            KeysUploadResponse.from_dict(self.keys_upload_response)
        )
        await client.receive_response(
            KeysQueryResponse.from_dict(self.keys_query_response)
        )

        BobId = "@bob:example.org"
        Bob_device = "BOBDEVICE"

        bob_olm = Olm(BobId, Bob_device, SqliteMemoryStore("ephemeral", "DEVICEID"))

        alice_device = OlmDevice(
            client.user_id, client.device_id, client.olm.account.identity_keys
        )

        bob_device = OlmDevice(
            bob_olm.user_id, bob_olm.device_id, bob_olm.account.identity_keys
        )

        client.olm.device_store.add(bob_device)
        bob_olm.device_store.add(alice_device)
        bob_olm.store.save_device_keys(
            {client.user_id: {client.device_id: alice_device}}
        )

        client.olm.account.generate_one_time_keys(1)
        one_time = list(client.olm.account.one_time_keys["curve25519"].values())[0]
        client.olm.account.mark_keys_as_published()

        bob_olm.create_session(one_time, alice_device.curve25519)

        _, to_device = bob_olm.share_group_session(
            TEST_ROOM_ID, [client.user_id], ignore_unverified_devices=True
        )
        outbound_session = bob_olm.outbound_group_sessions[TEST_ROOM_ID]
        olm_content = to_device["messages"][client.user_id][client.device_id]

        payload = {
            "sender": bob_olm.user_id,
            "type": "m.room.encrypted",
            "content": olm_content,
        }

        sync_response = self.empty_sync
        sync_response["to_device"]["events"].append(payload)

        session = client.olm.inbound_group_store.get(
            TEST_ROOM_ID, bob_device.curve25519, outbound_session.id
        )
        assert not session

        client.handle_to_device_from_sync_body(sync_response)

        session = client.olm.inbound_group_store.get(
            TEST_ROOM_ID, bob_device.curve25519, outbound_session.id
        )
        assert session
