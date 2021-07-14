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

import asyncio
import os
from collections import defaultdict
from pprint import pformat
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from aiohttp.client_exceptions import ClientConnectionError
from jsonschema import Draft4Validator, FormatChecker, validators
from playhouse.sqliteq import SqliteQueueDatabase
from nio import (
    AsyncClient,
    AsyncClientConfig,
    EncryptionError,
    Event,
    ToDeviceEvent,
    KeysQueryResponse,
    KeyVerificationEvent,
    KeyVerificationKey,
    KeyVerificationMac,
    KeyVerificationStart,
    LocalProtocolError,
    MegolmEvent,
    RoomContextError,
    RoomEncryptedMedia,
    RoomEncryptedImage,
    RoomEncryptedFile,
    RoomEncryptedVideo,
    RoomMessageMedia,
    RoomMessageText,
    RoomNameEvent,
    RoomTopicEvent,
    RoomKeyRequest,
    RoomKeyRequestCancellation,
    SyncResponse,
)
from nio.crypto import Sas
from nio.store import SqliteStore

from pantalaimon.index import INDEXING_ENABLED
from pantalaimon.log import logger
from pantalaimon.store import FetchTask, MediaInfo
from pantalaimon.thread_messages import (
    DaemonResponse,
    InviteSasSignal,
    SasDoneSignal,
    ShowSasSignal,
    UpdateDevicesMessage,
    KeyRequestMessage,
    ContinueKeyShare,
    CancelKeyShare,
)

SEARCH_KEYS = ["content.body", "content.name", "content.topic"]

SEARCH_TERMS_SCHEMA = {
    "type": "object",
    "properties": {
        "search_categories": {
            "type": "object",
            "properties": {
                "room_events": {
                    "type": "object",
                    "properties": {
                        "search_term": {"type": "string"},
                        "keys": {
                            "type": "array",
                            "items": {"type": "string", "enum": SEARCH_KEYS},
                            "default": SEARCH_KEYS,
                        },
                        "order_by": {"type": "string", "default": "rank"},
                        "include_state": {"type": "boolean", "default": False},
                        "filter": {"type": "object", "default": {}},
                        "event_context": {"type": "object"},
                        "groupings": {"type": "object", "default": {}},
                    },
                    "required": ["search_term"],
                }
            },
        },
        "required": ["room_events"],
    },
    "required": ["search_categories"],
}


def extend_with_default(validator_class):
    validate_properties = validator_class.VALIDATORS["properties"]

    def set_defaults(validator, properties, instance, schema):
        for prop, subschema in properties.items():
            if "default" in subschema:
                instance.setdefault(prop, subschema["default"])

        for error in validate_properties(validator, properties, instance, schema):
            yield error

    return validators.extend(validator_class, {"properties": set_defaults})


Validator = extend_with_default(Draft4Validator)


def validate_json(instance, schema):
    """Validate a dictionary using the provided json schema."""
    Validator(schema, format_checker=FormatChecker()).validate(instance)


class UnknownRoomError(Exception):
    pass


class InvalidOrderByError(Exception):
    pass


class InvalidLimit(Exception):
    pass


class SqliteQStore(SqliteStore):
    def _create_database(self):
        return SqliteQueueDatabase(
            self.database_path, pragmas=(("foregign_keys", 1), ("secure_delete", 1))
        )

    def close(self):
        self.database.stop()


class PanClient(AsyncClient):
    """A wrapper class around a nio AsyncClient extending its functionality."""

    def __init__(
        self,
        server_name,
        pan_store,
        pan_conf,
        homeserver,
        queue=None,
        user_id="",
        device_id="",
        store_path="",
        config=None,
        ssl=None,
        proxy=None,
        store_class=None,
        media_info=None,
    ):
        config = config or AsyncClientConfig(
            store=store_class or SqliteStore, store_name="pan.db"
        )
        super().__init__(homeserver, user_id, device_id, store_path, config, ssl, proxy)

        index_dir = os.path.join(store_path, server_name, user_id)

        try:
            os.makedirs(index_dir)
        except OSError:
            pass

        self.server_name = server_name
        self.pan_store = pan_store
        self.pan_conf = pan_conf
        self.media_info = media_info

        if INDEXING_ENABLED:
            logger.info("Indexing enabled.")
            from pantalaimon.index import IndexStore

            self.index = IndexStore(self.user_id, index_dir)
        else:
            logger.info("Indexing disabled.")
            self.index = None

        self.task = None
        self.queue = queue

        # Those two events are mainly used for testing.
        self.new_fetch_task = asyncio.Event()
        self.fetch_loop_event = asyncio.Event()

        self.room_members_fetched = defaultdict(bool)

        self.send_semaphores = defaultdict(asyncio.Semaphore)
        self.send_decision_queues = dict()  # type: asyncio.Queue
        self.last_sync_token = None

        self.history_fetcher_task = None
        self.history_fetch_queue = asyncio.Queue()

        self.add_to_device_callback(self.key_verification_cb, KeyVerificationEvent)
        self.add_to_device_callback(
            self.key_request_cb, (RoomKeyRequest, RoomKeyRequestCancellation)
        )
        self.add_event_callback(self.undecrypted_event_cb, MegolmEvent)
        self.add_event_callback(
            self.store_thumbnail_cb,
            (RoomEncryptedImage, RoomEncryptedVideo, RoomEncryptedFile),
        )

        if INDEXING_ENABLED:
            self.add_event_callback(
                self.store_message_cb,
                (
                    RoomMessageText,
                    RoomMessageMedia,
                    RoomEncryptedMedia,
                    RoomTopicEvent,
                    RoomNameEvent,
                ),
            )

        self.add_response_callback(self.keys_query_cb, KeysQueryResponse)
        self.add_response_callback(self.sync_tasks, SyncResponse)

    def store_message_cb(self, room, event):
        assert INDEXING_ENABLED

        display_name = room.user_name(event.sender)
        avatar_url = room.avatar_url(event.sender)

        if not room.encrypted and self.pan_conf.index_encrypted_only:
            return

        self.index.add_event(event, room.room_id, display_name, avatar_url)

    def store_thumbnail_cb(self, room, event):
        if not (
            event.thumbnail_url
            and event.thumbnail_key
            and event.thumbnail_iv
            and event.thumbnail_hashes
        ):
            return

        try:
            mxc = urlparse(event.thumbnail_url)
        except ValueError:
            return

        if mxc is None:
            return

        mxc_server = mxc.netloc.strip("/")
        mxc_path = mxc.path.strip("/")

        media = MediaInfo(
            mxc_server,
            mxc_path,
            event.thumbnail_key,
            event.thumbnail_iv,
            event.thumbnail_hashes,
        )
        self.media_info[(mxc_server, mxc_path)] = media
        self.pan_store.save_media(self.server_name, media)

    def store_event_media(self, event):
        try:
            mxc = urlparse(event.url)
        except ValueError:
            return

        if mxc is None:
            return

        mxc_server = mxc.netloc.strip("/")
        mxc_path = mxc.path.strip("/")

        logger.info(f"Adding media info for {mxc_server}/{mxc_path} to the store")

        media = MediaInfo(mxc_server, mxc_path, event.key, event.iv, event.hashes)
        self.media_info[(mxc_server, mxc_path)] = media
        self.pan_store.save_media(self.server_name, media)

    @property
    def unable_to_decrypt(self):
        """Room event signaling that the message couldn't be decrypted."""
        return {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": (
                    "** Unable to decrypt: The sender's device has not "
                    "sent us the keys for this message. **"
                ),
            },
        }

    async def send_message(self, message):
        """Send a thread message to the UI thread."""
        if self.queue:
            await self.queue.put(message)

    async def send_update_devices(self, devices):
        """Send a dictionary of devices to the UI thread."""
        dict_devices = defaultdict(dict)

        for user_devices in devices.values():
            for device in user_devices.values():
                # Turn the OlmDevice type into a dictionary, flatten the
                # keys dict and remove the deleted key/value.
                # Since all the keys and values are strings this also
                # copies them making it thread safe.
                device_dict = device.as_dict()
                device_dict = {**device_dict, **device_dict["keys"]}
                device_dict.pop("keys")
                display_name = device_dict.pop("display_name")
                device_dict["device_display_name"] = display_name
                dict_devices[device.user_id][device.id] = device_dict

        message = UpdateDevicesMessage(self.user_id, dict_devices)
        await self.send_message(message)

    async def send_update_device(self, device):
        """Send a single device to the UI thread to be updated."""
        await self.send_update_devices({device.user_id: {device.id: device}})

    def delete_fetcher_task(self, task):
        self.pan_store.delete_fetcher_task(self.server_name, self.user_id, task)

    async def fetcher_loop(self):
        assert INDEXING_ENABLED

        for t in self.pan_store.load_fetcher_tasks(self.server_name, self.user_id):
            await self.history_fetch_queue.put(t)

        while True:
            self.fetch_loop_event.set()
            self.fetch_loop_event.clear()

            try:
                await asyncio.sleep(self.pan_conf.history_fetch_delay)
                fetch_task = await self.history_fetch_queue.get()

                try:
                    room = self.rooms[fetch_task.room_id]
                except KeyError:
                    # The room is missing from our client, we probably left the
                    # room.
                    self.delete_fetcher_task(fetch_task)
                    continue

                try:
                    logger.debug(
                        f"Fetching room history for {room.display_name} "
                        f"({room.room_id}), token {fetch_task.token}."
                    )
                    response = await self.room_messages(
                        fetch_task.room_id,
                        fetch_task.token,
                        limit=self.pan_conf.indexing_batch_size,
                    )
                except ClientConnectionError as e:
                    logger.debug("Error fetching room history: ", e)
                    await self.history_fetch_queue.put(fetch_task)

                # The chunk was empty, we're at the start of the timeline.
                if not response.chunk:
                    self.delete_fetcher_task(fetch_task)
                    continue

                for event in response.chunk:
                    if not isinstance(
                        event,
                        (
                            RoomMessageText,
                            RoomMessageMedia,
                            RoomEncryptedMedia,
                            RoomTopicEvent,
                            RoomNameEvent,
                        ),
                    ):
                        continue

                    display_name = room.user_name(event.sender)
                    avatar_url = room.avatar_url(event.sender)
                    self.index.add_event(event, room.room_id, display_name, avatar_url)

                last_event = response.chunk[-1]

                if not self.index.event_in_store(last_event.event_id, room.room_id):
                    # There may be even more events to fetch, add a new task to
                    # the queue.
                    task = FetchTask(room.room_id, response.end)
                    self.pan_store.replace_fetcher_task(
                        self.server_name, self.user_id, fetch_task, task
                    )
                    await self.history_fetch_queue.put(task)
                    self.new_fetch_task.set()
                    self.new_fetch_task.clear()
                else:
                    await self.index.commit_events()
                    self.delete_fetcher_task(fetch_task)

            except (asyncio.CancelledError, KeyboardInterrupt):
                return

    @property
    def has_been_synced(self) -> bool:
        self.last_sync_token is not None

    async def sync_tasks(self, response):
        if self.index:
            await self.index.commit_events()

        if self.last_sync_token == self.next_batch:
            return

        self.last_sync_token = self.next_batch

        self.pan_store.save_token(self.server_name, self.user_id, self.next_batch)

        for room_id, room_info in response.rooms.join.items():
            if room_info.timeline.limited:
                room = self.rooms[room_id]

                if not room.encrypted and self.pan_conf.index_encrypted_only:
                    continue

                logger.info(
                    "Room {} had a limited timeline, queueing "
                    "room for history fetching.".format(room.display_name)
                )
                task = FetchTask(room_id, room_info.timeline.prev_batch)
                self.pan_store.save_fetcher_task(self.server_name, self.user_id, task)

                await self.history_fetch_queue.put(task)
                self.new_fetch_task.set()
                self.new_fetch_task.clear()

    async def keys_query_cb(self, response):
        if response.changed:
            await self.send_update_devices(response.changed)

    async def undecrypted_event_cb(self, room, event):
        logger.info(
            "Unable to decrypt event from {} via {}.".format(
                event.sender, event.device_id
            )
        )

        if event.session_id not in self.outgoing_key_requests:
            logger.info("Requesting room key for undecrypted event.")

            # TODO we may want to retry this
            try:
                await self.request_room_key(event)
            except ClientConnectionError:
                pass

    async def key_request_cb(self, event):
        if isinstance(event, RoomKeyRequest):
            logger.info(
                f"{event.sender} via {event.requesting_device_id} has "
                f" requested room keys from  us."
            )

            message = KeyRequestMessage(self.user_id, event)
            await self.send_message(message)

        elif isinstance(event, RoomKeyRequestCancellation):
            logger.info(
                f"{event.sender} via {event.requesting_device_id} has "
                f" canceled its key request."
            )

            message = KeyRequestMessage(self.user_id, event)
            await self.send_message(message)

        else:
            assert False

    async def key_verification_cb(self, event):
        logger.info("Received key verification event: {}".format(event))
        if isinstance(event, KeyVerificationStart):
            logger.info(
                f"{event.sender} via {event.from_device} has started "
                f"a key verification process."
            )

            message = InviteSasSignal(
                self.user_id, event.sender, event.from_device, event.transaction_id
            )

            await self.send_message(message)

        elif isinstance(event, KeyVerificationKey):
            sas = self.key_verifications.get(event.transaction_id, None)
            if not sas:
                return

            device = sas.other_olm_device
            emoji = sas.get_emoji()

            message = ShowSasSignal(
                self.user_id, device.user_id, device.id, sas.transaction_id, emoji
            )

            await self.send_message(message)

        elif isinstance(event, KeyVerificationMac):
            sas = self.key_verifications.get(event.transaction_id, None)
            if not sas:
                return
            device = sas.other_olm_device

            if sas.verified:
                await self.send_message(
                    SasDoneSignal(
                        self.user_id, device.user_id, device.id, sas.transaction_id
                    )
                )
                await self.send_update_device(device)

    def start_loop(self, loop_sleep_time=100):
        """Start a loop that runs forever and keeps on syncing with the server.

        The loop can be stopped with the stop_loop() method.
        """
        assert not self.task

        logger.info(f"Starting sync loop for {self.user_id}")

        loop = asyncio.get_event_loop()

        if INDEXING_ENABLED:
            self.history_fetcher_task = loop.create_task(self.fetcher_loop())

        timeout = 30000
        sync_filter = {"room": {"state": {"lazy_load_members": True}}}
        next_batch = self.pan_store.load_token(self.server_name, self.user_id)

        # We don't store any room state so initial sync needs to be with the
        # full_state parameter. Subsequent ones are normal.
        task = loop.create_task(
            self.sync_forever(
                timeout,
                sync_filter,
                full_state=True,
                since=next_batch,
                loop_sleep_time=loop_sleep_time,
            )
        )
        self.task = task

        return task

    async def start_sas(self, message, device):
        try:
            await self.start_key_verification(device)
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    "m.ok",
                    "Successfully started the key verification request",
                )
            )
        except ClientConnectionError as e:
            await self.send_message(
                DaemonResponse(
                    message.message_id, self.user_id, "m.connection_error", str(e)
                )
            )

    async def accept_sas(self, message):
        user_id = message.user_id
        device_id = message.device_id

        sas = self.get_active_sas(user_id, device_id)

        if not sas:
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    Sas._txid_error[0],
                    Sas._txid_error[1],
                )
            )
            return

        try:
            await self.accept_key_verification(sas.transaction_id)
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    "m.ok",
                    "Successfully accepted the key verification request",
                )
            )
        except LocalProtocolError as e:
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    Sas._unexpected_message_error[0],
                    str(e),
                )
            )
        except ClientConnectionError as e:
            await self.send_message(
                DaemonResponse(
                    message.message_id, self.user_id, "m.connection_error", str(e)
                )
            )

    async def cancel_sas(self, message):
        user_id = message.user_id
        device_id = message.device_id

        sas = self.get_active_sas(user_id, device_id)

        if not sas:
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    Sas._txid_error[0],
                    Sas._txid_error[1],
                )
            )
            return

        try:
            await self.cancel_key_verification(sas.transaction_id)
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    "m.ok",
                    "Successfully canceled the key verification request",
                )
            )
        except ClientConnectionError as e:
            await self.send_message(
                DaemonResponse(
                    message.message_id, self.user_id, "m.connection_error", str(e)
                )
            )

    async def confirm_sas(self, message):
        user_id = message.user_id
        device_id = message.device_id

        sas = self.get_active_sas(user_id, device_id)

        if not sas:
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    Sas._txid_error[0],
                    Sas._txid_error[1],
                )
            )
            return

        try:
            await self.confirm_short_auth_string(sas.transaction_id)
        except ClientConnectionError as e:
            await self.send_message(
                DaemonResponse(
                    message.message_id, self.user_id, "m.connection_error", str(e)
                )
            )

            return

        device = sas.other_olm_device

        if sas.verified:
            await self.send_update_device(device)
            await self.send_message(
                SasDoneSignal(
                    self.user_id, device.user_id, device.id, sas.transaction_id
                )
            )
        else:
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    "m.ok",
                    f"Waiting for {device.user_id} to confirm.",
                )
            )

    async def handle_key_request_message(self, message):
        if isinstance(message, ContinueKeyShare):
            continued = False
            for share in self.get_active_key_requests(
                message.user_id, message.device_id
            ):

                continued = True

                if not self.continue_key_share(share):
                    await self.send_message(
                        DaemonResponse(
                            message.message_id,
                            self.user_id,
                            "m.error",
                            (
                                f"Unable to continue the key sharing for "
                                f"{message.user_id} via {message.device_id}: The "
                                f"device is still not verified."
                            ),
                        )
                    )
                    return

            if continued:
                try:
                    await self.send_to_device_messages()
                except ClientConnectionError:
                    # We can safely ignore this since this will be retried
                    # after the next sync in the sync_forever method.
                    pass

                response = (
                    f"Succesfully continued the key requests from "
                    f"{message.user_id} via {message.device_id}"
                )
                ret = "m.ok"
            else:
                response = (
                    f"No active key requests from {message.user_id} "
                    f"via {message.device_id} found."
                )
                ret = "m.error"

            await self.send_message(
                DaemonResponse(message.message_id, self.user_id, ret, response)
            )

        elif isinstance(message, CancelKeyShare):
            cancelled = False

            for share in self.get_active_key_requests(
                message.user_id, message.device_id
            ):
                cancelled = self.cancel_key_share(share)

            if cancelled:
                response = (
                    f"Succesfully cancelled key requests from "
                    f"{message.user_id} via {message.device_id}"
                )
                ret = "m.ok"
            else:
                response = (
                    f"No active key requests from {message.user_id} "
                    f"via {message.device_id} found."
                )
                ret = "m.error"

            await self.send_message(
                DaemonResponse(message.message_id, self.user_id, ret, response)
            )

    async def loop_stop(self):
        """Stop the client loop."""
        logger.info("Stopping the sync loop")

        if self.task and not self.task.done():
            self.task.cancel()

            try:
                await self.task
            except KeyboardInterrupt:
                pass

            self.task = None

        if self.history_fetcher_task and not self.history_fetcher_task.done():
            self.history_fetcher_task.cancel()

            try:
                await self.history_fetcher_task
            except KeyboardInterrupt:
                pass

            self.history_fetcher_task = None

        if isinstance(self.store, SqliteQueueDatabase):
            self.store.close()

        self.history_fetch_queue = asyncio.Queue()

    def pan_decrypt_event(self, event_dict, room_id=None, ignore_failures=True):
        # type: (Dict[Any, Any], Optional[str], bool) -> (bool)
        event = Event.parse_encrypted_event(event_dict)

        if not isinstance(event, MegolmEvent):
            logger.warn(
                "Encrypted event is not a megolm event:"
                "\n{}".format(pformat(event_dict))
            )
            return False

        if not event.room_id:
            event.room_id = room_id

        try:
            decrypted_event = self.decrypt_event(event)
            logger.debug("Decrypted event: {}".format(decrypted_event))
            logger.info(
                "Decrypted event from {} in {}, event id: {}".format(
                    decrypted_event.sender,
                    decrypted_event.room_id,
                    decrypted_event.event_id,
                )
            )

            if isinstance(decrypted_event, RoomEncryptedMedia):
                self.store_event_media(decrypted_event)

                decrypted_event.source["content"]["url"] = decrypted_event.url

                if decrypted_event.thumbnail_url:
                    decrypted_event.source["content"]["info"][
                        "thumbnail_url"
                    ] = decrypted_event.thumbnail_url

            event_dict.update(decrypted_event.source)
            event_dict["decrypted"] = True
            event_dict["verified"] = decrypted_event.verified

            return True

        except EncryptionError as error:
            logger.warn(error)

            if ignore_failures:
                event_dict.update(self.unable_to_decrypt)
            else:
                raise

            return False

    def decrypt_messages_body(self, body, ignore_failures=True):
        # type: (Dict[Any, Any], bool) -> Dict[Any, Any]
        """Go through a messages response and decrypt megolm encrypted events.

        Args:
            body (Dict[Any, Any]): The dictionary of a Sync response.

        Returns the json response with decrypted events.
        """
        if "chunk" not in body:
            return body

        logger.info("Decrypting room messages")

        for event in body["chunk"]:
            if "type" not in event:
                continue

            if event["type"] != "m.room.encrypted":
                logger.debug("Event is not encrypted: " "\n{}".format(pformat(event)))
                continue

            self.pan_decrypt_event(event, ignore_failures=ignore_failures)

        return body

    def handle_to_device_from_sync_body(self, body):
        to_device_events = body.get("to_device")

        if not to_device_events or "events" not in to_device_events:
            return

        for event in to_device_events["events"]:
            event = ToDeviceEvent.parse_encrypted_event(event)

            if not isinstance(event, ToDeviceEvent):
                continue

            self.olm.handle_to_device_event(event)

    def decrypt_sync_body(self, body, ignore_failures=True):
        # type: (Dict[Any, Any], bool) -> Dict[Any, Any]
        """Go through a json sync response and decrypt megolm encrypted events.

        Args:
            body (Dict[Any, Any]): The dictionary of a Sync response.

        Returns the json response with decrypted events.
        """
        logger.info("Decrypting sync")

        self.handle_to_device_from_sync_body(body)

        for room_id, room_dict in body.get("rooms", {}).get("join", {}).items():
            try:
                if not self.rooms[room_id].encrypted:
                    logger.info(
                        "Room {} is not encrypted skipping...".format(
                            self.rooms[room_id].display_name
                        )
                    )
                    continue
            except KeyError:
                # We don't know if the room is encrypted or not, probably
                # because the client sync stream got to join the room before the
                # pan sync stream did. Let's assume that the room is encrypted.
                pass

            for event in room_dict.get("timeline", {}).get("events", []):
                if "type" not in event:
                    continue

                if event["type"] != "m.room.encrypted":
                    continue

                self.pan_decrypt_event(event, room_id, ignore_failures)

        return body

    async def search(self, search_terms):
        # type: (Dict[Any, Any]) -> Dict[Any, Any]
        assert INDEXING_ENABLED

        state_cache = dict()

        async def add_context(event_dict, room_id, event_id, include_state):
            try:
                context = await self.room_context(room_id, event_id, limit=0)
            except ClientConnectionError:
                return

            if isinstance(context, RoomContextError):
                return

            if include_state:
                state_cache[room_id] = [e.source for e in context.state]

            event_dict["context"]["start"] = context.start
            event_dict["context"]["end"] = context.end

        search_terms = search_terms["search_categories"]["room_events"]

        term = search_terms["search_term"]
        search_filter = search_terms["filter"]
        limit = search_filter.get("limit", 10)

        if limit <= 0:
            raise InvalidLimit("The limit must be strictly greater than 0.")

        rooms = search_filter.get("rooms", [])

        room_id = rooms[0] if len(rooms) == 1 else None

        order_by = search_terms.get("order_by")

        if order_by not in ["rank", "recent"]:
            raise InvalidOrderByError(f"Invalid order by: {order_by}")

        order_by_recent = order_by == "recent"

        before_limit = 0
        after_limit = 0
        include_profile = False

        event_context = search_terms.get("event_context")
        include_state = search_terms.get("include_state")

        if event_context:
            before_limit = event_context.get("before_limit", 5)
            after_limit = event_context.get("before_limit", 5)

        if before_limit < 0 or after_limit < 0:
            raise InvalidLimit(
                "Invalid context limit, the limit must be a " "positive number"
            )

        response_dict = await self.index.search(
            term,
            room=room_id,
            max_results=limit,
            order_by_recent=order_by_recent,
            include_profile=include_profile,
            before_limit=before_limit,
            after_limit=after_limit,
        )

        if (event_context or include_state) and self.pan_conf.search_requests:
            for event_dict in response_dict["results"]:
                await add_context(
                    event_dict,
                    event_dict["result"]["room_id"],
                    event_dict["result"]["event_id"],
                    include_state,
                )

        if include_state:
            response_dict["state"] = state_cache

        return {"search_categories": {"room_events": response_dict}}
