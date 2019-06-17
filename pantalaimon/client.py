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

from aiohttp.client_exceptions import ClientConnectionError
from jsonschema import Draft4Validator, FormatChecker, validators
from nio import (AsyncClient, ClientConfig, EncryptionError, KeysQueryResponse,
                 KeyVerificationEvent, KeyVerificationKey, KeyVerificationMac,
                 KeyVerificationStart, LocalProtocolError, MegolmEvent,
                 RoomContextError, RoomEncryptedEvent, RoomEncryptedMedia,
                 RoomMessageMedia, RoomMessageText, RoomNameEvent,
                 RoomTopicEvent, SyncResponse)
from nio.crypto import Sas
from nio.store import SqliteStore

from pantalaimon.index import IndexStore
from pantalaimon.log import logger
from pantalaimon.store import FetchTask
from pantalaimon.thread_messages import (DaemonResponse, InviteSasSignal,
                                         SasDoneSignal, ShowSasSignal,
                                         UpdateDevicesMessage)

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
                            "default": SEARCH_KEYS
                        },
                        "order_by": {"type": "string", "default": "rank"},
                        "include_state": {"type": "boolean", "default": False},
                        "filter": {"type": "object", "default": {}},
                        "event_context": {"type": "object"},
                        "groupings": {"type": "object", "default": {}},
                    },
                    "required": ["search_term"]
                },
            }
        },
        "required": ["room_events"]
    },
    "required": [
        "search_categories",
    ],
}


def extend_with_default(validator_class):
    validate_properties = validator_class.VALIDATORS["properties"]

    def set_defaults(validator, properties, instance, schema):
        for prop, subschema in properties.items():
            if "default" in subschema:
                instance.setdefault(prop, subschema["default"])

        for error in validate_properties(
                validator, properties, instance, schema
        ):
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
            proxy=None
    ):
        config = config or ClientConfig(store=SqliteStore, store_name="pan.db")
        super().__init__(homeserver, user_id, device_id, store_path, config,
                         ssl, proxy)

        index_dir = os.path.join(store_path, server_name, user_id)

        try:
            os.makedirs(index_dir)
        except OSError:
            pass

        self.server_name = server_name
        self.pan_store = pan_store
        self.pan_conf = pan_conf
        self.index = IndexStore(self.user_id, index_dir)
        self.task = None
        self.queue = queue

        self.room_members_fetched = defaultdict(bool)

        self.send_semaphores = defaultdict(asyncio.Semaphore)
        self.send_decision_queues = dict()  # type: asyncio.Queue

        self.history_fetcher_task = None
        self.history_fetch_queue = asyncio.Queue()

        self.add_to_device_callback(
            self.key_verification_cb,
            KeyVerificationEvent
        )
        self.add_event_callback(
            self.undecrypted_event_cb,
            MegolmEvent
        )
        self.add_event_callback(
            self.store_message_cb,
            (RoomMessageText, RoomMessageMedia, RoomEncryptedMedia,
             RoomTopicEvent, RoomNameEvent)
        )
        self.key_verificatins_tasks = []
        self.key_request_tasks = []

        self.add_response_callback(
            self.keys_query_cb,
            KeysQueryResponse
        )

        self.add_response_callback(
            self.sync_tasks,
            SyncResponse
        )

    def store_message_cb(self, room, event):
        display_name = room.user_name(event.sender)
        avatar_url = room.avatar_url(event.sender)

        if not room.encrypted and self.pan_conf.index_encrypted_only:
            return

        self.index.add_event(event, room.room_id, display_name, avatar_url)

    @property
    def unable_to_decrypt(self):
        """Room event signaling that the message couldn't be decrypted."""
        return {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": ("** Unable to decrypt: The sender's device has not "
                         "sent us the keys for this message. **")
            }
        }

    async def send_message(self, message):
        """Send a thread message to the UI thread."""
        await self.queue.put(message)

    async def send_update_devcies(self):
        message = UpdateDevicesMessage()
        await self.queue.put(message)

    def delete_fetcher_task(self, task):
        self.pan_store.delete_fetcher_task(
            self.server_name,
            self.user_id,
            task
        )

    async def fetcher_loop(self):
        for t in self.pan_store.load_fetcher_tasks(
                self.server_name,
                self.user_id
        ):
            await self.history_fetch_queue.put(t)

        while True:
            try:
                await asyncio.sleep(3)

                fetch_task = await self.history_fetch_queue.get()

                try:
                    room = self.rooms[fetch_task.room_id]
                except KeyError:
                    # The room is missing from our client, we probably left the
                    # room.
                    self.delete_fetcher_task(fetch_task)
                    continue

                try:
                    logger.debug("Fetching room history for {}".format(
                        room.display_name
                    ))
                    response = await self.room_messages(fetch_task.room_id,
                                                        fetch_task.token,
                                                        limit=100)
                except ClientConnectionError:
                    self.history_fetch_queue.put(fetch_task)

                # The chunk was empty, we're at the start of the timeline.
                if not response.chunk:
                    self.delete_fetcher_task(fetch_task)
                    continue

                for event in response.chunk:
                    if not isinstance(event, (
                            RoomMessageText,
                            RoomMessageMedia,
                            RoomEncryptedMedia,
                            RoomTopicEvent,
                            RoomNameEvent
                    )):
                        continue

                    display_name = room.user_name(event.sender)
                    avatar_url = room.avatar_url(event.sender)
                    self.index.add_event(event, room.room_id, display_name,
                                         avatar_url)

                last_event = response.chunk[-1]

                if not self.index.event_in_store(
                        last_event.event_id,
                        room.room_id
                ):
                    # There may be even more events to fetch, add a new task to
                    # the queue.
                    task = FetchTask(room.room_id, response.end)
                    self.pan_store.save_fetcher_task(self.server_name,
                                                     self.user_id, task)
                    await self.history_fetch_queue.put(task)

                await self.index.commit_events()
                self.delete_fetcher_task(fetch_task)
            except (asyncio.CancelledError, KeyboardInterrupt):
                return

    async def sync_tasks(self, response):
        try:
            await asyncio.gather(*self.key_verificatins_tasks)
        except LocalProtocolError as e:
            logger.info(e)

        await asyncio.gather(*self.key_request_tasks)

        self.key_verificatins_tasks = []
        self.key_request_tasks = []

        await self.index.commit_events()
        self.pan_store.save_token(
            self.server_name,
            self.user_id,
            self.next_batch
        )

        for room_id, room_info in response.rooms.join.items():
            if room_info.timeline.limited:
                room = self.rooms[room_id]

                if not room.encrypted and self.pan_conf.index_encrypted_only:
                    continue

                logger.info("Room {} had a limited timeline, queueing "
                            "room for history fetching.".format(
                                room.display_name
                            ))
                task = FetchTask(room_id, room_info.timeline.prev_batch)
                self.pan_store.save_fetcher_task(self.server_name,
                                                 self.user_id, task)

                await self.history_fetch_queue.put(task)

    async def keys_query_cb(self, response):
        await self.send_update_devcies()

    def undecrypted_event_cb(self, room, event):
        loop = asyncio.get_event_loop()

        logger.info("Unable to decrypt event from {} via {}.".format(
            event.sender,
            event.device_id
        ))

        if event.session_id not in self.outgoing_key_requests:
            logger.info("Requesting room key for undecrypted event.")
            task = loop.create_task(self.request_room_key(event))
            self.key_request_tasks.append(task)

    def key_verification_cb(self, event):
        logger.info("Received key verification event: {}".format(event))
        loop = asyncio.get_event_loop()

        if isinstance(event, KeyVerificationStart):
            logger.info(f"{event.sender} via {event.from_device} has started "
                        f"a key verification process.")

            message = InviteSasSignal(
                self.user_id,
                event.sender,
                event.from_device,
                event.transaction_id
            )

            task = loop.create_task(
                self.queue.put(message)
            )
            self.key_verificatins_tasks.append(task)

        elif isinstance(event, KeyVerificationKey):
            sas = self.key_verifications.get(event.transaction_id, None)
            if not sas:
                return

            device = sas.other_olm_device
            emoji = sas.get_emoji()

            message = ShowSasSignal(
                self.user_id,
                device.user_id,
                device.id,
                sas.transaction_id,
                emoji
            )

            task = loop.create_task(
                self.queue.put(message)
            )
            self.key_verificatins_tasks.append(task)

        elif isinstance(event, KeyVerificationMac):
            sas = self.key_verifications.get(event.transaction_id, None)
            if not sas:
                return
            device = sas.other_olm_device

            if sas.verified:
                task = loop.create_task(self.send_message(
                    SasDoneSignal(
                        self.user_id,
                        device.user_id,
                        device.id,
                        sas.transaction_id
                    )
                ))
                self.key_verificatins_tasks.append(task)
                task = loop.create_task(self.send_update_devcies())
                self.key_verificatins_tasks.append(task)

    def start_loop(self):
        """Start a loop that runs forever and keeps on syncing with the server.

        The loop can be stopped with the stop_loop() method.
        """
        assert not self.task

        logger.info(f"Starting sync loop for {self.user_id}")

        loop = asyncio.get_event_loop()

        self.history_fetcher_task = loop.create_task(self.fetcher_loop())

        timeout = 30000
        sync_filter = {
            "room": {
                "state": {"lazy_load_members": True}
            }
        }
        next_batch = self.pan_store.load_token(self.server_name, self.user_id)

        # We don't store any room state so initial sync needs to be with the
        # full_state parameter. Subsequent ones are normal.
        task = loop.create_task(
            self.sync_forever(
                timeout,
                sync_filter,
                full_state=True,
                since=next_batch
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
                    "Successfully started the key verification request"
                    ))
        except ClientConnectionError as e:
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    "m.connection_error",
                    str(e)
                ))

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
                    Sas._txid_error[1]
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
                    "Successfully accepted the key verification request"
                    ))
        except LocalProtocolError as e:
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    Sas._unexpected_message_error[0],
                    str(e)
                ))
        except ClientConnectionError as e:
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    "m.connection_error",
                    str(e)
                ))

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
                    Sas._txid_error[1]
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
                    "Successfully canceled the key verification request"
                    ))
        except ClientConnectionError as e:
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    "m.connection_error",
                    str(e)
                ))

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
                    Sas._txid_error[1]
                )

            )
            return

        try:
            await self.confirm_short_auth_string(sas.transaction_id)
        except ClientConnectionError as e:
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    "m.connection_error",
                    str(e)
                ))

            return

        device = sas.other_olm_device

        if sas.verified:
            await self.send_update_devcies()
            await self.send_message(
                SasDoneSignal(
                    self.user_id,
                    device.user_id,
                    device.id,
                    sas.transaction_id
                )
            )
        else:
            await self.send_message(
                DaemonResponse(
                    message.message_id,
                    self.user_id,
                    "m.ok",
                    f"Waiting for {device.user_id} to confirm."
                    ))

    async def loop_stop(self):
        """Stop the client loop."""
        logger.info("Stopping the sync loop")

        if self.task and not self.task.done():
            self.task.cancel()
            await self.task
            self.task = None

        if self.history_fetcher_task and not self.history_fetcher_task.done():
            self.history_fetcher_task.cancel()
            await self.history_fetcher_task
            self.history_fetcher_task = None

        self.history_fetch_queue = asyncio.Queue()

    def pan_decrypt_event(
            self,
            event_dict,
            room_id=None,
            ignore_failures=True
    ):
        # type: (Dict[Any, Any], Optional[str], bool) -> (bool)
        event = RoomEncryptedEvent.parse_event(event_dict)

        if not isinstance(event, MegolmEvent):
            logger.warn("Encrypted event is not a megolm event:"
                        "\n{}".format(pformat(event_dict)))
            return False

        if not event.room_id:
            event.room_id = room_id

        try:
            decrypted_event = self.decrypt_event(event)
            logger.info("Decrypted event: {}".format(decrypted_event))

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
                logger.debug("Event is not encrypted: "
                             "\n{}".format(pformat(event)))
                continue

            self.pan_decrypt_event(event, ignore_failures=ignore_failures)

        return body

    def decrypt_sync_body(self, body, ignore_failures=True):
        # type: (Dict[Any, Any], bool) -> Dict[Any, Any]
        """Go through a json sync response and decrypt megolm encrypted events.

        Args:
            body (Dict[Any, Any]): The dictionary of a Sync response.

        Returns the json response with decrypted events.
        """
        logger.info("Decrypting sync")
        for room_id, room_dict in body["rooms"]["join"].items():
            try:
                if not self.rooms[room_id].encrypted:
                    logger.info("Room {} is not encrypted skipping...".format(
                        self.rooms[room_id].display_name
                    ))
                    continue
            except KeyError:
                logger.info("Unknown room {} skipping...".format(room_id))
                continue

            for event in room_dict["timeline"]["events"]:
                if "type" not in event:
                    continue

                if event["type"] != "m.room.encrypted":
                    continue

                self.pan_decrypt_event(event, room_id, ignore_failures)

        return body

    async def search(self, search_terms):
        # type: (Dict[Any, Any]) -> Dict[Any, Any]
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
            raise InvalidLimit("Invalid context limit, the limit must be a "
                               "positive number")

        response_dict = await self.index.search(
            term,
            room=room_id,
            max_results=limit,
            order_by_recent=order_by_recent,
            include_profile=include_profile,
            before_limit=before_limit,
            after_limit=after_limit
        )

        if (event_context or include_state) and self.pan_conf.search_requests:
            for event_dict in response_dict["results"]:
                await add_context(
                    event_dict,
                    event_dict["result"]["room_id"],
                    event_dict["result"]["event_id"],
                    include_state
                )

        if include_state:
            response_dict["state"] = state_cache

        return {
            "search_categories": {
                "room_events": response_dict
            }
        }
