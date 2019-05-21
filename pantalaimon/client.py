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
from collections import defaultdict
from pprint import pformat
from typing import Any, Dict, Optional

from aiohttp.client_exceptions import ClientConnectionError
from nio import (AsyncClient, ClientConfig, EncryptionError, KeysQueryResponse,
                 KeyVerificationEvent, KeyVerificationKey, KeyVerificationMac,
                 KeyVerificationStart, LocalProtocolError, MegolmEvent,
                 RoomEncryptedEvent, SyncResponse)
from nio.crypto import Sas
from nio.store import SqliteStore

from pantalaimon.log import logger
from pantalaimon.thread_messages import (DaemonResponse, InviteSasSignal,
                                         SasDoneSignal, ShowSasSignal,
                                         UpdateDevicesMessage)


class PanClient(AsyncClient):
    """A wrapper class around a nio AsyncClient extending its functionality."""

    def __init__(
            self,
            homeserver,
            queue=None,
            user="",
            device_id="",
            store_path="",
            config=None,
            ssl=None,
            proxy=None
    ):
        config = config or ClientConfig(store=SqliteStore, store_name="pan.db")
        super().__init__(homeserver, user, device_id, store_path, config,
                         ssl, proxy)

        self.task = None
        self.queue = queue

        self.send_semaphores = defaultdict(asyncio.Semaphore)
        self.send_decision_queues = dict()  # type: asyncio.Queue

        self.add_to_device_callback(
            self.key_verification_cb,
            KeyVerificationEvent
        )
        self.add_event_callback(
            self.undecrypted_event_cb,
            MegolmEvent
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

    async def sync_tasks(self, response):
        try:
            await asyncio.gather(*self.key_verificatins_tasks)
        except LocalProtocolError as e:
            logger.info(e)

        await asyncio.gather(*self.key_request_tasks)

        self.key_verificatins_tasks = []
        self.key_request_tasks = []

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
        timeout = 30000

        sync_filter = {
            "room": {
                "state": {"lazy_load_members": True}
            }
        }

        task = loop.create_task(self.sync_forever(timeout, sync_filter))
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

        if not self.task or self.task.done():
            return

        self.task.cancel()
        await self.task

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
