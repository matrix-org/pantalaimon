import asyncio
from pprint import pformat
from typing import Any, Dict, Optional

from nio import (AsyncClient, ClientConfig, EncryptionError,
                 KeysQueryResponse, MegolmEvent,
                 RoomEncryptedEvent, SyncResponse,
                 KeyVerificationEvent, LocalProtocolError,
                 KeyVerificationStart, KeyVerificationKey, KeyVerificationMac)
from nio.store import SqliteStore

from pantalaimon.log import logger
from pantalaimon.ui import DevicesMessage, DeviceAuthStringMessage, InfoMessage


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
            self.verify_devices,
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

    async def send_info(self, string):
        """Send a info message to the UI thread."""
        message = InfoMessage(string)
        await self.queue.put(message)

    async def sync_tasks(self, response):
        try:
            await asyncio.gather(*self.key_verificatins_tasks)
        except LocalProtocolError as e:
            logger.info(e)

        await asyncio.gather(*self.key_request_tasks)

        self.key_verificatins_tasks = []
        self.key_request_tasks = []

    async def verify_devices(self, response):
        # Verify new devices automatically for now.
        changed_devices = response.changed

        for user_id, device_dict in changed_devices.items():
            for device in device_dict.values():
                if device.deleted:
                    continue

                logger.info("Automatically verifying device {} of "
                            "user {}".format(device.id, user_id))
                self.verify_device(device)

        message = DevicesMessage(self.user_id, response.changed)
        await self.queue.put(message)

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
            task = loop.create_task(
                self.accept_key_verification(event.transaction_id)
            )
            self.key_verificatins_tasks.append(task)

        elif isinstance(event, KeyVerificationKey):
            sas = self.key_verifications.get(event.transaction_id, None)
            if not sas:
                return

            device = sas.other_olm_device
            emoji = sas.get_emoji()

            message = DeviceAuthStringMessage(
                self.user_id,
                device.user_id,
                device.id,
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
                task = loop.create_task(
                    self.send_info(f"Device {device.id} of user "
                                   f"{device.user_id} succesfully "
                                   f"verified.")
                )
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

    async def confirm_sas(self, message):
        user_id = message.user_id
        device_id = message.device_id

        sas = self.get_active_sas(user_id, device_id)

        if not sas:
            self.send_info("No such verification process found.")
            return

        await self.confirm_short_auth_string(sas.transaction_id)

        device = sas.other_olm_device
        if sas.verified:
            await self.send_info(f"Device {device.id} of user {device.user_id}"
                                 f" succesfully verified.")
        else:
            await self.send_info(f"Waiting for {device.user_id} to confirm...")

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
        # type: (Dict[Any, Any]) -> Dict[Any, Any]
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
        # type: (Dict[Any, Any]) -> Dict[Any, Any]
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
                self.pan_decrypt_event(event, room_id, ignore_failures)

        return body
