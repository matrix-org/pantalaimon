import asyncio
from pprint import pformat
from typing import Any, Dict, Optional

from aiohttp.client_exceptions import (ClientProxyConnectionError,
                                       ServerDisconnectedError)
from nio import (AsyncClient, ClientConfig, EncryptionError,
                 GroupEncryptionError, KeysQueryResponse, MegolmEvent,
                 RoomEncryptedEvent, SyncResponse,
                 KeyVerificationEvent, LocalProtocolError,
                 KeyVerificationStart, KeyVerificationKey, KeyVerificationMac)
from nio.store import SqliteStore

from pantalaimon.log import logger
from pantalaimon.ui import DevicesMessage


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
        self.loop_stopped = asyncio.Event()
        self.synced = asyncio.Event()

        self.add_to_device_callback(
            self.key_verification_cb,
            KeyVerificationEvent
        )
        self.key_verificatins_tasks = []

    def verify_devices(self, changed_devices):
        # Verify new devices automatically for now.
        for user_id, device_dict in changed_devices.items():
            for device in device_dict.values():
                if device.deleted:
                    continue

                logger.info("Automatically verifying device {} of "
                            "user {}".format(device.id, user_id))
                self.verify_device(device)

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

            emoji = sas.get_emoji()

            emojies = [x[0] for x in emoji]
            descriptions = [x[1] for x in emoji]
            device = sas.other_olm_device

            emoji_str = u"{:^10}{:^10}{:^10}{:^10}{:^10}{:^10}{:^10}".format(
                *emojies
            )
            desc = u"{:^11}{:^11}{:^11}{:^11}{:^11}{:^11}{:^11}".format(
                *descriptions
            )
            short_string = u"\n".join([emoji_str, desc])

            logger.info(u"Short authentication string for {} via {}:\n"
                        u"{}".format(device.user_id, device.id, short_string))

        elif isinstance(event, KeyVerificationMac):
            task = loop.create_task(
                self.accept_short_auth_string(event.transaction_id)
            )
            self.key_verificatins_tasks.append(task)

    def start_loop(self):
        """Start a loop that runs forever and keeps on syncing with the server.

        The loop can be stopped with the stop_loop() method.
        """
        loop = asyncio.get_event_loop()
        task = loop.create_task(self.loop())
        self.task = task
        return task

    async def _to_device(self, message):
        response = await self.to_device(message)
        return message, response

    async def send_to_device_messages(self):
        if not self.outgoing_to_device_messages:
            return

        tasks = []

        for message in self.outgoing_to_device_messages:
            task = asyncio.create_task(self._to_device(message))
            tasks.append(task)

        responses = await asyncio.gather(*tasks)

        for message, response in responses:
            if response.transport_response.status == 200:
                self.mark_to_device_message_as_sent(message)

    async def loop(self):
        self.loop_running = True
        self.loop_stopped.clear()

        logger.info(f"Starting sync loop for {self.user_id}")

        while True:
            try:
                if not self.logged_in:
                    # TODO login
                    pass

                response = await self.sync(
                    30000,
                    sync_filter={
                        "room": {
                            "state": {"lazy_load_members": True}
                        }
                    }
                )

                if response.transport_response.status != 200:
                    await asyncio.sleep(5)
                    continue

                await self.send_to_device_messages()

                try:
                    await asyncio.gather(*self.key_verificatins_tasks)
                except LocalProtocolError as e:
                    logger.info(e)

                self.key_verificatins_tasks = []

                if self.should_upload_keys:
                    await self.keys_upload()

                if self.should_query_keys:
                    key_query_response = await self.keys_query()
                    if isinstance(key_query_response, KeysQueryResponse):
                        self.verify_devices(key_query_response.changed)
                        message = DevicesMessage(
                            self.user_id,
                            key_query_response.changed
                        )
                        await self.queue.put(message)

                if not isinstance(response, SyncResponse):
                    # TODO error handling
                    pass

                self.synced.set()
                self.synced.clear()

            except asyncio.CancelledError:
                logger.info("Stopping the sync loop")
                self._loop_stop()
                break

            except (
                ClientProxyConnectionError,
                ServerDisconnectedError,
                ConnectionRefusedError
            ):
                try:
                    await asyncio.sleep(5)
                except asyncio.CancelledError:
                    self._loop_stop()
                    break

    def _loop_stop(self):
        self.loop_running = False
        self.loop_stopped.set()

    async def loop_stop(self):
        """Stop the client loop."""
        if not self.task or self.task.done():
            return

        self.task.cancel()
        await self.loop_stopped.wait()

    async def encrypt(self, room_id, msgtype, content):
        try:
            return super().encrypt(
                room_id,
                msgtype,
                content
            )
        except GroupEncryptionError:
            await self.share_group_session(room_id)
            return super().encrypt(
                room_id,
                msgtype,
                content
            )

    def pan_decrypt_event(self, event_dict, room_id=None):
        # type: (Dict[Any, Any], Optional[str]) -> (bool)
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
            return False

    def decrypt_messages_body(self, body):
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

            self.pan_decrypt_event(event)

        return body

    def decrypt_sync_body(self, body):
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
                self.pan_decrypt_event(event, room_id)

        return body
