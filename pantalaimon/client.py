import asyncio
from typing import Any, Dict
from pprint import pformat

from nio import (
    AsyncClient,
    RoomEncryptedEvent,
    MegolmEvent,
    EncryptionError,
    SyncResponse,
    KeysQueryResponse,
    LocalProtocolError,
    GroupEncryptionError
)

from pantalaimon.log import logger


class PantaClient(AsyncClient):
    """A wrapper class around a nio AsyncClient extending its functionality."""

    def __init__(
            self,
            homeserver,
            user="",
            device_id="",
            store_path="",
            config=None,
            ssl=None,
            proxy=None
    ):
        super().__init__(homeserver, user, device_id, store_path, config,
                         ssl, proxy)

        self.loop_running = False
        self.loop_stopped = asyncio.Event()
        self.synced = asyncio.Event()

    def verify_devices(self, changed_devices):
        # Verify new devices automatically for now.
        for user_id, device_dict in changed_devices.items():
            for device in device_dict.values():
                if device.deleted:
                    continue

                logger.info("Automatically verifying device {} of "
                            "user {}".format(device.id, user_id))
                self.verify_device(device)

    async def loop(self):
        """Start a loop that runs forever and keeps on syncing with the server.

        The loop can be stopped with the stop_loop() method.
        """
        self.loop_running = True
        self.loop_stopped.clear()

        logger.info(f"Starting sync loop for {self.user_id}")

        while self.loop_running:
            if not self.logged_in:
                # TODO login
                pass

            # TODO use user lazy loading here
            response = await self.sync(30000)

            if self.should_upload_keys:
                await self.keys_upload()

            if self.should_query_keys:
                key_query_response = await self.keys_query()
                if isinstance(key_query_response, KeysQueryResponse):
                    self.verify_devices(key_query_response.changed)

            if not isinstance(response, SyncResponse):
                # TODO error handling
                pass

            self.synced.set()
            self.synced.clear()

        logger.info("Stopping the sync loop")
        self.loop_stopped.set()

    async def loop_stop(self):
        """Stop the client loop.

        Raises LocalProtocolError if the loop isn't running.
        """
        if not self.loop_running:
            raise LocalProtocolError("Loop is not running")

        self.loop_running = False
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

    def decrypt_sync_body(self, body):
        # type: (Dict[Any, Any]) -> Dict[Any, Any]
        """Go through a json sync response and decrypt megolm encrypted events.

        Args:
            body (Dict[Any, Any]): The dictionary of a Sync response.

            Returns the json response with decrypted events.
        """
        for room_id, room_dict in body["rooms"]["join"].items():
            if not self.rooms[room_id].encrypted:
                logger.info("Room {} is not encrypted skipping...".format(
                    self.rooms[room_id].display_name
                ))
                continue

            for event in room_dict["timeline"]["events"]:
                if event["type"] != "m.room.encrypted":
                    logger.info("Event is not encrypted: "
                                "\n{}".format(pformat(event)))
                    continue

                parsed_event = RoomEncryptedEvent.parse_event(event)
                parsed_event.room_id = room_id

                if not isinstance(parsed_event, MegolmEvent):
                    logger.warn("Encrypted event is not a megolm event:"
                                "\n{}".format(pformat(event)))
                    continue

                try:
                    decrypted_event = self.decrypt_event(parsed_event)
                    logger.info("Decrypted event: {}".format(decrypted_event))
                    event["type"] = "m.room.message"

                    # TODO support other event types
                    # This should be best done in nio, modify events so they
                    # keep the dictionary from which they are built in a source
                    # attribute.
                    event["content"] = {
                        "msgtype": "m.text",
                        "body": decrypted_event.body
                    }

                    if decrypted_event.formatted_body:
                        event["content"]["formatted_body"] = (
                            decrypted_event.formatted_body)
                        event["content"]["format"] = decrypted_event.format

                    event["decrypted"] = True
                    event["verified"] = decrypted_event.verified

                except EncryptionError as error:
                    logger.warn(error)
                    continue

        return body
