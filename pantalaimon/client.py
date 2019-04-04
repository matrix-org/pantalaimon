from typing import Any, Dict
from pprint import pformat

from nio import (
    AsyncClient,
    RoomEncryptedEvent,
    MegolmEvent,
    EncryptionError,
    SyncResponse
)

from pantalaimon.log import logger


class PantaClient(AsyncClient):
    """A wrapper class around a nio AsyncClient extending its functionality."""

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
                                "{}".format(pformat(event)))
                    continue

                parsed_event = RoomEncryptedEvent.parse_event(event)
                parsed_event.room_id = room_id

                if not isinstance(parsed_event, MegolmEvent):
                    logger.warn("Encrypted event is not a megolm event:"
                                "{}".format(pformat(event)))
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
