from typing import Any, Dict

from nio import (
    AsyncClient,
    RoomEncryptedEvent,
    MegolmEvent,
    EncryptionError,
    SyncResponse
)


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
                print("Room {} not encrypted skipping...".format(
                    self.rooms[room_id].display_name
                ))
                continue

            for event in room_dict["timeline"]["events"]:
                if event["type"] != "m.room.encrypted":
                    print("Event not encrypted skipping...")
                    continue

                parsed_event = RoomEncryptedEvent.parse_event(event)
                parsed_event.room_id = room_id

                if not isinstance(parsed_event, MegolmEvent):
                    print("Not a megolm event.")
                    continue

                try:
                    decrypted_event = self.decrypt_event(parsed_event)
                    print("Decrypted event: {}".format(decrypted_event))
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
                    print("ERROR decrypting {}".format(error))
                    continue

        return body
