import pdb

from nio import RoomMessage

from conftest import faker
from pantalaimon.index import Index

TEST_ROOM = "!SVkFJHzfwvuaIEawgC:localhost"
TEST_ROOM2 = "!testroom:localhost"


class TestClass(object):
    @property
    def test_event(self):
        return RoomMessage.parse_event(
            {
                "content": {"body": "Test message", "msgtype": "m.text"},
                "event_id": "$15163622445EBvZJ:localhost",
                "origin_server_ts": 1516362244026,
                "room_id": "!SVkFJHzfwvuaIEawgC:localhost",
                "sender": "@example2:localhost",
                "type": "m.room.message",
                "unsigned": {"age": 43289803095},
                "user_id": "@example2:localhost",
                "age": 43289803095
            }
        )

    @property
    def another_event(self):
        return RoomMessage.parse_event(
            {
                "content": {"body": "Another message", "msgtype": "m.text"},
                "event_id": "$15163622445EBvZJ:localhost",
                "origin_server_ts": 1516362244026,
                "room_id": "!SVkFJHzfwvuaIEawgC:localhost",
                "sender": "@example2:localhost",
                "type": "m.room.message",
                "unsigned": {"age": 43289803095},
                "user_id": "@example2:localhost",
                "age": 43289803095
            }
        )

    def test_account_loading(self, panstore):
        accounts = panstore.load_all_users()
        # pdb.set_trace()
        assert len(accounts) == 10

    def test_token_saving(self, panstore, access_token):
        accounts = panstore.load_all_users()
        user_id = accounts[0][0]
        device_id = accounts[0][1]

        panstore.save_access_token(user_id, device_id, access_token)

        token = panstore.load_access_token(user_id, device_id)
        access_token == token

    def test_event_storing(self, panstore_with_users):
        panstore = panstore_with_users
        accounts = panstore.load_all_users()
        user, _ = accounts[0]

        event = self.test_event

        event_id = panstore.save_event("example", user, event, TEST_ROOM,
                                       "Example2", None)

        assert event_id == 1

        event_id = panstore.save_event("example", user, event, TEST_ROOM,
                                       "Example2", None)
        assert event_id is None
        assert False

        event_dict = panstore.load_event_by_columns("example", user, 1)
        assert event.source == event_dict

        _, profile = panstore.load_event_by_columns("example", user, 1, True)

        assert profile == {
            "@example2:localhost": {
                "display_name": "Example2",
                "avatar_url": None
            }
        }

    def test_index(self, panstore_with_users):
        panstore = panstore_with_users
        accounts = panstore.load_all_users()
        user, _ = accounts[0]

        event = self.test_event
        another_event = self.another_event

        index = Index(panstore.store_path)

        event_id = panstore.save_event("example", user, event, TEST_ROOM,
                                       "Example2", None)
        assert event_id == 1
        index.add_event(event_id, event, TEST_ROOM)

        event_id = panstore.save_event("example", user, another_event,
                                       TEST_ROOM2, "Example2", None)
        assert event_id == 2
        index.add_event(event_id, another_event, TEST_ROOM2)

        index.commit()

        searcher = index.searcher()

        searched_events = searcher.search("message", TEST_ROOM)

        _, found_id = searched_events[0]

        event_dict = panstore.load_event_by_columns("example", user, found_id)

        assert event_dict == event.source
