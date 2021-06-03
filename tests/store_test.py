import asyncio
import pdb
import pprint
import pytest

from nio import RoomMessage, RoomEncryptedMedia

from urllib.parse import urlparse
from conftest import faker
from pantalaimon.index import INDEXING_ENABLED
from pantalaimon.store import FetchTask, MediaInfo, UploadInfo

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
                "event_id": "$15163622445EBvZK:localhost",
                "origin_server_ts": 1516362244030,
                "room_id": "!SVkFJHzfwvuaIEawgC:localhost",
                "sender": "@example2:localhost",
                "type": "m.room.message",
                "unsigned": {"age": 43289803095},
                "user_id": "@example2:localhost",
                "age": 43289803095
            }
        )

    @property
    def encrypted_media_event(self):
        return RoomEncryptedMedia.from_dict({
            "room_id": "!testroom:localhost",
            "event_id": "$15163622445EBvZK:localhost",
            "origin_server_ts": 1516362244030,
            "sender": "@example2:localhost",
            "type": "m.room.message",
            "content": {
                "body": "orange_cat.jpg",
                "msgtype": "m.image",
                "file": {
                    "v": "v2",
                    "key": {
                        "alg": "A256CTR",
                        "ext": True,
                        "k": "yx0QvkgYlasdWEsdalkejaHBzCkKEBAp3tB7dGtWgrs",
                        "key_ops": ["encrypt", "decrypt"],
                        "kty": "oct"
                    },
                    "iv": "0pglXX7fspIBBBBAEERLFd",
                    "hashes": {
                        "sha256": "eXRDFvh+aXsQRj8a+5ZVVWUQ9Y6u9DYiz4tq1NvbLu8"
                    },
                    "url": "mxc://localhost/maDtasSiPFjROFMnlwxIhhyW",
                    "mimetype": "image/jpeg"
                }
            }
        })

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

    def test_token_storing(self, panstore_with_users):
        panstore = panstore_with_users
        accounts = panstore.load_all_users()
        user, _ = accounts[0]

        assert not panstore.load_token("example", user)
        panstore.save_token("example", user, "abc123")

        assert panstore.load_token("example", user) == "abc123"

    def test_fetcher_tasks(self, panstore_with_users):
        panstore = panstore_with_users
        accounts = panstore.load_all_users()
        user, _ = accounts[0]

        task = FetchTask(TEST_ROOM, "abc1234")
        task2 = FetchTask(TEST_ROOM2, "abc1234")

        assert not panstore.load_fetcher_tasks("example", user)

        panstore.save_fetcher_task("example", user, task)
        panstore.save_fetcher_task("example", user, task2)

        tasks = panstore.load_fetcher_tasks("example", user)

        assert task in tasks
        assert task2 in tasks

        panstore.delete_fetcher_task("example", user, task)
        tasks = panstore.load_fetcher_tasks("example", user)

        assert task not in tasks
        assert task2 in tasks

    async def test_new_indexstore(self, tempdir):
        if not INDEXING_ENABLED:
            pytest.skip("Indexing needs to be enabled to test this")

        from pantalaimon.index import Index, IndexStore
        loop = asyncio.get_event_loop()

        store = IndexStore("example", tempdir)

        store.add_event(self.test_event, TEST_ROOM, None, None)
        store.add_event(self.another_event, TEST_ROOM, None, None)
        await store.commit_events()

        assert store.event_in_store(self.test_event.event_id, TEST_ROOM)
        assert not store.event_in_store("FAKE", TEST_ROOM)

        result = await store.search("test", TEST_ROOM, after_limit=10, before_limit=10)
        pprint.pprint(result)

        assert len(result["results"]) == 1
        assert result["count"] == 1
        assert result["results"][0]["result"] == self.test_event.source
        assert (result["results"][0]["context"]["events_after"][0]
                == self.another_event.source)

    def test_media_storage(self, panstore):
        server_name = "test"
        media_cache = panstore.load_media_cache(server_name)
        assert not media_cache

        event = self.encrypted_media_event

        mxc = urlparse(event.url)

        assert mxc

        mxc_server = mxc.netloc
        mxc_path = mxc.path

        assert not panstore.load_media(server_name, mxc_server, mxc_path)

        media = MediaInfo(mxc_server, mxc_path, event.key, event.iv, event.hashes)

        panstore.save_media(server_name, media)

        media_cache = panstore.load_media_cache(server_name)

        assert (mxc_server, mxc_path) in media_cache
        media_info = media_cache[(mxc_server, mxc_path)]
        assert media_info == media
        assert media_info == panstore.load_media(server_name, mxc_server, mxc_path)

    def test_upload_storage(self, panstore):
        server_name = "test"
        upload_cache = panstore.load_upload(server_name)
        assert not upload_cache

        filename = "orange_cat.jpg"
        mimetype = "image/jpeg"
        event = self.encrypted_media_event

        assert not panstore.load_upload(server_name, event.url)

        upload = UploadInfo(event.url, filename, mimetype)

        panstore.save_upload(server_name, event.url, filename, mimetype)

        upload_cache = panstore.load_upload(server_name)

        assert (event.url) in upload_cache
        upload_info = upload_cache[event.url]
        assert upload_info == upload
        assert upload_info == panstore.load_upload(server_name, event.url)
