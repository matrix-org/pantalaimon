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


class InvalidQueryError(Exception):
    pass


if False:
    import asyncio
    import datetime
    import json
    import os
    from functools import partial
    from typing import Any, Dict, List, Optional, Tuple

    import attr
    import tantivy
    from nio import (
        RoomEncryptedMedia,
        RoomMessageMedia,
        RoomMessageText,
        RoomNameEvent,
        RoomTopicEvent,
    )
    from peewee import (
        SQL,
        DateTimeField,
        ForeignKeyField,
        Model,
        SqliteDatabase,
        TextField,
    )

    from pantalaimon.store import use_database

    INDEXING_ENABLED = True

    class DictField(TextField):
        def python_value(self, value):  # pragma: no cover
            return json.loads(value)

        def db_value(self, value):  # pragma: no cover
            return json.dumps(value)

    class StoreUser(Model):
        user_id = TextField()

        class Meta:
            constraints = [SQL("UNIQUE(user_id)")]

    class Profile(Model):
        user_id = TextField()
        avatar_url = TextField(null=True)
        display_name = TextField(null=True)

        class Meta:
            constraints = [SQL("UNIQUE(user_id,avatar_url,display_name)")]

    class Event(Model):
        event_id = TextField()
        sender = TextField()
        date = DateTimeField()
        room_id = TextField()

        source = DictField()

        profile = ForeignKeyField(model=Profile, column_name="profile_id")

        class Meta:
            constraints = [SQL("UNIQUE(event_id, room_id, sender, profile_id)")]

    class UserMessages(Model):
        user = ForeignKeyField(model=StoreUser, column_name="user_id")
        event = ForeignKeyField(model=Event, column_name="event_id")

    @attr.s
    class MessageStore:
        user = attr.ib(type=str)
        store_path = attr.ib(type=str)
        database_name = attr.ib(type=str)
        database = attr.ib(type=SqliteDatabase, init=False)
        database_path = attr.ib(type=str, init=False)

        models = [StoreUser, Event, Profile, UserMessages]

        def __attrs_post_init__(self):
            self.database_path = os.path.join(
                os.path.abspath(self.store_path), self.database_name
            )

            self.database = self._create_database()
            self.database.connect()

            with self.database.bind_ctx(self.models):
                self.database.create_tables(self.models)

        def _create_database(self):
            return SqliteDatabase(
                self.database_path, pragmas={"foreign_keys": 1, "secure_delete": 1}
            )

        @use_database
        def event_in_store(self, event_id, room_id):
            user, _ = StoreUser.get_or_create(user_id=self.user)
            query = (
                Event.select()
                .join(UserMessages)
                .where(
                    (Event.room_id == room_id)
                    & (Event.event_id == event_id)
                    & (UserMessages.user == user)
                )
                .execute()
            )

            for _ in query:
                return True

            return False

        def save_event(self, event, room_id, display_name=None, avatar_url=None):
            user, _ = StoreUser.get_or_create(user_id=self.user)

            profile_id, _ = Profile.get_or_create(
                user_id=event.sender, display_name=display_name, avatar_url=avatar_url
            )

            event_source = event.source
            event_source["room_id"] = room_id

            event_id = (
                Event.insert(
                    event_id=event.event_id,
                    sender=event.sender,
                    date=datetime.datetime.fromtimestamp(event.server_timestamp / 1000),
                    room_id=room_id,
                    source=event_source,
                    profile=profile_id,
                )
                .on_conflict_ignore()
                .execute()
            )

            if event_id <= 0:
                return None

            _, created = UserMessages.get_or_create(user=user, event=event_id)

            if created:
                return event_id

            return None

        def _load_context(self, user, event, before, after):
            context = {}

            if before > 0:
                query = (
                    Event.select()
                    .join(UserMessages)
                    .where(
                        (Event.date <= event.date)
                        & (Event.room_id == event.room_id)
                        & (Event.id != event.id)
                        & (UserMessages.user == user)
                    )
                    .order_by(Event.date.desc())
                    .limit(before)
                )

                context["events_before"] = [e.source for e in query]
            else:
                context["events_before"] = []

            if after > 0:
                query = (
                    Event.select()
                    .join(UserMessages)
                    .where(
                        (Event.date >= event.date)
                        & (Event.room_id == event.room_id)
                        & (Event.id != event.id)
                        & (UserMessages.user == user)
                    )
                    .order_by(Event.date)
                    .limit(after)
                )

                context["events_after"] = [e.source for e in query]
            else:
                context["events_after"] = []

            return context

        @use_database
        def load_events(
            self,
            search_result,  # type: List[Tuple[int, int]]
            include_profile=False,  # type: bool
            order_by_recent=False,  # type: bool
            before=0,  # type: int
            after=0,  # type: int
        ):
            # type: (...) -> Dict[Any, Any]
            user, _ = StoreUser.get_or_create(user_id=self.user)

            search_dict = {r[1]: r[0] for r in search_result}
            columns = list(search_dict.keys())

            result_dict = {"results": []}

            query = (
                UserMessages.select()
                .where(
                    (UserMessages.user_id == user) & (UserMessages.event.in_(columns))
                )
                .execute()
            )

            for message in query:

                event = message.event

                event_dict = {
                    "rank": 1 if order_by_recent else search_dict[event.id],
                    "result": event.source,
                    "context": {},
                }

                if include_profile:
                    event_profile = event.profile

                    event_dict["context"]["profile_info"] = {
                        event_profile.user_id: {
                            "display_name": event_profile.display_name,
                            "avatar_url": event_profile.avatar_url,
                        }
                    }

                context = self._load_context(user, event, before, after)

                event_dict["context"]["events_before"] = context["events_before"]
                event_dict["context"]["events_after"] = context["events_after"]

                result_dict["results"].append(event_dict)

            return result_dict

    def sanitize_room_id(room_id):
        return room_id.replace(":", "/").replace("!", "")

    class Searcher:
        def __init__(
            self,
            index,
            body_field,
            name_field,
            topic_field,
            column_field,
            room_field,
            timestamp_field,
            searcher,
        ):
            self._index = index
            self._searcher = searcher

            self.body_field = body_field
            self.name_field = topic_field
            self.topic_field = name_field
            self.column_field = column_field
            self.room_field = room_field
            self.timestamp_field = timestamp_field

        def search(self, search_term, room=None, max_results=10, order_by_recent=False):
            # type (str, str, int, bool) -> List[int, int]
            """Search for events in the index.

            Returns the score and the column id for the event.
            """
            queryparser = tantivy.QueryParser.for_index(
                self._index,
                [self.body_field, self.name_field, self.topic_field, self.room_field],
            )

            # This currently supports only a single room since the query parser
            # doesn't seem to work with multiple room fields here.
            if room:
                query_string = "{} AND room:{}".format(
                    search_term, sanitize_room_id(room)
                )
            else:
                query_string = search_term

            try:
                query = queryparser.parse_query(query_string)
            except ValueError:
                raise InvalidQueryError(f"Invalid search term: {search_term}")

            if order_by_recent:
                collector = tantivy.TopDocs(
                    max_results, order_by_field=self.timestamp_field
                )
            else:
                collector = tantivy.TopDocs(max_results)

            result = self._searcher.search(query, collector)

            retrieved_result = []

            for score, doc_address in result:
                doc = self._searcher.doc(doc_address)
                column = doc.get_first(self.column_field)
                retrieved_result.append((score, column))

            return retrieved_result

    class Index:
        def __init__(self, path=None, num_searchers=None):
            schema_builder = tantivy.SchemaBuilder()

            self.body_field = schema_builder.add_text_field("body")
            self.name_field = schema_builder.add_text_field("name")
            self.topic_field = schema_builder.add_text_field("topic")

            self.timestamp_field = schema_builder.add_unsigned_field(
                "server_timestamp", fast="single"
            )
            self.date_field = schema_builder.add_date_field("message_date")
            self.room_field = schema_builder.add_facet_field("room")

            self.column_field = schema_builder.add_unsigned_field(
                "database_column", indexed=True, stored=True, fast="single"
            )

            schema = schema_builder.build()

            self.index = tantivy.Index(schema, path)

            self.reader = self.index.reader(num_searchers=num_searchers)
            self.writer = self.index.writer()

        def add_event(self, column_id, event, room_id):
            doc = tantivy.Document()

            room_path = "/{}".format(sanitize_room_id(room_id))

            room_facet = tantivy.Facet.from_string(room_path)

            doc.add_unsigned(self.column_field, column_id)
            doc.add_facet(self.room_field, room_facet)
            doc.add_date(
                self.date_field,
                datetime.datetime.fromtimestamp(event.server_timestamp / 1000),
            )
            doc.add_unsigned(self.timestamp_field, event.server_timestamp)

            if isinstance(event, RoomMessageText):
                doc.add_text(self.body_field, event.body)
            elif isinstance(event, (RoomMessageMedia, RoomEncryptedMedia)):
                doc.add_text(self.body_field, event.body)
            elif isinstance(event, RoomNameEvent):
                doc.add_text(self.name_field, event.name)
            elif isinstance(event, RoomTopicEvent):
                doc.add_text(self.topic_field, event.topic)
            else:
                raise ValueError("Invalid event passed.")

            self.writer.add_document(doc)

        def commit(self):
            self.writer.commit()

        def searcher(self):
            self.reader.reload()
            return Searcher(
                self.index,
                self.body_field,
                self.name_field,
                self.topic_field,
                self.column_field,
                self.room_field,
                self.timestamp_field,
                self.reader.searcher(),
            )

    @attr.s
    class StoreItem:
        event = attr.ib()
        room_id = attr.ib()
        display_name = attr.ib(default=None)
        avatar_url = attr.ib(default=None)

    @attr.s
    class IndexStore:
        user = attr.ib(type=str)
        index_path = attr.ib(type=str)
        store_path = attr.ib(type=str, default=None)
        store_name = attr.ib(default="events.db")

        index = attr.ib(type=Index, init=False)
        store = attr.ib(type=MessageStore, init=False)
        event_queue = attr.ib(factory=list)
        write_lock = attr.ib(factory=asyncio.Lock)
        read_semaphore = attr.ib(type=asyncio.Semaphore, init=False)

        def __attrs_post_init__(self):
            self.store_path = self.store_path or self.index_path
            num_searchers = os.cpu_count()
            self.index = Index(self.index_path, num_searchers)
            self.read_semaphore = asyncio.Semaphore(num_searchers or 1)
            self.store = MessageStore(self.user, self.store_path, self.store_name)

        def add_event(self, event, room_id, display_name, avatar_url):
            item = StoreItem(event, room_id, display_name, avatar_url)
            self.event_queue.append(item)

        @staticmethod
        def write_events(store, index, event_queue):
            with store.database.bind_ctx(store.models):
                with store.database.atomic():
                    for item in event_queue:
                        column_id = store.save_event(item.event, item.room_id)

                        if column_id:
                            index.add_event(column_id, item.event, item.room_id)
                    index.commit()

        async def commit_events(self):
            loop = asyncio.get_event_loop()

            event_queue = self.event_queue

            if not event_queue:
                return

            self.event_queue = []

            async with self.write_lock:
                write_func = partial(
                    IndexStore.write_events, self.store, self.index, event_queue
                )
                await loop.run_in_executor(None, write_func)

        def event_in_store(self, event_id, room_id):
            return self.store.event_in_store(event_id, room_id)

        async def search(
            self,
            search_term,  # type: str
            room=None,  # type: Optional[str]
            max_results=10,  # type: int
            order_by_recent=False,  # type: bool
            include_profile=False,  # type: bool
            before_limit=0,  # type: int
            after_limit=0,  # type: int
        ):
            # type: (...) -> Dict[Any, Any]
            """Search the indexstore for an event."""
            loop = asyncio.get_event_loop()

            # Getting a searcher from tantivy may block if there is no searcher
            # available. To avoid blocking we set up the number of searchers to be
            # the number of CPUs and the semaphore has the same counter value.
            async with self.read_semaphore:
                searcher = self.index.searcher()
                search_func = partial(
                    searcher.search,
                    search_term,
                    room=room,
                    max_results=max_results,
                    order_by_recent=order_by_recent,
                )

                result = await loop.run_in_executor(None, search_func)

                load_event_func = partial(
                    self.store.load_events,
                    result,
                    include_profile,
                    order_by_recent,
                    before_limit,
                    after_limit,
                )

                search_result = await loop.run_in_executor(None, load_event_func)

                search_result["count"] = len(search_result["results"])
                search_result["highlights"] = []

                return search_result


else:
    INDEXING_ENABLED = False
