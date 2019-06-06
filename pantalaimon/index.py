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

import datetime

import tantivy
from nio import RoomMessageText, RoomNameEvent, RoomTopicEvent


def sanitize_room_id(room_id):
    return room_id.replace(":", "/").replace("!", "")


class Searcher:
    def __init__(self, index, body_field, name_field, topic_field,
                 column_field, room_field, searcher):
        self._index = index
        self._searcher = searcher

        self.body_field = body_field
        self.name_field = topic_field
        self.topic_field = name_field
        self.column_field = column_field
        self.room_field = room_field

    def search(self, search_term, room=None, max_results=10):
        # type (str, str) -> List[int, int]
        """Search for events in the index.

        Returns the score and the column id for the event.
        """

        queryparser = tantivy.QueryParser.for_index(
            self._index,
            [
                self.body_field,
                self.name_field,
                self.topic_field,
                self.room_field
            ]
        )

        # This currently supports only a single room since the query parser
        # doesn't seem to work with multiple room fields here.
        if room:
            search_term = "{} AND room:{}".format(
                search_term,
                sanitize_room_id(room)
            )

        query = queryparser.parse_query(search_term)

        collector = tantivy.TopDocs(max_results)

        result = self._searcher.search(query, collector)

        retrieved_result = []

        for score, doc_address in result:
            doc = self._searcher.doc(doc_address)
            column = doc.get_first(self.column_field)
            retrieved_result.append((score, column))

        return retrieved_result


class Index:
    def __init__(self, path=None):
        schema_builder = tantivy.SchemaBuilder()

        self.body_field = schema_builder.add_text_field("body")
        self.name_field = schema_builder.add_text_field("name")
        self.topic_field = schema_builder.add_text_field("topic")

        self.timestamp_field = schema_builder.add_date_field(
            "server_timestamp"
        )
        self.room_field = schema_builder.add_facet_field("room")

        self.column_field = schema_builder.add_integer_field(
            "database_column",
            indexed=True,
            stored=True,
            fast="single"
        )

        schema = schema_builder.build()

        self.index = tantivy.Index(schema, path)

        self.reader = self.index.reader()
        self.writer = self.index.writer()

    def add_event(self, column_id, event, room_id):
        doc = tantivy.Document()

        room_path = "/{}".format(sanitize_room_id(room_id))

        room_facet = tantivy.Facet.from_string(room_path)

        doc.add_integer(self.column_field, column_id)
        doc.add_facet(self.room_field, room_facet)
        doc.add_date(
            self.timestamp_field,
            datetime.datetime.fromtimestamp(event.server_timestamp / 1000)
        )

        if isinstance(event, RoomMessageText):
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
            self.reader.searcher()
        )
