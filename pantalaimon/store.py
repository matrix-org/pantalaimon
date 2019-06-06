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
import json
import os
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple, Union

import attr
from nio.store import (Accounts, DeviceKeys, DeviceTrustState, TrustState,
                       use_database)
from peewee import (SQL, DateTimeField, DoesNotExist, ForeignKeyField, Model,
                    SqliteDatabase, TextField)


class DictField(TextField):
    def python_value(self, value):  # pragma: no cover
        return json.loads(value)

    def db_value(self, value):  # pragma: no cover
        return json.dumps(value)


class AccessTokens(Model):
    token = TextField()
    account = ForeignKeyField(
        model=Accounts,
        primary_key=True,
        backref="access_token",
        on_delete="CASCADE"
    )


class Servers(Model):
    name = TextField()

    class Meta:
        constraints = [SQL("UNIQUE(name)")]


class ServerUsers(Model):
    user_id = TextField()
    server = ForeignKeyField(
        model=Servers,
        column_name="server_id",
        backref="users",
        on_delete="CASCADE"
    )

    class Meta:
        constraints = [SQL("UNIQUE(user_id,server_id)")]


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

    profile = ForeignKeyField(
        model=Profile,
        column_name="profile_id",
    )

    class Meta:
        constraints = [SQL("UNIQUE(event_id, room_id, sender, profile_id)")]


class UserMessages(Model):
    user = ForeignKeyField(
        model=ServerUsers,
        column_name="user_id")
    event = ForeignKeyField(
        model=Event,
        column_name="event_id")


@attr.s
class ClientInfo:
    user_id = attr.ib(type=str)
    access_token = attr.ib(type=str)


@attr.s
class PanStore:
    store_path = attr.ib(type=str)
    database_name = attr.ib(type=str, default="pan.db")
    database = attr.ib(type=SqliteDatabase, init=False)
    database_path = attr.ib(type=str, init=False)
    models = [
        Accounts,
        AccessTokens,
        Servers,
        ServerUsers,
        DeviceKeys,
        DeviceTrustState,
        Profile,
        Event,
        UserMessages,
    ]

    def __attrs_post_init__(self):
        self.database_path = os.path.join(
            os.path.abspath(self.store_path),
            self.database_name
        )

        self.database = self._create_database()
        self.database.connect()

        with self.database.bind_ctx(self.models):
            self.database.create_tables(self.models)

    def _create_database(self):
        return SqliteDatabase(
            self.database_path,
            pragmas={
                "foreign_keys": 1,
                "secure_delete": 1,
            }
        )

    @use_database
    def _get_account(self, user_id, device_id):
        try:
            return Accounts.get(
                Accounts.user_id == user_id,
                Accounts.device_id == device_id,
            )
        except DoesNotExist:
            return None

    @use_database
    def save_event(self, server, pan_user, event, room_id, display_name,
                   avatar_url):
        # type (str, str, str, RoomMessage, str, str, str) -> Optional[int]
        """Save an event to the store.

        Returns the database id of the event.
        """
        server = Servers.get(name=server)
        user = ServerUsers.get(server=server, user_id=pan_user)

        profile_id, _ = Profile.get_or_create(
            user_id=event.sender,
            display_name=display_name,
            avatar_url=avatar_url
        )

        event_source = event.source
        event_source["room_id"] = room_id

        event_id = Event.insert(
            event_id=event.event_id,
            sender=event.sender,
            date=datetime.datetime.fromtimestamp(
                event.server_timestamp / 1000
            ),
            room_id=room_id,
            source=event_source,
            profile=profile_id
        ).on_conflict_ignore().execute()

        # TODO why do we get a 0 on conflict here, the test show that we get the
        # existing event id.
        if event_id <= 0:
            return None

        _, created = UserMessages.get_or_create(
            user=user,
            event=event_id,
        )

        if created:
            return event_id

        return None

    @use_database
    def load_event_by_columns(
            self,
            server,                # type: str
            pan_user,              # type: str
            column,                # type: List[int]
            include_profile=False  # type: bool
    ):
        # type: (...) -> Union[List[Dict[Any, Any]], List[Tuple[Dict, Dict]]]
        server = Servers.get(name=server)
        user = ServerUsers.get(server=server, user_id=pan_user)

        message = UserMessages.get_or_none(user=user, event=column)

        if not message:
            return None

        event = message.event
        event_profile = event.profile

        profile = {
            event_profile.user_id: {
                "display_name": event_profile.display_name,
                "avatar_url": event_profile.avatar_url,
            }
        }

        if include_profile:
            return event.source, profile

        return event.source

    @use_database
    def save_server_user(self, server_name, user_id):
        # type: (str, str) -> None
        server, _ = Servers.get_or_create(name=server_name)

        ServerUsers.insert(
            user_id=user_id,
            server=server
        ).on_conflict_ignore().execute()

    @use_database
    def load_all_users(self):
        users = []

        query = Accounts.select(
            Accounts.user_id,
            Accounts.device_id,
        )

        for account in query:
            users.append((account.user_id, account.device_id))

        return users

    @use_database
    def load_users(self, server_name):
        # type: (str) -> List[Tuple[str, str]]
        users = []

        server = Servers.get_or_none(Servers.name == server_name)

        if not server:
            return []

        server_users = []

        for u in server.users:
            server_users.append(u.user_id)

        query = Accounts.select(
            Accounts.user_id,
            Accounts.device_id,
        ).where(Accounts.user_id.in_(server_users))

        for account in query:
            users.append((account.user_id, account.device_id))

        return users

    @use_database
    def save_access_token(self, user_id, device_id, access_token):
        account = self._get_account(user_id, device_id)
        assert account

        AccessTokens.replace(
            account=account,
            token=access_token
        ).execute()

    @use_database
    def load_access_token(self, user_id, device_id):
        # type: (str, str) -> Optional[str]
        account = self._get_account(user_id, device_id)

        if not account:
            return None

        try:
            return account.access_token[0].token
        except IndexError:
            return None

    @use_database
    def load_all_devices(self):
        # type (str, str) -> Dict[str, Dict[str, DeviceStore]]
        store = dict()

        query = Accounts.select()

        for account in query:
            device_store = defaultdict(dict)

            for d in account.device_keys:

                if d.deleted:
                    continue

                try:
                    trust_state = d.trust_state[0].state
                except IndexError:
                    trust_state = TrustState.unset

                keys = {k.key_type: k.key for k in d.keys}

                device_store[d.user_id][d.device_id] = {
                    "user_id": d.user_id,
                    "device_id": d.device_id,
                    "ed25519": keys["ed25519"],
                    "curve25519": keys["curve25519"],
                    "trust_state": trust_state.name,
                    "device_display_name": d.display_name
                }

            store[account.user_id] = device_store

        return store
