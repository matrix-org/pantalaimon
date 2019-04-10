import os
from typing import List, Optional, Tuple

import attr
from nio.store import Accounts, use_database
from peewee import (DoesNotExist, ForeignKeyField, Model, SqliteDatabase,
                    TextField)


class AccessTokens(Model):
    token = TextField()
    account = ForeignKeyField(
        model=Accounts,
        primary_key=True,
        backref="access_token",
        on_delete="CASCADE"
    )


@attr.s
class PanStore:
    store_path = attr.ib(type=str)
    database_name = attr.ib(type=str, default="pan.db")
    database = attr.ib(type=SqliteDatabase, init=False)
    database_path = attr.ib(type=str, init=False)
    models = [Accounts, AccessTokens]

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
    def get_users(self):
        # type: () -> List[Tuple[str, str]]
        users = []

        query = Accounts.select(
                Accounts.user_id,
                Accounts.device_id,
        )

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
