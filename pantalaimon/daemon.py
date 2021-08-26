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

import asyncio
import json
import os
import urllib.parse
import concurrent.futures
from io import BufferedReader, BytesIO
from json import JSONDecodeError
from typing import Any, Dict
from urllib.parse import urlparse
from uuid import uuid4

import aiohttp
import attr
import keyring
from aiohttp import ClientSession, web
from aiohttp.client_exceptions import ClientConnectionError, ContentTypeError
from jsonschema import ValidationError
from multidict import CIMultiDict
from nio import (
    Api,
    EncryptionError,
    LoginResponse,
    OlmTrustError,
    SendRetryError,
    DownloadResponse,
    UploadResponse,
)
from nio.crypto import decrypt_attachment

from pantalaimon.client import (
    SEARCH_TERMS_SCHEMA,
    InvalidLimit,
    InvalidOrderByError,
    PanClient,
    UnknownRoomError,
    validate_json,
)
from pantalaimon.index import INDEXING_ENABLED, InvalidQueryError
from pantalaimon.log import logger
from pantalaimon.store import ClientInfo, PanStore, MediaInfo
from pantalaimon.thread_messages import (
    AcceptSasMessage,
    CancelSasMessage,
    CancelSendingMessage,
    ConfirmSasMessage,
    DaemonResponse,
    DeviceBlacklistMessage,
    DeviceUnblacklistMessage,
    DeviceUnverifyMessage,
    DeviceVerifyMessage,
    ExportKeysMessage,
    ImportKeysMessage,
    SasMessage,
    SendAnywaysMessage,
    StartSasMessage,
    UnverifiedDevicesSignal,
    UnverifiedResponse,
    UpdateUsersMessage,
    ContinueKeyShare,
    CancelKeyShare,
)

CORS_HEADERS = {
    "Access-Control-Allow-Headers": (
        "Origin, X-Requested-With, Content-Type, Accept, Authorization"
    ),
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Origin": "*",
}


class NotDecryptedAvailableError(Exception):
    """Exception that signals that no decrypted upload is available"""

    pass


@attr.s
class ProxyDaemon:
    name = attr.ib()
    homeserver = attr.ib()
    conf = attr.ib()
    data_dir = attr.ib()
    send_queue = attr.ib()
    recv_queue = attr.ib()
    proxy = attr.ib(default=None)
    ssl = attr.ib(default=None)
    client_store_class = attr.ib(default=None)

    decryption_timeout = 10
    unverified_send_timeout = 60

    store = attr.ib(type=PanStore, init=False)
    homeserver_url = attr.ib(init=False, default=attr.Factory(dict))
    hostname = attr.ib(init=False, default=attr.Factory(dict))
    pan_clients = attr.ib(init=False, default=attr.Factory(dict))
    client_info = attr.ib(init=False, default=attr.Factory(dict), type=dict)
    default_session = attr.ib(init=False, default=None)
    media_info = attr.ib(init=False, default=None)
    upload_info = attr.ib(init=False, default=None)
    database_name = "pan.db"

    def __attrs_post_init__(self):
        loop = asyncio.get_event_loop()

        self.homeserver_url = self.homeserver.geturl()
        self.hostname = self.homeserver.hostname
        self.store = PanStore(self.data_dir)
        accounts = self.store.load_users(self.name)
        self.media_info = self.store.load_media_cache(self.name)
        self.upload_info = self.store.load_upload(self.name)

        for user_id, device_id in accounts:
            if self.conf.keyring:
                try:
                    token = keyring.get_password(
                        "pantalaimon", f"{user_id}-{device_id}-token"
                    )
                except RuntimeError as e:
                    logger.error(e)
            else:
                token = self.store.load_access_token(user_id, device_id)

            if not token:
                logger.warn(
                    f"Not restoring client for {user_id} {device_id}, "
                    f"missing access token."
                )
                continue

            logger.info(f"Restoring client for {user_id} {device_id}")

            pan_client = PanClient(
                self.name,
                self.store,
                self.conf,
                self.homeserver_url,
                self.send_queue,
                user_id,
                device_id,
                store_path=self.data_dir,
                ssl=self.ssl,
                proxy=self.proxy,
                store_class=self.client_store_class,
                media_info=self.media_info,
            )
            pan_client.user_id = user_id
            pan_client.access_token = token
            pan_client.load_store()
            self.pan_clients[user_id] = pan_client

            loop.create_task(
                self.send_ui_message(
                    UpdateUsersMessage(self.name, user_id, pan_client.device_id)
                )
            )

            loop.create_task(pan_client.send_update_devices(pan_client.device_store))

            pan_client.start_loop()

    async def _find_client(self, access_token):
        client_info = self.client_info.get(access_token, None)

        if not client_info:
            async with aiohttp.ClientSession() as session:
                try:
                    method, path = Api.whoami(access_token)
                    resp = await session.request(
                        method,
                        self.homeserver_url + path,
                        proxy=self.proxy,
                        ssl=self.ssl,
                    )
                except ClientConnectionError:
                    return None

                if resp.status != 200:
                    return None

                try:
                    body = await resp.json()
                except (JSONDecodeError, ContentTypeError):
                    return None

                try:
                    user_id = body["user_id"]
                except KeyError:
                    return None

                if user_id not in self.pan_clients:
                    logger.warn(
                        f"User {user_id} doesn't have a matching pan " f"client."
                    )
                    return None

                logger.info(
                    f"Homeserver confirmed valid access token "
                    f"for user {user_id}, caching info."
                )

                client_info = ClientInfo(user_id, access_token)
                self.client_info[access_token] = client_info

        client = self.pan_clients.get(client_info.user_id, None)

        return client

    async def _verify_device(self, message_id, client, device):
        ret = client.verify_device(device)

        if ret:
            msg = (
                f"Device {device.id} of user " f"{device.user_id} succesfully verified."
            )
            await client.send_update_device(device)
        else:
            msg = f"Device {device.id} of user " f"{device.user_id} already verified."

        logger.info(msg)
        await self.send_response(message_id, client.user_id, "m.ok", msg)

    async def _unverify_device(self, message_id, client, device):
        ret = client.unverify_device(device)

        if ret:
            msg = (
                f"Device {device.id} of user "
                f"{device.user_id} succesfully unverified."
            )
            await client.send_update_device(device)
        else:
            msg = f"Device {device.id} of user " f"{device.user_id} already unverified."

        logger.info(msg)
        await self.send_response(message_id, client.user_id, "m.ok", msg)

    async def _blacklist_device(self, message_id, client, device):
        ret = client.blacklist_device(device)

        if ret:
            msg = (
                f"Device {device.id} of user "
                f"{device.user_id} succesfully blacklisted."
            )
            await client.send_update_device(device)
        else:
            msg = (
                f"Device {device.id} of user " f"{device.user_id} already blacklisted."
            )

        logger.info(msg)
        await self.send_response(message_id, client.user_id, "m.ok", msg)

    async def _unblacklist_device(self, message_id, client, device):
        ret = client.unblacklist_device(device)

        if ret:
            msg = (
                f"Device {device.id} of user "
                f"{device.user_id} succesfully unblacklisted."
            )
            await client.send_update_device(device)
        else:
            msg = (
                f"Device {device.id} of user "
                f"{device.user_id} already unblacklisted."
            )

        logger.info(msg)
        await self.send_response(message_id, client.user_id, "m.ok", msg)

    async def send_response(self, message_id, pan_user, code, message):
        """Send a thread response message to the UI thread."""
        message = DaemonResponse(message_id, pan_user, code, message)
        await self.send_ui_message(message)

    async def send_ui_message(self, message):
        """Send a thread message to the UI thread."""
        if self.send_queue:
            await self.send_queue.put(message)

    async def receive_message(self, message):
        client = self.pan_clients.get(message.pan_user)

        if isinstance(
            message,
            (
                DeviceVerifyMessage,
                DeviceUnverifyMessage,
                StartSasMessage,
                DeviceBlacklistMessage,
                DeviceUnblacklistMessage,
            ),
        ):

            device = client.device_store[message.user_id].get(message.device_id, None)

            if not device:
                msg = (
                    f"No device found for {message.user_id} and " f"{message.device_id}"
                )
                await self.send_response(
                    message.message_id, message.pan_user, "m.unknown_device", msg
                )
                logger.info(msg)
                return

            if isinstance(message, DeviceVerifyMessage):
                await self._verify_device(message.message_id, client, device)
            elif isinstance(message, DeviceUnverifyMessage):
                await self._unverify_device(message.message_id, client, device)
            elif isinstance(message, DeviceBlacklistMessage):
                await self._blacklist_device(message.message_id, client, device)
            elif isinstance(message, DeviceUnblacklistMessage):
                await self._unblacklist_device(message.message_id, client, device)
            elif isinstance(message, StartSasMessage):
                await client.start_sas(message, device)

        elif isinstance(message, SasMessage):
            if isinstance(message, AcceptSasMessage):
                await client.accept_sas(message)
            elif isinstance(message, ConfirmSasMessage):
                await client.confirm_sas(message)
            elif isinstance(message, CancelSasMessage):
                await client.cancel_sas(message)

        elif isinstance(message, ExportKeysMessage):
            path = os.path.abspath(os.path.expanduser(message.file_path))
            logger.info(f"Exporting keys to {path}")

            try:
                await client.export_keys(path, message.passphrase)
            except OSError as e:
                info_msg = (
                    f"Error exporting keys for {client.user_id} to" f" {path} {e}"
                )
                logger.info(info_msg)
                await self.send_response(
                    message.message_id, client.user_id, "m.os_error", str(e)
                )

            else:
                info_msg = (
                    f"Succesfully exported keys for {client.user_id} " f"to {path}"
                )
                logger.info(info_msg)
                await self.send_response(
                    message.message_id, client.user_id, "m.ok", info_msg
                )

        elif isinstance(message, ImportKeysMessage):
            path = os.path.abspath(os.path.expanduser(message.file_path))
            logger.info(f"Importing keys from {path}")

            try:
                await client.import_keys(path, message.passphrase)
            except (OSError, EncryptionError) as e:
                info_msg = (
                    f"Error importing keys for {client.user_id} " f"from {path} {e}"
                )
                logger.info(info_msg)
                await self.send_response(
                    message.message_id, client.user_id, "m.os_error", str(e)
                )
            else:
                info_msg = (
                    f"Succesfully imported keys for {client.user_id} " f"from {path}"
                )
                logger.info(info_msg)
                await self.send_response(
                    message.message_id, client.user_id, "m.ok", info_msg
                )

        elif isinstance(message, UnverifiedResponse):
            client = self.pan_clients[message.pan_user]

            if message.room_id not in client.send_decision_queues:
                msg = (
                    f"No send request found for user {message.pan_user} "
                    f"and room {message.room_id}."
                )
                await self.send_response(
                    message.message_id, message.pan_user, "m.unknown_request", msg
                )
                return

            queue = client.send_decision_queues[message.room_id]
            await queue.put(message)

        elif isinstance(message, (ContinueKeyShare, CancelKeyShare)):
            client = self.pan_clients[message.pan_user]
            await client.handle_key_request_message(message)

    def get_access_token(self, request):
        # type: (aiohttp.web.BaseRequest) -> str
        """Extract the access token from the request.

        This method extracts the access token either from the query string or
        from the Authorization header of the request.

        Returns the access token if it was found.
        """
        access_token = request.query.get("access_token", "")

        if not access_token:
            access_token = request.headers.get("Authorization", "").strip("Bearer ")

        return access_token

    def sanitize_subfilter(self, request_filter: Dict[Any, Any]):
        types_filter = request_filter.get("types", None)

        if types_filter:
            if "m.room.encrypted" not in types_filter:
                types_filter.append("m.room.encrypted")

        not_types_filter = request_filter.get("not_types", None)

        if not_types_filter:
            try:
                not_types_filter.remove("m.room.encrypted")
            except ValueError:
                pass

    def sanitize_filter(self, sync_filter):
        # type: (Dict[Any, Any]) -> Dict[Any, Any]
        """Make sure that a filter isn't filtering encrypted messages."""
        sync_filter = dict(sync_filter)
        room_filter = sync_filter.get("room", None)

        self.sanitize_subfilter(sync_filter)

        if room_filter:
            timeline_filter = room_filter.get("timeline", None)

            if timeline_filter:
                self.sanitize_subfilter(timeline_filter)

        return sync_filter

    async def forward_request(
        self,
        request,  # type: aiohttp.web.BaseRequest
        params=None,  # type: CIMultiDict
        data=None,  # type: bytes
        session=None,  # type: aiohttp.ClientSession
        token=None,  # type: str
    ):
        # type: (...) -> aiohttp.ClientResponse
        """Forward the given request to our configured homeserver.

        Args:
            request (aiohttp.BaseRequest): The request that should be
                forwarded.
            params (CIMultiDict, optional): The query parameters for the
                request.
            data (Dict, optional): Data for the request.
            session (aiohttp.ClientSession, optional): The client session that
                should be used to forward the request.
            token (str, optional): The access token that should be used for the
                request.
        """
        if not session:
            if not self.default_session:
                self.default_session = ClientSession()
            session = self.default_session

        assert session

        path = request.raw_path
        method = request.method

        headers = CIMultiDict(request.headers)
        headers.pop("Host", None)

        params = params or CIMultiDict(request.query)

        if token:
            if "Authorization" in headers:
                headers["Authorization"] = f"Bearer {token}"
            if "access_token" in params:
                params["access_token"] = token

        if data:
            data = data
            headers.pop("Content-Length", None)
        else:
            data = await request.read()

        return await session.request(
            method,
            self.homeserver_url + path,
            data=data,
            params=params,
            headers=headers,
            proxy=self.proxy,
            ssl=self.ssl,
        )

    async def forward_to_web(
        self, request, params=None, data=None, session=None, token=None
    ):
        """Forward the given request and convert the response to a Response.

        If there is a exception raised by the client session this method
        returns a Response with a 500 status code and the text set to the error
        message of the exception.

        Args:
            request (aiohttp.BaseRequest): The request that should be
                forwarded.
            params (CIMultiDict, optional): The query parameters for the
                request.
            data (Dict, optional): Data for the request.
            session (aiohttp.ClientSession, optional): The client session that
                should be used to forward the request.
            token (str, optional): The access token that should be used for the
                request.
        """
        try:
            response = await self.forward_request(
                request, params=params, data=data, session=session, token=token
            )
            return web.Response(
                status=response.status,
                content_type=response.content_type,
                headers=CORS_HEADERS,
                body=await response.read(),
            )
        except ClientConnectionError as e:
            return web.Response(status=500, text=str(e))

    async def router(self, request):
        """Catchall request router."""
        return await self.forward_to_web(request)

    def _get_login_user(self, body):
        identifier = body.get("identifier", None)

        if identifier:
            user = identifier.get("user", None)

            if not user:
                user = body.get("user", "")
        else:
            user = body.get("user", "")

        return user

    async def start_pan_client(
        self, access_token, user, user_id, password, device_id=None
    ):
        client = ClientInfo(user_id, access_token)
        self.client_info[access_token] = client
        self.store.save_server_user(self.name, user_id)

        if user_id in self.pan_clients:
            logger.info(
                f"Background sync client already exists for {user_id},"
                f" not starting new one"
            )
            return

        pan_client = PanClient(
            self.name,
            self.store,
            self.conf,
            self.homeserver_url,
            self.send_queue,
            user_id,
            store_path=self.data_dir,
            ssl=self.ssl,
            proxy=self.proxy,
            store_class=self.client_store_class,
            media_info=self.media_info,
        )

        if password == "":
            if device_id is None:
                logger.warn(
                    "Empty password provided and device_id was also None, not "
                    "starting background sync client "
                )
                return
            # If password is blank, we cannot login normally and must
            # fall back to using the provided device_id.
            pan_client.restore_login(user_id, device_id, access_token)
        else:
            response = await pan_client.login(password, "pantalaimon")

            if not isinstance(response, LoginResponse):
                await pan_client.close()
                return

        logger.info(f"Succesfully started new background sync client for " f"{user_id}")

        await self.send_ui_message(
            UpdateUsersMessage(self.name, user_id, pan_client.device_id)
        )

        self.pan_clients[user_id] = pan_client

        if self.conf.keyring:
            try:
                keyring.set_password(
                    "pantalaimon",
                    f"{user_id}-{pan_client.device_id}-token",
                    pan_client.access_token,
                )
            except RuntimeError as e:
                logger.error(e)
        else:
            self.store.save_access_token(
                user_id, pan_client.device_id, pan_client.access_token
            )

        pan_client.start_loop()

    async def login(self, request):
        try:
            body = await request.json()
        except (JSONDecodeError, ContentTypeError):
            # After a long debugging session the culprit ended up being aiohttp
            # and a similar bug to
            # https://github.com/aio-libs/aiohttp/issues/2277 but in the server
            # part of aiohttp. The bug is fixed in the latest master of
            # aiohttp.
            # Return 500 here for now since quaternion doesn't work otherwise.
            # After aiohttp 4.0 gets replace this with a 400 M_NOT_JSON
            # response.
            return web.json_response(
                {
                    "errcode": "M_NOT_JSON",
                    "error": "Request did not contain valid JSON.",
                },
                status=500,
            )

        user = self._get_login_user(body)
        password = body.get("password", "")

        logger.info(f"New user logging in: {user}")

        try:
            response = await self.forward_request(request)
        except ClientConnectionError as e:
            return web.Response(status=500, text=str(e))

        try:
            json_response = await response.json()
        except (JSONDecodeError, ContentTypeError):
            json_response = None

        if response.status == 200 and json_response:
            user_id = json_response.get("user_id", None)
            access_token = json_response.get("access_token", None)
            device_id = json_response.get("device_id", None)

            if user_id and access_token:
                logger.info(
                    f"User: {user} succesfully logged in, starting "
                    f"a background sync client."
                )
                await self.start_pan_client(
                    access_token, user, user_id, password, device_id
                )

        return web.Response(
            status=response.status,
            content_type=response.content_type,
            headers=CORS_HEADERS,
            body=await response.read(),
        )

    @property
    def _missing_token(self):
        return web.json_response(
            {"errcode": "M_MISSING_TOKEN", "error": "Missing access token."},
            headers=CORS_HEADERS,
            status=401,
        )

    @property
    def _unknown_token(self):
        return web.json_response(
            {"errcode": "M_UNKNOWN_TOKEN", "error": "Unrecognised access token."},
            headers=CORS_HEADERS,
            status=401,
        )

    @property
    def _not_json(self):
        return web.json_response(
            {"errcode": "M_NOT_JSON", "error": "Request did not contain valid JSON."},
            headers=CORS_HEADERS,
            status=400,
        )

    async def decrypt_body(self, client, body, sync=True):
        """Try to decrypt the a sync or messages body."""
        decryption_method = (
            client.decrypt_sync_body if sync else client.decrypt_messages_body
        )

        async def decrypt_loop(client, body):
            while True:
                try:
                    logger.info("Trying to decrypt sync")
                    return decryption_method(body, ignore_failures=False)
                except EncryptionError:
                    logger.info("Error decrypting sync, waiting for next pan " "sync")
                    await client.synced.wait(),
                    logger.info("Pan synced, retrying decryption.")

        try:
            return await asyncio.wait_for(
                decrypt_loop(client, body), timeout=self.decryption_timeout
            )
        except asyncio.TimeoutError:
            logger.info("Decryption attempt timed out, decrypting with " "failures")
            return decryption_method(body, ignore_failures=True)

    async def sync(self, request):
        access_token = self.get_access_token(request)

        if not access_token:
            return self._missing_token

        client = await self._find_client(access_token)
        if not client:
            return self._unknown_token

        sync_filter = request.query.get("filter", None)
        query = CIMultiDict(request.query)

        if sync_filter:
            try:
                sync_filter = json.loads(sync_filter)
            except (JSONDecodeError, TypeError):
                pass

            if isinstance(sync_filter, dict):
                sync_filter = json.dumps(self.sanitize_filter(sync_filter))

            query["filter"] = sync_filter

        try:
            response = await self.forward_request(
                request, params=query, token=client.access_token
            )
        except ClientConnectionError as e:
            return web.Response(status=500, text=str(e))

        if response.status == 200:
            try:
                json_response = await response.json()
                json_response = await self.decrypt_body(client, json_response)

                return web.json_response(
                    json_response, headers=CORS_HEADERS, status=response.status
                )
            except (JSONDecodeError, ContentTypeError):
                pass

        return web.Response(
            status=response.status,
            content_type=response.content_type,
            headers=CORS_HEADERS,
            body=await response.read(),
        )

    async def messages(self, request):
        access_token = self.get_access_token(request)

        if not access_token:
            return self._missing_token

        client = await self._find_client(access_token)
        if not client:
            return self._unknown_token

        request_filter = request.query.get("filter", None)
        query = CIMultiDict(request.query)

        if request_filter:
            try:
                request_filter = json.loads(request_filter)
            except (JSONDecodeError, TypeError):
                pass

            if isinstance(request_filter, dict):
                request_filter = json.dumps(self.sanitize_filter(request_filter))

            query["filter"] = request_filter

        try:
            response = await self.forward_request(request, params=query)
        except ClientConnectionError as e:
            return web.Response(status=500, text=str(e))

        if response.status == 200:
            try:
                json_response = await response.json()
                json_response = await self.decrypt_body(
                    client, json_response, sync=False
                )

                return web.json_response(
                    json_response, headers=CORS_HEADERS, status=response.status
                )
            except (JSONDecodeError, ContentTypeError):
                pass

        return web.Response(
            status=response.status,
            content_type=response.content_type,
            headers=CORS_HEADERS,
            body=await response.read(),
        )

    def _get_upload_and_media_info(self, content_uri: str):
        try:
            upload_info = self.upload_info[content_uri]
        except KeyError:
            upload_info = self.store.load_upload(self.name, content_uri)
            if not upload_info:
                return None, None

        self.upload_info[content_uri] = upload_info

        mxc = urlparse(content_uri)
        mxc_server = mxc.netloc.strip("/")
        mxc_path = mxc.path.strip("/")

        media_info = self.store.load_media(self.name, mxc_server, mxc_path)
        if not media_info:
            return None, None

        self.media_info[(mxc_server, mxc_path)] = media_info

        return upload_info, media_info

    async def _decrypt_uri(self, content_uri, client):
        upload_info, media_info = self._get_upload_and_media_info(content_uri)
        if not upload_info or not media_info:
            raise NotDecryptedAvailableError

        response, decrypted_file = await self._load_decrypted_file(
            media_info.mxc_server, media_info.mxc_path, upload_info.filename
        )

        if response is None and decrypted_file is None:
            raise NotDecryptedAvailableError

        if not isinstance(response, DownloadResponse):
            raise NotDecryptedAvailableError

        decrypted_upload, _ = await client.upload(
            data_provider=BufferedReader(BytesIO(decrypted_file)),
            content_type=upload_info.mimetype,
            filename=upload_info.filename,
            encrypt=False,
            filesize=len(decrypted_file),
        )

        if not isinstance(decrypted_upload, UploadResponse):
            raise NotDecryptedAvailableError

        return decrypted_upload.content_uri

    async def send_message(self, request):
        access_token = self.get_access_token(request)

        if not access_token:
            return self._missing_token

        client = await self._find_client(access_token)
        if not client:
            return self._unknown_token

        room_id = request.match_info["room_id"]

        try:
            room = client.rooms[room_id]
            encrypt = room.encrypted
        except KeyError:
            # The room is not in the joined rooms list, either the pan client
            # didn't manage to sync the state or we're not joined, in either
            # case send an error response.
            if client.has_been_synced:
                return web.json_response(
                    {
                        "errcode": "M_FORBIDDEN",
                        "error": "You do not have permission to send the event."
                    },
                    headers=CORS_HEADERS,
                    status=403,
                )
            else:
                logger.error(
                    "The internal Pantalaimon client did not manage "
                    "to sync with the server."
                )
                return web.json_response(
                    {
                        "errcode": "M_UNKNOWN",
                        "error": "The pantalaimon client did not manage to sync with "
                        "the server",
                    },
                    headers=CORS_HEADERS,
                    status=500,
                )

        # Don't encrypt reactions for now - they are weird and clients
        # need to support them like this.
        # TODO: Fix when MSC1849 is fully supported by clients.
        if request.match_info["event_type"] == "m.reaction":
            encrypt = False

        msgtype = request.match_info["event_type"]

        try:
            content = await request.json()
        except (JSONDecodeError, ContentTypeError):
            return self._not_json

        # The room isn't encrypted just forward the message.
        if not encrypt:
            content_msgtype = content.get("msgtype")
            if (
                content_msgtype in ["m.image", "m.video", "m.audio", "m.file"]
                or msgtype == "m.room.avatar"
            ):
                try:
                    content["url"] = await self._decrypt_uri(content["url"], client)
                    if "info" in content and "thumbnail_url" in content["info"]:
                        content["info"]["thumbnail_url"] = await self._decrypt_uri(
                            content["info"]["thumbnail_url"], client
                        )
                    return await self.forward_to_web(
                        request, data=json.dumps(content), token=client.access_token
                    )
                except ClientConnectionError as e:
                    return web.Response(status=500, text=str(e))
                except (KeyError, NotDecryptedAvailableError):
                    return await self.forward_to_web(request, token=client.access_token)

            return await self.forward_to_web(request, token=client.access_token)

        txnid = request.match_info.get("txnid", uuid4())

        async def _send(ignore_unverified=False):
            try:
                content_msgtype = content.get("msgtype")
                if (
                    content_msgtype in ["m.image", "m.video", "m.audio", "m.file"]
                    or msgtype == "m.room.avatar"
                ):
                    upload_info, media_info = self._get_upload_and_media_info(
                        content["url"]
                    )
                    if not upload_info or not media_info:
                        response = await client.room_send(
                            room_id, msgtype, content, txnid, ignore_unverified
                        )

                        return web.Response(
                            status=response.transport_response.status,
                            content_type=response.transport_response.content_type,
                            headers=CORS_HEADERS,
                            body=await response.transport_response.read(),
                        )

                    media_info.to_content(content, upload_info.mimetype)
                    if content["info"].get("thumbnail_url", False):
                        (
                            thumb_upload_info,
                            thumb_media_info,
                        ) = self._get_upload_and_media_info(
                            content["info"]["thumbnail_url"]
                        )
                        if thumb_upload_info and thumb_media_info:
                            thumb_media_info.to_thumbnail(
                                content, thumb_upload_info.mimetype
                            )

                    response = await client.room_send(
                        room_id, msgtype, content, txnid, ignore_unverified
                    )
                else:
                    response = await client.room_send(
                        room_id, msgtype, content, txnid, ignore_unverified
                    )

                return web.Response(
                    status=response.transport_response.status,
                    content_type=response.transport_response.content_type,
                    headers=CORS_HEADERS,
                    body=await response.transport_response.read(),
                )
            except ClientConnectionError as e:
                return web.Response(status=500, text=str(e))
            except SendRetryError as e:
                return web.Response(status=503, text=str(e))

        # Aquire a semaphore here so we only send out one
        # UnverifiedDevicesSignal
        sem = client.send_semaphores[room_id]

        async with sem:
            # Even though we request the full state we don't receive room
            # members since we're using lazy loading. The summary is for some
            # reason empty so nio can't know if room members are missing from
            # our state. Fetch the room members here instead.
            if not client.room_members_fetched[room_id]:
                try:
                    await client.joined_members(room_id)
                    client.room_members_fetched[room_id] = True
                except ClientConnectionError as e:
                    return web.Response(status=500, text=str(e))

            try:
                return await _send(self.conf.ignore_verification)
            except OlmTrustError as e:
                # There are unverified/unblocked devices in the room, notify
                # the UI thread about this and wait for a response.
                queue = asyncio.Queue()
                client.send_decision_queues[room_id] = queue

                message = UnverifiedDevicesSignal(
                    client.user_id, room_id, room.display_name
                )

                await self.send_ui_message(message)

                try:
                    response = await asyncio.wait_for(
                        queue.get(), self.unverified_send_timeout
                    )

                    if isinstance(response, CancelSendingMessage):
                        # The send was canceled notify the client that sent the
                        # request about this.
                        info_msg = (
                            f"Canceled message sending for room "
                            f"{room.display_name} ({room_id})."
                        )
                        logger.info(info_msg)
                        await self.send_response(
                            response.message_id, client.user_id, "m.ok", info_msg
                        )

                        return web.Response(status=503, text=str(e))

                    elif isinstance(response, SendAnywaysMessage):
                        # We are sending and ignoring devices along the way.
                        info_msg = (
                            f"Ignoring unverified devices and sending "
                            f"message to room "
                            f"{room.display_name} ({room_id})."
                        )
                        logger.info(info_msg)
                        await self.send_response(
                            response.message_id, client.user_id, "m.ok", info_msg
                        )

                        ret = await _send(True)
                        await client.send_update_devices(client.room_devices(room_id))
                        return ret

                except asyncio.TimeoutError:
                    # We didn't get a response to our signal, send out an error
                    # response.

                    return web.Response(
                        status=503,
                        text=(
                            f"Room contains unverified devices and no "
                            f"action was taken for "
                            f"{self.unverified_send_timeout} seconds, "
                            f"request timed out"
                        ),
                    )

                finally:
                    client.send_decision_queues.pop(room_id)

    async def filter(self, request):
        access_token = self.get_access_token(request)

        if not access_token:
            return self._missing_token

        try:
            content = await request.json()
        except (JSONDecodeError, ContentTypeError):
            return self._not_json

        sanitized_content = self.sanitize_filter(content)

        return await self.forward_to_web(request, data=json.dumps(sanitized_content))

    async def search_opts(self, request):
        return web.json_response({}, headers=CORS_HEADERS)

    async def search(self, request):
        access_token = self.get_access_token(request)

        if not access_token:
            return self._missing_token

        if not INDEXING_ENABLED:
            return await self.forward_to_web(request)

        client = await self._find_client(access_token)

        if not client:
            return self._unknown_token

        try:
            content = await request.json()
        except (JSONDecodeError, ContentTypeError):
            return self._not_json

        try:
            validate_json(content, SEARCH_TERMS_SCHEMA)
        except ValidationError:
            return web.json_response(
                {"errcode": "M_BAD_JSON", "error": "Invalid search query"},
                headers=CORS_HEADERS,
                status=400,
            )

        # If we're indexing only encrypted rooms check if the search request is
        # for an encrypted room, if it isn't forward it to the server.
        # TODO if the search request contains no rooms, that is a search in all
        # rooms or a mix of encrypted and unencrypted rooms we need to combine
        # search a local search with a remote search.
        if self.conf.index_encrypted_only:
            s_filter = content["search_categories"]["room_events"]["filter"]
            rooms = s_filter.get("rooms", list(client.rooms))

            for room_id in rooms:
                try:
                    room = client.rooms[room_id]
                    if room.encrypted:
                        break

                except KeyError:
                    return await self.forward_to_web(request)
            else:
                return await self.forward_to_web(request)

        try:
            result = await client.search(content)
        except (InvalidOrderByError, InvalidLimit, InvalidQueryError) as e:
            return web.json_response(
                {"errcode": "M_INVALID_PARAM", "error": str(e)},
                headers=CORS_HEADERS,
                status=400,
            )
        except UnknownRoomError:
            return await self.forward_to_web(request)

        return web.json_response(result, headers=CORS_HEADERS, status=200)

    async def upload(self, request):
        file_name = request.query.get("filename", "")
        content_type = request.headers.get("Content-Type", "application/octet-stream")
        client = next(iter(self.pan_clients.values()))

        body = await request.read()
        try:
            response, maybe_keys = await client.upload(
                data_provider=BufferedReader(BytesIO(body)),
                content_type=content_type,
                filename=file_name,
                encrypt=True,
                filesize=len(body),
            )

            if not isinstance(response, UploadResponse):
                return web.Response(
                    status=response.transport_response.status,
                    content_type=response.transport_response.content_type,
                    headers=CORS_HEADERS,
                    body=await response.transport_response.read(),
                )

            self.store.save_upload(
                self.name, response.content_uri, file_name, content_type
            )

            mxc = urlparse(response.content_uri)
            mxc_server = mxc.netloc.strip("/")
            mxc_path = mxc.path.strip("/")

            logger.info(f"Adding media info for {mxc_server}/{mxc_path} to the store")
            media_info = MediaInfo(
                mxc_server,
                mxc_path,
                maybe_keys["key"],
                maybe_keys["iv"],
                maybe_keys["hashes"],
            )
            self.store.save_media(self.name, media_info)

            return web.Response(
                status=response.transport_response.status,
                content_type=response.transport_response.content_type,
                headers=CORS_HEADERS,
                body=await response.transport_response.read(),
            )

        except ClientConnectionError as e:
            return web.Response(status=500, text=str(e))
        except SendRetryError as e:
            return web.Response(status=503, text=str(e))

    async def _load_decrypted_file(self, server_name, media_id, file_name):
        try:
            media_info = self.media_info[(server_name, media_id)]
        except KeyError:
            media_info = self.store.load_media(self.name, server_name, media_id)

            if not media_info:
                logger.info(f"No media info found for {server_name}/{media_id}")
                return None, None

            self.media_info[(server_name, media_id)] = media_info

        try:
            key = media_info.key["k"]
            hash = media_info.hashes["sha256"]
        except KeyError as e:
            logger.warn(
                f"Media info for {server_name}/{media_id} doesn't contain a key or hash."
            )
            raise e
        if not self.pan_clients:
            return None, None

        client = next(iter(self.pan_clients.values()))

        try:
            response = await client.download(server_name, media_id, file_name)
        except ClientConnectionError as e:
            raise e

        if not isinstance(response, DownloadResponse):
            return response, None

        logger.info(f"Decrypting media {server_name}/{media_id}")

        loop = asyncio.get_running_loop()
        with concurrent.futures.ProcessPoolExecutor() as pool:
            decrypted_file = await loop.run_in_executor(
                pool, decrypt_attachment, response.body, key, hash, media_info.iv
            )

        return response, decrypted_file

    async def profile(self, request):
        access_token = self.get_access_token(request)

        if not access_token:
            return self._missing_token

        client = await self._find_client(access_token)
        if not client:
            return self._unknown_token

        try:
            content = await request.json()
        except (JSONDecodeError, ContentTypeError):
            return self._not_json

        try:
            content["avatar_url"] = await self._decrypt_uri(
                content["avatar_url"], client
            )
            return await self.forward_to_web(
                request, data=json.dumps(content), token=client.access_token
            )
        except ClientConnectionError as e:
            return web.Response(status=500, text=str(e))
        except (KeyError, NotDecryptedAvailableError):
            return await self.forward_to_web(request, token=client.access_token)

    async def download(self, request):
        server_name = request.match_info["server_name"]
        media_id = request.match_info["media_id"]
        file_name = request.match_info.get("file_name")

        try:
            response, decrypted_file = await self._load_decrypted_file(
                server_name, media_id, file_name
            )

            if response is None and decrypted_file is None:
                return await self.forward_to_web(request)
        except ClientConnectionError as e:
            return web.Response(status=500, text=str(e))
        except KeyError:
            return await self.forward_to_web(request)

        if not isinstance(response, DownloadResponse):
            return web.Response(
                status=response.transport_response.status,
                content_type=response.transport_response.content_type,
                headers=CORS_HEADERS,
                body=await response.transport_response.read(),
            )

        return web.Response(
            status=response.transport_response.status,
            content_type=response.transport_response.content_type,
            headers=CORS_HEADERS,
            body=decrypted_file,
        )

    async def well_known(self, _):
        """Intercept well-known requests

        Clients might make this request before logging in and override the
        homeserver setting set by the user.
        """
        return web.Response(status=404)

    async def shutdown(self, _):
        """Shut the daemon down closing all the client sessions it has.

        This method is called when we shut the whole app down.
        """
        for client in self.pan_clients.values():
            await client.loop_stop()
            await client.close()

        if self.default_session:
            await self.default_session.close()
            self.default_session = None
