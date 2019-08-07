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

import attr


@attr.s
class Message:
    pass


@attr.s
class UnverifiedDevicesSignal(Message):
    pan_user = attr.ib()
    room_id = attr.ib()
    room_display_name = attr.ib()


@attr.s
class UnverifiedResponse(Message):
    message_id = attr.ib()
    pan_user = attr.ib()
    room_id = attr.ib()


@attr.s
class SendAnywaysMessage(UnverifiedResponse):
    pass


@attr.s
class CancelSendingMessage(UnverifiedResponse):
    pass


@attr.s
class KeyRequestMessage(Message):
    pan_user = attr.ib(type=str)
    event = attr.ib()


@attr.s
class _KeyShare(Message):
    message_id = attr.ib()
    pan_user = attr.ib()
    user_id = attr.ib()
    device_id = attr.ib()


@attr.s
class ContinueKeyShare(_KeyShare):
    pass


@attr.s
class CancelKeyShare(_KeyShare):
    pass


@attr.s
class DaemonResponse(Message):
    message_id = attr.ib()
    pan_user = attr.ib()
    code = attr.ib()
    message = attr.ib()


@attr.s
class UpdateUsersMessage(Message):
    server = attr.ib()
    user_id = attr.ib()
    device_id = attr.ib()


@attr.s
class UpdateDevicesMessage(Message):
    pan_user = attr.ib(type=str)
    devices = attr.ib(type=dict)


@attr.s
class _KeysOperation(Message):
    message_id = attr.ib()
    pan_user = attr.ib()
    file_path = attr.ib()
    passphrase = attr.ib()


@attr.s
class ImportKeysMessage(_KeysOperation):
    pass


@attr.s
class ExportKeysMessage(_KeysOperation):
    pass


@attr.s
class _VerificationMessage(Message):
    message_id = attr.ib()
    pan_user = attr.ib()
    user_id = attr.ib()
    device_id = attr.ib()


@attr.s
class DeviceVerifyMessage(_VerificationMessage):
    pass


@attr.s
class DeviceUnverifyMessage(_VerificationMessage):
    pass


@attr.s
class DeviceBlacklistMessage(_VerificationMessage):
    pass


@attr.s
class DeviceUnblacklistMessage(_VerificationMessage):
    pass


@attr.s
class SasMessage(_VerificationMessage):
    pass


@attr.s
class StartSasMessage(SasMessage):
    pass


@attr.s
class CancelSasMessage(SasMessage):
    pass


@attr.s
class ConfirmSasMessage(SasMessage):
    pass


@attr.s
class AcceptSasMessage(SasMessage):
    pass


@attr.s
class _SasSignal:
    pan_user = attr.ib()
    user_id = attr.ib()
    device_id = attr.ib()
    transaction_id = attr.ib()


@attr.s
class InviteSasSignal(_SasSignal):
    pass


@attr.s
class ShowSasSignal(_SasSignal):
    emoji = attr.ib()


@attr.s
class SasDoneSignal(_SasSignal):
    pass
