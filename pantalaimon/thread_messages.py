import attr


@attr.s
class Message:
    pass


@attr.s
class UnverifiedDevicesSignal(Message):
    pan_user = attr.ib()
    room_id = attr.ib()


@attr.s
class DaemonResponse(Message):
    message_id = attr.ib()
    pan_user = attr.ib()
    code = attr.ib()
    message = attr.ib()


@attr.s
class UpdateUsersMessage(Message):
    pass


@attr.s
class UpdateDevicesMessage(Message):
    pass


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
