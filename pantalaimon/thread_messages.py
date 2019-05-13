import attr


@attr.s
class Message:
    pass


@attr.s
class DaemonResponse(Message):
    message_id = attr.ib()
    pan_user = attr.ib()
    code = attr.ib()
    message = attr.ib()


@attr.s
class DevicesMessage(Message):
    user_id = attr.ib()
    devices = attr.ib()


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
class SasMessage(_VerificationMessage):
    pass


@attr.s
class DeviceConfirmSasMessage(SasMessage):
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
class StartSasSignal(_SasSignal):
    pass


@attr.s
class InviteSasSignal(_SasSignal):
    pass


@attr.s
class ShowSasSignal(_SasSignal):
    emoji = attr.ib()


@attr.s
class SasDoneSignal(_SasSignal):
    pass
