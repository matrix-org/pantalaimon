import attr


@attr.s
class Message:
    pass


@attr.s
class InfoMessage(Message):
    string = attr.ib()


@attr.s
class DevicesMessage(Message):
    user_id = attr.ib()
    devices = attr.ib()


@attr.s
class _KeysOperation(Message):
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
class DeviceStartSasMessage(_VerificationMessage):
    pass


@attr.s
class DeviceAcceptSasMessage(_VerificationMessage):
    pass


@attr.s
class DeviceConfirmSasMessage(_VerificationMessage):
    pass


@attr.s
class DeviceAuthStringMessage(_VerificationMessage):
    short_string = attr.ib()
