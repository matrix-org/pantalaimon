import attr

from gi.repository import GLib
from pydbus import SessionBus
from pydbus.generic import signal

from queue import Empty
from nio.store import TrustState

from pantalaimon.store import PanStore
from pantalaimon.thread_messages import (
    DeviceVerifyMessage,
    DeviceUnverifyMessage,
    DevicesMessage,
    AcceptSasMessage,
    DeviceConfirmSasMessage,
    ImportKeysMessage,
    ExportKeysMessage,
    StartSasSignal,
    ShowSasSignal,
    InviteSasSignal,
    SasDoneSignal,
    DaemonResponse
)
from pantalaimon.log import logger


class IdCounter:
    def __init__(self):
        self._message_id = 0

    @property
    def message_id(self):
        ret = self._message_id
        self._message_id += 1

        return ret


class Control:
    """
    <node>
        <interface name='org.pantalaimon1.control'>
            <method name='ListUsers'>
                <arg type='a(ss)' name='users' direction='out'/>
            </method>

            <method name='ExportKeys'>
                <arg type='s' name='pan_user' direction='in'/>
                <arg type='s' name='file_path' direction='in'/>
                <arg type='s' name='passphrase' direction='in'/>
                <arg type='u' name='id' direction='out'/>
            </method>

            <method name='ImportKeys'>
                <arg type='s' name='pan_user' direction='in'/>
                <arg type='s' name='file_path' direction='in'/>
                <arg type='s' name='passphrase' direction='in'/>
                <arg type='u' name='id' direction='out'/>
            </method>

            <signal name="Response">
                <arg direction="out" type="i" name="id"/>
                <arg direction="out" type="s" name="pan_user"/>
                <arg direction="out" type="a{ss}" name="message"/>
            </signal>
        </interface>
    </node>
    """

    Response = signal()

    def __init__(self, queue, user_list, id_counter):
        self.users = user_list
        self.queue = queue
        self.id_counter = id_counter

    @property
    def message_id(self):
        return self.id_counter.message_id

    def ListUsers(self):
        """Return the list of pan users."""
        return self.users

    def ExportKeys(self, pan_user, filepath, passphrase):
        message = ExportKeysMessage(
            self.message_id,
            pan_user,
            filepath,
            passphrase
        )
        self.queue.put(message)
        return message.message_id

    def ImportKeys(self, pan_user, filepath, passphrase):
        message = ImportKeysMessage(
            self.message_id,
            pan_user,
            filepath,
            passphrase
        )
        self.queue.put(message)
        return message.message_id


class Devices:
    """
    <node>
        <interface name='org.pantalaimon1.devices'>
            <method name='List'>
                <arg type='s' name='pan_user' direction='in'/>
                <arg type='aa{ss}' name='devices' direction='out'/>
            </method>

            <method name='ListUserDevices'>
                <arg type='s' name='pan_user' direction='in'/>
                <arg type='s' name='user_id' direction='in'/>
                <arg type='aa{ss}' name='devices' direction='out'/>
            </method>

            <method name='AcceptKeyVerification'>
                <arg type='s' name='pan_user' direction='in'/>
                <arg type='s' name='user_id' direction='in'/>
                <arg type='s' name='device_id' direction='in'/>
                <arg type='u' name='id' direction='out'/>
            </method>

            <method name='ConfirmKeyVerification'>
                <arg type='s' name='pan_user' direction='in'/>
                <arg type='s' name='user_id' direction='in'/>
                <arg type='s' name='device_id' direction='in'/>
                <arg type='u' name='id' direction='out'/>
            </method>

            <signal name="VerificationInvite">
                <arg direction="out" type="s" name="pan_user"/>
                <arg direction="out" type="s" name="user_id"/>
                <arg direction="out" type="s" name="device_id"/>
                <arg direction="out" type="s" name="transaction_id"/>
            </signal>

            <signal name="VerificationString">
                <arg direction="out" type="s" name="pan_user"/>
                <arg direction="out" type="s" name="user_id"/>
                <arg direction="out" type="s" name="device_id"/>
                <arg direction="out" type="s" name="transaction_id"/>
                <arg direction="out" type="a(ss)" name="emoji"/>
            </signal>

            <signal name="VerificationCancel">
                <arg direction="out" type="s" name="pan_user"/>
                <arg direction="out" type="s" name="user_id"/>
                <arg direction="out" type="s" name="device_id"/>
                <arg direction="out" type="s" name="transaction_id"/>
                <arg direction="out" type="s" name="reason"/>
                <arg direction="out" type="s" name="code"/>
            </signal>

            <signal name="VerificationDone">
                <arg direction="out" type="s" name="pan_user"/>
                <arg direction="out" type="s" name="user_id"/>
                <arg direction="out" type="s" name="device_id"/>
                <arg direction="out" type="s" name="transaction_id"/>
            </signal>

        </interface>
    </node>
    """

    VerificationInvite = signal()
    VerificationCancel = signal()
    VerificationString = signal()
    VerificationDone = signal()

    def __init__(self, queue, device_list, id_counter):
        self.device_list = device_list
        self.queue = queue
        self.id_counter = id_counter

    @property
    def message_id(self):
        return self.id_counter.message_id

    def List(self, pan_user):
        device_store = self.device_list.get(pan_user, None)

        if not device_store:
            return []

        device_list = [
            device for device_list in device_store.values() for device in
            device_list.values()
        ]

        return device_list

    def ListUserDevices(self, pan_user, user_id):
        device_store = self.device_list.get(pan_user, None)

        if not device_store:
            return []

        device_list = device_store.get(user_id, None)

        if not device_list:
            return []

        return device_list.values()

    def Verify(self, pan_user, user_id, device_id):
        message = DeviceVerifyMessage(
            pan_user,
            user_id,
            device_id
        )
        self.queue.put(message)
        return

    def UnVerify(self, pan_user, user_id, device_id):
        message = DeviceUnverifyMessage(
            pan_user,
            user_id,
            device_id
        )
        self.queue.put(message)
        return

    def StartSas(self, pan_user, user_id, device_id):
        device_store = self.device_list.get(pan_user)

        if not device_store:
            logger.info(f"Not verifying device, no store found for user "
                        f"{user_id}")
            return

        logger.info(f"Verifying device {user_id} {device_id}")
        return

    def ConfirmKeyVerification(self, pan_user, user_id, device_id):
        message = DeviceConfirmSasMessage(
            self.message_id,
            pan_user,
            user_id,
            device_id
        )
        print("HEEEELOOO {}".format(message.message_id))
        self.queue.put(message)
        return message.message_id

    def AcceptKeyVerification(self, pan_user, user_id, device_id):
        message = AcceptSasMessage(
            self.message_id,
            pan_user,
            user_id,
            device_id
        )
        self.queue.put(message)
        return message.message_id

    def update_devices(self, message):
        device_store = self.device_list[message.user_id]

        for user_id, device_dict in message.devices.items():
            for device in device_dict.values():
                if device.deleted:
                    device_store[user_id].remove(device.id, None)
                else:
                    device_store[user_id][device.id] = {
                        "user_id": device.user_id,
                        "device_id": device.id,
                        "e225519": device.ed25519,
                        "curve25519": device.curve25519,
                        "trust_state": TrustState.unset.name,
                    }


@attr.s
class GlibT:
    receive_queue = attr.ib()
    send_queue = attr.ib()
    data_dir = attr.ib()

    loop = attr.ib(init=False)
    store = attr.ib(init=False)
    users = attr.ib(init=False)
    devices = attr.ib(init=False)
    bus = attr.ib(init=False)
    control_if = attr.ib(init=False)
    device_if = attr.ib(init=False)

    def __attrs_post_init__(self):
        self.loop = None

        self.store = PanStore(self.data_dir)
        self.users = self.store.load_all_users()
        self.devices = self.store.load_all_devices()

        id_counter = IdCounter()

        self.control_if = Control(self.send_queue, self.users, id_counter)
        self.device_if = Devices(self.send_queue, self.devices, id_counter)

        self.bus = SessionBus()
        self.bus.publish("org.pantalaimon1", self.control_if, self.device_if)

    def message_callback(self):
        try:
            message = self.receive_queue.get_nowait()
        except Empty:
            return True

        logger.debug(f"UI loop received message {message}")

        if isinstance(message, DevicesMessage):
            self.device_if.update_devices(message)

        elif isinstance(message, InviteSasSignal):
            self.device_if.VerificationInvite(
                message.pan_user,
                message.user_id,
                message.device_id,
                message.transaction_id
            )

        elif isinstance(message, ShowSasSignal):
            self.device_if.VerificationString(
                message.pan_user,
                message.user_id,
                message.device_id,
                message.transaction_id,
                message.emoji,
            )

        elif isinstance(message, SasDoneSignal):
            self.device_if.VerificationDone(
                message.pan_user,
                message.user_id,
                message.device_id,
                message.transaction_id,
            )

        elif isinstance(message, DaemonResponse):
            self.control_if.Response(
                message.message_id,
                message.pan_user,
                {
                    "code": message.code,
                    "message": message.message
                }
            )

        self.receive_queue.task_done()
        return True

    def run(self):
        self.loop = GLib.MainLoop()
        GLib.timeout_add(100, self.message_callback)
        self.loop.run()

    def stop(self):
        if self.loop:
            self.loop.quit()
            self.loop = None
