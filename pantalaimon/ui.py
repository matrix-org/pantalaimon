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
    InfoMessage,
    DeviceAcceptSasMessage,
    DeviceConfirmSasMessage,
    DeviceAuthStringMessage,
    ImportKeysMessage,
    ExportKeysMessage,
)
from pantalaimon.log import logger


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
            </method>

            <method name='ImportKeys'>
                <arg type='s' name='pan_user' direction='in'/>
                <arg type='s' name='file_path' direction='in'/>
                <arg type='s' name='passphrase' direction='in'/>
            </method>

            <signal name="Info">
                <arg direction="out" type="s" name="message"/>
            </signal>
        </interface>
    </node>
    """

    def __init__(self, queue, user_list=None):
        self.users = user_list
        self.queue = queue

    def ListUsers(self):
        """Return the list of pan users."""
        return self.users

    def ExportKeys(self, pan_user, filepath, passphrase):
        message = ExportKeysMessage(pan_user, filepath, passphrase)
        self.queue.put(message)
        return

    def ImportKeys(self, pan_user, filepath, passphrase):
        message = ImportKeysMessage(pan_user, filepath, passphrase)
        self.queue.put(message)
        return

    Info = signal()


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
            </method>

            <method name='ConfirmKeyVerification'>
                <arg type='s' name='pan_user' direction='in'/>
                <arg type='s' name='user_id' direction='in'/>
                <arg type='s' name='device_id' direction='in'/>
            </method>

            <signal name="SasReceived">
                <arg direction="out" type="s" name="pan_user"/>
                <arg direction="out" type="s" name="user_id"/>
                <arg direction="out" type="s" name="device_id"/>
                <arg direction="out" type="a(ss)" name="emoji"/>
            </signal>

        </interface>
    </node>
    """

    SasReceived = signal()

    def __init__(self, queue, device_list):
        self.device_list = device_list
        self.queue = queue

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
        message = DeviceConfirmSasMessage(pan_user, user_id, device_id)
        self.queue.put(message)
        return

    def AcceptKeyVerification(self, pan_user, user_id, device_id):
        message = DeviceAcceptSasMessage(pan_user, user_id, device_id)
        self.queue.put(message)
        return

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

        self.control_if = Control(self.send_queue, self.users)
        self.device_if = Devices(self.send_queue, self.devices)

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

        elif isinstance(message, DeviceAuthStringMessage):
            self.device_if.SasReceived(
                message.pan_user,
                message.user_id,
                message.device_id,
                message.short_string
            )

        elif isinstance(message, InfoMessage):
            self.control_if.Info(message.string)

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
