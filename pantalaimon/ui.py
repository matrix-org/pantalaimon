import attr

import dbus
import dbus.exceptions
import dbus.service

from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

from queue import Empty

from nio.store import TrustState
from pantalaimon.store import PanStore
from pantalaimon.log import logger


@attr.s
class Message:
    pass


@attr.s
class ShutDownMessage(Message):
    pass


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


class Devices(dbus.service.Object):
    def __init__(self, bus_name, queue, device_list):
        super().__init__(bus_name, "/org/pantalaimon/Devices")
        self.device_list = device_list
        self.queue = queue

    @dbus.service.method("org.pantalaimon.devices.list",
                         out_signature="a{sa{saa{ss}}}")
    def list(self):
        return self.device_list

    @dbus.service.method("org.pantalaimon.devices.verify",
                         in_signature="sss")
    def verify(self, pan_user, user_id, device_id):
        message = DeviceVerifyMessage(
            pan_user,
            user_id,
            device_id
        )
        self.queue.put(message)
        return

    @dbus.service.method("org.pantalaimon.devices.unverify",
                         in_signature="sss")
    def unverify(self, pan_user, user_id, device_id):
        message = DeviceUnverifyMessage(
            pan_user,
            user_id,
            device_id
        )
        self.queue.put(message)
        return

    @dbus.service.method("org.pantalaimon.devices.start_verification",
                         in_signature="sss")
    def start_verify(self, pan_user, user_id, device_id):
        device_store = self.device_list.get(pan_user)

        if not device_store:
            logger.info(f"Not verifying device, no store found for user "
                        f"{user_id}")
            return

        logger.info(f"Verifying device {user_id} {device_id}")
        return

    def update_devices(self, message):
        device_store = self.device_list[message.user_id]

        for user_id, device_dict in message.devices.items():
            for device in device_dict.values():
                if device.deleted:
                    device_store[user_id].pop(device.id, None)
                else:
                    device_store[user_id][device.id] = {
                        "user_id": device.user_id,
                        "device_id": device.id,
                        "fingerprint_key": device.ed25519,
                        "sender_key": device.curve25519,
                        "trust_state": TrustState.unset.name,
                    }


class Control(dbus.service.Object):
    def __init__(self, bus_name, queue, user_list=None):
        super().__init__(bus_name, "/org/pantalaimon/Control")
        self.users = user_list
        self.queue = queue

    @dbus.service.method("org.pantalaimon.control.list_users",
                         out_signature="a(ss)")
    def list(self):
        return self.users

    @dbus.service.method("org.pantalaimon.control.export_keys",
                         in_signature="sss")
    def export_keys(self, pan_user, filepath, passphrase):
        message = ExportKeysMessage(
            pan_user,
            filepath,
            passphrase
        )
        self.queue.put(message)

        return


def glib_loop(receive_queue, send_queue, data_dir):
    DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()

    bus_name = dbus.service.BusName("org.pantalaimon",
                                    bus=dbus.SessionBus(),
                                    do_not_queue=True)

    store = PanStore(data_dir)
    users = store.load_all_users()
    devices = store.load_all_devices()

    Control(bus_name, send_queue, users)
    device_bus = Devices(bus_name, send_queue, devices)

    def message_callback():
        try:
            message = receive_queue.get_nowait()
        except Empty:
            return True

        logger.debug(f"UI loop received message {message}")

        if isinstance(message, ShutDownMessage):
            receive_queue.task_done()
            loop.quit()
            return False

        elif isinstance(message, DevicesMessage):
            device_bus.update_devices(message)
            receive_queue.task_done()

        return True

    GLib.timeout_add(100, message_callback)

    loop.run()


async def shutdown_glib_loop(future, queue, app):
    await queue.put(ShutDownMessage())
    await future
