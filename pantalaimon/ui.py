import attr

import dbus
import dbus.exceptions
import dbus.service

from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

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

DBusGMainLoop(set_as_default=True)


class Devices(dbus.service.Object):
    def __init__(self, bus_name, queue, device_list):
        super().__init__(bus_name, "/org/pantalaimon1/Devices")
        self.device_list = device_list
        self.queue = queue

    @dbus.service.method("org.pantalaimon1.devices",
                         in_signature="s",
                         out_signature="aa{ss}")
    def list(self, pan_user):
        device_store = self.device_list.get(pan_user, None)

        if not device_store:
            return []

        device_list = [
            device for device_list in device_store.values() for device in
            device_list.values()
        ]

        return device_list

    @dbus.service.method("org.pantalaimon1.devices",
                         in_signature="ss",
                         out_signature="aa{ss}")
    def list_user_devices(self, pan_user, user_id):
        device_store = self.device_list.get(pan_user, None)

        if not device_store:
            return []

        device_list = device_store.get(user_id, None)

        if not device_list:
            return []

        return device_list.values()

    @dbus.service.method("org.pantalaimon1.devices",
                         in_signature="sss")
    def verify(self, pan_user, user_id, device_id):
        message = DeviceVerifyMessage(
            pan_user,
            user_id,
            device_id
        )
        self.queue.put(message)
        return

    @dbus.service.method("org.pantalaimon1.devices",
                         in_signature="sss")
    def unverify(self, pan_user, user_id, device_id):
        message = DeviceUnverifyMessage(
            pan_user,
            user_id,
            device_id
        )
        self.queue.put(message)
        return

    @dbus.service.method("org.pantalaimon1.devices",
                         in_signature="sss")
    def start_verify(self, pan_user, user_id, device_id):
        device_store = self.device_list.get(pan_user)

        if not device_store:
            logger.info(f"Not verifying device, no store found for user "
                        f"{user_id}")
            return

        logger.info(f"Verifying device {user_id} {device_id}")
        return

    @dbus.service.signal(
        dbus_interface="org.pantalaimon1.devices",
        signature="sssa(ss)"
    )
    def sas_show(self, pan_user, user_id, device_id, auth_string):
        pass

    @dbus.service.method("org.pantalaimon1.devices",
                         in_signature="sss")
    def confirm_sas(self, pan_user, user_id, device_id):
        message = DeviceConfirmSasMessage(pan_user, user_id, device_id)
        self.queue.put(message)
        return

    @dbus.service.method("org.pantalaimon1.devices",
                         in_signature="sss")
    def accept_sas(self, pan_user, user_id, device_id):
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


class Control(dbus.service.Object):
    def __init__(self, bus_name, queue, user_list=None):
        super().__init__(bus_name, "/org/pantalaimon1/Control")
        self.users = user_list
        self.queue = queue

    @dbus.service.method("org.pantalaimon1.control",
                         out_signature="a(ss)")
    def list_users(self):
        return self.users

    @dbus.service.method("org.pantalaimon1.control",
                         in_signature="sss")
    def export_keys(self, pan_user, filepath, passphrase):
        message = ExportKeysMessage(
            pan_user,
            filepath,
            passphrase
        )
        self.queue.put(message)

        return

    @dbus.service.method("org.pantalaimon1.control",
                         in_signature="sss")
    def import_keys(self, pan_user, filepath, passphrase):
        message = ImportKeysMessage(
            pan_user,
            filepath,
            passphrase
        )
        self.queue.put(message)

        return

    @dbus.service.signal(
        dbus_interface="org.pantalaimon1.control",
        signature="s"
    )
    def info(self, message):
        pass


@attr.s
class GlibT:
    receive_queue = attr.ib()
    send_queue = attr.ib()
    data_dir = attr.ib()

    loop = attr.ib(init=False)
    bus_name = attr.ib(init=False)
    store = attr.ib(init=False)
    users = attr.ib(init=False)
    devices = attr.ib(init=False)
    control_bus = attr.ib(init=False)
    device_bus = attr.ib(init=False)

    def __attrs_post_init__(self):
        self.loop = None

        self.bus_name = dbus.service.BusName("org.pantalaimon1",
                                             bus=dbus.SessionBus(),
                                             do_not_queue=True)

        self.store = PanStore(self.data_dir)
        self.users = self.store.load_all_users()
        self.devices = self.store.load_all_devices()

        self.control_bus = Control(self.bus_name, self.send_queue, self.users)
        self.device_bus = Devices(self.bus_name, self.send_queue, self.devices)

    def message_callback(self):
        try:
            message = self.receive_queue.get_nowait()
        except Empty:
            return True

        logger.debug(f"UI loop received message {message}")

        if isinstance(message, DevicesMessage):
            self.device_bus.update_devices(message)

        elif isinstance(message, DeviceAuthStringMessage):
            self.device_bus.sas_show(
                message.pan_user,
                message.user_id,
                message.device_id,
                message.short_string
            )

        elif isinstance(message, InfoMessage):
            self.control_bus.info(message.string)

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
