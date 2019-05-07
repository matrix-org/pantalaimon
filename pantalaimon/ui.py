import attr

import dbus
import dbus.exceptions
import dbus.service

from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

from queue import Empty

from pantalaimon.store import PanStore
from pantalaimon.log import logger

DBusGMainLoop(set_as_default=True)


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
class DeviceConfirmSasMessage(_VerificationMessage):
    pass


@attr.s
class DeviceAuthStringMessage(_VerificationMessage):
    short_string = attr.ib()



class Devices(dbus.service.Object):
    def __init__(self, bus_name, queue, device_list):
        super().__init__(bus_name, "/org/pantalaimon/Devices")
        self.device_list = device_list
        self.queue = queue

    @dbus.service.method("org.pantalaimon.devices",
                         out_signature="a{sa{saa{ss}}}")
    def list(self):
        return self.device_list

    @dbus.service.method("org.pantalaimon.devices",
                         in_signature="sss")
    def verify(self, pan_user, user_id, device_id):
        message = DeviceVerifyMessage(
            pan_user,
            user_id,
            device_id
        )
        self.queue.put(message)
        return

    @dbus.service.method("org.pantalaimon.devices",
                         in_signature="sss")
    def unverify(self, pan_user, user_id, device_id):
        message = DeviceUnverifyMessage(
            pan_user,
            user_id,
            device_id
        )
        self.queue.put(message)
        return

    @dbus.service.method("org.pantalaimon.devices",
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
        dbus_interface="org.pantalaimon.devices",
        signature="sssa(ss)"
    )
    def sas_show(self, pan_user, user_id, device_id, auth_string):
        pass

    @dbus.service.method("org.pantalaimon.devices",
                         in_signature="sss")
    def confirm_sas(self, pan_user, user_id, device_id):
        message = DeviceConfirmSasMessage(pan_user, user_id, device_id)
        self.queue.put(message)
        return

    def update_devices(self, message):
        device_store = self.device_list[message.user_id]

        # TODO the store type got changed to a list, fix adding/removing of
        # devices.

        # for user_id, device_dict in message.devices.items():
        #     for device in device_dict.values():
        #         if device.deleted:
        #             device_store[user_id].remove(device.id, None)
        #         else:
        #             device_store[user_id][device.id] = {
        #                 "user_id": device.user_id,
        #                 "device_id": device.id,
        #                 "fingerprint_key": device.ed25519,
        #                 "sender_key": device.curve25519,
        #                 "trust_state": TrustState.unset.name,
        #             }


class Control(dbus.service.Object):
    def __init__(self, bus_name, queue, user_list=None):
        super().__init__(bus_name, "/org/pantalaimon/Control")
        self.users = user_list
        self.queue = queue

    @dbus.service.method("org.pantalaimon.control",
                         out_signature="a(ss)")
    def list_users(self):
        return self.users

    @dbus.service.method("org.pantalaimon.control",
                         in_signature="sss")
    def export_keys(self, pan_user, filepath, passphrase):
        message = ExportKeysMessage(
            pan_user,
            filepath,
            passphrase
        )
        self.queue.put(message)

        return

    @dbus.service.method("org.pantalaimon.control",
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
        dbus_interface="org.pantalaimon.control",
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

        self.bus_name = dbus.service.BusName("org.pantalaimon",
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
