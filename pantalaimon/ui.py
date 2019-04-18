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
    device_id = attr.ib()
    devices = attr.ib()


@attr.s
class DeviceVerifyMessage(Message):
    user_id = attr.ib()
    device_id = attr.ib()
    device_user = attr.ib()
    device_device_id = attr.ib()


class Devices(dbus.service.Object):
    def __init__(self, bus_name, device_list):
        super().__init__(bus_name, "/org/pantalaimon/Devices")
        self.device_list = device_list

    @dbus.service.method("org.pantalaimon.devices.list",
                         out_signature="a{sa{saa{ss}}}")
    def list(self):
        return self.device_list

    @dbus.service.method("org.pantalaimon.devices.verify",
                         in_signature="ssss")
    def verify(self, user_id, device_id, devices_user, devices_id):
        device_store = self.device_list[user_id].get(device_id, None)

        if not device_store:
            logger.debug(f"Not verifying device, no store found for user "
                        f"{user_id}")
            return

        logger.debug(f"Verifying device {devices_user} {devices_id}")
        return

    @dbus.service.method("org.pantalaimon.devices.start_verification",
                         in_signature="ssss")
    def start_verify(self, user_id, device_id, devices_user, devices_id):
        device_store = self.device_list[user_id].get(device_id, None)

        if not device_store:
            logger.info(f"Not verifying device, no store found for user "
                        f"{user_id}")
            return

        logger.info(f"Verifying device {devices_user} {devices_id}")
        return

    def update_devices(self, message):
        device_store = self.device_list[message.user_id][message.device_id]

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


class Users(dbus.service.Object):
    def __init__(self, bus_name, user_list=None):
        super().__init__(bus_name, "/org/pantalaimon/Control")
        self.users = user_list

    @dbus.service.method("org.pantalaimon.control.list_users",
                         out_signature="a(ss)")
    def list(self):
        return self.users

    @dbus.service.method("org.pantalaimon.control.export_keys",
                         in_signature="ss")
    def export_keys(self, user, filepath):
        return


def glib_loop(queue, data_dir):
    DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()

    bus_name = dbus.service.BusName("org.pantalaimon",
                                    bus=dbus.SessionBus(),
                                    do_not_queue=True)

    store = PanStore(data_dir)
    users = store.load_all_users()
    devices = store.load_all_devices()

    # TODO update bus data if the asyncio thread tells us so.
    Users(bus_name, users)
    device_bus = Devices(bus_name, devices)

    def message_callback():
        try:
            message = queue.get_nowait()
        except Empty:
            return True

        logger.info(f"Dbus loop received message {message}")

        if isinstance(message, ShutDownMessage):
            queue.task_done()
            loop.quit()
            return False

        elif isinstance(message, DevicesMessage):
            device_bus.update_devices(message)

        return True

    GLib.timeout_add(100, message_callback)

    loop.run()


async def shutdown_glib_loop(future, queue, app):
    await queue.put(ShutDownMessage())
    await future
