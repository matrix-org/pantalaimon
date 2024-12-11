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

from importlib import util

UI_ENABLED = (
    util.find_spec("gi") is not None
    and util.find_spec("gi.repository") is not None
    and util.find_spec("dasbus") is not None
)

if UI_ENABLED:
    from collections import defaultdict
    from queue import Empty

    import attr
    import dbus
    import notify2
    from gi.repository import GLib, Gio
    from dbus.mainloop.glib import DBusGMainLoop

    from nio import RoomKeyRequest, RoomKeyRequestCancellation

    from pantalaimon.log import logger
    from pantalaimon.thread_messages import (
        AcceptSasMessage,
        CancelSasMessage,
        CancelSendingMessage,
        ConfirmSasMessage,
        DaemonResponse,
        DeviceBlacklistMessage,
        DeviceUnblacklistMessage,
        DeviceUnverifyMessage,
        DeviceVerifyMessage,
        ExportKeysMessage,
        ImportKeysMessage,
        InviteSasSignal,
        SasDoneSignal,
        SendAnywaysMessage,
        ShowSasSignal,
        StartSasMessage,
        UnverifiedDevicesSignal,
        UpdateDevicesMessage,
        UpdateUsersMessage,
        KeyRequestMessage,
        ContinueKeyShare,
        CancelKeyShare,
    )

    UI_ENABLED = True

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
                <method name='ListServers'>
                    <arg type='a{sa(ss)}' name='servers' direction='out'/>
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

                <method name='SendAnyways'>
                    <arg type='s' name='pan_user' direction='in'/>
                    <arg type='s' name='room_id' direction='in'/>
                    <arg type='u' name='id' direction='out'/>
                </method>

                <method name='CancelSending'>
                    <arg type='s' name='pan_user' direction='in'/>
                    <arg type='s' name='room_id' direction='in'/>
                    <arg type='u' name='id' direction='out'/>
                </method>

                <signal name="Response">
                    <arg direction="out" type="i" name="id"/>
                    <arg direction="out" type="s" name="pan_user"/>
                    <arg direction="out" type="a{ss}" name="message"/>
                </signal>

                <signal name="UnverifiedDevices">
                    <arg direction="out" type="s" name="pan_user"/>
                    <arg direction="out" type="s" name="room_id"/>
                    <arg direction="out" type="s" name="room_display_name"/>
                </signal>

            </interface>
        </node>
        """

        def __init__(self, queue, server_list, id_counter, dbus_connection):
            self.queue = queue
            self.server_list = server_list
            self.id_counter = id_counter
            self.dbus_connection = dbus_connection
            self.users = defaultdict(set)

        def emit_response_signal(self, id, pan_user, message):
            self.dbus_connection.emit_signal(
                destination=None,
                object_path="/org/pantalaimon1/control",
                interface_name="org.pantalaimon1.control",
                signal_name="Response",
                parameters=GLib.Variant("(i, s, a{ss})", (id, pan_user, message)),
            )

        def emit_unverified_devices_signal(self, pan_user, room_id, room_display_name):
            self.dbus_connection.emit_signal(
                destination=None,
                object_path="/org/pantalaimon1/control",
                interface_name="org.pantalaimon1.control",
                signal_name="UnverifiedDevices",
                parameters=GLib.Variant(
                    "(s, s, s)", (pan_user, room_id, room_display_name)
                ),
            )

        def update_users(self, message):
            self.users[message.server].add((message.user_id, message.device_id))

        @property
        def message_id(self):
            return self.id_counter.message_id

        def ListServers(self):
            """Return the list of pan users."""
            return self.users

        def ExportKeys(self, pan_user, filepath, passphrase):
            message = ExportKeysMessage(self.message_id, pan_user, filepath, passphrase)
            self.queue.put(message)
            return message.message_id

        def ImportKeys(self, pan_user, filepath, passphrase):
            message = ImportKeysMessage(self.message_id, pan_user, filepath, passphrase)
            self.queue.put(message)
            return message.message_id

        def SendAnyways(self, pan_user, room_id):
            message = SendAnywaysMessage(self.message_id, pan_user, room_id)
            self.queue.put(message)
            return message.message_id

        def CancelSending(self, pan_user, room_id):
            message = CancelSendingMessage(self.message_id, pan_user, room_id)
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

                <method name='Verify'>
                    <arg type='s' name='pan_user' direction='in'/>
                    <arg type='s' name='user_id' direction='in'/>
                    <arg type='s' name='device_id' direction='in'/>
                    <arg type='u' name='id' direction='out'/>
                </method>

                <method name='Unverify'>
                    <arg type='s' name='pan_user' direction='in'/>
                    <arg type='s' name='user_id' direction='in'/>
                    <arg type='s' name='device_id' direction='in'/>
                    <arg type='u' name='id' direction='out'/>
                </method>

                <method name='Blacklist'>
                    <arg type='s' name='pan_user' direction='in'/>
                    <arg type='s' name='user_id' direction='in'/>
                    <arg type='s' name='device_id' direction='in'/>
                    <arg type='u' name='id' direction='out'/>
                </method>

                <method name='Unblacklist'>
                    <arg type='s' name='pan_user' direction='in'/>
                    <arg type='s' name='user_id' direction='in'/>
                    <arg type='s' name='device_id' direction='in'/>
                    <arg type='u' name='id' direction='out'/>
                </method>

                <method name='StartKeyVerification'>
                    <arg type='s' name='pan_user' direction='in'/>
                    <arg type='s' name='user_id' direction='in'/>
                    <arg type='s' name='device_id' direction='in'/>
                    <arg type='u' name='id' direction='out'/>
                </method>

                <method name='CancelKeyVerification'>
                    <arg type='s' name='pan_user' direction='in'/>
                    <arg type='s' name='user_id' direction='in'/>
                    <arg type='s' name='device_id' direction='in'/>
                    <arg type='u' name='id' direction='out'/>
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

                <method name='ContinueKeyShare'>
                    <arg type='s' name='pan_user' direction='in'/>
                    <arg type='s' name='user_id' direction='in'/>
                    <arg type='s' name='device_id' direction='in'/>
                    <arg type='u' name='id' direction='out'/>
                </method>

                <method name='CancelKeyShare'>
                    <arg type='s' name='pan_user' direction='in'/>
                    <arg type='s' name='user_id' direction='in'/>
                    <arg type='s' name='device_id' direction='in'/>
                    <arg type='u' name='id' direction='out'/>
                </method>

                <signal name="KeyRequest">
                    <arg direction="out" type="s" name="pan_user"/>
                    <arg direction="out" type="s" name="user_id"/>
                    <arg direction="out" type="s" name="device_id"/>
                    <arg direction="out" type="s" name="request_id"/>
                </signal>

                <signal name="KeyRequestCancel">
                    <arg direction="out" type="s" name="pan_user"/>
                    <arg direction="out" type="s" name="user_id"/>
                    <arg direction="out" type="s" name="device_id"/>
                    <arg direction="out" type="s" name="request_id"/>
                </signal>

            </interface>
        </node>
        """

        def __init__(self, queue, id_counter, dbus_connection):
            self.device_list = dict()
            self.queue = queue
            self.id_counter = id_counter
            self.dbus_connection = dbus_connection
            self.key_requests = dict()

        def emit_verification_invite_signal(
            self, pan_user, user_id, device_id, transaction_id
        ):
            self.dbus_connection.emit_signal(
                destination=None,
                object_path="/org/pantalaimon1/devices",
                interface_name="org.pantalaimon1.devices",
                signal_name="VerificationInvite",
                parameters=GLib.Variant(
                    "(s, s, s, s)", (pan_user, user_id, device_id, transaction_id)
                ),
            )

        def emit_verification_cancel_signal(
            self, pan_user, user_id, device_id, reason, code
        ):
            self.dbus_connection.emit_signal(
                destination=None,
                object_path="/org/pantalaimon1/devices",
                interface_name="org.pantalaimon1.devices",
                signal_name="VerificationCancel",
                parameters=GLib.Variant(
                    "(s, s, s, s, s)", (pan_user, user_id, device_id, reason, code)
                ),
            )

        def emit_verification_string_signal(
            self, pan_user, user_id, device_id, transaction_id, emoji
        ):
            self.dbus_connection.emit_signal(
                destination=None,
                object_path="/org/pantalaimon1/devices",
                interface_name="org.pantalaimon1.devices",
                signal_name="VerificationString",
                parameters=GLib.Variant(
                    "(s, s, s, s, s)",
                    (pan_user, user_id, device_id, transaction_id, emoji),
                ),
            )

        def emit_verification_done_signal(
            self, pan_user, user_id, device_id, transaction_id
        ):
            self.dbus_connection.emit_signal(
                destination=None,
                object_path="/org/pantalaimon1/devices",
                interface_name="org.pantalaimon1.devices",
                signal_name="VerificationDone",
                parameters=GLib.Variant(
                    "(s, s, s, s)", (pan_user, user_id, device_id, transaction_id)
                ),
            )

        def emit_key_request_signal(self, pan_user, user_id, device_id, request_id):
            self.dbus_connection.emit_signal(
                destination=None,
                object_path="/org/pantalaimon1/devices",
                interface_name="org.pantalaimon1.devices",
                signal_name="KeyRequest",
                parameters=GLib.Variant(
                    "(s, s, s, s)", (pan_user, user_id, device_id, request_id)
                ),
            )

        def emit_key_request_cancel_signal(
            self, pan_user, user_id, device_id, request_id
        ):
            self.dbus_connection.emit_signal(
                destination=None,
                object_path="/org/pantalaimon1/devices",
                interface_name="org.pantalaimon1.devices",
                signal_name="KeyRequestCancel",
                parameters=GLib.Variant(
                    "(s, s, s, s)", (pan_user, user_id, device_id, request_id)
                ),
            )

        @property
        def message_id(self):
            return self.id_counter.message_id

        def List(self, pan_user):
            device_store = self.device_list.get(pan_user, None)

            if not device_store:
                return []

            device_list = [
                device
                for device_list in device_store.values()
                for device in device_list.values()
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
            message = DeviceVerifyMessage(self.message_id, pan_user, user_id, device_id)
            self.queue.put(message)
            return message.message_id

        def Unverify(self, pan_user, user_id, device_id):
            message = DeviceUnverifyMessage(
                self.message_id, pan_user, user_id, device_id
            )
            self.queue.put(message)
            return message.message_id

        def Blacklist(self, pan_user, user_id, device_id):
            message = DeviceBlacklistMessage(
                self.message_id, pan_user, user_id, device_id
            )
            self.queue.put(message)
            return message.message_id

        def Unblacklist(self, pan_user, user_id, device_id):
            message = DeviceUnblacklistMessage(
                self.message_id, pan_user, user_id, device_id
            )
            self.queue.put(message)
            return message.message_id

        def StartKeyVerification(self, pan_user, user_id, device_id):
            message = StartSasMessage(self.message_id, pan_user, user_id, device_id)
            self.queue.put(message)
            return message.message_id

        def CancelKeyVerification(self, pan_user, user_id, device_id):
            message = CancelSasMessage(self.message_id, pan_user, user_id, device_id)
            self.queue.put(message)
            return message.message_id

        def ConfirmKeyVerification(self, pan_user, user_id, device_id):
            message = ConfirmSasMessage(self.message_id, pan_user, user_id, device_id)
            self.queue.put(message)
            return message.message_id

        def AcceptKeyVerification(self, pan_user, user_id, device_id):
            message = AcceptSasMessage(self.message_id, pan_user, user_id, device_id)
            self.queue.put(message)
            return message.message_id

        def ContinueKeyShare(self, pan_user, user_id, device_id):
            message = ContinueKeyShare(self.message_id, pan_user, user_id, device_id)
            self.queue.put(message)
            return message.message_id

        def CancelKeyShare(self, pan_user, user_id, device_id):
            message = CancelKeyShare(self.message_id, pan_user, user_id, device_id)
            self.queue.put(message)
            return message.message_id

        def update_devices(self, message):
            if message.pan_user not in self.device_list:
                self.device_list[message.pan_user] = defaultdict(dict)

            device_list = self.device_list.get(message.pan_user)

            for user_devices in message.devices.values():
                for device in user_devices.values():
                    if device["deleted"]:
                        try:
                            device_list[device["user_id"]].pop(device["device_id"])
                        except KeyError:
                            pass
                        continue

                    device.pop("deleted")
                    device_list[device["user_id"]][device["device_id"]] = device

        def update_key_requests(self, message):
            # type: (KeyRequestMessage) -> None
            event = message.event

            if isinstance(event, RoomKeyRequest):
                self.key_requests[event.request_id] = event
                self.emit_key_request_signal(
                    message.pan_user,
                    event.sender,
                    event.requesting_device_id,
                    event.request_id,
                )

            elif isinstance(event, RoomKeyRequestCancellation):
                self.key_requests.pop(event.request_id, None)
                self.emit_key_request_cancel_signal(
                    message.pan_user,
                    event.sender,
                    event.requesting_device_id,
                    event.request_id,
                )

    @attr.s
    class GlibT:
        receive_queue = attr.ib()
        send_queue = attr.ib()
        data_dir = attr.ib()
        server_list = attr.ib()
        config = attr.ib()

        loop = attr.ib(init=False)
        dbus_loop = attr.ib(init=False)
        store = attr.ib(init=False)
        users = attr.ib(init=False)
        devices = attr.ib(init=False)
        bus = attr.ib(init=False)
        control_if = attr.ib(init=False)
        device_if = attr.ib(init=False)
        notifications = attr.ib(type=bool, default=False, init=False)

        def __attrs_post_init__(self):
            self.loop = None
            self.dbus_loop = None

            id_counter = IdCounter()

            # Connect to the session bus
            self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)

            self.control_if = Control(
                self.send_queue, self.server_list, id_counter, self.bus
            )
            self.device_if = Devices(self.send_queue, id_counter)

            # Define introspection XML for the D-Bus interface
            introspection_xml = """
            <node>
              <interface name="org.pantalaimon1.control">
                <method name="SomeControlMethod">
                  <arg direction="in" type="s" name="input_arg"/>
                  <arg direction="out" type="s" name="output"/>
                </method>
              </interface>
              <interface name="org.pantalaimon1.devices">
                <method name="SomeDeviceMethod">
                  <arg direction="in" type="s" name="input_arg"/>
                  <arg direction="out" type="s" name="output"/>
                </method>
              </interface>
            </node>
            """
            self.introspection_data = Gio.DBusNodeInfo.new_for_xml(introspection_xml)

            # Interface vtable to handle method calls
            self.vtable = Gio.DBusInterfaceVTable(
                method_call=self.on_method_call, get_property=None, set_property=None
            )

            # Register the object on the bus
            self.bus.register_object(
                "/org/pantalaimon1",
                self.introspection_data.interfaces[0],  # Register control interface
                self.vtable,
                None,
            )

        def on_method_call(
            self,
            connection,
            sender,
            object_path,
            interface_name,
            method_name,
            parameters,
            invocation,
        ):
            """
            Handles incoming D-Bus method calls routed to the registered object.

            Parameters:
                connection (Gio.DBusConnection): The D-Bus connection on which the call was received.
                sender (str): The unique name of the caller on the D-Bus.
                object_path (str): The object path of the method call.
                interface_name (str): The interface name on which the method was called.
                method_name (str): The name of the method being called.
                parameters (GLib.Variant): The parameters passed to the method.
                invocation (Gio.DBusMethodInvocation): An object for replying to the call.

            Responds to specific methods defined within 'org.pantalaimon1.control' and
            'org.pantalaimon1.devices' interfaces, routing to the appropriate methods
            in 'self.control_if' and 'self.device_if' and returning results to the caller.
            """

            if interface_name == "org.pantalaimon1.control":
                if method_name == "ListServers":
                    result = self.control_if.ListServers()
                    invocation.return_value(GLib.Variant("(a{sa(ss)})", [result]))

                elif method_name == "ExportKeys":
                    pan_user, filepath, passphrase = parameters.unpack()
                    result = self.control_if.ExportKeys(pan_user, filepath, passphrase)
                    invocation.return_value(GLib.Variant("(u)", [result]))

                elif method_name == "ImportKeys":
                    pan_user, filepath, passphrase = parameters.unpack()
                    result = self.control_if.ImportKeys(pan_user, filepath, passphrase)
                    invocation.return_value(GLib.Variant("(u)", [result]))

                elif method_name == "SendAnyways":
                    pan_user, room_id = parameters.unpack()
                    result = self.control_if.SendAnyways(pan_user, room_id)
                    invocation.return_value(GLib.Variant("(u)", [result]))

                elif method_name == "CancelSending":
                    pan_user, room_id = parameters.unpack()
                    result = self.control_if.CancelSending(pan_user, room_id)
                    invocation.return_value(GLib.Variant("(u)", [result]))

        # def __attrs_post_init__(self):
        #     self.loop = None
        #     self.dbus_loop = None

        #     id_counter = IdCounter()

        #     self.control_if = Control(self.send_queue, self.server_list, id_counter)
        #     self.device_if = Devices(self.send_queue, id_counter)

        #     self.bus = SessionMessageBus()
        #     self.bus.publish_object("org.pantalaimon1", self.control_if, self.device_if)

        def unverified_notification(self, message):
            notification = notify2.Notification(
                "Unverified devices.",
                message=(
                    f"There are unverified devices in the room "
                    f"{message.room_display_name}."
                ),
            )
            notification.set_category("im")

            def send_cb(notification, action_key, user_data):
                message = user_data
                self.control_if.SendAnyways(message.pan_user, message.room_id)

            def cancel_cb(notification, action_key, user_data):
                message = user_data
                self.control_if.CancelSending(message.pan_user, message.room_id)

            if "actions" in notify2.get_server_caps():
                notification.add_action("send", "Send anyways", send_cb, message)
                notification.add_action("cancel", "Cancel sending", cancel_cb, message)

            notification.show()

        def sas_invite_notification(self, message):
            notification = notify2.Notification(
                "Key verification invite",
                message=(
                    f"{message.user_id} via {message.device_id} has started "
                    f"a key verification process."
                ),
            )
            notification.set_category("im")

            def accept_cb(notification, action_key, user_data):
                message = user_data
                self.device_if.AcceptKeyVerification(
                    message.pan_user, message.user_id, message.device_id
                )

            def cancel_cb(notification, action_key, user_data):
                message = user_data
                self.device_if.CancelKeyVerification(
                    message.pan_user, message.user_id, message.device_id
                )

            if "actions" in notify2.get_server_caps():
                notification.add_action("accept", "Accept", accept_cb, message)
                notification.add_action("cancel", "Cancel", cancel_cb, message)

            notification.show()

        def sas_show_notification(self, message):
            emojis = [x[0] for x in message.emoji]

            emoji_str = "   ".join(emojis)

            notification = notify2.Notification(
                "Short authentication string",
                message=(
                    f"Short authentication string for the key verification of"
                    f" {message.user_id} via {message.device_id}:\n"
                    f"{emoji_str}"
                ),
            )
            notification.set_category("im")

            def confirm_cb(notification, action_key, user_data):
                message = user_data
                self.device_if.ConfirmKeyVerification(
                    message.pan_user, message.user_id, message.device_id
                )

            def cancel_cb(notification, action_key, user_data):
                message = user_data
                self.device_if.CancelKeyVerification(
                    message.pan_user, message.user_id, message.device_id
                )

            if "actions" in notify2.get_server_caps():
                notification.add_action("confirm", "Confirm", confirm_cb, message)
                notification.add_action("cancel", "Cancel", cancel_cb, message)

            notification.show()

        def sas_done_notification(self, message):
            notification = notify2.Notification(
                "Device successfully verified.",
                message=(
                    f"Device {message.device_id} of user {message.user_id} "
                    f"successfully verified."
                ),
            )
            notification.set_category("im")
            notification.show()

        def message_callback(self):
            try:
                message = self.receive_queue.get_nowait()
            except Empty:
                return True

            logger.debug(f"UI loop received message {message}")

            if isinstance(message, UpdateDevicesMessage):
                self.device_if.update_devices(message)

            elif isinstance(message, UpdateUsersMessage):
                self.control_if.update_users(message)

            elif isinstance(message, UnverifiedDevicesSignal):
                self.control_if.emit_unverified_devices_signal(
                    message.pan_user, message.room_id, message.room_display_name
                )

                if self.notifications:
                    self.unverified_notification(message)

            elif isinstance(message, InviteSasSignal):
                self.device_if.emit_verification_invite_signal(
                    message.pan_user,
                    message.user_id,
                    message.device_id,
                    message.transaction_id,
                )

                if self.notifications:
                    self.sas_invite_notification(message)

            elif isinstance(message, ShowSasSignal):
                self.device_if.emit_verification_string_signal(
                    message.pan_user,
                    message.user_id,
                    message.device_id,
                    message.transaction_id,
                    message.emoji,
                )
                if self.notifications:
                    self.sas_show_notification(message)

            elif isinstance(message, SasDoneSignal):
                self.device_if.emit_verification_done_signal(
                    message.pan_user,
                    message.user_id,
                    message.device_id,
                    message.transaction_id,
                )

                if self.notifications:
                    self.sas_done_notification(message)

            elif isinstance(message, DaemonResponse):
                # Is message.message correct?
                self.control_if.emit_response_signal(
                    message.message_id, message.pan_user, message.message
                )
                # self.control_if.Response(
                #     message.message_id,
                #     message.pan_user,
                #     {"code": message.code, "message": message.message},
                # )

            elif isinstance(message, KeyRequestMessage):
                self.device_if.update_key_requests(message)

            self.receive_queue.task_done()
            return True

        def run(self):
            self.dbus_loop = DBusGMainLoop()
            self.loop = GLib.MainLoop()

            if self.config.notifications:
                try:
                    notify2.init("pantalaimon", mainloop=self.dbus_loop)
                    self.notifications = True
                except dbus.DBusException:
                    logger.error(
                        "Notifications are enabled but no notification "
                        "server could be found, disabling notifications."
                    )
                    self.notifications = False

            GLib.timeout_add(100, self.message_callback)

            if not self.loop:
                return

            self.loop.run()

        def stop(self):
            if self.loop:
                self.loop.quit()
                self.loop = None
