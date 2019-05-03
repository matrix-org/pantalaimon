"""Cli utility to control pantalaimon."""

import attr
import asyncio
import sys

from typing import List

from prompt_toolkit import PromptSession
from prompt_toolkit.eventloop.defaults import use_asyncio_event_loop
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.completion import Completer, Completion

import dbus
from gi.repository import GLib
from dbus.mainloop.glib import DBusGMainLoop
from janus import Queue
from queue import Empty

DBusGMainLoop(set_as_default=True)

use_asyncio_event_loop()


@attr.s
class PanCompleter(Completer):
    """Completer for panctl commands."""
    commands = attr.ib(type=List[str])

    def complete_commands(self, last_word):
        """Complete the available commands."""
        compl_words = []

        for command in self.commands:
            if last_word in command:
                compl_words.append(command)

        for compl_word in compl_words:
            yield Completion(compl_word, -len(last_word))

    def get_completions(self, document, complete_event):
        """Build the completions."""
        text_before_cursor = document.text_before_cursor
        text_before_cursor = str(text_before_cursor)
        words = text_before_cursor.split(" ")

        last_word = words[-1]

        if len(words) == 1:
            return self.complete_commands(last_word)

        return ""


@attr.s
class DbusT:
    loop = attr.ib()
    receive_queue = attr.ib()
    send_queue = attr.ib()

    async def send(self, message):
        self.receive_queue.async_q.put(message)
        GLib.idle_add(self._message_callback)

    def quit(self):
        self.loop.quit()

    def _message_callback(self):
        print("Message")
        try:
            message = self.receive_queue.get_nowait()
        except Empty:
            return True

        return True

    def dbus_loop(self):
        self.loop.run()


@attr.s
class PanCtl:
    bus_thread = attr.ib()
    bus = attr.ib(init=False)
    ctl = attr.ib(init=False)
    devices = attr.ib(init=False)

    commands = [
        "list-users",
        "export-keys",
        "import-keys",
        "accept-verification",
        "confirm-verification"
    ]

    def __attrs_post_init__(self):
        self.bus = dbus.SessionBus()
        self.ctl = self.bus.get_object(
            "org.pantalaimon",
            "/org/pantalaimon/Control",
            introspect=True
        )
        self.devices = self.bus.get_object(
            "org.pantalaimon",
            "/org/pantalaimon/Devices",
            introspect=True
        )
        self.bus.add_signal_receiver(
            self.show_sas,
            dbus_interface="org.pantalaimon.devices",
            signal_name="sas_show"
        )
        self.bus.add_signal_receiver(
            self.show_info,
            dbus_interface="org.pantalaimon.control",
            signal_name="info"
        )

    def show_info(self, message):
        print(message)

    # The emoji printing logic was taken from weechat-matrix and was written by
    # dkasak.
    def show_sas(self, pan_user, user_id, device_id, emoji):
        emojis = [x[0] for x in emoji]
        descriptions = [x[1] for x in emoji]

        centered_width = 12

        def center_emoji(emoji, width):
            # Assume each emoji has width 2
            emoji_width = 2

            # These are emojis that need VARIATION-SELECTOR-16 (U+FE0F) so
            # that they are rendered with coloured glyphs. For these, we
            # need to add an extra space after them so that they are
            # rendered properly in weechat.
            variation_selector_emojis = [
                '☁️',
                '❤️',
                '☂️',
                '✏️',
                '✂️',
                '☎️',
                '✈️'
            ]

            if emoji in variation_selector_emojis:
                emoji += " "

            # This is a trick to account for the fact that emojis are wider
            # than other monospace characters.
            placeholder = '.' * emoji_width

            return placeholder.center(width).replace(placeholder, emoji)

        emoji_str = u"".join(center_emoji(e, centered_width)
                             for e in emojis)
        desc = u"".join(d.center(centered_width) for d in descriptions)
        short_string = u"\n".join([emoji_str, desc])

        print(f"Short authentication string for pan "
              f"user {pan_user} from {user_id} via "
              f"{device_id}:\n{short_string}")

    def list_users(self):
        """List the daemons users."""
        users = self.ctl.list_users(
            dbus_interface="org.pantalaimon.control"
        )
        print("pantalaimon users:")
        for user, devic in users:
            print(" ", user, devic)

    def import_keys(self, args):
        try:
            user, filepath, passphrase = args
        except ValueError:
            print("Invalid arguments for command")
            return

        self.ctl.import_keys(
            user,
            filepath,
            passphrase,
            dbus_interface="org.pantalaimon.control"
        )

    def export_keys(self, args):
        try:
            user, filepath, passphrase = args
        except ValueError:
            print("Invalid arguments for command")
            return

        self.ctl.export_keys(
            user,
            filepath,
            passphrase,
            dbus_interface="org.pantalaimon.control"
        )

    def confirm_sas(self, args):
        try:
            pan_user, user, device = args
        except ValueError:
            print("Invalid arguments for command")
            return

        self.devices.confirm_sas(
            pan_user,
            user,
            device,
            dbus_interface="org.pantalaimon.devices"
        )

    async def loop(self):
        """Event loop for panctl."""
        completer = PanCompleter(self.commands)
        promptsession = PromptSession("panctl> ", completer=completer)

        while True:
            with patch_stdout():
                try:
                    result = await promptsession.prompt(async_=True)
                except EOFError:
                    break

            words = result.split(" ")

            if not words:
                continue

            command = words[0]

            if command == "list-users":
                self.list_users()

            elif command == "export-keys":
                args = words[1:]
                self.export_keys(args)

            elif command == "import-keys":
                args = words[1:]
                self.import_keys(args)

            elif command == "accept-verification":
                pass

            elif command == "confirm-verification":
                args = words[1:]
                self.confirm_sas(args)

            else:
                print(f"Unknown command {command}.")


def main():
    loop = asyncio.get_event_loop()
    main_queue = Queue()
    glib_queue = Queue()
    glib_loop = GLib.MainLoop()

    bus_thread = DbusT(glib_loop, main_queue.sync_q, glib_queue.sync_q)

    try:
        panctl = PanCtl(bus_thread)
    except dbus.exceptions.DBusException:
        print("Error, no pantalaimon bus found")
        sys.exit(-1)

    fut = loop.run_in_executor(
        None,
        bus_thread.dbus_loop
    )

    try:
        loop.run_until_complete(panctl.loop())
    except KeyboardInterrupt:
        pass

    GLib.idle_add(bus_thread.quit)
    loop.run_until_complete(fut)


if __name__ == '__main__':
    main()
