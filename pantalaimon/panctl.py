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

"""Cli utility to control pantalaimon."""

import argparse
import asyncio
import sys
from collections import defaultdict
from itertools import zip_longest
from typing import List

import attr
import click
from gi.repository import GLib
from prompt_toolkit import __version__ as ptk_version
from prompt_toolkit import HTML, PromptSession, print_formatted_text
from prompt_toolkit.completion import Completer, Completion, PathCompleter
from prompt_toolkit.document import Document
from prompt_toolkit.patch_stdout import patch_stdout
from pydbus import SessionBus

PTK2 = ptk_version.startswith("2.")

if PTK2:
    from prompt_toolkit.eventloop.defaults import use_asyncio_event_loop

    use_asyncio_event_loop()


class ParseError(Exception):
    pass


class PanctlArgParse(argparse.ArgumentParser):
    def print_usage(self, file=None):
        pass

    def error(self, message):
        message = f"Error: {message} " f"(see help)"
        print(message)
        raise ParseError


class PanctlParser:
    def __init__(self, commands):
        self.commands = commands
        self.parser = PanctlArgParse()
        subparsers = self.parser.add_subparsers(dest="subcommand")
        subparsers.add_parser("list-servers")

        help = subparsers.add_parser("help")
        help.add_argument("command", choices=self.commands)

        list_devices = subparsers.add_parser("list-devices")
        list_devices.add_argument("pan_user", type=str)
        list_devices.add_argument("user_id", type=str)

        start = subparsers.add_parser("start-verification")
        start.add_argument("pan_user", type=str)
        start.add_argument("user_id", type=str)
        start.add_argument("device_id", type=str)

        cancel = subparsers.add_parser("cancel-verification")
        cancel.add_argument("pan_user", type=str)
        cancel.add_argument("user_id", type=str)
        cancel.add_argument("device_id", type=str)

        accept = subparsers.add_parser("accept-verification")
        accept.add_argument("pan_user", type=str)
        accept.add_argument("user_id", type=str)
        accept.add_argument("device_id", type=str)

        confirm = subparsers.add_parser("confirm-verification")
        confirm.add_argument("pan_user", type=str)
        confirm.add_argument("user_id", type=str)
        confirm.add_argument("device_id", type=str)

        verify = subparsers.add_parser("verify-device")
        verify.add_argument("pan_user", type=str)
        verify.add_argument("user_id", type=str)
        verify.add_argument("device_id", type=str)

        unverify = subparsers.add_parser("unverify-device")
        unverify.add_argument("pan_user", type=str)
        unverify.add_argument("user_id", type=str)
        unverify.add_argument("device_id", type=str)

        blacklist = subparsers.add_parser("blacklist-device")
        blacklist.add_argument("pan_user", type=str)
        blacklist.add_argument("user_id", type=str)
        blacklist.add_argument("device_id", type=str)

        unblacklist = subparsers.add_parser("unblacklist-device")
        unblacklist.add_argument("pan_user", type=str)
        unblacklist.add_argument("user_id", type=str)
        unblacklist.add_argument("device_id", type=str)

        import_keys = subparsers.add_parser("import-keys")
        import_keys.add_argument("pan_user", type=str)
        import_keys.add_argument("path", type=str)
        import_keys.add_argument("passphrase", type=str)

        export_keys = subparsers.add_parser("export-keys")
        export_keys.add_argument("pan_user", type=str)
        export_keys.add_argument("path", type=str)
        export_keys.add_argument("passphrase", type=str)

        send_anyways = subparsers.add_parser("send-anyways")
        send_anyways.add_argument("pan_user", type=str)
        send_anyways.add_argument("room_id", type=str)

        cancel_sending = subparsers.add_parser("cancel-sending")
        cancel_sending.add_argument("pan_user", type=str)
        cancel_sending.add_argument("room_id", type=str)

        continue_key_share = subparsers.add_parser("continue-keyshare")
        continue_key_share.add_argument("pan_user", type=str)
        continue_key_share.add_argument("user_id", type=str)
        continue_key_share.add_argument("device_id", type=str)

        cancel_key_share = subparsers.add_parser("cancel-keyshare")
        cancel_key_share.add_argument("pan_user", type=str)
        cancel_key_share.add_argument("user_id", type=str)
        cancel_key_share.add_argument("device_id", type=str)

    def parse_args(self, argv):
        return self.parser.parse_args(argv)


@attr.s
class PanCompleter(Completer):
    """Completer for panctl commands."""

    commands = attr.ib(type=List[str])
    ctl = attr.ib()
    devices = attr.ib()
    rooms = attr.ib(init=False, default=attr.Factory(lambda: defaultdict(set)))
    path_completer = PathCompleter(expanduser=True)

    def complete_commands(self, last_word):
        """Complete the available commands."""
        compl_words = self.filter_words(self.commands, last_word)
        for compl_word in compl_words:
            yield Completion(compl_word, -len(last_word))

    def complete_users(self, last_word, pan_user):
        devices = self.devices.List(pan_user)
        users = set(device["user_id"] for device in devices)
        compl_words = self.filter_words(users, last_word)

        for compl_word in compl_words:
            yield Completion(compl_word, -len(last_word))

        return ""

    def complete_devices(self, last_word, pan_user, user_id):
        devices = self.devices.ListUserDevices(pan_user, user_id)
        device_ids = [device["device_id"] for device in devices]
        compl_words = self.filter_words(device_ids, last_word)

        for compl_word in compl_words:
            yield Completion(compl_word, -len(last_word))

        return ""

    def filter_words(self, words, last_word):
        compl_words = []

        for word in words:
            if last_word in word:
                compl_words.append(word)

        return compl_words

    def complete_pan_users(self, last_word):
        servers = self.ctl.ListServers()
        users = [item[0] for sublist in servers.values() for item in sublist]
        compl_words = self.filter_words(users, last_word)

        for compl_word in compl_words:
            yield Completion(compl_word, -len(last_word))

    def complete_verification(self, command, last_word, words):
        if len(words) == 2:
            return self.complete_pan_users(last_word)
        elif len(words) == 3:
            pan_user = words[1]
            return self.complete_users(last_word, pan_user)
        elif len(words) == 4:
            pan_user = words[1]
            user_id = words[2]
            return self.complete_devices(last_word, pan_user, user_id)

        return ""

    def complete_key_file_cmds(
        self, document, complete_event, command, last_word, words
    ):
        if len(words) == 2:
            return self.complete_pan_users(last_word)
        elif len(words) == 3:
            return self.path_completer.get_completions(
                Document(last_word), complete_event
            )

        return ""

    def complete_rooms(self, pan_user, last_word, words):
        rooms = self.rooms[pan_user]
        compl_words = self.filter_words(list(rooms), last_word)

        for compl_word in compl_words:
            yield Completion(compl_word, -len(last_word))

        return ""

    def complete_send_cmds(self, last_word, words):
        if len(words) == 2:
            return self.complete_pan_users(last_word)
        elif len(words) == 3:
            pan_user = words[1]
            return self.complete_rooms(pan_user, last_word, words)

        return ""

    def complete_list_devices(self, last_word, words):
        if len(words) == 2:
            return self.complete_pan_users(last_word)
        elif len(words) == 3:
            pan_user = words[1]
            return self.complete_users(last_word, pan_user)

        return ""

    def get_completions(self, document, complete_event):
        """Build the completions."""
        text_before_cursor = document.text_before_cursor
        text_before_cursor = str(text_before_cursor)
        words = text_before_cursor.split(" ")

        last_word = words[-1]

        if len(words) == 1:
            return self.complete_commands(last_word)

        if len(words) > 1:
            command = words[0]

            if command in [
                "start-verification",
                "accept-verification",
                "confirm-verification",
                "cancel-verification",
                "verify-device",
                "unverify-device",
                "blacklist-device",
                "unblacklist-device",
            ]:
                return self.complete_verification(command, last_word, words)

            elif command in ["export-keys", "import-keys"]:
                return self.complete_key_file_cmds(
                    document, complete_event, command, last_word, words
                )

            elif command in ["send-anyways", "cancel-sending"]:
                return self.complete_send_cmds(last_word, words)

            elif command == "list-devices":
                return self.complete_list_devices(last_word, words)

            elif command == "help":
                if len(words) == 2:
                    return self.complete_commands(last_word)
                else:
                    return ""

            elif command in ["cancel-keyshare", "continue-keyshare"]:
                return self.complete_verification(command, last_word, words)

        return ""


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def partition_key(key):
    groups = grouper(key, 4, " ")
    return " ".join("".join(g) for g in groups)


def get_color(string):
    def djb2(string):
        hash = 5381
        for x in string:
            hash = ((hash << 5) + hash) + ord(x)
        return hash & 0xFFFFFFFF

    colors = [
        "ansiblue",
        "ansigreen",
        "ansired",
        "ansiyellow",
        "ansicyan",
        "ansimagenta",
    ]

    return colors[djb2(string) % 5]


@attr.s
class PanCtl:
    bus = attr.ib(init=False)
    pan_bus = attr.ib(init=False)
    ctl = attr.ib(init=False)
    devices = attr.ib(init=False)
    completer = attr.ib(init=False)
    own_message_ids = attr.ib(init=False)

    command_help = {
        "help": "Display help about commands.",
        "list-servers": (
            "List the configured homeservers and pan users on each homeserver."
        ),
        "list-devices": ("List the devices of a user that are known to the pan-user."),
        "start-verification": (
            "Start an interactive key verification between "
            "the given pan-user and user."
        ),
        "accept-verification": (
            "Accept an interactive key verification that "
            "the given user has started with our given "
            "pan-user."
        ),
        "cancel-verification": (
            "Cancel an interactive key verification "
            "between the given pan-user and user."
        ),
        "confirm-verification": (
            "Confirm that the short authentication "
            "string of the interactive key verification "
            "with the given pan-user and user is "
            "matching."
        ),
        "verify-device": ("Manually mark the given device as verified."),
        "unverify-device": (
            "Mark a previously verified device of the given user as unverified."
        ),
        "blacklist-device": (
            "Manually mark the given device of the given user as blacklisted."
        ),
        "unblacklist-device": (
            "Mark a previously blacklisted device of the "
            "given user as unblacklisted."
        ),
        "send-anyways": (
            "Send a room message despite having unverified "
            "devices in the room and mark the devices as "
            "ignored."
        ),
        "cancel-sending": (
            "Cancel the send of a room message in a room that "
            "contains unverified devices"
        ),
        "import-keys": (
            "Import end-to-end encryption keys from the given "
            "file for the given pan-user."
        ),
        "export-keys": (
            "Export end-to-end encryption keys to the given file "
            "for the given pan-user."
        ),
        "continue-keyshare": (
            "Export end-to-end encryption keys to the given file "
            "for the given pan-user."
        ),
        "cancel-keyshare": (
            "Export end-to-end encryption keys to the given file "
            "for the given pan-user."
        ),
    }

    commands = list(command_help.keys())

    def __attrs_post_init__(self):
        self.bus = SessionBus()
        self.pan_bus = self.bus.get("org.pantalaimon1")

        self.ctl = self.pan_bus["org.pantalaimon1.control"]
        self.devices = self.pan_bus["org.pantalaimon1.devices"]

        self.own_message_ids = []

        self.ctl.Response.connect(self.show_response)
        self.ctl.UnverifiedDevices.connect(self.unverified_devices)

        self.completer = PanCompleter(self.commands, self.ctl, self.devices)

        self.devices.VerificationInvite.connect(self.show_sas_invite)
        self.devices.VerificationString.connect(self.show_sas)
        self.devices.VerificationDone.connect(self.sas_done)

        self.devices.KeyRequest.connect(self.show_key_request)
        self.devices.KeyRequestCancel.connect(self.show_key_request_cancel)

    def show_help(self, command):
        print(self.command_help[command])

    def unverified_devices(self, pan_user, room_id, display_name):
        self.completer.rooms[pan_user].add(room_id)
        print(
            f"Error sending message for user {pan_user}, "
            f"there are unverified devices in the room {display_name} "
            f"({room_id}).\nUse the send-anyways or cancel-sending commands "
            f"to ignore the devices or cancel the sending."
        )

    def show_response(self, response_id, pan_user, message):
        if response_id not in self.own_message_ids:
            return

        self.own_message_ids.remove(response_id)

        print(message["message"])

    def show_key_request(self, pan_user, user_id, device_id, request_id):
        print(
            f"{user_id} has requested room keys from our pan "
            f"user {pan_user}, but the requesting device "
            f"{device_id} is unverified\n"
            f"After verifying the device accept the key share request with "
            f"the continue-keyshare, alternatively cancel the "
            f"request with the cancel-keyshare command."
        )

    def show_key_request_cancel(self, pan_user, user_id, device_id, request_id):
        print(
            f"{user_id} via {device_id} has "
            f"canceled the room key request from our pan user "
            f"{pan_user}."
        )

    def sas_done(self, pan_user, user_id, device_id, _):
        print(
            f"Device {device_id} of user {user_id}"
            f" succesfully verified for pan user {pan_user}."
        )

    def show_sas_invite(self, pan_user, user_id, device_id, _):
        print(
            f"{user_id} has started an interactive device "
            f"verification for their device {device_id} with pan user "
            f"{pan_user}\n"
            f"Accept the invitation with the accept-verification command."
        )

    # The emoji printing logic was taken from weechat-matrix and was written by
    # dkasak.
    def show_sas(self, pan_user, user_id, device_id, _, emoji):
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
            variation_selector_emojis = ["☁️", "❤️", "☂️", "✏️", "✂️", "☎️", "✈️"]

            if emoji in variation_selector_emojis:
                emoji += " "

            # This is a trick to account for the fact that emojis are wider
            # than other monospace characters.
            placeholder = "." * emoji_width

            return placeholder.center(width).replace(placeholder, emoji)

        emoji_str = "".join(center_emoji(e, centered_width) for e in emojis)
        desc = "".join(d.center(centered_width) for d in descriptions)
        short_string = "\n".join([emoji_str, desc])

        print(
            f"Short authentication string for pan "
            f"user {pan_user} from {user_id} via "
            f"{device_id}:\n{short_string}"
        )

    def list_servers(self):
        """List the daemons users."""
        servers = self.ctl.ListServers()

        print("pantalaimon servers:")

        for server, server_users in servers.items():
            server_c = get_color(server)

            print_formatted_text(HTML(f" - Name: <{server_c}>{server}</{server_c}>"))

            user_list = []

            for user, device in server_users:
                user_c = get_color(user)
                device_c = get_color(device)

                user_list.append(
                    f"   - <{user_c}>{user}</{user_c}> "
                    f"<{device_c}>{device}</{device_c}>"
                )

            if user_list:
                print(" - Pan users:")
                user_string = "\n".join(user_list)
                print_formatted_text(HTML(user_string))

    def list_devices(self, args):
        devices = self.devices.ListUserDevices(args.pan_user, args.user_id)

        print_formatted_text(HTML(f"Devices for user <b>{args.user_id}</b>:"))

        for device in devices:
            if device["trust_state"] == "verified":
                trust_state = "<ansigreen>Verified</ansigreen>"
            elif device["trust_state"] == "blacklisted":
                trust_state = "<ansired>Blacklisted</ansired>"
            elif device["trust_state"] == "ignored":
                trust_state = "Ignored"
            else:
                trust_state = "Unset"

            key = partition_key(device["ed25519"])
            color = get_color(device["device_id"])
            print_formatted_text(
                HTML(
                    f" - Display name:  "
                    f"{device['device_display_name']}\n"
                    f"   - Device id:   "
                    f"<{color}>{device['device_id']}</{color}>\n"
                    f"   - Device key:  "
                    f"<ansiyellow>{key}</ansiyellow>\n"
                    f"   - Trust state: "
                    f"{trust_state}"
                )
            )

    async def loop(self):
        """Event loop for panctl."""
        promptsession = PromptSession("panctl> ", completer=self.completer)

        while True:
            with patch_stdout():
                try:
                    if PTK2:
                        result = await promptsession.prompt(async_=True)
                    else:
                        result = await promptsession.prompt_async()
                except EOFError:
                    break

            if not result:
                continue

            parser = PanctlParser(self.commands)

            try:
                args = parser.parse_args(result.split())
            except ParseError:
                continue

            command = args.subcommand

            if command == "list-servers":
                self.list_servers()

            if command == "help":
                self.show_help(args.command)

            elif command == "import-keys":
                self.own_message_ids.append(
                    self.ctl.ImportKeys(args.pan_user, args.path, args.passphrase)
                )

            elif command == "export-keys":
                self.own_message_ids.append(
                    self.ctl.ExportKeys(args.pan_user, args.path, args.passphrase)
                )

            elif command == "send-anyways":
                self.own_message_ids.append(
                    self.ctl.SendAnyways(args.pan_user, args.room_id)
                )

            elif command == "cancel-sending":
                self.own_message_ids.append(
                    self.ctl.CancelSending(args.pan_user, args.room_id)
                )

            elif command == "list-devices":
                self.list_devices(args)

            elif command == "verify-device":
                self.own_message_ids.append(
                    self.devices.Verify(args.pan_user, args.user_id, args.device_id)
                )

            elif command == "unverify-device":
                self.own_message_ids.append(
                    self.devices.Unverify(args.pan_user, args.user_id, args.device_id)
                )

            elif command == "blacklist-device":
                self.own_message_ids.append(
                    self.devices.Blacklist(args.pan_user, args.user_id, args.device_id)
                )

            elif command == "unblacklist-device":
                self.own_message_ids.append(
                    self.devices.Unblacklist(
                        args.pan_user, args.user_id, args.device_id
                    )
                )

            elif command == "start-verification":
                self.own_message_ids.append(
                    self.devices.StartKeyVerification(
                        args.pan_user, args.user_id, args.device_id
                    )
                )

            elif command == "cancel-verification":
                self.own_message_ids.append(
                    self.devices.CancelKeyVerification(
                        args.pan_user, args.user_id, args.device_id
                    )
                )

            elif command == "accept-verification":
                self.own_message_ids.append(
                    self.devices.AcceptKeyVerification(
                        args.pan_user, args.user_id, args.device_id
                    )
                )

            elif command == "confirm-verification":
                self.own_message_ids.append(
                    self.devices.ConfirmKeyVerification(
                        args.pan_user, args.user_id, args.device_id
                    )
                )

            elif command == "continue-keyshare":
                self.own_message_ids.append(
                    self.devices.ContinueKeyShare(
                        args.pan_user, args.user_id, args.device_id
                    )
                )

            elif command == "cancel-keyshare":
                self.own_message_ids.append(
                    self.devices.CancelKeyShare(
                        args.pan_user, args.user_id, args.device_id
                    )
                )


@click.command(
    help=(
        "panctl is a small interactive repl to introspect and control"
        "the pantalaimon daemon."
    )
)
@click.version_option(version="0.10.3", prog_name="panctl")
def main():
    loop = asyncio.get_event_loop()
    glib_loop = GLib.MainLoop()

    try:
        panctl = PanCtl()
    except GLib.Error as e:
        print(f"Error, {e}")
        sys.exit(-1)

    fut = loop.run_in_executor(None, glib_loop.run)

    try:
        loop.run_until_complete(panctl.loop())
    except KeyboardInterrupt:
        pass

    GLib.idle_add(glib_loop.quit)
    loop.run_until_complete(fut)


if __name__ == "__main__":
    main()
