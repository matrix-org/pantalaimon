import asyncio

import os
import sys
from functools import partial
from ipaddress import ip_address
from urllib.parse import urlparse

import click
import janus
import logbook

from appdirs import user_data_dir
from logbook import StderrHandler

from aiohttp import web

from nio import EncryptionError

from pantalaimon.ui import GlibT
from pantalaimon.log import logger
from pantalaimon.daemon import ProxyDaemon
from pantalaimon.client import PanClient
from pantalaimon.store import PanStore


async def init(homeserver, http_proxy, ssl, send_queue, recv_queue):
    """Initialize the proxy and the http server."""
    data_dir = user_data_dir("pantalaimon", "")

    try:
        os.makedirs(data_dir)
    except OSError:
        pass

    proxy = ProxyDaemon(
        homeserver,
        data_dir,
        send_queue=send_queue,
        recv_queue=recv_queue,
        proxy=http_proxy,
        ssl=ssl,
    )

    app = web.Application()
    app.add_routes([
        web.post("/_matrix/client/r0/login", proxy.login),
        web.get("/_matrix/client/r0/sync", proxy.sync),
        web.get("/_matrix/client/r0/rooms/{room_id}/messages", proxy.messages),
        web.put(
            r"/_matrix/client/r0/rooms/{room_id}/send/{event_type}/{txnid}",
            proxy.send_message
        ),
        web.post("/_matrix/client/r0/user/{user_id}/filter", proxy.filter),
    ])
    app.router.add_route("*", "/" + "{proxyPath:.*}", proxy.router)
    return proxy, app


class URL(click.ParamType):
    name = 'url'

    def convert(self, value, param, ctx):
        try:
            value = urlparse(value)

            if value.scheme not in ('http', 'https'):
                self.fail(f"Invalid URL scheme {value.scheme}. Only HTTP(s) "
                          "URLs are allowed")
            value.port
        except ValueError as e:
            self.fail(f"Error parsing URL: {e}")

        return value


class ipaddress(click.ParamType):
    name = "ipaddress"

    def convert(self, value, param, ctx):
        try:
            value = ip_address(value)
        except ValueError as e:
            self.fail(f"Error parsing ip address: {e}")

        return value


@click.group(
    help=("pantalaimon is a reverse proxy for matrix homeservers that "
          "transparently encrypts and decrypts messages for clients that "
          "connect to pantalaimon.\n\n"
          "HOMESERVER - the homeserver that the daemon should connect to.")

)
def cli():
    pass


def _find_device(user):
    data_dir = user_data_dir("pantalaimon", "")
    store = PanStore(data_dir)
    accounts = store.load_all_users()

    for user_id, device in accounts:
        if user == user_id:
            return device

    click.echo("No such user/device combination found.")
    sys.exit()


@cli.command(
    "keys-import",
    help="Import encryption keys into the pantalaimon store."
)
@click.argument("user", type=str)
@click.argument("infile", type=click.Path(exists=True))
@click.argument("passphrase", type=str)
def keys_import(user, infile, passphrase):
    device = _find_device(user)
    data_dir = user_data_dir("pantalaimon", "")

    click.echo(f"Importing encryption keys for {user}, {device}...")

    client = PanClient("", user, device, data_dir)
    client.user_id = user
    client.load_store()

    try:
        client.import_keys(infile, passphrase)
    except (OSError, EncryptionError) as e:
        click.echo(f"Error importing keys: {e}")
        return

    click.echo(
        f"Succesfully imported encryption keys for {user}, {device}."
    )


@cli.command(
    "keys-export",
    help="Export encryption keys from the pantalaimon store."
)
@click.argument("user", type=str)
@click.argument("outfile", type=click.Path())
@click.argument("passphrase", type=str)
def keys_export(user, outfile, passphrase):
    device = _find_device(user)
    data_dir = user_data_dir("pantalaimon", "")

    click.echo(f"Exporting encryption keys for {user}, {device}...")

    client = PanClient("", user, device, data_dir)
    client.user_id = user
    client.load_store()

    try:
        client.export_keys(outfile, passphrase)
    except OSError as e:
        click.echo(f"Error exporting keys: {e}")
        return

    click.echo(
        f"Succesfully exported encryption keys for {user}, {device}."
    )


@cli.command("list-users", help="List the user/device pairs of the daemon")
def list_users():
    data_dir = user_data_dir("pantalaimon", "")
    store = PanStore(data_dir)
    accounts = store.load_all_users()

    click.echo(f"Pantalaimon users:")
    for user, device in accounts:
        click.echo(f"  {user} - {device}")


@cli.command(help=("Start the daemon"))
@click.option(
    "--proxy",
    type=URL(),
    default=None,
    help="A proxy that will be used to connect to the homeserver."
)
@click.option(
    "-k",
    "--ssl-insecure/--no-ssl-insecure",
    default=False,
    help="Disable SSL verification for the homeserver connection."
)
@click.option(
    "-l",
    "--listen-address",
    type=ipaddress(),
    default=ip_address("127.0.0.1"),
    help=("The listening address for incoming client connections "
          "(default: 127.0.0.1)")
)
@click.option(
    "-p",
    "--listen-port",
    type=int,
    default=8009,
    help="The listening port for incoming client connections (default: 8009)"
)
@click.option("--log-level", type=click.Choice([
    "error",
    "warning",
    "info",
    "debug"
]), default="error")
@click.argument(
    "homeserver",
    type=URL(),
)
def start(
    proxy,
    ssl_insecure,
    listen_address,
    listen_port,
    log_level,
    homeserver
):
    ssl = None if ssl_insecure is False else False

    StderrHandler(level=log_level.upper()).push_application()

    if log_level == "info":
        logger.level = logbook.INFO
    elif log_level == "warning":
        logger.level = logbook.WARNING
    elif log_level == "error":
        logger.level = logbook.ERROR
    elif log_level == "debug":
        logger.level = logbook.DEBUG

    loop = asyncio.get_event_loop()

    pan_queue = janus.Queue(loop=loop)
    ui_queue = janus.Queue(loop=loop)

    proxy, app = loop.run_until_complete(init(
        homeserver,
        proxy.geturl() if proxy else None,
        ssl,
        pan_queue.async_q,
        ui_queue.async_q
    ))

    data_dir = user_data_dir("pantalaimon", "")
    glib_thread = GlibT(pan_queue.sync_q, ui_queue.sync_q, data_dir)

    fut = loop.run_in_executor(
        None,
        glib_thread.run
    )

    async def wait_for_glib(glib_thread, fut, app):
        glib_thread.stop()
        await fut

    stop_glib = partial(wait_for_glib, glib_thread, fut)

    app.on_shutdown.append(proxy.shutdown)
    app.on_shutdown.append(stop_glib)

    home = os.path.expanduser("~")
    os.chdir(home)

    web.run_app(app, host=str(listen_address), port=listen_port)


if __name__ == "__main__":
    cli()
