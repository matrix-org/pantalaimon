import asyncio

import os
from functools import partial
from ipaddress import ip_address
from urllib.parse import urlparse

import click
import janus
import logbook

from appdirs import user_data_dir
from logbook import StderrHandler

from aiohttp import web

from pantalaimon.ui import GlibT
from pantalaimon.log import logger
from pantalaimon.daemon import ProxyDaemon


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


@click.command(
    help=("pantalaimon is a reverse proxy for matrix homeservers that "
          "transparently encrypts and decrypts messages for clients that "
          "connect to pantalaimon.\n\n"
          "HOMESERVER - the homeserver that the daemon should connect to.")

)
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
def main(
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
    main()
