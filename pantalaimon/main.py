import asyncio

import os
from functools import partial
from ipaddress import ip_address
from urllib.parse import urlparse

import click
import janus

from appdirs import user_data_dir, user_config_dir
from logbook import StderrHandler

from aiohttp import web

from pantalaimon.ui import GlibT
from pantalaimon.daemon import ProxyDaemon
from pantalaimon.config import PanConfig, PanConfigError, parse_log_level
from pantalaimon.log import logger


def create_dirs(data_dir, conf_dir):
    try:
        os.makedirs(data_dir)
    except OSError:
        pass

    try:
        os.makedirs(conf_dir)
    except OSError:
        pass


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
          "connect to pantalaimon.")

)
@click.option("--log-level", type=click.Choice([
    "error",
    "warning",
    "info",
    "debug"
]), default=None)
@click.option("-c", "--config", type=click.Path(exists=True))
@click.pass_context
def main(
    context,
    log_level,
    config
):
    conf_dir = user_config_dir("pantalaimon", "")
    data_dir = user_data_dir("pantalaimon", "")
    create_dirs(data_dir, conf_dir)

    config = config or os.path.join(conf_dir, "pantalaimon.conf")

    if log_level:
        log_level = parse_log_level(log_level)

    pan_conf = PanConfig(config, log_level)

    try:
        pan_conf.read()
    except (OSError, PanConfigError) as e:
        context.fail(e)

    if not pan_conf.servers:
        context.fail("Homeserver is not configured.")

    logger.level = pan_conf.log_level
    StderrHandler().push_application()

    loop = asyncio.get_event_loop()
    pan_queue = janus.Queue(loop=loop)
    ui_queue = janus.Queue(loop=loop)

    # TODO start the other servers as well
    server_conf = list(pan_conf.servers.values())[0]

    proxy, app = loop.run_until_complete(init(
        server_conf.homeserver,
        server_conf.proxy.geturl() if server_conf.proxy else None,
        server_conf.ssl,
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

    web.run_app(
        app,
        host=str(server_conf.listen_address),
        port=server_conf.listen_port
    )


if __name__ == "__main__":
    main()
