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

import asyncio
import os
import signal
from typing import Optional

import click
import janus
import keyring
import logbook
import nio
from aiohttp import web
from appdirs import user_config_dir, user_data_dir
from logbook import StderrHandler

from pantalaimon.config import PanConfig, PanConfigError, parse_log_level
from pantalaimon.daemon import ProxyDaemon
from pantalaimon.log import logger
from pantalaimon.thread_messages import DaemonResponse
from pantalaimon.ui import UI_ENABLED


def create_dirs(data_dir, conf_dir):
    try:
        os.makedirs(data_dir)
    except OSError:
        pass

    try:
        os.makedirs(conf_dir)
    except OSError:
        pass


async def init(data_dir, server_conf, send_queue, recv_queue):
    """Initialize the proxy and the http server."""
    proxy = ProxyDaemon(
        server_conf.name,
        server_conf.homeserver,
        server_conf,
        data_dir,
        send_queue=send_queue.async_q if send_queue else None,
        recv_queue=recv_queue.async_q if recv_queue else None,
        proxy=server_conf.proxy.geturl() if server_conf.proxy else None,
        ssl=None if server_conf.ssl is True else False,
    )

    app = web.Application()

    app.add_routes(
        [
            web.post("/_matrix/client/r0/login", proxy.login),
            web.get("/_matrix/client/r0/sync", proxy.sync),
            web.get("/_matrix/client/r0/rooms/{room_id}/messages", proxy.messages),
            web.put(
                r"/_matrix/client/r0/rooms/{room_id}/send/{event_type}/{txnid}",
                proxy.send_message,
            ),
            web.post("/_matrix/client/r0/user/{user_id}/filter", proxy.filter),
            web.post("/.well-known/matrix/client", proxy.well_known),
            web.get("/.well-known/matrix/client", proxy.well_known),
            web.post("/_matrix/client/r0/search", proxy.search),
            web.options("/_matrix/client/r0/search", proxy.search_opts),
            web.get(
                "/_matrix/media/r0/download/{server_name}/{media_id}", proxy.download
            ),
            web.get(
                "/_matrix/media/r0/download/{server_name}/{media_id}/{file_name}",
                proxy.download,
            ),
        ]
    )
    app.router.add_route("*", "/" + "{proxyPath:.*}", proxy.router)
    app.on_shutdown.append(proxy.shutdown)

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, str(server_conf.listen_address), server_conf.listen_port)

    return proxy, runner, site


async def message_router(receive_queue, send_queue, proxies):
    """Find the recipient of a message and forward it to the right proxy."""

    def find_proxy_by_user(user):
        # type: (str) -> Optional[ProxyDaemon]
        for proxy in proxies:
            if user in proxy.pan_clients:
                return proxy

        return None

    async def send_info(message_id, pan_user, code, string):
        message = DaemonResponse(message_id, pan_user, code, string)
        await send_queue.put(message)

    while True:
        message = await receive_queue.get()
        logger.debug(f"Router got message {message}")

        proxy = find_proxy_by_user(message.pan_user)

        if not proxy:
            msg = f"No pan client found for {message.pan_user}."
            logger.warn(msg)
            await send_info(
                message.message_id, message.pan_user, "m.unknown_client", msg
            )

        await proxy.receive_message(message)


@click.command(
    help=(
        "pantalaimon is a reverse proxy for matrix homeservers that "
        "transparently encrypts and decrypts messages for clients that "
        "connect to pantalaimon."
    )
)
@click.version_option(version="0.5.1", prog_name="pantalaimon")
@click.option(
    "--log-level",
    type=click.Choice(["error", "warning", "info", "debug"]),
    default=None,
)
@click.option("--debug-encryption", is_flag=True)
@click.option("-c", "--config", type=click.Path(exists=True))
@click.option("--data-path", type=click.Path(exists=True))
@click.pass_context
def main(context, log_level, debug_encryption, config, data_path):
    loop = asyncio.get_event_loop()

    conf_dir = user_config_dir("pantalaimon", "")
    data_dir = user_data_dir("pantalaimon", "")
    create_dirs(data_dir, conf_dir)

    config = config or os.path.join(conf_dir, "pantalaimon.conf")
    data_dir = data_path or data_dir

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

    if pan_conf.debug_encryption or debug_encryption:
        nio.crypto.logger.level = logbook.DEBUG

    StderrHandler().push_application()

    servers = []
    proxies = []

    if UI_ENABLED:
        from pantalaimon.ui import GlibT

        pan_queue = janus.Queue(loop=loop)
        ui_queue = janus.Queue(loop=loop)

        glib_thread = GlibT(
            pan_queue.sync_q,
            ui_queue.sync_q,
            data_dir,
            pan_conf.servers.values(),
            pan_conf,
        )

        glib_fut = loop.run_in_executor(None, glib_thread.run)
        message_router_task = loop.create_task(
            message_router(ui_queue.async_q, pan_queue.async_q, proxies)
        )

    else:
        glib_thread = None
        glib_fut = None
        pan_queue = None
        ui_queue = None
        message_router_task = None

    try:

        for server_conf in pan_conf.servers.values():
            proxy, runner, site = loop.run_until_complete(
                init(data_dir, server_conf, pan_queue, ui_queue)
            )
            servers.append((proxy, runner, site))
            proxies.append(proxy)

    except keyring.errors.KeyringError as e:
        context.fail(f"Error initializing keyring: {e}")

    async def wait_for_glib(glib_thread, fut):
        glib_thread.stop()
        await fut

    home = os.path.expanduser("~")
    os.chdir(home)

    def handler(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, handler)

    try:
        for proxy, _, site in servers:
            click.echo(
                f"======== Starting daemon for homeserver "
                f"{proxy.name} on {site.name} ========"
            )
            loop.run_until_complete(site.start())

        click.echo("(Press CTRL+C to quit)")
        loop.run_forever()
    except KeyboardInterrupt:
        for _, runner, _ in servers:
            loop.run_until_complete(runner.cleanup())

        if glib_fut:
            loop.run_until_complete(wait_for_glib(glib_thread, glib_fut))

        if message_router_task:
            message_router_task.cancel()
            loop.run_until_complete(asyncio.wait({message_router_task}))

        loop.close()


if __name__ == "__main__":
    main()
