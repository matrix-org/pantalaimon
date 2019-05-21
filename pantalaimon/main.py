import asyncio
import os
import signal
from typing import Optional

import click
import janus
from aiohttp import web
from appdirs import user_config_dir, user_data_dir
from logbook import StderrHandler

from pantalaimon.config import PanConfig, PanConfigError, parse_log_level
from pantalaimon.daemon import ProxyDaemon
from pantalaimon.log import logger
from pantalaimon.thread_messages import DaemonResponse
from pantalaimon.ui import GlibT


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
        send_queue=send_queue,
        recv_queue=recv_queue,
        proxy=server_conf.proxy.geturl() if server_conf.proxy else None,
        ssl=None if server_conf.ssl is True else False
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
    app.on_shutdown.append(proxy.shutdown)

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(
        runner,
        str(server_conf.listen_address),
        server_conf.listen_port
    )

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
                message.message_id,
                message.pan_user,
                "m.unknown_client",
                msg
            )

        await proxy.receive_message(message)


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

    servers = []
    proxies = []

    for server_conf in pan_conf.servers.values():
        proxy, runner, site = loop.run_until_complete(
            init(
                data_dir,
                server_conf,
                pan_queue.async_q,
                ui_queue.async_q
            )
        )
        servers.append((proxy, runner, site))
        proxies.append(proxy)

    print(pan_conf.servers.keys())

    glib_thread = GlibT(pan_queue.sync_q, ui_queue.sync_q, data_dir,
                        pan_conf.servers.values())

    glib_fut = loop.run_in_executor(
        None,
        glib_thread.run
    )

    async def wait_for_glib(glib_thread, fut):
        glib_thread.stop()
        await fut

    message_router_task = loop.create_task(
        message_router(ui_queue.async_q, pan_queue.async_q, proxies)
    )

    home = os.path.expanduser("~")
    os.chdir(home)

    def handler(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, handler)

    try:
        for proxy, _, site in servers:
            click.echo(f"======== Starting daemon for homeserver "
                       f"{proxy.name} on {site.name} ========")
            loop.run_until_complete(site.start())

        click.echo("(Press CTRL+C to quit)")
        loop.run_forever()
    except KeyboardInterrupt:
        for _, runner, _ in servers:
            loop.run_until_complete(runner.cleanup())

        loop.run_until_complete(wait_for_glib(glib_thread, glib_fut))
        message_router_task.cancel()
        loop.run_until_complete(asyncio.wait({message_router_task}))
        loop.close()


if __name__ == "__main__":
    main()
