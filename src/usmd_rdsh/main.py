"""Entry point of a USMD-RDSH node.

    usmd                     the console of the node running on this machine
                             (service); with none running, start one with it
    usmd --no-console        start the node only (service mode)
    usmd --config usmd.yaml  configuration file (layout of usmd.example.yaml)
    usmd --dev 2             virtual node 2 of a development cluster (127.0.0.3)
    usmd -c "show version"   run console lines and exit: on the running node,
                             or, with none, against the saved configuration
                             without starting the node's protocols

Several virtual nodes at once: ``python -m usmd_rdsh.dev --nodes 3``.

The web interface starts with the node when ``system web-interface`` has
``status enable``.
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

import dotenv

dotenv.load_dotenv()

# pylint: disable=wrong-import-position
from prompt_toolkit.patch_stdout import patch_stdout  # noqa: E402

from usmd_rdsh.cli import bridge, control, operate  # noqa: E402
from usmd_rdsh.cli.runtime import RUNTIME  # noqa: E402
from usmd_rdsh.cli.shell import ShellFactory, banner  # noqa: E402
from usmd_rdsh.cli import startup  # noqa: E402
from usmd_rdsh.cli.store import STATE_ENV_VAR, ConfigStore, TokenStore, state_directory  # noqa: E402
from nan_runtime.state import StateDirectory  # noqa: E402
from usmd_rdsh.node.node import Node  # noqa: E402
from usmd_rdsh.web.server import WebServer  # noqa: E402


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="usmd", description="USMD-RDSH node")
    parser.add_argument(
        "--no-console", action="store_true", help="run without the interactive console"
    )
    parser.add_argument(
        "-c", "--command", action="append", default=[], metavar="LINE",
        help="run a console line and exit (repeatable)",
    )
    parser.add_argument(
        "-y", "--yes", action="store_true",
        help="with -c: answer yes to every confirmation (scripts)",
    )
    parser.add_argument(
        "--config", metavar="FILE", default=os.getenv("USMD_CONFIG"),
        help="usmd.yaml configuration file (layout of usmd.example.yaml)",
    )
    parser.add_argument(
        "--dev", type=int, metavar="N",
        help="development: run virtual node N (127.0.0.N+1) of a cluster on this machine",
    )
    parser.add_argument(
        "--dev-nodes", type=int, default=3, metavar="COUNT",
        help="development: number of virtual nodes in the cluster (default 3)",
    )
    return parser.parse_args(argv)


async def _run_commands(factory: ShellFactory, lines: list[str]) -> None:
    shell = factory.console()
    for line in lines:
        await shell.execute_line(line)


async def _serve(factory: ShellFactory, console: bool) -> None:
    node = RUNTIME.node
    assert node is not None
    await node.start()

    if not console:
        logging.warning("[SYS] Node %s started without console", node.node_id)
        await asyncio.Event().wait()
        return

    async def ready() -> None:
        banner()

    shell = factory.console(on_ready=ready)
    with patch_stdout(raw=True):
        await shell.run()


async def _main(args: argparse.Namespace) -> None:
    factory = ShellFactory()
    operate.install(factory)  # the console lent to elected operators [ARCH 12.5]
    one_shot = bool(args.command)
    if one_shot and args.yes:
        from nan_actions.ports import set_confirm_prompt  # pylint: disable=import-outside-toplevel

        class _Yes:
            async def ask(self, message: str) -> bool:
                logging.warning("[CLI] %s -> yes (--yes)", message)
                return True

        set_confirm_prompt(_Yes())
    consoles = None
    if not one_shot:
        RUNTIME.web = WebServer(factory)
        # Dev nodes share the machine: each listens in its own state directory.
        consoles = control.ControlServer(
            factory, state_directory().path("usmd.sock") if args.dev is not None else None)
    # What is in force (signed objects) is what the tree shows.
    bridge.reflect()
    await RUNTIME.apply_all()
    if not one_shot and hasattr(signal, "SIGTERM") and sys.platform != "win32":
        # systemd stops the service with SIGTERM: leave through the 'finally'
        # below, which stops the services cleanly, not by dying mid-way.
        main_task = asyncio.current_task()
        loop = asyncio.get_running_loop()
        for number in (signal.SIGTERM, signal.SIGHUP):
            loop.add_signal_handler(number, main_task.cancel)
    try:
        if one_shot:
            await _run_commands(factory, args.command)
        else:
            await consoles.start()
            await _serve(factory, console=not args.no_console)
    finally:
        if consoles is not None:
            await consoles.stop()
        if RUNTIME.web is not None:
            await RUNTIME.web.stop()
        if RUNTIME.node is not None and not one_shot:
            await RUNTIME.node.stop_services()
            await RUNTIME.node.stop()


def main(argv: list[str] | None = None) -> None:
    """Start the node."""
    args = _arguments(argv)
    if not args.no_console and args.dev is None:
        # A node already runs here (the service): talk to it, never start a second one.
        running = control.running_node()
        if running is not None:
            if args.command:
                control.run_lines(running, args.command, yes=args.yes)
            else:
                control.attach(running)
            return
        if os.getenv(control.ATTACH_ONLY_ENV_VAR):
            # The installed 'usmd' command: the node is the service, not this process.
            raise SystemExit("No node is running on this machine: 'sudo systemctl start usmd' "
                             "(logs: 'journalctl -u usmd -e').")

    # A module-level logging call made during the imports above installs
    # logging's implicit stderr handler; the buffer and its console level
    # replace it, so every message goes through one place.
    root = logging.getLogger()
    for handler in list(root.handlers):
        if type(handler) is logging.StreamHandler:  # pylint: disable=unidiomatic-typecheck
            root.removeHandler(handler)
    RUNTIME.logbuffer.attach()
    RUNTIME.logbuffer.set_console(print)

    dev = args.dev
    if dev is not None and not os.getenv(STATE_ENV_VAR):
        if not 1 <= dev <= 250 or not 1 <= args.dev_nodes <= 250:
            raise SystemExit("--dev and --dev-nodes are between 1 and 250")
        os.environ[STATE_ENV_VAR] = str(startup.dev_state(dev).root)
    state = state_directory()
    state.ensure()
    yaml_path = Path(args.config) if args.config else (
        state.path("usmd.yaml") if dev is not None else None)
    RUNTIME.config_store = ConfigStore(state, yaml_path)
    RUNTIME.tokens = TokenStore(state)
    RUNTIME.document = RUNTIME.config_store.load()
    for warning in RUNTIME.config_store.warnings:
        logging.warning("[CONFIG] %s", warning)
    RUNTIME.node = Node(state, identity_file=RUNTIME.config_store.keys_file,
                        authority_dir=StateDirectory(startup.DEV_ROOT) if dev else None)
    RUNTIME.node.on_signed_change = bridge.reflect

    messages: list[str] = []
    if dev is not None:
        startup.prepare_dev(dev, args.dev_nodes, messages)
    elif RUNTIME.config_store.bootstrap:
        startup.found(messages)
    for message in messages:
        logging.warning("[SYS] %s", message)
    if messages or dev is not None:
        RUNTIME.config_store.save_now(RUNTIME.document)

    try:
        asyncio.run(_main(args))
    except KeyboardInterrupt:
        sys.exit(1)
    except asyncio.CancelledError:
        logging.warning("[SYS] Stopped by a signal; services stopped cleanly")


if __name__ == "__main__":
    main()
