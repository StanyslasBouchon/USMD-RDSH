"""Entry point of a USMD-RDSH node.

    usmd                     start the node and its console
    usmd --no-console        start the node only (service mode)
    usmd -c "show version"   run console lines against the saved configuration
                             and exit, without starting the node's protocols

The web interface starts with the node when ``system web-interface`` has
``status enable``.
"""

import argparse
import asyncio
import logging
import sys
import threading

import dotenv

dotenv.load_dotenv()

# pylint: disable=wrong-import-position
from prompt_toolkit.patch_stdout import patch_stdout  # noqa: E402

from usmd_rdsh.cli.runtime import RUNTIME  # noqa: E402
from usmd_rdsh.cli.shell import ShellFactory, banner  # noqa: E402
from usmd_rdsh.self.core import Core  # noqa: E402
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
    return parser.parse_args(argv)


async def _run_commands(factory: ShellFactory, lines: list[str]) -> None:
    shell = factory.console()
    for line in lines:
        await shell.execute_line(line)


async def _serve(factory: ShellFactory, console: bool) -> None:
    core = RUNTIME.core
    assert core is not None
    threading.Thread(target=core.run, name="usmd-core", daemon=True).start()

    if not console:
        logging.warning("[SYS] Node %s started without console", core.properties.node_id)
        await asyncio.Event().wait()
        return

    async def ready() -> None:
        banner()

    shell = factory.console(on_ready=ready)
    with patch_stdout(raw=True):
        await shell.run()


async def _main(args: argparse.Namespace) -> None:
    factory = ShellFactory()
    one_shot = bool(args.command)
    if not one_shot:
        RUNTIME.web = WebServer(factory)
    await RUNTIME.apply_all()
    try:
        if one_shot:
            await _run_commands(factory, args.command)
        else:
            await _serve(factory, console=not args.no_console)
    finally:
        if RUNTIME.web is not None:
            await RUNTIME.web.stop()
        if RUNTIME.core is not None and RUNTIME.core.is_running():
            RUNTIME.core.stop()


def main(argv: list[str] | None = None) -> None:
    """Start the node."""
    args = _arguments(argv)

    # A module-level logging call made during the imports above installs
    # logging's implicit stderr handler; the buffer and its console level
    # replace it, so every message goes through one place.
    root = logging.getLogger()
    for handler in list(root.handlers):
        if type(handler) is logging.StreamHandler:  # pylint: disable=unidiomatic-typecheck
            root.removeHandler(handler)
    RUNTIME.logbuffer.attach()
    RUNTIME.logbuffer.set_console(print)
    RUNTIME.document = RUNTIME.config_store.load()
    RUNTIME.core = Core()

    try:
        asyncio.run(_main(args))
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    main()
