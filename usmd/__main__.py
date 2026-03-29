"""Entry point for USMD-RDSH.

Two modes of operation:

**Daemon** (default) — start or join a USD::

    python -m usmd [--config PATH] [--bootstrap] [--role ROLE] [--address IP]

**Status** — inspect a running daemon via its control interface::

    python -m usmd status [--socket PATH] [--port PORT] [--json]

Examples::

    # Bootstrap the first node in a new USD
    python -m usmd --config usmd.yaml --bootstrap

    # Join an existing USD as a plain executor
    python -m usmd --config usmd.yaml

    # Inspect a running node (pretty output)
    python -m usmd status

    # Inspect and pipe to jq
    python -m usmd status --json | jq .node

    # Inspect with a custom socket path (Linux/macOS)
    python -m usmd status --socket usmd.sock

    # Inspect via TCP loopback (Windows)
    python -m usmd status --port 5627

"""

import argparse
import asyncio
import json
import logging
import signal
import sys

from .config import NodeConfig
from .ctl.client import get_status, print_status
from .node_daemon import NodeDaemon


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="usmd",
        description="USMD-RDSH — Unified System Management and Deployment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --- Daemon arguments (apply when no subcommand is given) ---
    parser.add_argument(
        "--config",
        default="usmd.yaml",
        metavar="PATH",
        help="YAML configuration file (default: usmd.yaml)",
    )
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        default=None,
        help="Create a new USD instead of joining an existing one",
    )
    parser.add_argument(
        "--role",
        choices=["executor", "operator", "usd_operator", "ucd_operator"],
        default=None,
        help="Override the node role from the config file",
    )
    parser.add_argument(
        "--address",
        default=None,
        metavar="IP",
        help="Override the node's network address (default: auto-detect)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    # --- Subcommands ---
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    status = subparsers.add_parser(
        "status",
        help="Inspect the state of a running USMD node",
        description="Connect to a running node's control interface and print its status.",
    )
    status.add_argument(
        "--socket",
        default=None,
        metavar="PATH",
        help=(
            "Path to the Unix control socket (Linux/macOS). "
            "Default: read from config, or usmd.sock"
        ),
    )
    status.add_argument(
        "--port",
        default=None,
        type=int,
        metavar="PORT",
        help=(
            "TCP loopback port of the CTL server (Windows). "
            "Default: read from config (ctl_port: 5627)"
        ),
    )
    status.add_argument(
        "--config",
        default="usmd.yaml",
        metavar="PATH",
        help="Config file to read ctl_socket / ctl_port from (default: usmd.yaml)",
    )
    status.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output raw JSON instead of formatted text",
    )

    return parser


# ---------------------------------------------------------------------------
# Status command
# ---------------------------------------------------------------------------


def _run_status(args: argparse.Namespace) -> None:
    """Connect to the CTL server of a running daemon and print its status."""
    cfg = NodeConfig.from_file(args.config)

    # Resolve socket path (Linux/macOS) and CTL port (Windows)
    socket_path: str = args.socket or cfg.ctl_socket
    ctl_port: int = args.port if args.port is not None else cfg.ctl_port

    data = asyncio.run(get_status(socket_path, ctl_port))

    if args.as_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print_status(data)


# ---------------------------------------------------------------------------
# Daemon command (default)
# ---------------------------------------------------------------------------


def _run_daemon(args: argparse.Namespace) -> None:
    """Start the USMD node daemon."""
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    cfg = NodeConfig.from_file(args.config)

    # CLI overrides (only if explicitly given)
    if args.bootstrap is not None:
        cfg.bootstrap = args.bootstrap
    if args.role is not None:
        cfg.role = args.role
    if args.address is not None:
        cfg.address = args.address

    daemon = NodeDaemon.from_config(cfg)

    if sys.platform == "win32":
        _run_daemon_windows(daemon)
    else:
        _run_daemon_unix(daemon)


def _run_daemon_unix(daemon: "NodeDaemon") -> None:
    """Run the daemon on Linux/macOS with proper Ctrl+C and SIGTERM support.

    Uses ``loop.add_signal_handler()`` (Unix-only) to intercept SIGINT and
    SIGTERM before any third-party library (e.g. uvicorn) can steal them.
    The main asyncio task is cancelled gracefully, which lets the ``finally``
    block in NodeDaemon.run() close all sub-tasks cleanly.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    main_task = loop.create_task(daemon.run())

    def _request_stop() -> None:
        logging.info("[\x1b[38;5;51mUSMD\x1b[0m] Arrêt demandé (signal)…")
        main_task.cancel()

    loop.add_signal_handler(signal.SIGINT, _request_stop)
    loop.add_signal_handler(signal.SIGTERM, _request_stop)

    try:
        loop.run_until_complete(main_task)
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logging.critical("[\x1b[38;5;51mUSMD\x1b[0m] Fatal error: %s", exc)
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


def _run_daemon_windows(daemon: "NodeDaemon") -> None:
    """Run the daemon on Windows with proper Ctrl+C support.

    ``new_event_loop()`` sur Windows instancie souvent un Proactor qui bloque
    longtemps en I/O native et retarde ``KeyboardInterrupt``.  On force un
    :class:`asyncio.SelectorEventLoop` (comme dans ``main()`` pour NNDP/UDP).

    Un réveil périodique (250 ms) laisse aussi l'interpréteur traiter Ctrl+C.
    """
    loop = asyncio.SelectorEventLoop()
    asyncio.set_event_loop(loop)

    def _wakeup() -> None:
        """Reschedule itself every 250 ms so signals can be delivered."""
        loop.call_later(0.25, _wakeup)

    loop.call_soon(_wakeup)
    main_task = loop.create_task(daemon.run())

    # Handler explicite : même avec uvicorn corrigé, certaines consoles Windows
    # ne livrent pas KeyboardInterrupt pendant ``run_until_complete``.
    def _win_sigint(_signum: int, _frame: object | None) -> None:
        logging.info("[\x1b[38;5;51mUSMD\x1b[0m] Arrêt demandé (Ctrl+C)…")
        if not main_task.done():
            loop.call_soon_threadsafe(main_task.cancel)

    prev_sigint = signal.signal(signal.SIGINT, _win_sigint)

    try:
        loop.run_until_complete(main_task)
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        logging.info("[\x1b[38;5;51mUSMD\x1b[0m] Arrêt demandé (Ctrl+C)…")
        if not main_task.done():
            main_task.cancel()
        try:
            loop.run_until_complete(main_task)
        except asyncio.CancelledError:
            pass
    except Exception as exc:  # pylint: disable=broad-except
        logging.critical("[\x1b[38;5;51mUSMD\x1b[0m] Fatal error: %s", exc)
    finally:
        try:
            signal.signal(signal.SIGINT, prev_sigint)
        except (OSError, ValueError):
            pass
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Dispatch to daemon or status command."""
    # On Windows, the default ProactorEventLoop does not support UDP
    # (required by the NNDP service).  Switch to SelectorEventLoop instead.
    if sys.platform == "win32":
        asyncio.set_event_loop(asyncio.SelectorEventLoop())

    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "status":
        _run_status(args)
    else:
        _run_daemon(args)


if __name__ == "__main__":
    main()
