"""Entry point for USMD-RDSH.

Two modes of operation:

**Daemon** (default) — start or join a USD::

    python -m usmd [--config PATH] [--bootstrap] [--role ROLE] [--address IP]

**Status** — inspect a running daemon via its control socket::

    python -m usmd status [--socket PATH] [--json]

Examples::

    # Bootstrap the first node in a new USD
    python -m usmd --config usmd.yaml --bootstrap

    # Join an existing USD as a plain executor
    python -m usmd --config usmd.yaml

    # Inspect a running node (pretty output)
    python -m usmd status

    # Inspect and pipe to jq
    python -m usmd status --json | jq .node

    # Inspect with a custom socket path
    python -m usmd status --socket /run/usmd/usmd.sock

"""

import argparse
import asyncio
import json
import logging
import sys

from .config import NodeConfig
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
        description="Connect to a running node's control socket and print its status.",
    )
    status.add_argument(
        "--socket",
        default=None,
        metavar="PATH",
        help=(
            "Path to the Unix control socket "
            "(default: read from config, or usmd.sock)"
        ),
    )
    status.add_argument(
        "--config",
        default="usmd.yaml",
        metavar="PATH",
        help="Config file to read ctl_socket path from (default: usmd.yaml)",
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
    """Connect to the CTL socket of a running daemon and print its status."""
    from .ctl.client import get_status, print_status  # pylint: disable=import-outside-toplevel

    # Resolve socket path: CLI > config file > default
    socket_path: str
    if args.socket:
        socket_path = args.socket
    else:
        cfg = NodeConfig.from_file(args.config)
        socket_path = cfg.ctl_socket

    data = asyncio.run(get_status(socket_path))

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

    try:
        asyncio.run(daemon.run())
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # pylint: disable=broad-except
        logging.critical("[\x1b[38;5;51mUSMD\x1b[0m] Fatal error: %s", exc)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Dispatch to daemon or status command."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "status":
        _run_status(args)
    else:
        _run_daemon(args)


if __name__ == "__main__":
    main()
