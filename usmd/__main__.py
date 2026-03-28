"""Entry point for USMD-RDSH.

Run with::

    python -m usmd [options]

or, if installed::

    usmd [options]

Examples::

    # Bootstrap the first node in a new USD
    python -m usmd --config usmd.yaml --bootstrap

    # Join an existing USD as a plain executor
    python -m usmd --config usmd.yaml

    # Override role and address on the command line
    python -m usmd --role usd_operator --address 192.168.1.5

"""

import argparse
import asyncio
import logging
import sys

from .config import NodeConfig
from .node_daemon import NodeDaemon


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="usmd",
        description="USMD-RDSH node — Unified System Management and Deployment",
    )
    parser.add_argument(
        "--config",
        default="usmd.yaml",
        metavar="PATH",
        help="Path to YAML configuration file (default: usmd.yaml)",
    )
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        default=None,
        help="Bootstrap: create a new USD instead of joining an existing one",
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
    return parser.parse_args()


def main() -> None:
    """Parse arguments, load config, and run the node daemon."""
    args = _parse_args()

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


if __name__ == "__main__":
    main()
