"""Internal helpers for NodeDaemon — resource usage and key persistence.

This module is private to the USMD-RDSH daemon subsystem.  It provides
two module-level utility functions used by multiple daemon sub-modules:

- :func:`_get_resource_usage` — reads current CPU/RAM/Disk/Network metrics.
- :func:`_load_or_generate_keys` — loads or generates Ed25519/X25519 keys.

Constants:
    _KEYS_VERSION: JSON schema version for the keys file.
    _HEARTBEAT_INTERVAL: Seconds between heartbeat ticks.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time

from .mutation.transmutation import ResourceUsage
from .security.crypto import Ed25519Pair, X25519Pair

logger = logging.getLogger(__name__)

_KEYS_VERSION = 1
_HEARTBEAT_INTERVAL = 5.0  # seconds between resource checks


def _get_resource_usage() -> ResourceUsage:
    """Return current resource usage via psutil if available, else dummy 0s.

    Returns:
        ResourceUsage: CPU, RAM, disk, and network metrics (0–1 fractions).
    """
    try:
        import psutil

        ram = psutil.virtual_memory().percent / 100.0
        # cpu_percent(interval=None) returns 0.0 on the very first call
        # because it needs a previous baseline measurement.  Subsequent calls
        # (done every _HEARTBEAT_INTERVAL seconds) return real values.
        cpu = psutil.cpu_percent(interval=None) / 100.0
        _disk_root = "C:\\" if sys.platform == "win32" else "/"
        disk = psutil.disk_usage(_disk_root).percent / 100.0
        net_io = psutil.net_io_counters()
        # Approximate network usage as bytes_sent fraction of a 125 MB/s link
        net = min(1.0, (net_io.bytes_sent + net_io.bytes_recv) / (125_000_000 * 10))
        return ResourceUsage(
            ram_percent=ram,
            cpu_percent=cpu,
            disk_percent=disk,
            network_percent=net,
        )
    except ImportError:
        logger.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] psutil non installé — "
            "métriques ressources indisponibles. Exécutez : pip install psutil"
        )
        return ResourceUsage(
            ram_percent=0.0,
            cpu_percent=0.0,
            disk_percent=0.0,
            network_percent=0.0,
        )
    except Exception as exc:
        logger.debug("[\x1b[38;5;51mUSMD\x1b[0m] Erreur lecture ressources : %s", exc)
        return ResourceUsage(
            ram_percent=0.0,
            cpu_percent=0.0,
            disk_percent=0.0,
            network_percent=0.0,
        )


def _load_or_generate_keys(path: str) -> tuple[bytes, bytes, bytes, bytes, int]:
    """Load keys from JSON or generate fresh ones.

    Args:
        path: Filesystem path to the JSON keys file.

    Returns:
        tuple: ``(ed_priv, ed_pub, x_priv, x_pub, node_name)``.
    """
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            ed_priv = bytes.fromhex(data["ed25519_priv"])
            ed_pub  = bytes.fromhex(data["ed25519_pub"])
            x_priv  = bytes.fromhex(data["x25519_priv"])
            x_pub   = bytes.fromhex(data["x25519_pub"])
            node_name = int(data["node_name"])
            logger.info(
                "[\x1b[38;5;51mUSMD\x1b[0m] Keys loaded from %s (node_name=%d)",
                path,
                node_name,
            )
            return ed_priv, ed_pub, x_priv, x_pub, node_name
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] Keys file %s invalid (%s); "
                "generating new keys",
                path,
                exc,
            )

    ed_priv, ed_pub = Ed25519Pair.generate()
    x_priv, x_pub   = X25519Pair.generate()
    node_name        = int(time.time())

    data = {
        "version":      _KEYS_VERSION,
        "node_name":    node_name,
        "ed25519_priv": ed_priv.hex(),
        "ed25519_pub":  ed_pub.hex(),
        "x25519_priv":  x_priv.hex(),
        "x25519_pub":   x_pub.hex(),
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] New keys generated and saved to %s",
            path,
        )
    except OSError as exc:
        logger.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] Could not save keys to %s: %s",
            path,
            exc,
        )
    return ed_priv, ed_pub, x_priv, x_pub, node_name
