"""Control socket client — queries a running USMD-RDSH node.

On **Linux / macOS** connects to the Unix-domain socket exposed by a running
NodeDaemon.  On **Windows** connects to the TCP loopback server instead.

Usage (from __main__.py):
    python -m usmd status [--socket PATH] [--port PORT] [--json]

Examples:
    >>> isinstance(_format_uptime(3661), str)
    True
    >>> _format_uptime(45)
    '45s'
    >>> _format_uptime(125)
    '2m 5s'
    >>> _format_uptime(7384)
    '2h 3m 4s'
"""

import asyncio
import datetime
import json
import sys
from typing import Any

from ..utils.io import close_writer


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

async def get_status(socket_path: str, ctl_port: int = 0) -> dict:
    """Connect to the daemon and return its status dict.

    On Linux/macOS *socket_path* is used (a Unix-domain socket).
    On Windows *ctl_port* is used (a TCP loopback connection to 127.0.0.1).

    Args:
        socket_path: Path to the Unix-domain CTL socket (Linux/macOS).
        ctl_port: TCP port of the CTL server (Windows).

    Returns:
        dict: Parsed status snapshot from the daemon.

    Raises:
        SystemExit: On connection failure.
    """
    if sys.platform == "win32":
        return await _get_status_tcp(ctl_port)
    return await _get_status_unix(socket_path)


async def _get_status_unix(socket_path: str) -> dict:
    """Connect via Unix-domain socket (Linux / macOS)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(socket_path),
            timeout=3.0,
        )
    except FileNotFoundError:
        print(
            f"Erreur : socket introuvable à {socket_path!r}.",
            file=sys.stderr,
        )
        print("Le daemon USMD est-il en cours d'exécution ?", file=sys.stderr)
        sys.exit(1)
    except (ConnectionRefusedError, PermissionError) as exc:
        print(f"Erreur de connexion : {exc}", file=sys.stderr)
        sys.exit(1)
    except asyncio.TimeoutError:
        print("Délai dépassé en se connectant au daemon.", file=sys.stderr)
        sys.exit(1)

    return await _exchange(reader, writer)


async def _get_status_tcp(ctl_port: int) -> dict:
    """Connect via TCP loopback (Windows)."""
    if ctl_port <= 0:
        print(
            "Erreur : ctl_port non configuré. "
            "Ajoutez 'ctl_port: 5627' à votre usmd.yaml.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", ctl_port),
            timeout=3.0,
        )
    except ConnectionRefusedError:
        print(
            f"Erreur : connexion refusée sur 127.0.0.1:{ctl_port}.",
            file=sys.stderr,
        )
        print("Le daemon USMD est-il en cours d'exécution ?", file=sys.stderr)
        sys.exit(1)
    except asyncio.TimeoutError:
        print("Délai dépassé en se connectant au daemon.", file=sys.stderr)
        sys.exit(1)

    return await _exchange(reader, writer)


async def _exchange(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> dict:
    """Send a status request and return the parsed response."""
    try:
        writer.write(b'{"cmd": "status"}\n')
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=5.0)
        return json.loads(line.decode().strip())
    except (asyncio.TimeoutError, json.JSONDecodeError) as exc:
        print(f"Erreur lors de la lecture de la réponse : {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        close_writer(writer)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _format_uptime(seconds: float) -> str:
    """Return a human-readable uptime string.

    Examples:
        >>> _format_uptime(0)
        '0s'
        >>> _format_uptime(3600)
        '1h 0m 0s'
    """
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {sec}s"
    if m:
        return f"{m}m {sec}s"
    return f"{sec}s"


def _format_expiry(ts: int) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _bar(value: float, width: int = 18) -> str:
    """Return a Unicode block progress bar for *value* ∈ [0, 1]."""
    filled = max(0, min(width, int(value * width)))
    return "█" * filled + "░" * (width - filled)


def _row(label: str, value: Any, indent: int = 2) -> None:
    pad = " " * indent
    print(f"{pad}{label:<22}{value}")


def _print_nrt(nrt: list, thin: str) -> None:
    count = len(nrt)
    print(f"\n  NRT  —  {count} entrée{'s' if count != 1 else ''} (distances vers les pairs)")
    if nrt:
        print(f"  {'Adresse':<18} {'Distance':>10} {'Ping':>9}  Mis à jour")
        print(f"  {thin[:54]}")
        for entry in nrt:
            stale = "  \033[33m[périmé]\033[0m" if entry.get("stale") else ""
            print(
                f"  {entry.get('address', '?'):<18} "
                f"{entry.get('distance', 0.0):>10.4f} "
                f"{entry.get('ping_ms', 0.0):>7.1f}ms  "
                f"{entry.get('updated_at_str', '?')}{stale}"
            )
    else:
        print("  (vide)")


def _print_nqt(promotions: list, thin: str) -> None:
    count = len(promotions)
    plural = "s" if count != 1 else ""
    print(f"\n  NQT  —  {count} promotion{plural} enregistrée{plural}")
    if promotions:
        print(f"  {thin[:54]}")
        for p in promotions:
            role = p.get("role_name", "?")
            role_col = (
                "\033[33m" if role == "node_operator" else
                "\033[36m" if role == "usd_operator"  else
                "\033[34m"
            )
            print(
                f"  #{p.get('epoch', '?'):<4} "
                f"{role_col}{role:<20}\033[0m "
                f"{p.get('address', '?'):<18}  "
                f"{p.get('promoted_at_str', '?')}"
            )
            print(f"       Clé : {p.get('pub_key', '?')}  —  {p.get('reason', '?')}")
    else:
        print("  (vide — aucun quorum élu)")


def _print_nrl(nrl: list) -> None:
    count = len(nrl)
    print(f"\n  NRL  —  {count} mandataire{'s' if count != 1 else ''} (nœuds qui nous référencent)")
    if nrl:
        for entry in nrl:
            print(
                f"  #{entry.get('name', '?'):<14} "
                f"{entry.get('address', '?'):<18}  "
                f"depuis {entry.get('declared_at_str', '?')}"
            )
    else:
        print("  (vide — aucun nœud ne nous référence)")


# ---------------------------------------------------------------------------
# Pretty-printer
# ---------------------------------------------------------------------------

def print_status(data: dict) -> None:
    """Pretty-print a status snapshot dict to stdout.

    Args:
        data: Status dict as returned by :func:`get_status`.
    """
    sep   = "═" * 56
    thin  = "─" * 56

    # ------------------------------------------------------------------ #
    # Header                                                              #
    # ------------------------------------------------------------------ #
    print(f"\n{sep}")
    print("  USMD-RDSH — État du nœud")
    print(sep)

    # ------------------------------------------------------------------ #
    # Node                                                                #
    # ------------------------------------------------------------------ #
    node = data.get("node", {})
    state = node.get("state", "—").upper()
    state_colour = (
        "\033[32m" if state == "ACTIVE" else
        "\033[31m" if "EXCLU" in state else
        "\033[33m"
    )
    print("\n  Nœud")
    _row("Nom (node_name)", node.get("name", "—"))
    _row("Adresse IP",      node.get("address", "—"))
    _row("État",            f"{state_colour}{state}\033[0m")
    _row("Rôle",            node.get("role", "—"))
    _row("Uptime",          _format_uptime(node.get("uptime_seconds", 0)))

    # ------------------------------------------------------------------ #
    # USD                                                                 #
    # ------------------------------------------------------------------ #
    usd = data.get("usd", {})
    print(f"\n  USD  —  {usd.get('name', '—')}")
    _row("Cluster",          usd.get("cluster_name") or "(aucun)")
    _row("EDB",              usd.get("edb_address") or "(aucun)")
    _row("Version config",   usd.get("config_version", 0))
    _row("Nœuds dans l'USD", usd.get("node_count", 0))

    # ------------------------------------------------------------------ #
    # NIT                                                                 #
    # ------------------------------------------------------------------ #
    nit = data.get("nit", [])
    count = len(nit)
    print(f"\n  NIT  —  {count} entrée{'s' if count != 1 else ''}")
    if nit:
        print(f"  {'Adresse':<18} {'Clé publique (tronquée)':<24} TTL")
        print(f"  {thin[:54]}")
        for entry in nit:
            ttl_str = f"{entry.get('ttl_remaining', 0)}s"
            flag = "  \033[31m[EXPIRÉ]\033[0m" if entry.get("expired") else ""
            print(
                f"  {entry.get('address', '?'):<18} "
                f"{entry.get('pub_key', '?'):<24} "
                f"{ttl_str}{flag}"
            )
    else:
        print("  (vide)")

    # ------------------------------------------------------------------ #
    # NAL                                                                 #
    # ------------------------------------------------------------------ #
    nal = data.get("nal", [])
    count = len(nal)
    print(f"\n  NAL  —  {count} entrée{'s' if count != 1 else ''}")
    if nal:
        for entry in nal:
            perm  = "  \033[36m[permanent]\033[0m" if entry.get("permanent") else ""
            roles = ", ".join(entry.get("roles", []))
            print(f"  {entry.get('pub_key', '?'):<26} {roles}{perm}")

    # ------------------------------------------------------------------ #
    # NEL                                                                 #
    # ------------------------------------------------------------------ #
    nel = data.get("nel", {})
    issued  = nel.get("issued", [])
    received = nel.get("received")
    print(f"\n  NEL  —  {len(issued)} endossement{'s' if len(issued) != 1 else ''} émis")
    if issued:
        for ep in issued:
            print(f"  → {ep.get('node_pub_key', '?')} (serial {ep.get('serial', '?')})")
    if received is None:
        print("  Endossement reçu : (aucun — nœud bootstrap ou en attente de réadhésion)")
    else:
        endorser = received.get("endorser_key", "?")
        print(f"  Endossement reçu : de {endorser}")
