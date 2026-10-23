"""Services reached from outside USMD (extension, not in the drafts).

A service whose file declares ``expose: {port, protocol, allow}`` is reached
on every node hosting it at **60000 + its service id** (``0d1`` -> 60209),
on the node's own addresses: the kernel redirects that port to the local
instance (its VIP, the declared port). Clients that do not speak SP - an
application, a member of the service's own cluster - use it as any port.

The redirection lives in one nftables table of the node, ``ip usmd``,
replaced as a whole each time the hosted services change: a service that is
withdrawn (unbuilt, failed check_health) leaves no rule behind, and the port
then refuses connections. The client's address is kept (DNAT, no SNAT), so
the instance sees who connects; ``allow`` restricts the sources.

Linux only, with ``nft`` and CAP_NET_ADMIN (the usmd service has both, see
scripts/install.sh, which also reserves 60001-64094 so that no outgoing
connection takes one of these ports as its source port).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger("usmd_rdsh.exposure")

BASE_PORT = 60000
TABLE = "usmd"


def public_port(service_id: int) -> int:
    """The port a service is reached at from outside USMD: 60000 + its id."""
    return BASE_PORT + service_id


@dataclass(frozen=True, slots=True)
class Rule:
    """One hosted service's port, redirected to its local instance."""

    service: str
    port: int  # 60000 + service id
    protocol: str  # tcp | udp
    target: str  # the instance's address on this node (the service's VIP)
    target_port: int
    allow: tuple[str, ...] = ()

    def nft(self) -> str:
        """The rule, for the node's own addresses only (fib daddr type local)."""
        sources = f" ip saddr {{ {', '.join(self.allow)} }}" if self.allow else ""
        return (f"fib daddr type local {self.protocol} dport {self.port}{sources} "
                f"dnat to {self.target}:{self.target_port}")


def ruleset(rules: list[Rule]) -> str:
    """The ``nft -f`` text that replaces the table at once (none: removes it)."""
    lines = [f"table ip {TABLE}", f"delete table ip {TABLE}"]
    if rules:
        body = [f"\t\t{rule.nft()} comment \"{rule.service}\"" for rule in sorted(
            rules, key=lambda r: r.port)]
        lines += [f"table ip {TABLE} {{",
                  "\tchain prerouting {",
                  "\t\ttype nat hook prerouting priority -100; policy accept;",
                  *body,
                  "\t}",
                  # Connections opened on the node itself, to its own address.
                  "\tchain output {",
                  "\t\ttype nat hook output priority -100; policy accept;",
                  *body,
                  "\t}",
                  "}"]
    return "\n".join(lines) + "\n"


def _nft(text: str) -> str:
    """Run ``nft -f -``; the error text, or "" when it applied."""
    try:
        done = subprocess.run(["nft", "-f", "-"], input=text, capture_output=True, text=True,
                              check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)
    return "" if done.returncode == 0 else (done.stderr or done.stdout).strip()


class ExposureTable:
    """What this node exposes, and whether the kernel holds it."""

    def __init__(self, apply: Callable[[str], str] | None = None) -> None:
        self._apply = apply or _nft
        self.rules: list[Rule] = []
        self.error = ""
        self._applied: list[Rule] | None = None
        self.available = apply is not None or (sys.platform.startswith("linux")
                                               and shutil.which("nft") is not None)

    def update(self, rules: list[Rule]) -> None:
        """Make the kernel hold exactly *rules* (nothing to do if it already does)."""
        rules = sorted(rules, key=lambda r: r.port)
        self.rules = rules
        if rules == self._applied:
            return
        if not self.available:
            if rules and not self.error:
                self.error = "nft is not available: no service is exposed outside USMD"
                log.error("[EXPOSE] %s", self.error)
            return
        error = self._apply(ruleset(rules))
        if error:
            if error != self.error:
                log.error("[EXPOSE] nftables refused the rules: %s", error)
            self.error = error
            return
        self.error = ""
        self._applied = rules
        for rule in rules:
            log.info("[EXPOSE] %s on port %d/%s -> %s:%d", rule.service, rule.port,
                     rule.protocol, rule.target, rule.target_port)
