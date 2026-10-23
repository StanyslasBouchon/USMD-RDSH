"""Balance VIPs: one address for a whole service (extension, not in the drafts).

A service whose file declares ``balance: {vip, port, vlan, mode}`` (with
``expose``) is reached by clients outside USMD at *vip*:*port*. The USD
master elects, in its Raft log, one node hosting the service to hold the VIP
(``BALANCE_OWNER`` records, announced with Send_balance to the nodes without
the log); it keeps the owner while that node is Active and hosts the service,
and elects another as soon as it is not.

The owner, and only it:

- puts the VIP on its physical interface (``system service-host
  balance-interface``, by default the one holding the node's address), or on
  that interface's VLAN sub-interface ``<interface>.<vlan>``, created if needed;
- announces it with gratuitous ARP, so that the switch and the clients move
  to it at once after a failover;
- spreads the new connections over the instances that take clients (Active,
  hosting, probe passing: asked with Balance_status) in turn, in the kernel:
  nftables table ``ip usmd_balance``, DNAT to each instance's exposed port
  (60000 + id; its own instance directly), with address substitution (SNAT,
  masquerade) so that the answers come back through it.

The instance sees the owner's address, not the client's (substitution); the
direct-return mode, which keeps it, comes later. Linux only, with ``ip``,
``nft``, CAP_NET_ADMIN and CAP_NET_RAW (scripts/install.sh gives both).
"""

from __future__ import annotations

import logging
import shutil
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

log = logging.getLogger("usmd_rdsh.balance")

TABLE = "usmd_balance"
#: Before the exposure table (-100): a public port equal to 60000 + id still
#: reaches the balance, not the owner's own instance.
PRIORITY = -101
IFNAMSIZ = 15

#: Balance_status answers (NCP 0x0018).
NOT_HOSTED, NO_CLIENTS, TAKES_CLIENTS = 0, 1, 2


@dataclass(frozen=True, slots=True)
class Plan:  # pylint: disable=too-many-instance-attributes
    """One VIP this node holds, and where its connections go."""

    service: str
    vip: str  # address/prefix
    interface: str  # the physical (parent) interface
    vlan: int
    port: int  # public port on the VIP
    protocol: str
    backends: tuple[tuple[str, int], ...] = ()  # (address, port), in turn
    local: str = ""  # address of the owner's own instance (its SP VIP)

    @property
    def address(self) -> str:
        return self.vip.partition("/")[0]

    @property
    def forwards(self) -> bool:
        """Connections leave for other nodes: the interface must forward."""
        return any(a != self.local for a, _ in self.backends)

    @property
    def device(self) -> str:
        return f"{self.interface}.{self.vlan}" if self.vlan else self.interface

    def dnat(self) -> str:
        """The rule spreading new connections, "" while no instance takes clients."""
        if not self.backends:
            return ""
        targets = ", ".join(f"{i} : {a} . {p}" for i, (a, p) in enumerate(self.backends))
        return (f"ip daddr {self.address} {self.protocol} dport {self.port} dnat ip to "
                f"numgen inc mod {len(self.backends)} map {{ {targets} }}")


def ruleset(plans: list[Plan]) -> str:
    """The ``nft -f`` text that replaces the table at once (none: removes it)."""
    lines = [f"table ip {TABLE}", f"delete table ip {TABLE}"]
    rules = [(p, p.dnat()) for p in sorted(plans, key=lambda p: p.address)]
    rules = [(p, r) for p, r in rules if r]
    if rules:
        body = [f"\t\t{rule} comment \"{plan.service}\"" for plan, rule in rules]
        lines += [f"table ip {TABLE} {{",
                  "\tchain prerouting {",
                  f"\t\ttype nat hook prerouting priority {PRIORITY}; policy accept;",
                  *body,
                  "\t}",
                  "\tchain output {",  # connections opened on the owner itself
                  f"\t\ttype nat hook output priority {PRIORITY}; policy accept;",
                  *body,
                  "\t}",
                  # Address substitution: the instance answers the owner.
                  "\tchain postrouting {",
                  "\t\ttype nat hook postrouting priority 100; policy accept;",
                  *[f"\t\tct original ip daddr {plan.address} masquerade "
                    f"comment \"{plan.service}\"" for plan, _ in rules],
                  "\t}",
                  "}"]
    return "\n".join(lines) + "\n"


def _run(argv: list[str], text: str | None = None) -> str:
    """Run a command; its error text, or "" when it succeeded."""
    try:
        done = subprocess.run(argv, input=text, capture_output=True, text=True, check=False,
                              timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)
    return "" if done.returncode == 0 else (done.stderr or done.stdout).strip() or \
        f"{argv[0]} exited with {done.returncode}"


def gratuitous_arp(device: str, address: str, count: int = 3) -> str:
    """Announce *address* on *device* (ARP request for itself, broadcast)."""
    try:
        mac = bytes.fromhex(Path(f"/sys/class/net/{device}/address").read_text(
            encoding="ascii").strip().replace(":", ""))
        ip = socket.inet_aton(address)
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac + ip + bytes(6) + ip
        frame = (b"\xff" * 6 + mac + b"\x08\x06" + arp).ljust(60, b"\x00")
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as raw:  # type: ignore[attr-defined]
            raw.bind((device, 0))
            for _ in range(count):
                raw.send(frame)
    except (OSError, ValueError, AttributeError) as exc:
        return f"gratuitous ARP on {device}: {exc}"
    return ""


def default_interface(address: str) -> str:
    """The interface holding *address*, "" when none does."""
    try:
        done = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True,
                              check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) > 3 and parts[3].partition("/")[0] == address:
            return parts[1].partition("@")[0]
    return ""


@dataclass
class System:
    """What the balance changes on the host; replaced in the tests."""

    run: Callable[[list[str], str | None], str] = _run
    arp: Callable[[str, str], str] = gratuitous_arp
    read: Callable[[str], str] = lambda path: Path(path).read_text(encoding="ascii").strip()
    write: Callable[[str, str], None] = lambda path, value: Path(path).write_text(
        value + "\n", encoding="ascii")


@dataclass
class _Held:
    plan: Plan
    created_link: bool = False


@dataclass
class BalanceHost:
    """The VIPs this node holds, and whether the kernel does what they say."""

    system: System | None = None
    available: bool = field(default=False)
    plans: list[Plan] = field(default_factory=list)
    error: str = ""
    _held: dict[str, _Held] = field(default_factory=dict)  # VIP address -> held
    _forwarding: dict[str, str] = field(default_factory=dict)  # device -> value before
    _applied: str | None = None
    #: Called with :meth:`held` when it changed, to find them again after a crash.
    on_change: Callable[[list[dict]], None] | None = None

    def __post_init__(self) -> None:
        if self.system is None:
            self.system = System()
            self.available = sys.platform.startswith("linux") and \
                shutil.which("ip") is not None and shutil.which("nft") is not None
        else:
            self.available = True

    def update(self, plans: list[Plan]) -> None:
        """Hold exactly *plans*: VIPs added or removed, the table replaced."""
        self.plans = sorted(plans, key=lambda p: p.address)
        if not plans and not self._held and self._applied is None:
            return  # nothing held, nothing ever applied: the host is left alone
        if not self.available:
            if plans and not self.error:
                self.error = "ip or nft is not available: no balance VIP is held"
                log.error("[BALANCE] %s", self.error)
            return
        errors: list[str] = []
        before = self.held()
        wanted = {p.address: p for p in self.plans}
        for address in [a for a in self._held if a not in wanted or
                        self._held[a].plan.device != wanted[a].device or
                        self._held[a].plan.vip != wanted[a].vip]:
            errors += self._release(self._held.pop(address))
        for address, plan in wanted.items():
            if address in self._held:
                self._held[address].plan = plan
                continue
            held, problems = self._take(plan)
            errors += problems
            if held is not None:
                self._held[address] = held
        errors += self._forward({p.device for p in self.plans if p.forwards})
        text = ruleset([h.plan for h in self._held.values()])
        if text != self._applied:
            problem = self.system.run(["nft", "-f", "-"], text)
            if problem:
                errors.append(f"nftables refused the rules: {problem}")
            else:
                self._applied = text
                for held in self._held.values():
                    plan = held.plan
                    log.info("[BALANCE] %s at %s:%d/%s -> %s", plan.service, plan.address,
                             plan.port, plan.protocol,
                             ", ".join(f"{a}:{p}" for a, p in plan.backends) or "no instance")
        error = "; ".join(errors)
        if error and error != self.error:
            log.error("[BALANCE] %s", error)
        self.error = error
        if self.on_change is not None and self.held() != before:
            self.on_change(self.held())

    def held(self) -> list[dict]:
        """The VIPs on the interfaces now, as saved in the state directory."""
        return [{"vip": h.plan.vip, "interface": h.plan.interface, "vlan": h.plan.vlan,
                 "created_link": h.created_link}
                for _, h in sorted(self._held.items())]

    def adopt(self, saved: list[dict]) -> None:
        """VIPs a previous run left (it ended without releasing them): the next
        :meth:`update` keeps those still wanted and releases the others."""
        for item in saved:
            try:
                plan = Plan("(previous run)", str(item["vip"]), str(item["interface"]),
                            int(item.get("vlan", 0)), 0, "tcp")
            except (KeyError, TypeError, ValueError):
                continue
            self._held.setdefault(plan.address, _Held(plan, bool(item.get("created_link"))))

    def _take(self, plan: Plan) -> tuple[_Held | None, list[str]]:
        system = self.system
        held = _Held(plan)
        if plan.vlan:
            if len(plan.device) > IFNAMSIZ:
                return None, [f"{plan.device}: an interface name has at most {IFNAMSIZ} "
                              "characters"]
            problem = system.run(["ip", "link", "add", "link", plan.interface, "name",
                                  plan.device, "type", "vlan", "id", str(plan.vlan)], None)
            if problem and "exists" not in problem:
                return None, [f"VLAN {plan.vlan} on {plan.interface}: {problem}"]
            held.created_link = not problem
            problem = system.run(["ip", "link", "set", plan.device, "up"], None)
            if problem:
                return None, self._release(held) + [f"{plan.device} up: {problem}"]
        problem = system.run(["ip", "addr", "add", plan.vip, "dev", plan.device], None)
        if problem and "exists" not in problem:
            return None, self._release(held) + [f"VIP {plan.vip} on {plan.device}: {problem}"]
        log.warning("[BALANCE] %s: VIP %s held on %s", plan.service, plan.vip, plan.device)
        problem = system.arp(plan.device, plan.address)
        return held, [problem] if problem else []

    def _release(self, held: _Held) -> list[str]:
        system, plan = self.system, held.plan
        errors = []
        problem = system.run(["ip", "addr", "del", plan.vip, "dev", plan.device], None)
        if problem and "Cannot assign" not in problem and "not exist" not in problem:
            errors.append(f"VIP {plan.vip} off {plan.device}: {problem}")
        else:
            log.warning("[BALANCE] %s: VIP %s released from %s", plan.service, plan.vip,
                        plan.device)
        if held.created_link:
            problem = system.run(["ip", "link", "del", plan.device], None)
            if problem:
                errors.append(f"{plan.device}: {problem}")
        return errors

    def _forward(self, devices: set[str]) -> list[str]:
        """Forwarding on the VIP's interface while connections leave for other nodes;
        its previous value back when no longer needed."""
        errors = []
        for device in sorted(set(self._forwarding) - devices):
            try:
                self.system.write(_knob(device), self._forwarding.pop(device))
            except OSError:
                pass  # the VLAN sub-interface is gone with its knob
        for device in sorted(devices - set(self._forwarding)):
            try:
                before = self.system.read(_knob(device))
                if before != "1":
                    self.system.write(_knob(device), "1")
                self._forwarding[device] = before
            except OSError as exc:
                errors.append(f"forwarding on {device}: {exc}")
        return errors

    def stop(self) -> None:
        """Release every VIP and remove the table (the node stops)."""
        if self._held or self._applied:
            self.update([])


def _knob(device: str) -> str:
    return f"/proc/sys/net/ipv4/conf/{device}/forwarding"
