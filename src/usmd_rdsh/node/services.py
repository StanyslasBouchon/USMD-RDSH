"""Service files and their execution [ARCH-02 8].

A service file is a UTF-8 YAML stream, one document per service [8.3]::

    name: web            (required, unique in the USD)
    type: static         (static | dynamic, static by default)
    dependencies: [db]
    build / unbuild / emergency / check_health / update:   sequences

    files:               (extension) name -> base64 content, written to
                         $USMD_FILES_DIR before every sequence
    expose:              (extension) {port: 5432, protocol: tcp, allow: [prefixes]}
                         - the instance's port, reached from outside USMD on
                         every hosting node at 60000 + service id
    balance:             (extension) {vip: 192.168.1.50/24, port: 5432, vlan: 0,
                         mode: snat} - with expose: one node elected by the
                         master holds the VIP on its physical interface and
                         spreads the clients over the instances (node/balance.py)
    probe / peers_changed: (extension) sequences: whether the instance takes
                         clients now (exit 0), and what to do when the other
                         instances of the service changed ($USMD_PEERS)

A sequence is a list of steps; a step has either ``command`` (run by the
operating system) or ``action`` (the name of another sequence of the same
service, build or unbuild), and optionally ``timeout`` in seconds (300). A
command succeeds when it ends in time with exit code 0; the first failure
stops the sequence, which fails. Since ARCH-02 the VIP and group address live
in the catalogue: an ``sp`` key is accepted and ignored.

Commands run with the node's account, inside its sandbox. On a node installed
by ``scripts/install.sh``, a step changes the system through the root relay,
for the commands root listed in ``/etc/usmd-root/commands``::

    - command: sudo usmd-root apt-get install -y nginx
    - command: sudo usmd-root install -m 644 "$USMD_FILES_DIR/site.conf" /etc/nginx/conf.d/
    - command: sudo usmd-root systemctl restart nginx

Such a command runs outside the sandbox: it sees the system's /tmp, not the
node's private one, so files are passed from $USMD_FILES_DIR or $USMD_DATA_DIR.

Nothing is executed unless the authority's signature on the mutation
properties carrying the file has been checked [8.3] - the caller's duty,
enforced by :class:`ServiceRunner` refusing an unverified mutation.

Every command gets the instance's ``USMD_*`` variables (SP address, data
identifier prefix, VIP, data directory, files directory...); build, update and check_health
are refused without an SP address, and the sequences of one service never
overlap [ARCH-03 8.7].
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable

import yaml

log = logging.getLogger("usmd_rdsh.services")

SEQUENCES = ("build", "unbuild", "emergency", "check_health", "update",
             "probe", "peers_changed")
DEFAULT_TIMEOUT = 300
KNOWN_KEYS = {"name", "type", "dependencies", "sp", "files", "expose", "balance", *SEQUENCES}
PROTOCOLS = ("tcp", "udp")
BALANCE_MODES = ("snat",)  # dr (direct return) comes later
#: A file delivered with a service: a plain name, no directory, not hidden.
FILE_NAME = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$")
#: Every file of one service together, decoded; the mutation travels in one
#: NCP message (1024 fragments of 1111 bytes) with the base64 on top.
MAX_FILES_BYTES = 512 * 1024


class ServiceFileError(ValueError):
    """A service file that does not follow [ARCH 8.3]."""


# ---------------------------------------------------------------------------
# YAML 1.2 core schema [ARCH 8.3]
# ---------------------------------------------------------------------------

_CORE_TAGS = {"tag:yaml.org,2002:bool", "tag:yaml.org,2002:int", "tag:yaml.org,2002:float",
              "tag:yaml.org,2002:timestamp", "tag:yaml.org,2002:value"}


class Yaml12Loader(yaml.SafeLoader):  # pylint: disable=too-many-ancestors
    """A safe loader resolving plain scalars as the YAML 1.2 core schema does.

    PyYAML follows YAML 1.1, where ``yes``/``no``/``on``/``off`` are booleans,
    ``1:30`` is a sexagesimal integer, ``010`` is octal and ``2024-01-01`` a
    date. A service file is YAML 1.2 [ARCH 8.3]: only ``true``/``false`` (in
    the three spellings of the core schema) are booleans, octal is written
    ``0o...``, and everything else stays a string.
    """

    yaml_implicit_resolvers = {
        first: [(tag, regexp) for tag, regexp in resolvers if tag not in _CORE_TAGS]
        for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_core_int(self, node: yaml.ScalarNode) -> int:
        """Decimal, ``0o`` octal or ``0x`` hexadecimal [YAML 1.2 10.3.2]."""
        value = str(self.construct_scalar(node))
        sign = -1 if value.startswith("-") else 1
        digits = value.lstrip("+-")
        if digits.startswith("0o"):
            return sign * int(digits[2:], 8)
        if digits.startswith("0x"):
            return sign * int(digits[2:], 16)
        return sign * int(digits, 10)


Yaml12Loader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"))
Yaml12Loader.add_implicit_resolver(
    "tag:yaml.org,2002:int", re.compile(r"^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$"),
    list("-+0123456789"))
Yaml12Loader.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    re.compile(r"^(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?"
               r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"),
    list("-+.0123456789"))
Yaml12Loader.add_constructor("tag:yaml.org,2002:int", Yaml12Loader.construct_core_int)


def load_yaml_stream(text: str) -> list:
    """Every document of a YAML 1.2 stream (core schema), ``None`` ones included."""
    return list(yaml.load_all(text, Loader=Yaml12Loader))  # nosec B506 - safe loader


@dataclass(frozen=True, slots=True)
class Step:
    command: str | None
    action: str | None
    timeout: int


@dataclass(frozen=True, slots=True)
class Exposure:
    """The instance's port that clients outside USMD reach, at 60000 + service id
    on every hosting node, and the source prefixes allowed (empty: any)."""

    port: int
    protocol: str = "tcp"
    allow: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Balance:
    """The address clients outside USMD use for the whole service: *vip*
    (address/prefix) on the physical interface of one elected node, in VLAN
    *vlan* (0: none), port *port*, spread over the instances' exposed ports."""

    vip: str  # 192.168.1.50/24
    port: int
    vlan: int = 0
    mode: str = "snat"

    @property
    def address(self) -> str:
        return self.vip.partition("/")[0]


@dataclass(slots=True)
class ServiceSpec:  # pylint: disable=too-many-instance-attributes
    name: str
    type: str = "static"
    dependencies: list[str] = field(default_factory=list)
    sequences: dict[str, list[Step]] = field(default_factory=dict)
    files: dict[str, bytes] = field(default_factory=dict)
    expose: Exposure | None = None
    balance: Balance | None = None


def _parse_expose(value: object) -> Exposure | None:
    """``expose: {port: 5432, protocol: tcp, allow: [192.168.0.0/16]}``."""
    import ipaddress  # pylint: disable=import-outside-toplevel

    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"port", "protocol", "allow"}:
        raise ServiceFileError("'expose' has port, protocol (tcp or udp) and allow")
    port = value.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ServiceFileError("'expose: port' is the instance's port, 1 to 65535")
    protocol = value.get("protocol", "tcp")
    if protocol not in PROTOCOLS:
        raise ServiceFileError("'expose: protocol' is tcp or udp")
    allow = value.get("allow") or []
    if not isinstance(allow, list):
        raise ServiceFileError("'expose: allow' is a list of IPv4 prefixes")
    try:
        prefixes = tuple(str(ipaddress.IPv4Network(str(p), strict=False)) for p in allow)
    except ValueError as exc:
        raise ServiceFileError(f"'expose: allow': {exc}") from exc
    return Exposure(port, protocol, prefixes)


def _parse_balance(value: object, expose: Exposure | None) -> Balance | None:
    """``balance: {vip: 192.168.1.50/24, port: 5432, vlan: 0, mode: snat}``."""
    import ipaddress  # pylint: disable=import-outside-toplevel

    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"vip", "port", "vlan", "mode"}:
        raise ServiceFileError("'balance' has vip, port, vlan and mode")
    if expose is None:
        raise ServiceFileError("'balance' needs 'expose': the VIP spreads clients over "
                               "the exposed ports of the instances")
    try:
        interface = ipaddress.IPv4Interface(str(value.get("vip", "")))
    except ValueError as exc:
        raise ServiceFileError(f"'balance: vip' is an IPv4 address/prefix: {exc}") from exc
    broadcast = interface.network.prefixlen < 31 and \
        interface.ip == interface.network.broadcast_address
    if interface.ip.is_unspecified or interface.ip.is_multicast or interface.ip.is_loopback \
            or broadcast:
        raise ServiceFileError(f"'balance: vip' {interface.ip} cannot be held by an interface")
    port = value.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ServiceFileError("'balance: port' is the public port on the VIP, 1 to 65535")
    vlan = value.get("vlan", 0)
    if not isinstance(vlan, int) or isinstance(vlan, bool) or not 0 <= vlan <= 4094:
        raise ServiceFileError("'balance: vlan' is 0 (none) or a VLAN id, 1 to 4094")
    mode = value.get("mode", "snat")
    if mode == "dr":
        raise ServiceFileError("'balance: mode dr' (direct return) is not available yet: snat")
    if mode not in BALANCE_MODES:
        raise ServiceFileError("'balance: mode' is snat")
    return Balance(str(interface), port, vlan, mode)


def check_file_name(name: str) -> str:
    """ServiceFileError unless *name* can be a file of $USMD_FILES_DIR."""
    if not isinstance(name, str) or not FILE_NAME.match(name):
        raise ServiceFileError(f"'{name}' is not a file name (letters, digits, . _ -; "
                               "no directory, not hidden)")
    return name


def _parse_files(value: object) -> dict[str, bytes]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ServiceFileError("'files' maps file names to base64 contents")
    files = {}
    for name, content in value.items():
        check_file_name(name)
        try:
            files[name] = base64.b64decode(str(content), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ServiceFileError(f"file '{name}' is not valid base64") from exc
    if sum(len(c) for c in files.values()) > MAX_FILES_BYTES:
        raise ServiceFileError(f"the files of a service total at most {MAX_FILES_BYTES // 1024} KiB")
    return files


def parse_service_file(text: str | bytes) -> list[ServiceSpec]:
    """Every service of a YAML stream."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    try:
        documents = [d for d in load_yaml_stream(text) if d is not None]
    except yaml.YAMLError as exc:
        raise ServiceFileError(f"invalid YAML: {exc}") from exc
    services = []
    for document in documents:
        if not isinstance(document, dict):
            raise ServiceFileError("each document describes one service")
        unknown = set(document) - KNOWN_KEYS
        if unknown:
            raise ServiceFileError(f"unknown keys: {', '.join(sorted(unknown))}")
        name = document.get("name")
        if not isinstance(name, str) or not name:
            raise ServiceFileError("'name' is required")
        kind = document.get("type", "static")
        if kind not in ("static", "dynamic"):
            raise ServiceFileError("'type' is static or dynamic")
        dependencies = document.get("dependencies") or []
        if not isinstance(dependencies, list) or not all(isinstance(d, str) for d in dependencies):
            raise ServiceFileError("'dependencies' is a list of service names")
        sequences = {}
        for sequence in SEQUENCES:
            steps = document.get(sequence) or []
            if not isinstance(steps, list):
                raise ServiceFileError(f"'{sequence}' is a list of steps")
            parsed = []
            for step in steps:
                if not isinstance(step, dict) or ("command" in step) == ("action" in step):
                    raise ServiceFileError(f"a step of '{sequence}' has command or action")
                action = step.get("action")
                if action is not None and action not in ("build", "unbuild"):
                    raise ServiceFileError("an action names build or unbuild")
                timeout = int(step.get("timeout", DEFAULT_TIMEOUT))
                if timeout <= 0:
                    raise ServiceFileError("timeout is a positive number of seconds")
                parsed.append(Step(step.get("command"), action, timeout))
            sequences[sequence] = parsed
        expose = _parse_expose(document.get("expose"))
        services.append(ServiceSpec(name, kind, dependencies, sequences,
                                    _parse_files(document.get("files")), expose,
                                    _parse_balance(document.get("balance"), expose)))
    names = [s.name for s in services]
    if len(names) != len(set(names)):
        raise ServiceFileError("a service appears twice")
    vips = [s.balance.address for s in services if s.balance]
    if len(vips) != len(set(vips)):
        raise ServiceFileError("two services balance on the same VIP")
    return services


def write_files(directory: "os.PathLike[str] | str", files: dict[str, bytes]) -> None:
    """Make *directory* hold exactly the service's files.

    A file starting with ``#!`` is made executable, so a step can run it as
    ``"$USMD_FILES_DIR/script.sh"``; the others are only readable. Files the
    service no longer carries are removed.
    """
    os.makedirs(directory, mode=0o755, exist_ok=True)
    for stale in set(os.listdir(directory)) - set(files):
        path = os.path.join(directory, stale)
        if os.path.isfile(path):
            os.remove(path)
    for name, content in files.items():
        path = os.path.join(directory, check_file_name(name))
        try:
            with open(path, "rb") as held:
                unchanged = held.read() == content
        except OSError:
            unchanged = False
        if not unchanged:
            with open(path, "wb") as out:
                out.write(content)
        os.chmod(path, 0o755 if content.startswith(b"#!") else 0o644)


def dependency_order(services: list[ServiceSpec]) -> list[ServiceSpec]:
    """Dependencies first (only those inside the list); cycles are refused."""
    by_name = {s.name: s for s in services}
    ordered: list[ServiceSpec] = []
    state: dict[str, int] = {}

    def visit(name: str) -> None:
        if state.get(name) == 2:
            return
        if state.get(name) == 1:
            raise ServiceFileError(f"dependency cycle through '{name}'")
        state[name] = 1
        for dependency in by_name[name].dependencies:
            if dependency in by_name:
                visit(dependency)
        state[name] = 2
        ordered.append(by_name[name])

    for service in services:
        visit(service.name)
    return ordered


@dataclass(slots=True)
class RunResult:
    ok: bool
    log: list[str]
    duration: float


#: Sequences that need the instance's SP address [ARCH-03 8.7].
NEEDS_ADDRESS = ("build", "update", "check_health", "probe", "peers_changed")

#: (service, sequence) -> the USMD_* variables, or None without an SP address.
Environment = Callable[[ServiceSpec, str], "dict[str, str] | None"]


class ServiceRunner:
    """Runs sequences with the node's privileges, step by step."""

    def __init__(self, *, shell: bool = True, run_as: str | None = None,
                 environment: Environment | None = None) -> None:
        self.shell = shell
        #: Commands run with the least privileges needed [ARCH 14]: on POSIX,
        #: as this user instead of the node's own account.
        self.run_as = run_as
        self.environment = environment
        self.last: dict[tuple[str, str], RunResult] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def run(self, service: ServiceSpec, sequence: str) -> RunResult:
        """One sequence; two sequences of a service never overlap [ARCH-03 8.7]."""
        lock = self._locks.setdefault(service.name, asyncio.Lock())
        async with lock:
            started = time.monotonic()
            variables = self.environment(service, sequence) if self.environment else {}
            if variables is None:
                if sequence in NEEDS_ADDRESS:
                    result = RunResult(False, [f"no SP address for {service.name}: "
                                               f"{sequence} refused"], 0.0)
                    self.last[(service.name, sequence)] = result
                    log.error("[SERVICE] %s %s refused: no management id", service.name,
                              sequence)
                    return result
                variables = {}
            env = {**os.environ, **variables} if variables else None
            ok, lines = await self._sequence(service, sequence, env, depth=0)
            result = RunResult(ok, lines, time.monotonic() - started)
        self.last[(service.name, sequence)] = result
        log.log(logging.INFO if ok else logging.ERROR, "[SERVICE] %s %s %s in %.1fs",
                service.name, sequence, "succeeded" if ok else "failed", result.duration)
        return result

    async def _sequence(self, service: ServiceSpec, sequence: str, env: dict | None, *,
                        depth: int) -> tuple[bool, list[str]]:
        lines: list[str] = []
        ok = True
        if depth > 2:
            return False, ["action recursion too deep"]
        for step in service.sequences.get(sequence, []):
            if step.action:  # runs inside the calling sequence
                ok, inner = await self._sequence(service, step.action, env, depth=depth + 1)
                lines.extend(inner)
                if not ok:
                    break
                continue
            ok, output = await self._command(step.command or "", step.timeout, env)
            lines.append(f"$ {step.command} -> {'ok' if ok else 'FAILED'}")
            lines.extend(output)
            if not ok:
                break
        return ok, lines

    async def _command(self, command: str, timeout: int,
                       env: dict | None = None) -> tuple[bool, list[str]]:
        try:
            extra = {"user": self.run_as} if self.run_as and os.name != "nt" else {}
            process = await asyncio.create_subprocess_shell(
                command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                env=env, **extra,
            )
        except OSError as exc:
            return False, [str(exc)]
        try:
            output, _ = await asyncio.wait_for(process.communicate(), timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return False, [f"timed out after {timeout}s"]
        text = output.decode("utf-8", errors="replace").splitlines()[-20:]
        return process.returncode == 0, text
