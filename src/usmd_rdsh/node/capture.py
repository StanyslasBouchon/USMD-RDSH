"""Live capture of the protocol frames a node sends and receives.

Every NNDP datagram, every NCP message (reassembled and decrypted) and every
SP frame is recorded the way Wireshark shows a packet: a summary line, a tree
of named fields, and the bytes, in a bounded ring read by ``show capture`` and
by the Capture tab of the web interface. The dissectors live in
:mod:`usmd_rdsh.node.dissect`; this module holds the ring and the filters.

Display filters take Wireshark's syntax over the field names of the tree::

    nndp && ip.src == 127.0.0.2
    ncp.command == GET_STATUS || ncp.type == ERROR
    sp && !sp.keepalive
    frame.status != ok
    ip.addr == 127.0.0.0/8 and frame.len > 200
    nndp.node_id contains "01JAB"
    "01JAB"                       any field showing this text

Example:
    >>> capture = PacketCapture(capacity=10)
    >>> d = Dissection()
    >>> capture.record("NNDP", "in", "10.0.0.2:5221", "10.0.0.1:5222", b"x", "HIA", d).number
    1
    >>> flt = compile_filter("frame.protocol == nndp && udp.dstport == 5222")
    >>> [p.number for p in capture.packets(flt=flt)]
    [1]
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

#: Every field a filter may name, with its label: the base fields below, and
#: what :mod:`usmd_rdsh.node.dissect` registers [the ``hf_`` table of Wireshark].
FIELDS: dict[str, str] = {
    "frame": "Frame",
    "frame.number": "Frame number",
    "frame.time": "Arrival time",
    "frame.len": "Frame length",
    "frame.dir": "Direction (in, out)",
    "frame.status": "Status (ok, dropped, malformed, retransmission)",
    "frame.reason": "Why the frame was dropped",
    "frame.protocol": "Protocol",
    "ip.src": "Source address",
    "ip.dst": "Destination address",
    "ip.addr": "Source or destination address",
    "udp": "User Datagram Protocol",
    "udp.srcport": "Source port",
    "udp.dstport": "Destination port",
    "udp.port": "Source or destination port",
}


def register(fields: dict[str, str]) -> None:
    """Declare fields a dissector adds."""
    FIELDS.update(fields)


# ---------------------------------------------------------------------------
# Dissection tree
# ---------------------------------------------------------------------------


def show(value: Any) -> str:
    """How a raw value reads in the tree."""
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value).hex()
        return text if len(text) <= 64 else text[:64] + "…"
    return "" if value is None else str(value)


class Item:
    """One line of the tree; ``add`` hangs a line under it."""

    __slots__ = ("_dissection", "node", "_buffer")

    def __init__(self, dissection: "Dissection", node: dict, buffer: int) -> None:
        self._dissection = dissection
        self.node = node
        self._buffer = buffer

    def add(  # pylint: disable=too-many-arguments
        self,
        name: str,
        label: str | None = None,
        value: Any = None,
        shown: str | None = None,
        *,
        alias: str | None = None,
        at: int | None = None,
        size: int | None = None,
        buffer: int | None = None,
    ) -> "Item":
        """A field: *value* is what filters compare, *shown* what the tree prints.

        *alias* is a symbolic name a filter may use instead of the number
        (``GET_STATUS`` for 0x0001); *at*/*size* locate the field in the bytes
        of buffer *buffer* (the parent's by default), to highlight them.
        """
        if name not in FIELDS:
            raise KeyError(f"field '{name}' is not registered")
        buf = self._buffer if buffer is None else buffer
        text = show(value) if shown is None else shown
        node: dict[str, Any] = {"f": name, "l": label or FIELDS[name], "v": text, "c": []}
        if at is not None and size:
            node.update(o=at, n=size, b=buf)
        self.node["c"].append(node)
        self._dissection.fields.setdefault(name, []).append((value, text, alias))
        return Item(self._dissection, node, buf)

    def text(self, label: str, *, at: int | None = None, size: int | None = None) -> "Item":
        """A line with no field behind it (an expert note, a list header)."""
        node: dict[str, Any] = {"f": "", "l": label, "v": "", "c": []}
        if at is not None and size:
            node.update(o=at, n=size, b=self._buffer)
        self.node["c"].append(node)
        return Item(self._dissection, node, self._buffer)


class Dissection:
    """A packet decoded: its tree, its fields by name and its byte buffers."""

    def __init__(self) -> None:
        self.tree: list[dict] = []
        self.fields: dict[str, list[tuple[Any, str, str | None]]] = {}
        self.buffers: list[tuple[str, bytes]] = []
        self.root = Item(self, {"c": self.tree}, 0)

    def buffer(self, name: str, data: bytes) -> int:
        """Add a byte view (the decrypted plaintext...); its index, the frame being 0."""
        self.buffers.append((name, bytes(data)))
        return len(self.buffers)


# ---------------------------------------------------------------------------
# Packets and the ring
# ---------------------------------------------------------------------------


def _split(endpoint: str) -> tuple[str, int | None]:
    host, sep, port = endpoint.rpartition(":")
    if not sep or not port.isdigit():
        return endpoint, None
    return host, int(port)


@dataclass(slots=True)
class Packet:  # pylint: disable=too-many-instance-attributes
    """One captured frame."""

    number: int
    time: float
    protocol: str
    direction: str  # "in" or "out"
    source: str
    destination: str
    length: int
    info: str
    status: str
    reason: str
    tree: list[dict]
    fields: dict[str, list[tuple[Any, str, str | None]]]
    buffers: list[tuple[str, bytes]] = field(default_factory=list)

    def row(self) -> dict[str, Any]:
        """The line of the packet list."""
        return {
            "number": self.number,
            "time": round(self.time, 6),
            "protocol": self.protocol,
            "direction": self.direction,
            "source": self.source,
            "destination": self.destination,
            "length": self.length,
            "info": self.info,
            "status": self.status,
            "reason": self.reason,
        }

    def detail(self) -> dict[str, Any]:
        """Everything: the line, the tree and the bytes (hex)."""
        return {
            **self.row(),
            "tree": self.tree,
            "buffers": [{"name": name, "hex": data.hex()} for name, data in self.buffers],
        }

    def matches(self, text: str) -> bool:
        """Whether any field shows *text* (case-insensitive)."""
        needle = text.lower()
        return needle in self.info.lower() or any(
            needle in shown.lower() or (alias and needle in alias.lower())
            for values in self.fields.values() for _, shown, alias in values)


class PacketCapture:  # pylint: disable=too-many-instance-attributes
    """The bounded ring of captured frames, and who waits for new ones."""

    PROTOCOLS = ("NNDP", "NCP", "SP")

    def __init__(self, capacity: int = 5000, snaplen: int = 4096) -> None:
        self._lock = threading.Lock()
        self._packets: deque[Packet] = deque(maxlen=capacity)
        self._number = 0
        self._waiters: set[asyncio.Future] = set()
        self.enabled = True
        self.protocols: set[str] = set(self.PROTOCOLS)
        self.snaplen = snaplen
        self.counts: Counter = Counter()
        self.started = time.time()

    @property
    def capacity(self) -> int:
        return self._packets.maxlen or 0

    @property
    def last_number(self) -> int:
        return self._number

    def resize(self, capacity: int) -> None:
        with self._lock:
            self._packets = deque(self._packets, maxlen=max(16, int(capacity)))

    def wants(self, protocol: str) -> bool:
        """Whether frames of *protocol* are recorded; checked before dissecting."""
        return self.enabled and protocol in self.protocols

    def record(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        protocol: str,
        direction: str,
        source: str,
        destination: str,
        data: bytes,
        info: str,
        dissection: Dissection,
        *,
        status: str = "ok",
        reason: str = "",
        length: int | None = None,
    ) -> Packet | None:
        """Add one frame; *data* is the frame as it travels (first buffer)."""
        if not self.wants(protocol):
            return None
        stamp = time.time()
        size = len(data) if length is None else length
        with self._lock:
            self._number += 1
            number = self._number
        # The base layers, above what the dissector found, as Wireshark puts them.
        base = Dissection()
        frame = base.root.add("frame", f"Frame {number}", True,
                              f"{size} bytes, {'received' if direction == 'in' else 'sent'}")
        frame.add("frame.number", value=number)
        frame.add("frame.time", value=stamp,
                  shown=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stamp))
                  + f".{int(stamp * 1000) % 1000:03d}")
        frame.add("frame.len", value=size)
        frame.add("frame.dir", value=direction)
        frame.add("frame.protocol", value=protocol.lower(), shown=protocol)
        frame.add("frame.status", value=status)
        if reason:
            frame.add("frame.reason", value=reason)
        src_ip, src_port = _split(source)
        dst_ip, dst_port = _split(destination)
        frame.add("ip.src", value=src_ip)
        frame.add("ip.dst", value=dst_ip)
        base.fields.setdefault("ip.addr", []).extend(
            [(src_ip, src_ip, None), (dst_ip, dst_ip, None)])
        if src_port is not None and dst_port is not None:
            udp = base.root.add("udp", value=True,
                                shown=f"Src Port: {src_port}, Dst Port: {dst_port}")
            udp.add("udp.srcport", value=src_port)
            udp.add("udp.dstport", value=dst_port)
            base.fields.setdefault("udp.port", []).extend(
                [(src_port, str(src_port), None), (dst_port, str(dst_port), None)])
        fields = base.fields
        for name, values in dissection.fields.items():
            fields.setdefault(name, []).extend(values)
        buffers = [(name, raw[:self.snaplen]) for name, raw in
                   ([("Trame", data)] + dissection.buffers)]
        packet = Packet(number, stamp, protocol, direction, source, destination, size, info,
                        status, reason, base.tree + dissection.tree, fields, buffers)
        with self._lock:
            self._packets.append(packet)
            self.counts[protocol] += 1
            self.counts[status] += 1
            waiters, self._waiters = self._waiters, set()
        for waiter in waiters:
            # Frames may be recorded off the event loop (the SP interface reader).
            waiter.get_loop().call_soon_threadsafe(_wake, waiter)
        return packet

    def packets(self, *, since: int = 0, flt: "Filter | None" = None,
                last: int | None = None) -> list[Packet]:
        """Frames numbered above *since*, oldest first, matching *flt*."""
        with self._lock:
            held = [p for p in self._packets if p.number > since]
        if flt is not None:
            held = [p for p in held if flt(p)]
        return held[-last:] if last else held

    def get(self, number: int) -> Packet | None:
        with self._lock:
            return next((p for p in self._packets if p.number == number), None)

    def held(self) -> int:
        with self._lock:
            return len(self._packets)

    def clear(self) -> int:
        with self._lock:
            count = len(self._packets)
            self._packets.clear()
            self.counts.clear()
            self.started = time.time()
        return count

    async def wait(self, since: int, timeout: float) -> None:
        """Return once a frame numbered above *since* exists, or after *timeout*."""
        if self._number > since or timeout <= 0:
            return
        waiter = asyncio.get_running_loop().create_future()
        with self._lock:
            self._waiters.add(waiter)
        try:
            await asyncio.wait_for(waiter, timeout)
        except asyncio.TimeoutError:
            pass
        finally:
            with self._lock:
                self._waiters.discard(waiter)


def _wake(waiter: asyncio.Future) -> None:
    if not waiter.done():
        waiter.set_result(None)


#: The capture of this process; ``system capture`` configures it.
CAPTURE = PacketCapture()


# ---------------------------------------------------------------------------
# Display filters
# ---------------------------------------------------------------------------


class FilterError(ValueError):
    """A filter that does not parse; the message says where."""


Filter = Callable[[Packet], bool]

_TOKEN = re.compile(
    r'\s*(?:(?P<str>"(?:[^"\\]|\\.)*")|(?P<op>==|!=|>=|<=|&&|\|\||[()!<>~])'
    r"|(?P<word>[A-Za-z0-9_.:/\-]+))"
)
_WORD_OPS = {"eq": "==", "ne": "!=", "gt": ">", "lt": "<", "ge": ">=", "le": "<=",
             "contains": "contains", "matches": "~"}
_COMPARISONS = {"==", "!=", ">", "<", ">=", "<=", "contains", "~"}


def _tokens(text: str) -> list[tuple[str, str]]:
    out, at = [], 0
    text = text.rstrip()
    while at < len(text):
        match = _TOKEN.match(text, at)
        if not match or match.end() == at:
            raise FilterError(f"unexpected '{text[at:].strip()[:12]}' at {at + 1}")
        at = match.end()
        if match.group("str") is not None:
            raw = match.group("str")[1:-1]
            out.append(("str", re.sub(r"\\(.)", r"\1", raw)))
        elif match.group("op") is not None:
            out.append(("op", match.group("op")))
        else:
            word = match.group("word")
            lowered = word.lower()
            if lowered in ("and", "or", "not"):
                out.append(("op", {"and": "&&", "or": "||", "not": "!"}[lowered]))
            elif lowered in _WORD_OPS:
                out.append(("op", _WORD_OPS[lowered]))
            else:
                out.append(("word", word))
    return out


@dataclass(frozen=True, slots=True)
class _Literal:
    text: str
    number: float | None
    network: ipaddress.IPv4Network | None
    pattern: re.Pattern | None

    @classmethod
    def of(cls, text: str, operator: str) -> "_Literal":
        number = None
        lowered = text.lower()
        if lowered in ("true", "false"):
            number = 1.0 if lowered == "true" else 0.0
        else:
            try:
                number = float(int(text, 0)) if re.fullmatch(r"-?(0x[0-9a-f]+|\d+)", lowered) \
                    else float(text)
            except ValueError:
                number = None
        network = None
        if "/" in text:
            try:
                network = ipaddress.IPv4Network(text, strict=False)
            except ValueError as exc:
                raise FilterError(f"'{text}' is not a network") from exc
        pattern = None
        if operator == "~":
            try:
                pattern = re.compile(text, re.IGNORECASE)
            except re.error as exc:
                raise FilterError(f"bad regular expression: {exc}") from exc
        return cls(text, number, network, pattern)


def _equal(value: Any, shown: str, alias: str | None, lit: _Literal) -> bool:
    if lit.network is not None:
        try:
            return ipaddress.IPv4Address(str(value)) in lit.network
        except ValueError:
            return False
    if isinstance(value, (int, float)) and lit.number is not None:
        return float(value) == lit.number
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex() == lit.text.lower().replace(":", "")
    needle = lit.text.lower()
    return needle in (shown.lower(), str(value).lower(), (alias or "").lower())


def _compare(operator: str, value: Any, shown: str, alias: str | None, lit: _Literal) -> bool:
    if operator == "==":
        return _equal(value, shown, alias, lit)
    if operator == "contains":
        needle = lit.text.lower()
        if isinstance(value, (bytes, bytearray)):
            return needle.replace(":", "") in bytes(value).hex()
        return needle in shown.lower() or needle in (alias or "").lower()
    if operator == "~":
        assert lit.pattern is not None
        return bool(lit.pattern.search(shown) or (alias and lit.pattern.search(alias)))
    if isinstance(value, (int, float)) and not isinstance(value, bool) and lit.number is not None:
        left, right = float(value), lit.number
    else:
        left, right = shown.lower(), lit.text.lower()  # type: ignore[assignment]
    return {">": left > right, "<": left < right,  # type: ignore[operator]
            ">=": left >= right, "<=": left <= right}[operator]  # type: ignore[operator]


class _Parser:
    """Recursive descent: or -> and -> not -> primary."""

    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self._tokens = tokens
        self._at = 0

    def _peek(self) -> tuple[str, str] | None:
        return self._tokens[self._at] if self._at < len(self._tokens) else None

    def _take(self) -> tuple[str, str]:
        token = self._peek()
        if token is None:
            raise FilterError("the filter ends too early")
        self._at += 1
        return token

    def parse(self) -> Filter:
        result = self._or()
        if self._peek() is not None:
            raise FilterError(f"unexpected '{self._peek()[1]}'")  # type: ignore[index]
        return result

    def _or(self) -> Filter:
        parts = [self._and()]
        while self._peek() == ("op", "||"):
            self._take()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda p: any(f(p) for f in parts))

    def _and(self) -> Filter:
        parts = [self._not()]
        while self._peek() == ("op", "&&"):
            self._take()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda p: all(f(p) for f in parts))

    def _not(self) -> Filter:
        if self._peek() == ("op", "!"):
            self._take()
            inner = self._not()
            return lambda p: not inner(p)
        return self._primary()

    def _primary(self) -> Filter:
        kind, text = self._take()
        if (kind, text) == ("op", "("):
            inner = self._or()
            if self._take() != ("op", ")"):
                raise FilterError("missing ')'")
            return inner
        if kind == "str":
            return lambda p: p.matches(text)
        if kind != "word":
            raise FilterError(f"unexpected '{text}'")
        name = text.lower()
        if name not in FIELDS:
            close = [f for f in FIELDS if f.startswith(name.split(".")[0])][:4]
            hint = f" (known: {', '.join(close)}…)" if close else ""
            raise FilterError(f"unknown field '{text}'{hint}")
        nxt = self._peek()
        if nxt is None or nxt[0] != "op" or nxt[1] not in _COMPARISONS:
            # A bare field: present, and not a false flag.
            return lambda p: any(v is not False for v, _, _ in p.fields.get(name, ()))
        operator = self._take()[1]
        kind, value = self._take()
        if kind == "op":
            raise FilterError(f"a value is expected after '{operator}'")
        lit = _Literal.of(value, operator)
        if operator == "!=":
            return lambda p: not any(_equal(v, s, a, lit) for v, s, a in p.fields.get(name, ()))
        return lambda p: any(_compare(operator, v, s, a, lit) for v, s, a in p.fields.get(name, ()))


def compile_filter(text: str | None) -> Filter | None:
    """A predicate over packets, or None for an empty filter; FilterError if invalid."""
    if not text or not text.strip():
        return None
    return _Parser(_tokens(text)).parse()


def field_names() -> Iterable[tuple[str, str]]:
    """Every filterable field and its label, sorted."""
    return sorted(FIELDS.items())
