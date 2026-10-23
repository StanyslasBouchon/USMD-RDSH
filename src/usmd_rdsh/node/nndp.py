"""NNDP: neighbour discovery [NNDP-01].

A node sends a signed Here I am (HIA) every I seconds, broadcast on its segment
and unicast to each of its reference nodes; every receiver checks it in the
order of section 6.2, records the sender, and merges its services vector into
the table of nearest services (section 6.5). There is no response message.

Datagram [5.2]::

    Ed25519 public key (32) | signature (64) | frame header (9) | HIA payload

the signature covering the whole frame (header and payload).
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Callable

from usmd_rdsh.node import addresses
from usmd_rdsh.node.capture import CAPTURE
from usmd_rdsh.node.crypto import SigningKey, is_valid
from usmd_rdsh.node.dissect import dissect_nndp
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import HEADER_SIZE, FrameHeader, Reader, WireError, Writer, frame, now_ms

log = logging.getLogger("usmd_rdsh.nndp")

EVENT_HIA = 0x0001
SOURCE_PORT = 5221
DESTINATION_PORT = 5222
BROADCAST = "255.255.255.255"
MIN_DATAGRAM = 105  # key + signature + frame header [6.2]
MAX_DATAGRAM = 1200
MAX_HOSTED = 32
MAX_VECTOR = 120
MAX_HOPS = 15
UNREACHABLE = 65535
MIN_INTERVAL_MS = 1_000
MAX_INTERVAL_MS = 3_600_000
TRIGGERED_SPACING = 1.0
MAX_PER_SENDER = 4 * MAX_VECTOR  # entries one neighbour may make us hold
RATE_PER_SOURCE = 20  # datagrams per second and source address before checks


@dataclass(frozen=True, slots=True)
class VectorEntry:
    """One services-vector entry [5.4]: 4 + 2 + 1 bytes."""

    address: int
    distance: int
    hops: int


@dataclass(slots=True)
class HereIAm:
    """The HIA payload [NNDP-01 5.4]."""

    node_id: str
    next_emission: int
    state: int
    timestamp: int
    x25519: bytes
    hosted: list[int] = field(default_factory=list)
    vector: list[VectorEntry] = field(default_factory=list)

    @property
    def interval_ms(self) -> int:
        """The announced interval I: next emission minus timestamp."""
        return self.next_emission - self.timestamp

    def encode_payload(self) -> bytes:
        if len(self.hosted) > MAX_HOSTED or len(self.vector) > MAX_VECTOR:
            raise WireError("at most 32 hosted services and 120 vector entries per HIA")
        if (self.state >> 12) == 0x4:
            raise WireError("an excluded state (0x4xxx) is never announced")
        out = Writer().u16(26).ident(self.node_id).u64(self.next_emission)
        out.u16(self.state).u64(self.timestamp).raw(self.x25519)
        out.u16(len(self.hosted))
        for address in self.hosted:
            out.u32(address)
        out.u16(len(self.vector))
        for entry in self.vector:
            out.u32(entry.address).u16(entry.distance).u8(entry.hops)
        return out.bytes()

    def sign(self, key: SigningKey) -> bytes:
        """The whole datagram."""
        signed = frame(EVENT_HIA, self.encode_payload())
        return key.public + key.sign(signed) + signed

    @classmethod
    def decode_payload(cls, payload: bytes) -> "HereIAm":
        reader = Reader(payload)
        if reader.u16() != 26:
            raise WireError("identifier length must be 26 in version 1")
        node_id = reader.ident()
        next_emission = reader.u64()
        state = reader.u16()
        timestamp = reader.u64()
        x25519 = reader.raw(32)
        hosted_count = reader.u16()
        if hosted_count > MAX_HOSTED:
            raise WireError("more than 32 hosted services")
        hosted = [reader.u32() for _ in range(hosted_count)]
        vector_count = reader.u16()
        if vector_count > MAX_VECTOR:
            raise WireError("more than 120 vector entries")
        vector = [VectorEntry(reader.u32(), reader.u16(), reader.u8()) for _ in range(vector_count)]
        reader.end()  # the declared length matches exactly the announced lists
        for address in hosted + [e.address for e in vector]:
            if address >> 28:
                raise WireError("the 4 high bits of an SP address must be 0")
        return cls(node_id, next_emission, state, timestamp, x25519, hosted, vector)


@dataclass(frozen=True, slots=True)
class Received:
    """A datagram that passed the checks of [6.2]."""

    public_key: bytes
    hia: HereIAm


def check_datagram(  # pylint: disable=too-many-arguments
    data: bytes,
    source_port: int,
    *,
    expected_source_port: int = SOURCE_PORT,
    freshness_ms: int = 30_000,
    now: int | None = None,
) -> Received:
    """Every reception check of [NNDP-01 6.2] that needs no history, in order."""
    if source_port != expected_source_port:
        raise WireError("source port is not 5221")
    if not MIN_DATAGRAM <= len(data) <= MAX_DATAGRAM:
        raise WireError("datagram size out of 105..1200")
    public, signature, signed = data[:32], data[32:96], data[96:]
    # Cheap header check before the costly signature [8]; the draft lists it
    # after, and a header that fails here would fail there too.
    FrameHeader.decode(signed)
    if not is_valid(public, signature, signed):
        raise WireError("bad signature")
    header = FrameHeader.decode(signed)
    if header.event != EVENT_HIA:
        raise WireError(f"unexpected event 0x{header.event:04X}")
    hia = HereIAm.decode_payload(signed[HEADER_SIZE:])
    if hia.state >> 12 == 0x4:
        raise WireError("excluded state announced")
    current = now_ms() if now is None else now
    if abs(hia.timestamp - current) > freshness_ms:
        raise WireError("timestamp outside the freshness window")
    if not MIN_INTERVAL_MS <= hia.interval_ms <= MAX_INTERVAL_MS:
        raise WireError("announced interval outside 1..3600 s")
    return Received(public, hia)


# ---------------------------------------------------------------------------
# Neighbours [6.2, 6.3]
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Neighbor:
    """What is known of one (public key, address) pair."""

    public_key: bytes
    address: str
    node_id: str
    state: int
    x25519: bytes
    hosted: list[int]
    timestamp: int
    interval_ms: int
    received_at: int
    inactive: bool = False

    @property
    def deadline(self) -> int:
        """2 x I after the last valid HIA [6.3]."""
        return self.received_at + 2 * self.interval_ms


# ---------------------------------------------------------------------------
# Nearest services [6.5]
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ServiceEntry:
    """One instance in the table of nearest services."""

    address: int
    distance: int
    hops: int
    learned_from: bytes | None  # None: our own instance
    expires: int | None  # None: local, never expires


class NearestServices:
    """At most K instances per service of the node's areas [NNDP-01 6.5]."""

    def __init__(self, k: int = 3) -> None:
        self.k = k
        self.entries: dict[int, list[ServiceEntry]] = {}
        # Local instances being withdrawn: address -> remaining announcements.
        self._withdrawing: dict[int, int] = {}

    # -- local instances ---------------------------------------------------

    def set_local(self, address: int, load_per_mille: int) -> None:
        """Our healthy instance: distance = our reference load, 0 hop."""
        service = addresses.service_of(address)
        self._withdrawing.pop(address, None)
        rows = [e for e in self.entries.get(service, []) if e.address != address]
        rows.append(ServiceEntry(address, min(load_per_mille, UNREACHABLE - 1), 0, None, None))
        self.entries[service] = self._trim(rows)

    def withdraw_local(self, address: int) -> None:
        """Stop hosting: announce 65535 for three intervals, then remove [6.5]."""
        service = addresses.service_of(address)
        self.entries[service] = [
            e for e in self.entries.get(service, []) if e.address != address
        ]
        self._withdrawing[address] = 3

    def local_addresses(self) -> list[int]:
        return [
            e.address for rows in self.entries.values() for e in rows if e.learned_from is None
        ]

    # -- reception -----------------------------------------------------------

    def receive(  # pylint: disable=too-many-arguments
        self,
        vector: list[VectorEntry],
        *,
        sender: bytes,
        sender_interval_ms: int,
        rtt_ms: float | None,
        ping_tolerance_ms: int,
        my_services: set[int],
        my_addresses: set[int],
        now: int,
    ) -> bool:
        """Merge a received vector; True when a best instance changed."""
        before = self._bests()
        expires = now + 3 * sender_interval_ms
        t = ping_tolerance_ms if rtt_ms is None else rtt_ms
        for entry in vector:
            service = addresses.service_of(entry.address)
            if service not in my_services or entry.address in my_addresses:
                continue
            distance = min(UNREACHABLE, int(entry.distance + 1000 * t / ping_tolerance_ms))
            hops = entry.hops + 1
            unreachable = entry.distance >= UNREACHABLE or hops > MAX_HOPS
            rows = self.entries.setdefault(service, [])
            if not unreachable and self._count_from(sender) >= MAX_PER_SENDER and not any(
                    e.address == entry.address and e.learned_from == sender for e in rows):
                continue  # bound what one sender can make us store [8]
            same = next(
                (e for e in rows if e.address == entry.address and e.learned_from == sender),
                None,
            )
            if same is not None:
                if unreachable:
                    rows.remove(same)
                else:
                    same.distance, same.hops, same.expires = distance, hops, expires
            elif not unreachable:
                other = next((e for e in rows if e.address == entry.address), None)
                if other is None:
                    rows.append(ServiceEntry(entry.address, distance, hops, sender, expires))
                elif other.learned_from is not None and distance < other.distance:
                    rows.remove(other)
                    rows.append(ServiceEntry(entry.address, distance, hops, sender, expires))
            self.entries[service] = self._trim(rows)
        return self._bests() != before

    def expire(self, now: int) -> bool:
        """Drop expired entries; True when a best instance changed."""
        before = self._bests()
        for service, rows in list(self.entries.items()):
            self.entries[service] = [e for e in rows if e.expires is None or e.expires > now]
        return self._bests() != before

    def forget(self, sender: bytes) -> bool:
        """Drop everything learnt from a node declared inactive [6.5]."""
        before = self._bests()
        for service, rows in list(self.entries.items()):
            self.entries[service] = [e for e in rows if e.learned_from != sender]
        return self._bests() != before

    # -- announcement --------------------------------------------------------

    def best(self, service: int) -> ServiceEntry | None:
        rows = self.entries.get(service) or []
        return min(rows, key=lambda e: (e.distance, e.hops)) if rows else None

    def vector(self, *, towards: bytes | None = None,
               now: int | None = None) -> list[VectorEntry]:
        """What to announce, at most one entry per service [5.4, 6.5].

        Unicast to *towards* poisons what was learnt from it [6.1]. A service
        whose local instance is being withdrawn announces the withdrawal
        (65535) unless another instance is known, which then takes its place.
        Expired entries are never announced.
        """
        if now is not None:
            self.expire(now)
        out: list[VectorEntry] = []
        withdrawn = {addresses.service_of(a): a for a in self._withdrawing}
        for service in sorted(set(self.entries) | set(withdrawn)):
            best = self.best(service)
            if best is None:
                if service in withdrawn:
                    out.append(VectorEntry(withdrawn[service], UNREACHABLE, 0))
                continue
            distance = best.distance
            if towards is not None and best.learned_from == towards:
                distance = UNREACHABLE
            out.append(VectorEntry(best.address, distance, best.hops))
        return out

    def tick_withdrawals(self) -> None:
        """Called once per regular interval."""
        for address in list(self._withdrawing):
            self._withdrawing[address] -= 1
            if self._withdrawing[address] <= 0:
                del self._withdrawing[address]

    def _trim(self, rows: list[ServiceEntry]) -> list[ServiceEntry]:
        """The K closest; our own healthy instance is never evicted."""
        rows.sort(key=lambda e: (e.distance, e.hops))
        local = [e for e in rows if e.learned_from is None]
        learnt = [e for e in rows if e.learned_from is not None]
        return sorted(local + learnt[: max(0, self.k - len(local))],
                      key=lambda e: (e.distance, e.hops))

    def _count_from(self, sender: bytes) -> int:
        return sum(1 for rows in self.entries.values() for e in rows if e.learned_from == sender)

    def _bests(self) -> dict[int, int]:
        return {s: b.address for s in self.entries if (b := self.best(s)) is not None}


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------


@dataclass
class NndpHooks:  # pylint: disable=too-many-instance-attributes
    """What the node supplies to NNDP and is told by it."""

    state: Callable[[], int]
    reference_addresses: Callable[[], list[tuple[bytes, str]]]  # (key, ipv4)
    hosted: Callable[[], list[int]]
    is_admitted: Callable[[bytes], bool]
    nit_accepts: Callable[[bytes, str], bool]
    my_services: Callable[[], set[int]]
    rtt_ms: Callable[[bytes], float | None]
    ping_tolerance_ms: Callable[[], int]
    on_neighbor: Callable[[Neighbor, bool], None]  # (neighbor, is_new_key)
    on_inactive: Callable[[Neighbor], None]
    on_vector_change: Callable[[], None]
    my_addresses: Callable[[], set[int]] = lambda: set()  # noqa: E731


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, service: "NndpService") -> None:
        self._service = service

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        self._service.handle_datagram(data, addr[0], addr[1])


class NndpService:  # pylint: disable=too-many-instance-attributes
    """Emission, reception and inactivity detection."""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        node_id: Callable[[], str],
        signing: SigningKey,
        x25519_public: bytes,
        hooks: NndpHooks,
        *,
        interval_s: int = 15,
        freshness_s: int = 30,
        source_port: int = SOURCE_PORT,
        destination_port: int = DESTINATION_PORT,
        k: int = 3,
        bind_address: str = "0.0.0.0",
        broadcast_targets: list[str] | None = None,
    ) -> None:
        self._node_id = node_id
        self._signing = signing
        self._x25519 = x25519_public
        self.hooks = hooks
        self.interval_s = interval_s
        self.freshness_s = freshness_s
        self.source_port = source_port
        self.destination_port = destination_port
        self.services = NearestServices(k)
        # Development mode: several nodes on one host, each on its own loopback
        # address; the limited broadcast is replaced by a send to each of them.
        self.bind_address = bind_address
        self.broadcast_targets = broadcast_targets
        self.neighbors: dict[tuple[bytes, str], Neighbor] = {}
        self._last_timestamp: dict[bytes, int] = {}
        self._seen: dict[tuple[bytes, int], int] = {}
        self._send_transport: asyncio.DatagramTransport | None = None
        self._recv_transport: asyncio.DatagramTransport | None = None
        self._tasks: list[asyncio.Task] = []
        self._last_triggered = 0.0
        self._next_emission = 0
        self.sent = 0
        self.received = 0
        self.rejected = 0
        self.last_rejection = ""
        self._rate: dict[str, list[float]] = {}

    @property
    def running(self) -> bool:
        return self._recv_transport is not None

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        recv_sock.bind((self.bind_address, self.destination_port))
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        send_sock.bind((self.bind_address, self.source_port))
        self._recv_transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(self), sock=recv_sock
        )
        self._send_transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, sock=send_sock
        )
        self._tasks = [
            asyncio.create_task(self._emit_loop(), name="nndp-emit"),
            asyncio.create_task(self._watch_loop(), name="nndp-watch"),
        ]
        log.info("[NNDP] Listening on UDP %d, sending from %d", self.destination_port,
                 self.source_port)

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # pylint: disable=broad-except
                pass
        self._tasks = []
        for transport in (self._recv_transport, self._send_transport):
            if transport is not None:
                transport.close()
        self._recv_transport = self._send_transport = None

    # -- emission [6.1] -------------------------------------------------------

    def build(self, *, towards: bytes | None = None, timestamp: int | None = None) -> list[bytes]:
        """The datagrams of one emission (several when the vector exceeds 120)."""
        stamp = now_ms() if timestamp is None else timestamp
        if not self._next_emission or self._next_emission <= stamp:
            self._next_emission = stamp + self.interval_s * 1000
        vector = self.services.vector(towards=towards, now=stamp)
        state = self.hooks.state()
        hosted = self.hooks.hosted()[:MAX_HOSTED]
        if state == State.APPROVAL_REQUIRED:
            hosted, vector = [], []  # empty for a node not admitted [5.4]
        chunks = [vector[i:i + MAX_VECTOR] for i in range(0, len(vector), MAX_VECTOR)] or [[]]
        out = []
        for index, chunk in enumerate(chunks):
            hia = HereIAm(
                node_id=self._node_id(),
                next_emission=self._next_emission,
                state=state,
                timestamp=stamp + index,  # each HIA has its own emission timestamp
                x25519=self._x25519,
                hosted=hosted,
                vector=chunk,
            )
            out.append(hia.sign(self._signing))
        return out

    def emit(self) -> None:
        """Broadcast, then unicast to each reference node."""
        if self._send_transport is None:
            return
        targets = self.broadcast_targets if self.broadcast_targets is not None else [BROADCAST]
        for datagram in self.build():
            for target in targets:
                self._sendto(datagram, target)
            self.sent += 1
        if self.hooks.state() == State.APPROVAL_REQUIRED:
            return
        for key, address in self.hooks.reference_addresses():
            for datagram in self.build(towards=key):
                self._sendto(datagram, address)
                self.sent += 1

    def trigger(self) -> None:
        """An anticipated HIA, at least 1 s after the previous one [6.1]."""
        loop = asyncio.get_running_loop()
        if loop.time() - self._last_triggered < TRIGGERED_SPACING:
            return
        self._last_triggered = loop.time()
        self.emit()

    async def _emit_loop(self) -> None:
        while True:
            self._next_emission = 0
            try:
                self.emit()
            except Exception:  # pylint: disable=broad-except
                log.exception("[NNDP] Emission failed")
            self.services.tick_withdrawals()
            await asyncio.sleep(self.interval_s)

    # -- reception [6.2] ------------------------------------------------------

    def _rate_ok(self, address: str) -> bool:
        """Token-bucket-like bound per source, before any signature check [8]."""
        now = time.monotonic()
        recent = [t for t in self._rate.get(address, []) if now - t < 1.0]
        recent.append(now)
        self._rate[address] = recent
        if len(self._rate) > 4096:
            self._rate = {a: v for a, v in self._rate.items() if v and now - v[-1] < 1.0}
        return len(recent) <= RATE_PER_SOURCE

    def handle_datagram(self, data: bytes, address: str, port: int) -> None:
        # Bounded per source address and per announced key, before any
        # signature work [NNDP 8].
        if not self._rate_ok(address) or not self._rate_ok("key:" + data[:32].hex()):
            self.rejected += 1
            self._capture_in(data, address, port, "dropped", "rate limit [NNDP 8]")
            return
        try:
            received = self.accept(data, address, port)
        except WireError as exc:
            self.rejected += 1
            self.last_rejection = f"{address}:{port}: {exc}"
            log.debug("[NNDP] Dropped HIA from %s: %s", address, exc)
            self._capture_in(data, address, port, "dropped", str(exc))
            return
        if received is not None:
            self.received += 1
            self._capture_in(data, address, port, "ok", "")
        else:
            self._capture_in(data, address, port, "ignored", "our own HIA")

    def _capture_in(self, data: bytes, address: str, port: int, status: str,
                    reason: str) -> None:
        if CAPTURE.wants("NNDP"):
            info, dissection = dissect_nndp(data)
            CAPTURE.record("NNDP", "in", f"{address}:{port}",
                           f"{self.bind_address}:{self.destination_port}", data, info,
                           dissection, status=status, reason=reason)

    def _sendto(self, datagram: bytes, target: str) -> None:
        assert self._send_transport is not None
        self._send_transport.sendto(datagram, (target, self.destination_port))
        if CAPTURE.wants("NNDP"):
            info, dissection = dissect_nndp(datagram)
            CAPTURE.record("NNDP", "out", f"{self.bind_address}:{self.source_port}",
                           f"{target}:{self.destination_port}", datagram, info, dissection)

    def accept(self, data: bytes, address: str, port: int, *, now: int | None = None) -> Neighbor | None:
        """Run every check; record the sender. None for our own HIA."""
        current = now_ms() if now is None else now
        received = check_datagram(
            data, port, expected_source_port=self.source_port,
            freshness_ms=self.freshness_s * 1000, now=current,
        )
        key, hia = received.public_key, received.hia
        if key == self._signing.public:
            return None
        if (key, hia.timestamp) in self._seen:
            raise WireError("replayed HIA")
        if hia.timestamp <= self._last_timestamp.get(key, -1):
            raise WireError("HIA older than the last one of this key")
        if not self.hooks.nit_accepts(key, address):
            raise WireError("(address, key) association contradicts the NIT")
        self._seen[(key, hia.timestamp)] = current + self.freshness_s * 1000
        self._last_timestamp[key] = hia.timestamp

        is_new_key = not any(k == key for k, _ in self.neighbors)
        neighbor = Neighbor(
            public_key=key, address=address, node_id=hia.node_id, state=hia.state,
            x25519=hia.x25519, hosted=list(hia.hosted), timestamp=hia.timestamp,
            interval_ms=hia.interval_ms, received_at=current,
        )
        self.neighbors[(key, address)] = neighbor
        self.hooks.on_neighbor(neighbor, is_new_key)

        if self.hooks.is_admitted(key):
            changed = self.services.receive(
                hia.vector,
                sender=key,
                sender_interval_ms=hia.interval_ms,
                rtt_ms=self.hooks.rtt_ms(key),
                ping_tolerance_ms=self.hooks.ping_tolerance_ms(),
                my_services=self.hooks.my_services(),
                my_addresses=set(self.services.local_addresses()) | self.hooks.my_addresses(),
                now=current,
            )
            if changed:
                self.hooks.on_vector_change()
        return neighbor

    # -- inactivity [6.3] ------------------------------------------------------

    def check_inactivity(self, now: int | None = None) -> list[Neighbor]:
        """A node is inactive when no valid HIA of its key arrived for 2 x I [6.3]."""
        current = now_ms() if now is None else now
        latest: dict[bytes, int] = {}
        for neighbor in self.neighbors.values():
            latest[neighbor.public_key] = max(latest.get(neighbor.public_key, 0),
                                              neighbor.deadline)
        lost = []
        for neighbor in self.neighbors.values():
            if not neighbor.inactive and current > latest[neighbor.public_key]:
                neighbor.inactive = True
                if not any(n is not neighbor and n.public_key == neighbor.public_key
                           for n in lost):
                    lost.append(neighbor)
        changed = False
        for neighbor in lost:
            changed |= self.services.forget(neighbor.public_key)
            self.hooks.on_inactive(neighbor)
        changed |= self.services.expire(current)
        self._seen = {k: v for k, v in self._seen.items() if v > current}
        if changed:
            self.hooks.on_vector_change()
        return lost

    async def _watch_loop(self) -> None:
        while True:
            await asyncio.sleep(1)
            try:
                self.check_inactivity()
            except Exception:  # pylint: disable=broad-except
                log.exception("[NNDP] Inactivity check failed")


__all__ = [
    "HereIAm", "NearestServices", "Neighbor", "NndpHooks", "NndpService",
    "VectorEntry", "check_datagram",
]
