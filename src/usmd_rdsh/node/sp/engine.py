"""The SP engine: SAT, destination choice, sessions and broadcast [SP-01 5-9].

The engine owns the session, flow and broadcast tables. Everything else it
reads from the node through :class:`SpContext`: the catalogue (SP/VIP table),
the SP address table built from the node records, the nearest services
learnt by NNDP, and what the NIT/NAL say about a peer.
"""

from __future__ import annotations

import ipaddress
import logging
import random
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Protocol

from usmd_rdsh.node import addresses
from usmd_rdsh.node.crypto import AgreementKey, CryptoError, SigningKey
from usmd_rdsh.node.sp import handshake as hs
from usmd_rdsh.node.sp import packets
from usmd_rdsh.node.sp.flows import FlowTable
from usmd_rdsh.node.sp.session import (
    KEEPALIVE_S,
    Payload,
    ReplayWindow,
    Session,
    data_frame_index,
)
from usmd_rdsh.node.wire import FrameHeader, WireError, now_ms

log = logging.getLogger("usmd_rdsh.sp")

PENDING_PER_PEER = 32
RETRANSMIT_S = (2.0, 4.0)
INELIGIBLE_S = 30.0
INITIATION_RATE = 10  # per second and source address [7.7]
EPHEMERAL_MEMORY_S = 60.0
FRESHNESS_MS = 30_000
BROADCAST_CACHE_S = 60.0


@dataclass(frozen=True, slots=True)
class CatalogService:
    """One entry of the SP/VIP table."""

    service_id: int
    area: str
    vip: str
    group: str | None


@dataclass(frozen=True, slots=True)
class Peer:
    """What the node knows of another node, for SP."""

    ed25519: bytes
    x25519: bytes
    address: str  # IPv4 from the NIT
    active: bool
    hia_hosted: frozenset[int] | None  # SP addresses of its last HIA, None if none
    mutation_services: frozenset[int]  # service ids of its mutation (node record)


class SpContext(Protocol):  # pragma: no cover - interface
    """What the engine reads from the node."""

    def catalog(self) -> dict[int, CatalogService]: ...
    def area_networks(self) -> dict[str, ipaddress.IPv4Network]: ...
    def management_id(self, service_id: int) -> int | None: ...
    def hosted_services(self) -> set[int]: ...
    def owner(self, sp_address: int) -> bytes | None: ...
    def peer(self, ed25519: bytes) -> Peer | None: ...
    def peers(self) -> list[Peer]: ...
    def nearest(self, service_id: int) -> list[tuple[int, int]]: ...  # (address, D)
    def initiator_allowed(self, ed25519: bytes, address: str) -> bool: ...
    def address_known(self, address: str) -> bool: ...


@dataclass
class _Pending:
    """A handshake in progress towards one peer."""

    state: hs.InitiatorState
    started: float
    attempts: int
    queue: deque = field(default_factory=lambda: deque(maxlen=PENDING_PER_PEER))


class SpEngine:  # pylint: disable=too-many-instance-attributes
    """One node's SP."""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        context: SpContext,
        signing: SigningKey,
        static: AgreementKey,
        *,
        send_udp: Callable[[bytes, str, int], None],
        write_tun: Callable[[bytes], None],
        port: int,
        mtu: int = 1412,
        selection_margin: float = 0.1,
        pending_per_peer: int = PENDING_PER_PEER,
        ineligible_s: float = INELIGIBLE_S,
        replay_window: int = 2048,
        flow_idle_s: float = 300.0,
        broadcast_rate: int = 1000,
        clock: Callable[[], float] = time.monotonic,
        wall_ms: Callable[[], int] = now_ms,
    ) -> None:
        self.context = context
        self._signing = signing
        self._static = static
        self._send_udp = send_udp  # (frame, ipv4, outer tos)
        self._write_tun = write_tun
        self.port = port
        self.mtu = mtu
        self.margin = selection_margin
        self.pending_per_peer = pending_per_peer
        self.ineligible_s = ineligible_s
        self.replay_window = replay_window
        self.broadcast_rate = broadcast_rate
        self._broadcast_sent: dict[int, deque] = {}
        self._clock = clock
        self._wall_ms = wall_ms
        self.sessions: dict[int, Session] = {}  # by local index
        self.flows = FlowTable(flow_idle_s)
        self._pending: dict[bytes, _Pending] = {}
        self._ineligible: dict[bytes, float] = {}
        self._seen_ephemeral: dict[bytes, float] = {}
        self._rate: dict[str, deque] = {}
        self._broadcast_seen: dict[tuple[bytes, int], float] = {}
        self.stats = {"tx_frames": 0, "rx_frames": 0, "dropped": 0, "handshakes": 0,
                      "icmp": 0, "broadcast": 0}

    # ------------------------------------------------------------------
    # Tables
    # ------------------------------------------------------------------

    def _by_ip(self, ip: str) -> CatalogService | None:
        """SP/VIP table lookup: a VIP or a group address [4.3]."""
        for service in self.context.catalog().values():
            if ip in (service.vip, service.group):
                return service
        return None

    def _local_vip(self, ip: str) -> CatalogService | None:
        service = self._by_ip(ip)
        if service and service.vip == ip and service.service_id in self.context.hosted_services():
            return service
        return None

    def session_for(self, peer: bytes) -> Session | None:
        """The most recently established session that may still send [7.6]."""
        now = self._clock()
        usable = [s for s in self.sessions.values() if s.peer == peer and s.can_send(now)]
        return max(usable, key=lambda s: s.established) if usable else None

    # ------------------------------------------------------------------
    # Emission (SAT) [5.2]
    # ------------------------------------------------------------------

    def from_tun(self, raw: bytes) -> None:
        """One packet read on the SP interface."""
        try:
            packet = packets.parse(raw)
        except packets.PacketError:
            self.stats["dropped"] += 1
            return
        source = self._local_vip(packet.source)
        destination = self._by_ip(packet.destination)
        if source is None or destination is None or source.area != destination.area:
            self.stats["dropped"] += 1
            return
        management = self.context.management_id(source.service_id)
        if management is None:
            self.stats["dropped"] += 1  # no management id yet [4.2]
            return
        sp_source = addresses.pack(source.service_id, management)

        if packet.total_length > self.mtu:
            if packet.dont_fragment:
                self._icmp(packet, 4, destination)
                return
            fragments = [packets.parse(f) for f in packets.fragment(packet, self.mtu)]
        else:
            fragments = [packet]

        if packet.destination == destination.group:
            for piece in fragments:
                self._broadcast(piece, sp_source, destination.service_id)
            return

        now = self._clock()
        target = self.flows.lookup(packet, now)
        if target is not None and not self._eligible(target, now):
            self.flows.drop_address(target)
            target = None
        if target is None:
            target = self.select(destination.service_id, now)
        if target is None:
            self._icmp(packet, 1, destination)
            return
        self.flows.record_outbound(packet, target, now)
        owner = self.context.owner(target)
        if owner is None:
            self._icmp(packet, 1, destination)
            return
        for piece in fragments:
            self._send_payload(owner, Payload(False, sp_source, target, None, piece.raw),
                               piece.tos)

    def _icmp(self, packet: packets.IPv4, code: int, service: CatalogService) -> None:
        self.stats["icmp"] += 1
        self._write_tun(packets.icmp_unreachable(packet, code, source=service.vip,
                                                 mtu=self.mtu))

    # ------------------------------------------------------------------
    # Destination choice [6]
    # ------------------------------------------------------------------

    def _eligible(self, address: int, now: float) -> bool:
        owner = self.context.owner(address)
        if owner is None:
            return False
        peer = self.context.peer(owner)
        if peer is None or not peer.active:
            return False
        if peer.hia_hosted is not None and address not in peer.hia_hosted:
            return False
        until = self._ineligible.get(owner)
        return until is None or until <= now

    def select(self, service_id: int, now: float | None = None) -> int | None:
        """Random choice among eligible instances within k_min + delta [6.2]."""
        now = self._clock() if now is None else now
        candidates = [(a, d / 1000) for a, d in self.context.nearest(service_id)
                      if d < 65535 and self._eligible(a, now)]
        if not candidates:
            return None
        k_min = min(cost for _, cost in candidates)
        pool = [a for a, cost in candidates if cost <= k_min + self.margin]
        return random.choice(pool)

    # ------------------------------------------------------------------
    # Broadcast [8]
    # ------------------------------------------------------------------

    def _broadcast(self, packet: packets.IPv4, sp_source: int, service_id: int) -> None:
        now = self._clock()
        sent = self._broadcast_sent.setdefault(service_id, deque())
        while sent and now - sent[0] > 1.0:
            sent.popleft()
        if len(sent) >= self.broadcast_rate:
            self.stats["dropped"] += 1  # per-service bound on fan-out [8, 11]
            return
        sent.append(now)
        group = addresses.pack(service_id, addresses.ALL_INSTANCES)
        bid = secrets.randbits(64)
        self.stats["broadcast"] += 1
        for peer in self.context.peers():
            if peer.active and service_id in peer.mutation_services \
                    and peer.ed25519 != self._signing.public:
                self._send_payload(peer.ed25519, Payload(False, sp_source, group, bid, packet.raw),
                                   packet.tos)

    # ------------------------------------------------------------------
    # Sessions [7.6]
    # ------------------------------------------------------------------

    def _send_payload(self, peer_key: bytes, payload: Payload, tos: int = 0) -> None:
        session = self.session_for(peer_key)
        now = self._clock()
        if session is not None:
            peer = self.context.peer(peer_key)
            if peer is None:
                return
            self._send_udp(session.seal(payload, now), peer.address, tos)
            self.stats["tx_frames"] += 1
            if session.needs_rekey(now) and peer_key not in self._pending:
                self._initiate(peer_key, now)
            return
        pending = self._pending.get(peer_key) or self._initiate(peer_key, now)
        if pending is not None:
            pending.queue.append((payload, tos))  # oldest dropped beyond 32

    def _initiate(self, peer_key: bytes, now: float) -> _Pending | None:
        peer = self.context.peer(peer_key)
        if peer is None:
            return None
        data, state = hs.build_initiation(self._signing, peer.ed25519, peer.x25519,
                                          self._wall_ms(), index=self._free_index())
        previous = self._pending.get(peer_key)
        if previous is not None:
            previous.state.forget()  # the replaced ephemeral key is erased [7.4]
        pending = _Pending(state, now, (previous.attempts + 1) if previous else 1,
                           previous.queue if previous else deque(maxlen=self.pending_per_peer))
        self._pending[peer_key] = pending
        self._send_udp(data, peer.address, 0)
        self.stats["handshakes"] += 1
        return pending

    def tick(self) -> None:
        """Timers: retransmission, abandonment, renewal, expiry, keepalives."""
        now = self._clock()
        for peer_key, pending in list(self._pending.items()):
            elapsed = now - pending.started
            if elapsed < RETRANSMIT_S[min(pending.attempts, len(RETRANSMIT_S)) - 1]:
                continue
            if pending.attempts >= 3:
                del self._pending[peer_key]
                self._ineligible[peer_key] = now + self.ineligible_s
                log.info("[SP] Handshake abandoned with %s", peer_key.hex()[:12])
                self._redirect(pending)
            else:
                self._initiate(peer_key, now)  # new ephemeral key [7.6]
        for index, session in list(self.sessions.items()):
            peer = self.context.peer(session.peer)
            if session.idle(now) or not session.can_receive(now) or peer is None \
                    or not peer.active:
                del self.sessions[index]
                continue
            # Keep alive a session carrying data one way only; keepalives
            # themselves never call for another one [7.5].
            if session.can_send(now) and now - session.last_sent >= KEEPALIVE_S \
                    and now - session.last_data_received < KEEPALIVE_S:
                self._send_udp(session.seal(Payload(keepalive=True), now), peer.address, 0)
            if session.needs_rekey(now) and session.keys.initiator \
                    and session.peer not in self._pending \
                    and self.session_for(session.peer) is session:
                self._initiate(session.peer, now)
        self.flows.expire(now)
        self._seen_ephemeral = {k: t for k, t in self._seen_ephemeral.items() if t > now}
        self._broadcast_seen = {k: t for k, t in self._broadcast_seen.items() if t > now}
        self._ineligible = {k: t for k, t in self._ineligible.items() if t > now}

    def _redirect(self, pending: _Pending) -> None:
        """Re-route or drop what waited for an abandoned peer [7.6]."""
        for payload, tos in pending.queue:
            if payload.destination & 0xFFFF == addresses.ALL_INSTANCES:
                continue
            self.flows.drop_address(payload.destination)
            service = addresses.service_of(payload.destination)
            target = self.select(service)
            owner = self.context.owner(target) if target is not None else None
            if owner is not None:
                self._send_payload(owner, Payload(False, payload.source, target, None,
                                                  payload.packet), tos)

    def _free_index(self) -> int:
        """A local index used by no session nor pending handshake [7.3]."""
        taken = set(self.sessions) | {p.state.index for p in self._pending.values()}
        while True:
            index = hs.new_index()
            if index not in taken:
                return index

    def drop_peer(self, peer_key: bytes) -> None:
        """Peer left Active, was excluded or left the NIT [7.6]."""
        for index in [i for i, s in self.sessions.items() if s.peer == peer_key]:
            del self.sessions[index]
        self._pending.pop(peer_key, None)

    # ------------------------------------------------------------------
    # Reception
    # ------------------------------------------------------------------

    def from_udp(self, data: bytes, source: str, port: int, outer_ecn: int = 0) -> None:
        """One datagram received on the SP port."""
        if port != self.port:
            return
        try:
            header = FrameHeader.decode(data)
            if header.event == hs.EVENT_INITIATION:
                self._on_initiation(data, source)
            elif header.event == hs.EVENT_RESPONSE:
                self._on_response(data, source)
            elif header.event == hs.EVENT_DATA:
                self._on_data(data, source, outer_ecn)
        except (WireError, CryptoError, packets.PacketError) as exc:
            self.stats["dropped"] += 1
            log.debug("[SP] Dropped frame from %s: %s", source, exc)

    def _on_initiation(self, data: bytes, source: str) -> None:
        """The checks of [7.7], cheapest first."""
        _index, e_i, timestamp = hs.parse_initiation_header(data)
        if not self.context.address_known(source):
            raise WireError("initiation from an address outside the NIT")
        now = self._clock()
        window = self._rate.setdefault(source, deque())
        while window and now - window[0] > 1.0:
            window.popleft()
        if len(window) >= INITIATION_RATE:
            raise WireError("initiation rate exceeded")
        window.append(now)
        if abs(timestamp - self._wall_ms()) > FRESHNESS_MS:
            raise WireError("initiation timestamp outside 30 s")
        if e_i in self._seen_ephemeral:
            raise WireError("ephemeral key replayed")
        opened = hs.open_initiation(data, self._static, self._signing.public)
        self._seen_ephemeral[e_i] = now + EPHEMERAL_MEMORY_S
        if not self.context.initiator_allowed(opened.initiation.initiator_ed25519, source):
            raise WireError("initiator not associated with its address or not executor")
        initiation = hs.verify_initiation(opened)
        response, keys = hs.build_response(self._signing, self._static, initiation,
                                           index=self._free_index())
        self.sessions[keys.local_index] = Session(keys, source, now,
                                                  window=ReplayWindow(self.replay_window))
        self._send_udp(response, source, 0)

    def _on_response(self, data: bytes, source: str) -> None:
        _index_r, index_i = hs.response_indexes(data)
        peer_key, pending = next(
            ((k, p) for k, p in self._pending.items() if p.state.index == index_i), (None, None)
        )
        if pending is None:
            raise WireError("response to no pending initiation")
        peer = self.context.peer(peer_key)
        if peer is None or peer.address != source:
            raise WireError("response from an unexpected address")
        keys = hs.open_response(data, pending.state, self._signing.public)
        now = self._clock()
        session = Session(keys, source, now, window=ReplayWindow(self.replay_window))
        self.sessions[keys.local_index] = session
        del self._pending[peer_key]
        if not pending.queue:
            self._send_udp(session.seal(Payload(keepalive=True), now), source, 0)
        for payload, tos in pending.queue:
            self._send_udp(session.seal(payload, now), source, tos)
            self.stats["tx_frames"] += 1

    def _on_data(self, data: bytes, source: str, outer_ecn: int) -> None:
        session = self.sessions.get(data_frame_index(data))
        if session is None:
            raise WireError("unknown session index")
        peer = self.context.peer(session.peer)
        if peer is None or peer.address != source:
            raise WireError("frame from an address the NIT does not give the peer")
        now = self._clock()
        payload = session.open(data, now)
        self.stats["rx_frames"] += 1
        if payload.keepalive:
            return
        session.last_data_received = now
        self._deliver(payload, session.peer, outer_ecn, now)

    def _deliver(self, payload: Payload, peer_key: bytes, outer_ecn: int, now: float) -> None:
        """[5.3] checks, then write to the interface."""
        destination_service = addresses.service_of(payload.destination)
        hosted = self.context.hosted_services()
        if destination_service not in hosted:
            raise WireError("destination service not hosted here")
        if payload.destination & 0xFFFF != addresses.ALL_INSTANCES and \
                self.context.management_id(destination_service) != payload.destination & 0xFFFF:
            raise WireError("destination is not one of our SP addresses")
        if self.context.owner(payload.source) != peer_key:
            raise WireError("source SP address not attributed to the peer")
        catalog = self.context.catalog()
        source_service = catalog.get(addresses.service_of(payload.source))
        destination = catalog.get(destination_service)
        if source_service is None or destination is None or source_service.area != destination.area:
            raise WireError("services in different areas")
        inner = packets.parse(payload.packet)
        broadcast = payload.destination & 0xFFFF == addresses.ALL_INSTANCES
        expected_destination = destination.group if broadcast else destination.vip
        if inner.source != source_service.vip or inner.destination != expected_destination:
            raise WireError("inner addresses do not match the SP addresses")
        if broadcast:
            key = (peer_key, payload.broadcast_id or 0)
            if key in self._broadcast_seen:
                return
            self._broadcast_seen[key] = now + BROADCAST_CACHE_S
        raw = packets.decapsulate_ecn(payload.packet, outer_ecn)
        if raw is None:
            return
        if not broadcast:
            self.flows.record_inbound(inner, payload.source, now)
        self._write_tun(raw)
