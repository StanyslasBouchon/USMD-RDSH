"""The USMD-RDSH node [ARCH-02]: lifecycle, cooperation and service hosting.

One object, one asyncio loop. It owns the identity, the trust tables, the
signed configuration, NNDP, NCP, SP, Raft and the services it runs, and it
implements the procedures of the architecture draft:

    5.2 bootstrap   contact node, EDB, NNDP; founder self-admission [NCP 7.7]
    5.3 admission   Request_approval, endorsement
    5.4 sync        node table, properties, reference nodes, record "Active"
    6   distance    load sampling, Check_distance_to_node, NNR, hysteresis
    7   delegation  weakened / emergency, help, switch-over, expiry, healing
    8   services    transmutation, health checks, dependencies, updates
    9   config      signed objects, versions, propagation
    11/12           areas, management ids, SP addresses, Raft master,
                    operators elected by the master (12.4)
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import random
import secrets
import socket
import ssl
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nan_runtime.state import StateDirectory

from usmd_rdsh.node import addresses, dataid, distance
from usmd_rdsh.node.authority import Authority
from usmd_rdsh.node.crypto import CryptoError, b64u, unb64u
from usmd_rdsh.node.handlers import NcpHandlers
from usmd_rdsh.node.identity import Identity, load_identity, save_identity
from usmd_rdsh.node.load import LoadMonitor
from usmd_rdsh.node.ncp.codec import (
    Command,
    CreationToken,
    EndorsementPacket,
    MutationProperties,
    OPERATOR_ROLES,
    NodeRecord,
    OperateRequest,
    Role,
    TableEntry,
    UscProperties,
    UsdProperties,
    encode_mutations,
)
from usmd_rdsh.node.ncp.transport import NcpRemoteError, NcpTimeout, NcpTransport
from usmd_rdsh.node.nndp import Neighbor, NndpHooks, NndpService
from usmd_rdsh.node.raft import Raft, assign_record, operator_record, voter_record
from usmd_rdsh.node.services import (
    ServiceRunner,
    ServiceSpec,
    dependency_order,
    parse_service_file,
    write_files,
)
from usmd_rdsh.node.signed import SignedConfig, parameter
from usmd_rdsh.node.sp.engine import CatalogService, Peer, SpEngine
from usmd_rdsh.node.states import State
from usmd_rdsh.node.tables import Tables
from usmd_rdsh.node.wire import Reader, WireError, Writer, now_ms

log = logging.getLogger("usmd_rdsh.node")


def _redirect(answer: bytes) -> list[tuple[str, bytes, bytes]] | None:
    """The operators an Operate answer redirects to, or None when it is the answer."""
    try:
        data = json.loads(answer)
    except ValueError:
        return None
    if not isinstance(data, dict) or "redirect" not in data:
        return None
    try:
        return [(str(r["address"]), unb64u(r["ed25519"]), unb64u(r["x25519"]))
                for r in data["redirect"]]
    except (KeyError, TypeError, ValueError):
        return []


def _jitter(seconds: float) -> float:
    """±25 % [NCP 8]."""
    return seconds * random.uniform(0.75, 1.25)


def local_ipv4() -> str:
    """The address this node uses towards the network."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"


@dataclass
class LocalSettings:  # pylint: disable=too-many-instance-attributes
    """Settings that are this node's own (not the authority's)."""

    nndp_enabled: bool = True
    hia_interval: int = 15
    freshness_s: int = 30  # NCP freshness window [NCP 8]
    nndp_freshness_s: int = 30  # NNDP F, a local receiver parameter [NNDP 7]
    nndp_source_port: int = 5221
    nndp_destination_port: int = 5222
    ncp_port: int = 9992
    exclusion_ms: int = 600_000
    properties_interval: int = 60
    reconcile_interval: int = 600
    relay_delay: float = 1.0
    raft_heartbeat: float = 1.0
    raft_election: tuple[float, float] = (5.0, 10.0)
    ncp_retransmit: float = 2.0
    ncp_attempts: int = 3
    sp_margin: float = 0.1
    service_data: dict = field(default_factory=dict)  # service -> data path [ARCH 7.1]
    sp_flow_idle: float = 300.0
    sp_pending: int = 32
    sp_ineligible: float = 30.0
    sp_replay_window: int = 2048
    sp_broadcast_rate: int = 1000
    roles: list[Role] = field(default_factory=lambda: [Role.NODE_EXECUTOR])  # authorised
    creation_token: str = ""
    founder: bool = False
    contact_node: str = ""
    contact_ed25519: str = ""
    contact_x25519: str = ""
    edb_domain: str = ""
    usc_anchor: str = ""
    usd_anchor: str = ""
    address: str = ""
    bind_address: str = "0.0.0.0"
    dev_peers: list[str] | None = None  # development mode: the other virtual nodes


@dataclass
class DelegationState:
    """Where this node stands in a delegation [ARCH 7]."""

    weakened: bool = False
    emergency: State | None = None
    last_request: float = 0.0
    favourable: dict[str, list[str]] = field(default_factory=dict)  # service -> node ids
    health_failures: int = 0
    handed_over: bool = False  # services handed over, back to Active when the load allows


class Node(NcpHandlers):  # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """A USMD-RDSH node."""

    def __init__(self, state_dir: StateDirectory, *, identity_file: str = "",
                 authority_dir: StateDirectory | None = None) -> None:
        self.state_dir = state_dir
        self.identity_file = identity_file
        self.identity: Identity = load_identity(state_dir, identity_file or None)
        self.authority = Authority(authority_dir or state_dir)
        self.settings = LocalSettings()
        self.tables = Tables()
        self.signed = SignedConfig.load(state_dir)
        self.load = LoadMonitor()
        self.runner = ServiceRunner(environment=self.sequence_environment)
        self.state: State = State.APPROVAL_REQUIRED
        self.state_validity: int | None = None
        self.mutation: str = ""
        self.hosted: set[int] = set()  # service ids running and healthy
        self.references: list[str] = []
        self.referenced_by: dict[str, list[str]] = {}  # node id -> its references
        self.distances: dict[str, float] = {}
        self.rtt: dict[bytes, float] = {}
        self.observed: dict[bytes, State] = {}  # states attributed to peers [5.5]
        self.endorsement: EndorsementPacket | None = None
        self.endorser: bytes | None = None
        self.token: CreationToken | None = None
        self.management: dict[int, int] = {}  # service id -> management id
        self.record_date = 0
        self.delegation = DelegationState()
        self.transmutations: list[dict[str, Any]] = []
        self.events: list[str] = []
        self.started = time.time()
        self.known_voters: list[str] = []
        # Operator roles the master elected, as last known [ARCH 12.4]: role -> node ids.
        self.operators: dict[int, set[str]] = {}
        self.operators_term = 0
        self._unfilled: set[Role] = set()  # operator roles without candidate, reported once
        # Operate [ARCH 12.5]: the console answering an operator, set by the CLI:
        # (origin, sender key, session, JSON) -> JSON.
        self.operate_handler = None
        #: Contact node of each other USD of the USC: USDN -> (address, Ed25519, X25519).
        self.usc_peers: dict[str, tuple[str, bytes, bytes]] = {}
        self._usc_relays: dict[str, tuple[str, bytes, bytes]] = {}  # USDN -> its operator
        self._foreign_x25519: dict[bytes, bytes] = {}  # keys of other USDs' operators
        self._background: set[asyncio.Task] = set()
        self._measuring = False
        self.transfer_rate: float = 0.0  # bytes/s measured towards references
        self.loads: dict[str, int] = {}  # reference load of each measured node [ARCH 3.2]
        self.updating: dict[str, MutationProperties] = {}  # previous version during update
        self.on_signed_change = None  # called after newer signed objects are applied
        self._tasks: list[asyncio.Task] = []
        self._relay_from: dict[bytes, bytes | None] = {}
        self._relay_task: asyncio.Task | None = None
        self.nndp: NndpService | None = None
        self.ncp: NcpTransport | None = None
        self.sp: SpEngine | None = None
        self._sp_transport: asyncio.DatagramTransport | None = None
        self.tun = None
        self.raft: Raft | None = None
        self._load_admission()

    # ------------------------------------------------------------------
    # Identity and persistence
    # ------------------------------------------------------------------

    @property
    def node_id(self) -> str:
        return self.identity.node_id

    @property
    def key(self) -> bytes:
        return self.identity.ed25519_public

    def set_state(self, new: State, *, reason: str = "", force: bool = False) -> None:
        """Change the declared state along the transitions of [ARCH 5.6]."""
        from usmd_rdsh.node.states import transition_allowed  # pylint: disable=import-outside-toplevel

        if not force and not transition_allowed(self.state, new):
            raise ValueError(f"transition {self.state.name} -> {new.name} is not allowed "
                             "[ARCH 5.6]")
        if new != self.state:
            self.event(f"State {self.state.name} -> {new.name}{': ' + reason if reason else ''}")
        self.state = new

    def event(self, text: str, level: int = logging.INFO) -> None:
        self.events = (self.events + [f"{time.strftime('%H:%M:%S')} {text}"])[-200:]
        log.log(level, "[NODE] %s", text)

    def _save_admission(self) -> None:
        self.state_dir.write_json({
            "state": int(self.state),
            "token": self.token.encode().hex() if self.token else None,
            "endorsement": self.endorsement.encode().hex() if self.endorsement else None,
            "management": {str(k): v for k, v in self.management.items()},
            "mutation": self.mutation,
            "references": self.references,
            "record_date": self.record_date,
            "table": [e.encode().hex() for e in self.tables.nodes.sorted()],
            "nel": [p.encode().hex() for p in self.tables.nel],
        }, "admission.json")

    def _load_admission(self) -> None:
        data = self.state_dir.read_json("admission.json", default=None)
        if not data:
            return
        try:
            if data.get("token"):
                self.token = CreationToken.read(Reader(bytes.fromhex(data["token"])))
            if data.get("endorsement"):
                self.endorsement = EndorsementPacket.decode(bytes.fromhex(data["endorsement"]))
                self.endorser = self.endorsement.endorser
            for raw in data.get("table", []):
                entry = TableEntry.read(Reader(bytes.fromhex(raw)))
                self.tables.nodes.merge(entry.token, entry.record)
            self.tables.nodes.take_modified()
            self.tables.nel = [EndorsementPacket.decode(bytes.fromhex(r))
                               for r in data.get("nel", [])]
        except (WireError, ValueError):
            self.event("Saved admission state unreadable; starting unadmitted", logging.ERROR)
            return
        self.management = {int(k): v for k, v in (data.get("management") or {}).items()}
        self.mutation = data.get("mutation", "")
        self.references = list(data.get("references", []))
        self.record_date = int(data.get("record_date", 0))
        saved = State(int(data.get("state", 0)))
        # An admitted node restarts synchronising, then becomes Active again.
        self.state = State.SYNCHRONISING if saved != State.APPROVAL_REQUIRED else saved
        for entry in self.tables.nodes.entries.values():
            self._learn_entry(entry.token, entry.record)

    def save_signed(self) -> None:
        self.signed.save(self.state_dir)
        if self.on_signed_change is not None:
            self.on_signed_change()

    @property
    def admitted(self) -> bool:
        return self.endorsement is not None or self._is_founder_admitted()

    def _is_founder_admitted(self) -> bool:
        return self.tables.nodes.get(self.key) is not None and self.token is not None \
            and self.token.founder

    # ------------------------------------------------------------------
    # Trust anchors [ARCH 4.4] and authority keys
    # ------------------------------------------------------------------

    @property
    def usc_key(self) -> bytes | None:
        """The authority key: trust anchor, else the in-force USC properties."""
        if self.settings.usc_anchor:
            return unb64u(self.settings.usc_anchor)
        if self.authority.usc is not None:
            return self.authority.usc.public
        return None

    @property
    def usd_key(self) -> bytes | None:
        if self.settings.usd_anchor:
            return unb64u(self.settings.usd_anchor)
        if self.signed.usd is not None:
            return self.signed.usd.public_key
        if self.authority.usd is not None:
            return self.authority.usd.public
        return None

    def apply_anchors(self) -> None:
        if self.usc_key:
            self.tables.nal.grant(self.usc_key, [Role.USC_OPERATOR], anchor=True)
        if self.usd_key:
            self.tables.nal.grant(self.usd_key, [Role.USD_OPERATOR], anchor=True)
        self.tables.nal.grant(self.key, self.settings.roles or [Role.NODE_EXECUTOR], anchor=True)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self.settings.address = self.settings.address or local_ipv4()
        self.apply_anchors()
        if self.settings.creation_token and self.token is None:
            self.install_token(self.settings.creation_token)
        await self._start_ncp()
        await self._start_nndp()
        await self.start_sp()
        self._start_raft()
        loops = [self._bootstrap_loop, self._load_loop, self._distance_loop,
                 self._properties_loop, self._reconcile_loop, self._healing_loop,
                 self._health_loop, self._dependency_loop, self._maintenance_loop]
        self._tasks = [asyncio.create_task(loop(), name=loop.__name__) for loop in loops]
        self.event(f"Node {self.node_id} started in state {self.state.name}")

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        if self.nndp:
            await self.nndp.stop()
        if self.raft:
            await self.raft.stop()
        if self.ncp:
            self.ncp.close()
        await self.stop_sp()

    async def _start_ncp(self) -> None:
        loop = asyncio.get_running_loop()
        self.ncp = NcpTransport(
            self.identity.signing, self.identity.agreement,
            x25519_of=self.x25519_of, handler=self.handle_request,
            address_known=self._address_known, reply_x25519=self._reply_x25519,
            freshness_ms=self.settings.freshness_s * 1000,
            retransmit_s=self.settings.ncp_retransmit, attempts=self.settings.ncp_attempts,
        )
        # Bound to the node's own address, so several nodes can share a host.
        await loop.create_datagram_endpoint(
            lambda: self.ncp, local_addr=(self.settings.bind_address, self.settings.ncp_port))


    async def _start_nndp(self) -> None:
        hooks = NndpHooks(
            state=lambda: int(self.state if not self.state.excluded else State.INACTIVE),
            reference_addresses=self.reference_addresses,
            hosted=lambda: [addresses.pack(s, self.management[s]) for s in sorted(self.hosted)
                            if s in self.management],
            is_admitted=self.is_admitted_key,
            nit_accepts=lambda key, address: self.tables.nit.accepts(key, address),
            my_services=self.my_area_services,
            rtt_ms=lambda key: self.rtt.get(key),
            ping_tolerance_ms=lambda: parameter(self.signed.usd, 0x0002) or 1000,
            on_neighbor=self._on_neighbor,
            on_inactive=self._on_neighbor_inactive,
            on_vector_change=lambda: self.nndp.trigger() if self.nndp else None,
            my_addresses=lambda: {addresses.pack(s, m) for s, m in self.management.items()},
        )
        self.nndp = NndpService(
            lambda: self.node_id, self.identity.signing, self.identity.x25519_public, hooks,
            interval_s=self.settings.hia_interval, freshness_s=self.settings.nndp_freshness_s,
            source_port=self.settings.nndp_source_port,
            destination_port=self.settings.nndp_destination_port,
            k=parameter(self.signed.usd, 0x000A) or 3,
            bind_address=self.settings.bind_address,
            broadcast_targets=self.settings.dev_peers,
        )
        if self.settings.nndp_enabled:
            try:
                await self.nndp.start()
            except OSError as exc:
                self.event(f"NNDP could not bind its ports: {exc}", logging.ERROR)

    async def restart_nndp(self) -> None:
        if self.nndp is None:
            return
        await self.nndp.stop()
        self.nndp.interval_s = self.settings.hia_interval
        self.nndp.freshness_s = self.settings.nndp_freshness_s
        self.nndp.source_port = self.settings.nndp_source_port
        self.nndp.destination_port = self.settings.nndp_destination_port
        if self.settings.nndp_enabled:
            await self.nndp.start()

    # ------------------------------------------------------------------
    # Tables helpers
    # ------------------------------------------------------------------

    def x25519_of(self, key: bytes, address: str) -> bytes | None:
        known = self.tables.nit.x25519_of(key)
        if known is not None:
            return known
        pending = getattr(self, "_approval_x25519", {}).get(key)
        if pending is not None:
            return pending
        if key in self._foreign_x25519:
            return self._foreign_x25519[key]
        if self.nndp is not None:
            for neighbor in self.nndp.neighbors.values():
                if neighbor.public_key == key:
                    return neighbor.x25519
        return None

    def _address_known(self, address: str) -> bool:
        """Whether a new NCP message from *address* is worth decrypting [NCP 10]."""
        if self.tables.nit.address_known(address) or address == self.settings.contact_node:
            return True
        return any(e.record.address == address for e in self.tables.nodes.entries.values())

    def _reply_x25519(self, message) -> bytes | None:
        """The requester's X25519 key carried in a Request_approval [NCP 6.7]."""
        return getattr(self, "_approval_x25519", {}).get(message.sender)

    def is_admitted_key(self, key: bytes) -> bool:
        return self.tables.nodes.get(key) is not None and \
            not self.tables.exclusions.is_excluded(key)

    def node_key(self, node_id: str) -> bytes | None:
        entry = self.tables.nodes.by_id(node_id)
        return entry.key if entry else None

    def peer_state(self, key: bytes) -> State:
        """Observed state first, else the declared one."""
        if key in self.observed:
            return self.observed[key]
        entry = self.tables.nodes.get(key)
        return State(entry.record.state) if entry else State.INACTIVE

    def active_nodes(self) -> list[str]:
        return [e.record.node_id for e in self.tables.nodes.sorted()
                if e.key != self.key and self.peer_state(e.key) == State.ACTIVE
                and not self.tables.exclusions.is_excluded(e.key)]

    def reference_addresses(self) -> list[tuple[bytes, str]]:
        out = []
        for node_id in self.references:
            entry = self.tables.nodes.by_id(node_id)
            if entry is not None:
                out.append((entry.key, entry.record.address))
        return out

    def my_areas(self) -> set[int]:
        return self.signed.areas_of_mutation(self.mutation) if self.mutation else set()

    def my_area_services(self) -> set[int]:
        return self.signed.services_in_areas(self.my_areas())

    def _learn_entry(self, token: CreationToken, record: NodeRecord) -> None:
        """NIT and NAL from a node-table entry [7.9]."""
        self.tables.nit.associate(token.node_key, record.node_id, record.address,
                                  record.x25519)  # TTL 300 s, renewed by traffic [ARCH 4.3]
        if not self.tables.exclusions.is_excluded(token.node_key):
            self.tables.nal.grant(token.node_key, token.roles)

    def renew_nit(self, key: bytes, address: str) -> None:
        """A valid HIA or authenticated message renews the (key, address) TTL."""
        entry = self.tables.nodes.get(key)
        known = self.tables.nit.entries.get(key)
        if known is not None and address in known.addresses:
            self.tables.nit.associate(key, known.node_id, address, known.x25519)
        elif entry is not None and entry.record.address == address:
            self.tables.nit.associate(key, entry.record.node_id, address, entry.record.x25519)

    # ------------------------------------------------------------------
    # NNDP hooks
    # ------------------------------------------------------------------

    def _on_neighbor(self, neighbor: Neighbor, is_new_key: bool) -> None:
        observed = self.observed.get(neighbor.public_key)
        if observed == State.INACTIVE_NNDP_TIMEOUT or (
                observed is not None and neighbor.state == State.ACTIVE):
            # A valid HIA ends 0x3400 [NNDP 6.3]; an Active one heals [ARCH 7.6].
            del self.observed[neighbor.public_key]
            self.event(f"{neighbor.node_id} is back (HIA)")
            self._soon(self.measure_distances())  # [ARCH 7.6]
        self.renew_nit(neighbor.public_key, neighbor.address)
        if is_new_key and self.tables.nit.knows(neighbor.public_key) is False:
            self.event(f"Discovered {neighbor.node_id} at {neighbor.address}", logging.DEBUG)

    def _on_neighbor_inactive(self, neighbor: Neighbor) -> None:
        if self.is_admitted_key(neighbor.public_key):
            self.observed[neighbor.public_key] = State.INACTIVE_NNDP_TIMEOUT
            self.event(f"{neighbor.node_id} silent for 2 x I: 0x3400")
            if neighbor.node_id in self.references:
                self.references.remove(neighbor.node_id)
                if self.token is not None and self.tables.nodes.get(self.key) is not None:
                    self.publish_record()  # references are in the record [NCP 7.8]
                self._soon(self.measure_distances())  # replaced at once [ARCH 6.4]
            if self.sp:
                self.sp.drop_peer(neighbor.public_key)
            self._soon(self.take_over(neighbor.public_key))

    def _soon(self, coroutine) -> None:
        """Run *coroutine* in the background when the node is running."""
        if not self._tasks:
            coroutine.close()
            return
        task = asyncio.get_running_loop().create_task(self._quiet(coroutine))
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def take_over(self, key: bytes) -> None:
        """A mutation holder fell silent: a reference node of it whose help keeps the
        mutation above its minimum takes it over [ARCH 7.5, 9.4], once."""
        entry = self.tables.nodes.get(key)
        if entry is None or not entry.record.mutation or self.mutation:
            return
        if self.node_id not in entry.record.reference_nodes:
            return
        mutation = entry.record.mutation
        props = self.signed.mutations.get(mutation)
        if props is None or self.instance_count(mutation) >= max(props.min_instances, 1):
            return
        if self._can_take(0, mutation):
            await self.transmute(mutation, reason=f"{entry.record.node_id} lost (0x3400)")

    # ------------------------------------------------------------------
    # NCP client side
    # ------------------------------------------------------------------

    async def call(self, node_id_or_key: str | bytes, command: Command, body: bytes = b"",
                   *, address: str | None = None, x25519: bytes | None = None,
                   attempts: int | None = None) -> bytes:
        """One NCP request to a node of the table (or an explicit address/key)."""
        key = node_id_or_key if isinstance(node_id_or_key, bytes) else \
            self.node_key(node_id_or_key)
        if key is None:
            raise NcpTimeout(f"unknown node {node_id_or_key!r}")
        address = address or self.tables.nit.address_of(key)
        x25519 = x25519 or self.x25519_of(key, address or "")
        if address is None or x25519 is None or self.ncp is None:
            raise NcpTimeout("no address or key for this node")
        started = time.monotonic()
        answer = await self.ncp.request((address, self.settings.ncp_port), int(command), body,
                                        key, x25519, attempts)
        if command == Command.CHECK_DISTANCE_TO_NODE:
            # Only a measured round trip counts as t [ARCH 6.2, NNDP 6.5].
            self.rtt[key] = (time.monotonic() - started) * 1000
        return answer

    # ------------------------------------------------------------------
    # Creation token, bootstrap, admission [ARCH 5.1-5.4, NCP 7.2, 7.7]
    # ------------------------------------------------------------------

    def install_token(self, text: str) -> CreationToken:
        token = CreationToken.read(Reader(unb64u(text.strip())))
        if token.node_key != self.key:
            raise ValueError("this creation token is bound to another node key")
        token.verify()
        self.token = token
        self._save_admission()
        return token

    def initial_record(self) -> NodeRecord:
        self.record_date = max(self.record_date + 1, now_ms())
        return NodeRecord(self.node_id, self.settings.address, self.identity.x25519_public,
                          int(State.APPROVAL_REQUIRED), self.record_date).sign(
            self.identity.signing)

    def current_record(self) -> NodeRecord:
        held = self.tables.nodes.get(self.key)
        return held.record if held else self.initial_record()

    def publish_record(self) -> NodeRecord:
        """A new record each time something it carries changes [NCP 7.8]."""
        self.record_date = max(self.record_date + 1, now_ms())
        state = self.state if self.state.declarable else State.INACTIVE
        sp_addrs = [addresses.pack(s, m) for s, m in sorted(self.management.items())]
        voter = bool(self.raft and self.raft.is_voter)
        record = NodeRecord(self.node_id, self.settings.address, self.identity.x25519_public,
                            int(state), self.record_date, self.mutation, list(self.references),
                            sp_addrs, voter, operators=sorted(self.elected_roles)
                            ).sign(self.identity.signing)
        if self.token is not None:
            self.tables.nodes.merge(self.token, record)
            self._learn_entry(self.token, record)
            self.schedule_relay(None, [self.key])
        self._save_admission()
        return record

    def candidates(self) -> list[tuple[bytes | None, str, bytes | None]]:
        """(key, address, x25519) to ask for admission, in the order of [5.2]."""
        out: list[tuple[bytes | None, str, bytes | None]] = []
        if self.settings.contact_node:
            # A contact node beyond the segment is never heard: its keys come
            # with the bootstrap settings (see recette, open point).
            heard = self._heard_at(self.settings.contact_node)
            ed = unb64u(self.settings.contact_ed25519) if self.settings.contact_ed25519 else None
            x = unb64u(self.settings.contact_x25519) if self.settings.contact_x25519 else None
            out.append((heard.public_key if heard else ed, self.settings.contact_node,
                        heard.x25519 if heard else x))
        for address in self.edb_addresses():
            heard = self._heard_at(address)
            if heard:
                out.append((heard.public_key, address, heard.x25519))
        if self.nndp:
            for neighbor in self.nndp.neighbors.values():
                if not neighbor.inactive and neighbor.state == State.ACTIVE:
                    out.append((neighbor.public_key, neighbor.address, neighbor.x25519))
        return out

    def _heard_at(self, address: str) -> Neighbor | None:
        if self.nndp is None:
            return None
        return next((n for n in self.nndp.neighbors.values() if n.address == address), None)

    _edb_cache: tuple[float, list[str]] = (0.0, [])

    def edb_addresses(self) -> list[str]:
        """Contact addresses of the EDB [ARCH 3.4], cached 5 minutes."""
        domain = self.settings.edb_domain
        if not domain:
            return []
        fetched, cached = self._edb_cache
        if time.monotonic() - fetched < 300:
            return cached
        self._edb_cache = (time.monotonic(), cached)  # one fetch at a time
        self._soon(self._fetch_edb(f"https://{domain}/.well-known/usmd/edb"))
        return cached

    async def _fetch_edb(self, url: str) -> None:
        """Fetch and validate the EDB, off the event loop [ARCH 3.4]."""
        def fetch() -> str:
            context = ssl.create_default_context()  # the certificate DOIT be validated
            with urllib.request.urlopen(url, timeout=5, context=context) as answer:
                return answer.read().decode("utf-8")

        try:
            text = await asyncio.to_thread(fetch)
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            self.event(f"EDB {url} unreachable: {exc}", logging.WARNING)
            return
        self._edb_cache = (time.monotonic(), parse_edb(text))

    async def _bootstrap_loop(self) -> None:
        rounds = 0
        while True:
            await asyncio.sleep(2 if rounds == 0 else self.settings.hia_interval)
            if self.state != State.APPROVAL_REQUIRED:
                if self.state == State.SYNCHRONISING and self.admitted:
                    await self.finish_synchronisation()
                continue
            if self.token is None:
                continue
            rounds += 1
            for key, address, x25519 in self.candidates():
                if key is None or x25519 is None:
                    continue
                if await self.request_approval(key, address, x25519):
                    break
            else:
                # [NCP 7.7] founder: nobody admitted found at the end of bootstrap.
                if self.token.founder and rounds >= 3 and not self.candidates():
                    await self.found()

    async def request_approval(self, key: bytes, address: str, x25519: bytes) -> bool:
        """[NCP 6.7, 7.2]."""
        assert self.token is not None
        record = self.initial_record()
        body = (self.token.encode() + record.encode() + secrets.token_bytes(16)
                + Writer().u16(len(self.token.roles)).raw(bytes(self.token.roles)).bytes())
        try:
            answer = await self.call(key, Command.REQUEST_APPROVAL, body, address=address,
                                     x25519=x25519)
        except NcpRemoteError as exc:
            if exc.code == 0x0008:
                self.identity.regenerate_id()
                save_identity(self.state_dir, self.identity, self.identity_file or None)
                self.event("Identifier already used: new ULID generated")
            else:
                self.event(f"Admission refused by {address}: {exc}", logging.WARNING)
            return False
        except NcpTimeout:
            return False
        reader = Reader(answer)
        if not reader.boolean():
            return False
        packet = EndorsementPacket.read(reader)
        try:
            packet.verify()
        except CryptoError:
            return False
        self.endorsement, self.endorser = packet, packet.endorser
        self.tables.nit.associate(key, "", address, x25519)
        self.set_state(State.SYNCHRONISING, reason="endorsed")
        self.event(f"Endorsed by {address}: synchronising")
        self._save_admission()
        return True

    async def found(self) -> None:
        """Founder self-admission [NCP 7.7, ARCH 12.2]."""
        assert self.token is not None
        record = self.initial_record()
        self.tables.nodes.merge(self.token, record)
        self._learn_entry(self.token, record)
        self._start_raft(found=True)
        self.set_state(State.ACTIVE, reason="founder", force=True)
        self.publish_record()
        self.event("No admitted node found: founded the USD", logging.WARNING)

    async def finish_synchronisation(self) -> None:
        """[ARCH 5.4]: choose references, inform them, record Active."""
        if len(self.tables.nodes.entries) <= 1 and self.endorser is not None:
            return  # still waiting for the endorser's table
        await self.measure_distances()
        # References learn they are ours before our records are relayed to them.
        await self.inform_references()
        self.set_state(State.ACTIVE, reason="synchronised")
        self.publish_record()

    # ------------------------------------------------------------------
    # Load and distances [ARCH 6]
    # ------------------------------------------------------------------

    async def _load_loop(self) -> None:
        while True:
            await asyncio.sleep(parameter(self.signed.usd, 0x0007) or 5)
            self.load.sample()
            if self.state == State.ACTIVE or self.state.inactive:
                await self.check_weakness()
            if self.nndp:
                for service in self.hosted:
                    if service in self.management:
                        self.nndp.services.set_local(addresses.pack(service,
                                                                    self.management[service]),
                                                     self.load.reference)

    async def measure(self, node_id: str) -> distance.Measure | None:
        key = self.node_key(node_id)
        if key is None:
            return None
        try:
            started = time.monotonic()
            answer = await self.call(key, Command.CHECK_DISTANCE_TO_NODE,
                                     Writer().u64(now_ms()).bytes())
            rtt = (time.monotonic() - started) * 1000
        except (NcpTimeout, NcpRemoteError):
            return None
        try:
            reader = Reader(answer)
            reader.u64()
            load, service, has_us = _permille(reader), reader.string(), reader.boolean()
            reader.end()
        except WireError:
            return None  # a malformed answer is no measure [NCP 6.1]
        self.loads[node_id] = load
        self.referenced_by.setdefault(node_id, [])
        return distance.Measure(node_id, rtt, load, service, has_us)

    def my_service_name(self) -> str:
        return self.mutation

    async def measure_distances(self) -> None:
        tolerance = parameter(self.signed.usd, 0x0002) or 1000
        nnr = parameter(self.signed.usd, 0x0001) or 5
        targets = distance.sample(self.active_nodes(), self.references)
        measures = await asyncio.gather(*(self.measure(n) for n in targets))
        self.distances = {}
        for m in measures:
            if m is None:
                continue
            d = distance.distance(m, self.my_service_name(), tolerance)
            if d is not None:
                self.distances[m.node_id] = d
        inactive = {n for n in self.references if n not in self.active_nodes()}
        chosen = distance.reselect(self.references, self.distances, nnr, inactive)
        if chosen != self.references:
            self.references = chosen
            self.event(f"Reference nodes: {', '.join(chosen) or 'none'}")
            if self.state == State.ACTIVE or self.state.inactive:
                await self.inform_references()
                self.publish_record()  # references are in the record [NCP 7.8]

    async def inform_references(self) -> None:
        from usmd_rdsh.node.ncp.codec import ids  # pylint: disable=import-outside-toplevel

        body = ids(self.references)
        await asyncio.gather(*(self._quiet(self.call(n, Command.INFORM_REFERENCE_NODE, body))
                               for n in self.references))

    @staticmethod
    async def _quiet(coroutine) -> Any:
        try:
            return await coroutine
        except (NcpTimeout, NcpRemoteError, WireError, OSError):
            return None

    async def _distance_loop(self) -> None:
        while True:
            await asyncio.sleep(parameter(self.signed.usd, 0x0006) or 300)
            if self.state == State.ACTIVE:
                await self.measure_distances()

    # ------------------------------------------------------------------
    # Configuration propagation [ARCH 9.3, NCP 6.8-6.10]
    # ------------------------------------------------------------------

    async def push_properties(self, targets: list[str] | None = None) -> None:
        targets = self.references if targets is None else targets
        bodies = []
        if self.signed.usc:
            bodies.append((Command.SEND_USC_PROPERTIES, self.signed.usc.encode()))
        if self.signed.usd:
            bodies.append((Command.SEND_USD_PROPERTIES, self.signed.usd.encode()))
        if self.signed.mutations:
            # A version still being updated here is not propagated yet [ARCH 8.5].
            mutations = [self.updating.get(name, m) for name, m in self.signed.mutations.items()]
            bodies.append((Command.SEND_MUTATION_PROPERTIES, encode_mutations(mutations)))
        for node_id in targets:
            for command, body in bodies:
                await self._quiet(self.call(node_id, command, body))

    async def _properties_loop(self) -> None:
        while True:
            await asyncio.sleep(_jitter(self.settings.properties_interval))
            if self.state == State.ACTIVE:
                await self.push_properties()

    def inject(self, usc: UscProperties | None = None, usd: UsdProperties | None = None,
               mutations: list[MutationProperties] | None = None) -> list[str]:
        """The authority injects new signed objects here [9.3]."""
        authority = self.usc_key
        if authority is None:
            raise ValueError("no authority key known")
        applied = []
        if usc is not None and self.signed.offer_usc(usc, authority):
            applied.append("usc")
        if usd is not None and self.signed.offer_usd(usd, authority):
            applied.append("usd")
        for mutation in mutations or []:
            previous = self.signed.mutations.get(mutation.name)
            if self.signed.offer_mutation(mutation, authority):
                applied.append(f"mutation {mutation.name}")
                if mutation.name == self.mutation:
                    self._soon(self.apply_mutation_update(mutation.name, previous))
        if applied:
            self.save_signed()
            self.on_config_changed()
            self._soon(self._push_after_updates())
        return applied

    async def _push_after_updates(self) -> None:
        """Propagate once local updates finished (a failed one is rolled back)."""
        while self.updating:
            await asyncio.sleep(0.2)
        await self.push_properties()

    def on_config_changed(self) -> None:
        """New USD or mutation properties: areas, ids, SP and services follow."""
        if self.nndp:
            self.nndp.services.k = parameter(self.signed.usd, 0x000A) or 3
        if self.sp:
            self.sp.mtu = parameter(self.signed.usd, 0x0013) or 1412
        if not self._tasks:
            return  # not started (``usmd -c``): nothing runs yet
        loop = asyncio.get_running_loop()
        loop.create_task(self.request_management_ids())
        loop.create_task(self.restart_sp())


    # ------------------------------------------------------------------
    # Node table propagation [NCP 7.9]
    # ------------------------------------------------------------------

    def accept_entry(self, entry: TableEntry, *, for_admission: bool = False) -> bool:
        """Verify and merge one (token, record); True when it changed the table."""
        usd_key = self.usd_key
        if usd_key is None:
            return False
        held = self.tables.nodes.get(entry.token.node_key)
        if held is not None and entry.record.date <= held.record.date:
            return False  # not newer: no signature work [NCP 7.9, 10]
        try:
            entry.verify(usd_key)
            self.check_token(entry.token, for_admission=for_admission)
        except (WireError, CryptoError, ValueError):
            return False
        record = entry.record
        try:
            if not State(record.state).declarable:
                return False  # origin O never travels [NCP 7.8]
        except ValueError:
            return False
        if record.date > now_ms() + self.settings.freshness_s * 1000:
            return False
        if self.tables.exclusions.is_excluded(entry.token.node_key):
            return False
        raft = self.raft
        if raft is not None and raft.is_voter and raft.commit_index:
            for address in record.sp_addresses:
                owner = raft.state.assignments.get(((address >> 16) & 0xFFF, address & 0xFFFF))
                if owner is None or owner.key != entry.token.node_key:
                    self.event(f"{record.node_id} publishes an SP address the master did not "
                               "assign it: record ignored", logging.WARNING)
                    return False  # [NCP 7.8, 10]
        if self.tables.nodes.merge(entry.token, record):
            self._learn_entry(entry.token, record)
            if record.state == State.ACTIVE and self.state == State.ACTIVE and \
                    len(self.references) < (parameter(self.signed.usd, 0x0001) or 5) and \
                    not self._measuring:
                # A new active node and free reference slots: choose now [ARCH 6.3].
                self._measuring = True
                self._soon(self._measure_once())
            return True
        return False

    async def _measure_once(self) -> None:
        try:
            await asyncio.sleep(1)
            await self.measure_distances()
        finally:
            self._measuring = False

    def check_token(self, token: CreationToken, *, for_admission: bool,
                    requester: bytes | None = None) -> None:
        """[NCP 7.7] acceptance rules (expiry and binding only for an admission)."""
        anchors = {k for k in (self.usd_key,) if k}
        if token.issuer not in anchors:
            raise ValueError("token not issued by the USD key")
        token.verify()
        usdn = self.signed.usd.usdn if self.signed.usd else None
        if usdn is not None and token.usdn != usdn:
            raise ValueError("token issued for another USD")
        if token.expires - token.issued > 7 * 24 * 3600 * 1000:
            raise ValueError("token valid more than 7 days")
        if for_admission:
            now = now_ms()
            if requester is not None and token.node_key != requester:
                raise ValueError("token bound to another key")
            if not token.issued - self.settings.freshness_s * 1000 <= now <= token.expires:
                raise ValueError("token not yet valid or expired")

    def schedule_relay(self, sender: bytes | None, keys: list[bytes] | None = None) -> None:
        """Relay modified entries in increment mode after at most 1 s [7.9].

        *sender* is who the change of *keys* came from (None: ourselves); the
        latest change of an entry decides whom it is not relayed back to.
        """
        for entry in self.tables.nodes.entries.values():
            if keys is not None and entry.key in keys:
                self._relay_from[entry.key] = sender
            elif entry.modified:
                self._relay_from.setdefault(entry.key, sender)
        if self._relay_task is None or self._relay_task.done():
            try:
                self._relay_task = asyncio.get_running_loop().create_task(self._relay())
            except RuntimeError:
                pass

    async def _relay(self) -> None:
        try:
            await self._relay_once()
        except Exception:  # pylint: disable=broad-except
            log.exception("[NODE] Relay of the node table failed")

    async def _relay_once(self) -> None:
        await asyncio.sleep(self.settings.relay_delay)
        modified = self.tables.nodes.take_modified()
        senders = self._relay_from
        self._relay_from = {}
        self._save_admission()
        for node_id in self.references:
            key = self.node_key(node_id)
            entries = [e for e in modified if senders.get(e.key) != key]
            log.debug("[NODE] Relaying %d modified entries to %s", len(entries), node_id)
            if entries:
                await self._quiet(self.send_table(node_id, entries, mode=0x01))

    async def send_table(self, node_id_or_key: str | bytes, entries, *, mode: int,
                         address: str | None = None, x25519: bytes | None = None) -> None:
        """Send entries in pages that each fit one message [6.14]."""
        pages: list[list] = [[]]
        size = 0
        for entry in entries:
            raw = entry.encode() if hasattr(entry, "encode") else entry
            if size + len(raw) > 1000 * 1111:
                pages.append([])
                size = 0
            pages[-1].append(TableEntry(entry.token, entry.record) if hasattr(entry, "token")
                             else entry)
            size += len(raw)
        peer = node_id_or_key if isinstance(node_id_or_key, bytes) else \
            self.node_key(node_id_or_key)
        if mode == 0x01:
            # An increment is one page per exchange [6.14].
            exchanges = [(page, 0, 1) for page in pages]
        else:
            exchanges = [(page, i, len(pages)) for i, page in enumerate(pages)]
        for page, index, count in exchanges:
            body = (Writer().u8(mode).u16(index).u16(count).u16(len(page))
                    .raw(b"".join(e.encode() for e in page)).bytes())
            started = time.monotonic()
            answer = await self.call(node_id_or_key, Command.SEND_NODE_TABLE, body,
                                     address=address, x25519=x25519)
            elapsed = time.monotonic() - started
            if len(body) >= 8 * 1111 and elapsed > 0:
                # D for Tm = Tmoy + V / D [ARCH 7.1]: measured on large exchanges.
                rate = (len(body) + len(answer)) / elapsed
                self.transfer_rate = rate if not self.transfer_rate else \
                    0.7 * self.transfer_rate + 0.3 * rate
            reader = Reader(answer)
            accepted = []
            for _ in range(reader.u16()):
                entry = TableEntry.read(reader)
                if self.accept_entry(entry):
                    accepted.append(entry.token.node_key)
            if accepted:
                self.schedule_relay(peer, accepted)

    async def _reconcile_loop(self) -> None:
        while True:
            await asyncio.sleep(_jitter(self.settings.reconcile_interval))
            if self.references and self.state == State.ACTIVE:
                await self._quiet(self.send_table(random.choice(self.references),
                                                  self.tables.nodes.sorted(), mode=0x00))

    # ------------------------------------------------------------------
    # Healing and endorsement verification [ARCH 7.6, NCP 7.4]
    # ------------------------------------------------------------------

    async def _healing_loop(self) -> None:
        while True:
            await asyncio.sleep(parameter(self.signed.usd, 0x000B) or 60)
            for key, observed in list(self.observed.items()):
                if observed.family != 0x3:
                    continue
                try:
                    answer = await self.call(key, Command.GET_STATUS)
                except (NcpTimeout, NcpRemoteError):
                    continue
                try:
                    reader = Reader(answer)
                    for _ in range(4):
                        _permille(reader)
                    reader.string()
                    declared = reader.u16()
                    reader.end()
                except WireError:
                    continue
                if declared == State.ACTIVE:
                    del self.observed[key]
                    self.event("A peer answered Get_status Active: healed")
                    await self.measure_distances()
            await self.enforce_instance_bounds()

    async def verify_endorsement_of(self, key: bytes, address: str) -> None:
        """[NCP 7.4]: Endorsement_check_required, then Verify_endorsement."""
        if key in self.tables.endorsements or self.tables.nodes.get(key) is None:
            return
        try:
            packet = EndorsementPacket.decode(await self.call(key, Command.ENDORSEMENT_CHECK_REQUIRED,
                                                              address=address))
            packet.verify()
            entry = self.tables.nodes.get(key)
            if packet.node_key != key or packet.expiration < now_ms() or entry is None \
                    or packet.node_id != entry.record.node_id \
                    or packet.node_x25519 != entry.record.x25519 \
                    or not set(packet.roles) <= set(entry.token.roles):
                raise CryptoError("packet for another node, expired, or wider than the token")
        except (CryptoError, WireError):
            self.tables.exclusions.exclude(key, State.EXCLUDED_INVALID_ENDORSEMENT)
            return
        except (NcpTimeout, NcpRemoteError):
            return
        endorser = packet.endorser
        if self.tables.nodes.get(endorser) is None and self.references:
            await self._quiet(self.send_table(random.choice(self.references),
                                              self.tables.nodes.sorted(), mode=0x00))
        try:
            answer = await self.call(endorser, Command.VERIFY_ENDORSEMENT, packet.encode())
            approved = Reader(answer).boolean()
        except (NcpTimeout, NcpRemoteError):
            self.tables.exclusions.exclude(key, State.EXCLUDED_UNVERIFIABLE_ENDORSEMENT,
                                           duration_ms=self.settings.exclusion_ms)
            return
        if not approved:
            self.tables.exclusions.exclude(key, State.EXCLUDED_INVALID_ENDORSEMENT)
            return
        self.tables.endorsements[key] = packet

    # ------------------------------------------------------------------
    # Retirement [ARCH 5.7, NCP 7.5]
    # ------------------------------------------------------------------

    async def rekey(self) -> Identity:
        """New Ed25519 and X25519 pairs; a new admission follows [ARCH 4.2]."""
        from usmd_rdsh.node.crypto import AgreementKey, SigningKey  # pylint: disable=import-outside-toplevel

        if self.mutation:
            await self.delegate_all(State.INACTIVE)
        self.identity.signing = SigningKey.generate()
        self.identity.agreement = AgreementKey.generate()
        save_identity(self.state_dir, self.identity, self.identity_file or None)
        # Every protocol switches to the new keys now, not at the next restart.
        if self.ncp is not None:
            self.ncp.close()
            await self._start_ncp()
        if self.nndp is not None:
            await self.nndp.stop()
            self.nndp = None
            await self._start_nndp()
        if self.sp is not None:
            await self.restart_sp()
        self.token = self.endorsement = self.endorser = None
        self.management = {}
        self.references = []
        self.set_state(State.APPROVAL_REQUIRED, reason="new keys")
        self._save_admission()
        self.event("Keys renewed: a new creation token and admission are needed",
                   logging.WARNING)
        return self.identity

    async def retire(self) -> None:
        for packet in list(self.tables.nel):
            await self._quiet(self.call(packet.node_key, Command.NOTIFY_END_OF_SERVICE,
                                        Writer().ident(self.node_id).bytes()))
        if self.endorser is not None:
            await self._quiet(self.call(self.endorser, Command.REQUEST_REVOCATION,
                                        Writer().ident(self.node_id).bytes()))
        if self.mutation:
            await self.delegate_all(State.INACTIVE)
        if self.nndp:
            await self.nndp.stop()
        self.event("Retired: no longer emitting", logging.WARNING)

    # ------------------------------------------------------------------
    # Raft and management identifiers [ARCH 11.4, 12]
    # ------------------------------------------------------------------

    def _start_raft(self, *, found: bool = False) -> None:
        if self.raft is None:
            self.raft = Raft(self.node_id, self.key, self.state_dir.path("raft.json"),
                             self._raft_send, heartbeat_s=self.settings.raft_heartbeat,
                             election_s=self.settings.raft_election,
                             on_voter_change=self._on_voter_change)
        if found:
            self.raft.found()
        try:
            self.raft.start()
        except RuntimeError:
            pass

    def _on_voter_change(self) -> None:
        """The voter flag is in our record: a new record [NCP 7.8]."""
        if self.token is not None and self.tables.nodes.get(self.key) is not None:
            self.publish_record()

    async def _raft_send(self, voter: str, command: int, body: bytes) -> bytes:
        return await self.call(voter, Command(command), body)

    async def request_management_ids(self, attempts: int = 3) -> None:
        """Ask the master for an id per service of our areas [11.4, NCP 6.15].

        The master reads our areas off our node record, so the record naming
        our mutation is relayed first; 0x000B (record not there yet) is retried.
        """
        if self._relay_task is not None and not self._relay_task.done():
            await self._relay_task
        wanted = sorted(s for s in self.my_area_services() if s not in self.management)
        if not wanted or self.state not in (State.ACTIVE, State.INACTIVE_MUTATING):
            return
        body = Writer().u16(len(wanted)).raw(b"".join(s.to_bytes(2, "big") for s in wanted))
        targets = [self.raft.leader] if self.raft and self.raft.leader else []
        voters = list(self.raft.voters if self.raft else {}) + list(self.known_voters)
        voters += [e.record.node_id for e in self.tables.nodes.sorted() if e.record.voter]
        targets += [v for v in voters if v not in targets]
        targets += [r for r in self.references if r not in targets]
        for target in targets:
            if target == self.node_id:
                answer = await self.allocate_management_ids(self.node_id, self.key, wanted)
            else:
                try:
                    answer = await self.call(target, Command.REQUEST_MANAGEMENT_ID, body.bytes())
                except NcpRemoteError as exc:
                    if exc.code == 0x000B and attempts > 1:
                        await asyncio.sleep(1)
                        await self.request_management_ids(attempts - 1)
                        return
                    continue
                except NcpTimeout:
                    continue
            reader = Reader(answer)
            status, _term, master = reader.u8(), reader.u64(), reader.raw(26)
            self.known_voters = [reader.ident() for _ in range(reader.u16())]
            if status == 0x00:
                for _ in range(reader.u16()):
                    service, management = reader.u16(), reader.u16()
                    self.management[service] = management
                self.publish_record()
                self.event(f"Management ids: {self.management}")
                return
            if status == 0x01 and master != bytes(26):
                leader = master.decode("ascii")
                if leader not in targets:
                    targets.append(leader)

    async def allocate_management_ids(self, node_id: str, key: bytes,
                                      services: list[int]) -> bytes:
        """The master's side of Request_management_id."""
        raft = self.raft
        voters = list(raft.voters) if raft else []

        def answer(status: int, pairs: list[tuple[int, int]] | None = None) -> bytes:
            master = (raft.leader if raft and raft.leader else "").encode("ascii") or bytes(26)
            out = Writer().u8(status).u64(raft.term if raft else 0).raw(master.ljust(26, b"\0"))
            out.u16(len(voters))
            for voter in voters:
                out.ident(voter)
            pairs = pairs or []
            out.u16(len(pairs))
            for service, management in pairs:
                out.u16(service).u16(management)
            return out.bytes()

        if raft is None or not raft.is_voter:
            return answer(0x01 if raft and raft.leader else 0x03)
        if not raft.is_leader:
            return answer(0x01 if raft.leader else 0x03)
        entry = self.tables.nodes.get(key)
        mutation = entry.record.mutation if entry else (self.mutation if key == self.key else "")
        allowed = self.signed.services_in_areas(self.signed.areas_of_mutation(mutation))
        if any(s not in self.signed.catalog() or s not in allowed for s in services):
            raise NcpRemoteError(0x000B, "service unknown or outside the requester's areas")
        from usmd_rdsh.node.raft import Assignment  # pylint: disable=import-outside-toplevel

        pairs, records = [], []
        state = raft.state
        for service in services:
            held = state.management_of(node_id, service)
            if held is None:
                # The state machine changes only once the record is committed.
                taken = {r.data[2:4] for r in records if r.data[:2] == service.to_bytes(2, "big")}
                free_for = getattr(raft, "free_id_for", None)
                held = free_for(service, {int.from_bytes(t, "big") for t in taken}) \
                    if free_for else next((m for m in range(1, 0xFFFF)
                                           if (service, m) not in state.assignments
                                           and m.to_bytes(2, "big") not in taken), None)
                if held is None:
                    continue
                records.append(assign_record(raft.term, Assignment(service, held, node_id, key)))
            pairs.append((service, held))
        if records and not await raft.propose(records, self.settings.ncp_retransmit):
            return answer(0x02)
        return answer(0x00, pairs)

    # ------------------------------------------------------------------
    # Roles: executor for all, operators elected by the master [ARCH 12.4]
    # ------------------------------------------------------------------

    #: Operators the master keeps elected per role: at least one USC operator
    #: and one USD operator in the USD, and one node operator when authorised.
    OPERATOR_MINIMUM = {Role.USC_OPERATOR: 1, Role.USD_OPERATOR: 1, Role.NODE_OPERATOR: 1}

    def authorised_roles(self, node_id: str) -> set[int]:
        """The roles *node_id*'s creation token authorises, unless revoked [NCP 7.7, ARCH 14]."""
        if node_id == self.node_id:
            return set(self.token.roles) if self.token else {int(r) for r in self.settings.roles}
        key = self.node_key(node_id)
        entry = self.tables.nodes.get(key) if key else None
        if entry is None or self.tables.exclusions.is_excluded(key) or not self.tables.nal.of(key):
            return set()
        return set(entry.token.roles)

    @property
    def elected_roles(self) -> set[int]:
        return {r for r, ids in self.operators.items() if self.node_id in ids}

    @property
    def roles(self) -> set[int]:
        """The roles this node exercises: executor, plus those it was elected to."""
        return {int(Role.NODE_EXECUTOR)} | self.elected_roles

    def set_operators(self, operators: dict[int, set[str]], term: int) -> None:
        """The master's table of operators; a change of our own roles changes our record."""
        before = self.elected_roles
        self.operators = {r: set(ids) for r, ids in operators.items() if ids}
        self.operators_term = max(self.operators_term, term)
        after = self.elected_roles
        if after != before:
            names = ", ".join(Role(r).name.lower() for r in sorted(after)) or "executor only"
            self.event(f"Operator roles of this node: {names}", logging.WARNING)
            if self.token is not None and self.tables.nodes.get(self.key) is not None:
                self.publish_record()

    def _serving(self, node_id: str) -> bool:
        if node_id == self.node_id:
            return self.state == State.ACTIVE
        key = self.node_key(node_id)
        return key is not None and self.peer_state(key) == State.ACTIVE and \
            not self.tables.exclusions.is_excluded(key)

    async def elect_operators(self, inactive_since: dict[tuple[int, str], float]) -> bool:
        """The master's side [ARCH 12.4]; at most one change per call, True when made.

        A holder that lost its authorisation is deposed at once, one inactive
        for longer than 0x0015 is deposed; while a role has fewer serving
        holders than its minimum, the oldest active node authorised for it
        (smallest ULID) is elected, as for voters [12.2].
        """
        raft = self.raft
        if raft is None or not raft.is_leader:
            return False
        now = time.monotonic()
        grace = parameter(self.signed.usd, 0x0015) or 600
        for role in OPERATOR_ROLES:
            holders = set(raft.state.operators.get(int(role), set()))
            for holder in sorted(holders):
                if int(role) not in self.authorised_roles(holder):
                    reason = "no longer authorised"
                elif self._serving(holder):
                    inactive_since.pop((role, holder), None)
                    continue
                elif now - inactive_since.setdefault((role, holder), now) <= grace:
                    continue
                else:
                    reason = "inactive"
                if await raft.propose([operator_record(raft.term, role, holder, elected=False)],
                                      5):
                    inactive_since.pop((role, holder), None)
                    self.event(f"{holder} deposed as {role.name.lower()} ({reason})",
                               logging.WARNING)
                return True
            if sum(1 for h in holders if self._serving(h)) >= self.OPERATOR_MINIMUM[role]:
                continue
            candidates = sorted(n for n in (self.node_id, *self.active_nodes())
                                if n not in holders and self._serving(n)
                                and int(role) in self.authorised_roles(n))
            if not candidates:
                if not holders and role in (Role.USC_OPERATOR, Role.USD_OPERATOR) and \
                        role not in self._unfilled:
                    self._unfilled.add(role)
                    self.event(f"No active node is authorised as {role.name.lower()}: "
                               "the USD has none [ARCH 12.4]", logging.ERROR)
                continue
            self._unfilled.discard(role)
            if await raft.propose([operator_record(raft.term, role, candidates[0], elected=True)],
                                  5):
                self.event(f"{candidates[0]} elected {role.name.lower()}", logging.WARNING)
            return True
        return False

    def operators_body(self) -> bytes:
        """Send_operators [NCP 6.19]: term ‖ master ‖ List<(role, node id)>."""
        out = Writer().u64(self.operators_term).ident(self.node_id)
        pairs = sorted((r, n) for r, ids in self.operators.items() for n in ids)
        out.u16(len(pairs))
        for role, node_id in pairs:
            out.u8(role).ident(node_id)
        return out.bytes()

    async def announce_operators(self) -> None:
        """The master tells the nodes outside the configuration, which have no log."""
        body = self.operators_body()
        voters = self.raft.voters if self.raft else {}
        await asyncio.gather(*(self._quiet(self.call(n, Command.SEND_OPERATORS, body))
                               for n in self.active_nodes() if n not in voters))

    # ------------------------------------------------------------------
    # Operate: an elected operator manages the other nodes [ARCH 12.5]
    # ------------------------------------------------------------------

    #: Transmissions of an Operate request (2+4+...+64 s): a command may take long.
    OPERATE_ATTEMPTS = 6

    def operator_scope(self) -> str:
        """"usc", "usd" or "" : what this node manages, by the roles it was elected to."""
        if Role.USC_OPERATOR in self.elected_roles:
            return "usc"
        if Role.USD_OPERATOR in self.elected_roles:
            return "usd"
        return ""

    def operator_ids(self, *roles: Role) -> set[str]:
        """Nodes elected to any of *roles*, as last known."""
        return set().union(*(self.operators.get(int(r), set()) for r in roles))

    async def operate(self, node_id: str, session: int, payload: bytes) -> bytes:
        """One console exchange with a node of this USD."""
        if not self.operator_scope():
            raise ValueError("this node is not an elected usc-operator or usd-operator "
                             "[ARCH 12.5]")
        body = OperateRequest(session, payload).encode()
        return await self.call(node_id, Command.OPERATE, body, attempts=self.OPERATE_ATTEMPTS)

    async def operate_foreign(self, usdn: str, session: int, payload: bytes,
                              target: str = "") -> bytes:
        """One console exchange with a node of another USD of the USC.

        Sent to that USD's elected usc-operator, which checks our credentials
        and relays to *target*; a contact node that is not one answers with
        the operators to ask instead.
        """
        if self.operator_scope() != "usc":
            raise ValueError("only an elected usc-operator manages the other USDs [ARCH 12.5]")
        if self.signed.usd is None or self.token is None:
            raise ValueError("no USD properties or creation token to present")
        usdn = usdn.upper()
        if self.signed.usc is None or usdn not in self.signed.usc.usd:
            raise ValueError(f"USD {usdn} is not a member of the USC in force")
        contact = self._usc_relays.get(usdn) or self.usc_peers.get(usdn)
        if contact is None:
            raise ValueError(f"no contact node for USD {usdn}: 'config trust usc-peer'")
        body = OperateRequest(session, payload, target, self.signed.usd, self.token,
                              self.identity.x25519_public).encode()
        for _ in range(3):
            address, key, x25519 = contact
            self._foreign_x25519[key] = x25519
            answer = await self.call(key, Command.OPERATE, body, address=address, x25519=x25519,
                                     attempts=self.OPERATE_ATTEMPTS)
            redirect = _redirect(answer)
            if redirect is None:
                self._usc_relays[usdn] = contact
                return answer
            if not redirect:
                raise ValueError(f"USD {usdn} has no elected usc-operator to relay")
            contact = redirect[0]
        raise ValueError(f"USD {usdn}: too many redirections")

    def operators_to_redirect(self) -> list[dict[str, str]]:
        """The usc-operators of this USD, for an operator of another USD."""
        out = []
        for node_id in sorted(self.operator_ids(Role.USC_OPERATOR)):
            entry = self.tables.nodes.by_id(node_id)
            if node_id == self.node_id:
                out.append({"address": self.settings.address, "ed25519": b64u(self.key),
                            "x25519": b64u(self.identity.x25519_public)})
            elif entry is not None:
                out.append({"address": entry.record.address, "ed25519": b64u(entry.key),
                            "x25519": b64u(entry.record.x25519)})
        return out

    def _sync_operators(self) -> None:
        """A voter reads the operators off its own applied state."""
        raft = self.raft
        if raft is None or not raft.is_voter or not raft.commit_index:
            return
        current = {r: ids for r, ids in raft.state.operators.items() if ids}
        if current != self.operators or raft.term > self.operators_term:
            self.set_operators(current, raft.term)

    async def _maintenance_loop(self) -> None:
        """Voters (Nv, oldest executor first, removal after 0x0015), operators,
        NIT expiry, SP timers."""
        inactive_since: dict[str, float] = {}
        operator_since: dict[tuple[int, str], float] = {}
        while True:
            await asyncio.sleep(1)
            self.tables.nit.expire()
            if self.sp:
                self.sp.tick()
            ticks = getattr(self, "_ticks", 0) + 1
            self._ticks = ticks
            if ticks % 30 == 0 and self.settings.bind_address == "0.0.0.0" and (
                    self.state == State.ACTIVE or self.state.inactive):
                address = local_ipv4()
                if address != self.settings.address and address != "127.0.0.1":
                    self.settings.address = address
                    self.publish_record()  # a new address, a new record [NCP 7.8]
            if self.delegation.handed_over and self.state.inactive and not self.mutation and \
                    self.load.reference < (parameter(self.signed.usd, 0x0004) or 800):
                # Back to Active once the services were handed over [ARCH 5.6].
                self.delegation.handed_over = False
                self.set_state(State.ACTIVE, reason="load back under the threshold")
                self.publish_record()
            self._sync_operators()
            raft = self.raft
            if raft is None or not raft.is_leader:
                continue
            if await self.elect_operators(operator_since):
                self._sync_operators()
                self._soon(self.announce_operators())
            elif ticks % 30 == 0 and self.operators:
                self._soon(self.announce_operators())  # nodes added since, lost messages
            voters = raft.voters
            now = time.monotonic()
            for voter in list(voters):
                if voter == self.node_id:
                    continue
                key = self.node_key(voter)
                if key is None or self.peer_state(key) != State.ACTIVE:
                    inactive_since.setdefault(voter, now)
                    if now - inactive_since[voter] > (parameter(self.signed.usd, 0x0015) or 600):
                        if await raft.propose([voter_record(raft.term, voter, None)], 5):
                            # The removed voter is told once, so it stops campaigning.
                            await self._quiet(raft._replicate_to(voter))  # pylint: disable=protected-access
                        inactive_since.pop(voter, None)
                        break
                else:
                    inactive_since.pop(voter, None)
            if len(raft.voters) < (parameter(self.signed.usd, 0x0014) or 5):
                for node_id in sorted(self.active_nodes()):  # oldest = smallest ULID
                    key = self.node_key(node_id)
                    if node_id in raft.voters or key is None:
                        continue
                    if Role.NODE_EXECUTOR in self.tables.nal.of(key) or \
                            self.tables.nal.allows(key, Role.NODE_EXECUTOR):
                        await raft.propose([voter_record(raft.term, node_id, key)], 5)
                        break

    # ------------------------------------------------------------------
    # Services, transmutation, delegation [ARCH 7, 8]
    # ------------------------------------------------------------------

    def mutation_specs(self, mutation: str) -> list[ServiceSpec]:
        """The services of a mutation in dependency order; the authority's
        signature is checked every time, before any command runs [ARCH 8.3]."""
        props = self.signed.mutations.get(mutation)
        if props is None:
            return []
        try:
            props.verify(self.usc_key or bytes(32))
        except CryptoError:
            self.event(f"Mutation '{mutation}' fails its authority signature: refused",
                       logging.ERROR)
            return []
        return dependency_order(parse_service_file(props.service_file))

    def uncatalogued(self, mutation: str) -> list[str]:
        """Services of a mutation the catalogue does not list [ARCH 11.1]."""
        return [s.name for s in self.mutation_specs(mutation)
                if self.signed.service_by_name(s.name) is None]

    async def transmute(self, mutation: str, *, reason: str = "") -> bool:
        """[ARCH 8.1]: 0x3100, unbuild old, ids, build new, check, 0x2000/0x3303."""
        props = self.signed.mutations.get(mutation) if mutation else None
        if mutation and props is None:
            raise ValueError(f"unknown mutation '{mutation}'")
        if not (self.state == State.ACTIVE or self.state.inactive):
            raise ValueError(f"no transmutation from {self.state.name} [ARCH 5.6]")
        if props is not None:
            props.verify(self.usc_key or bytes(32))  # signature checked before any command
            missing = self.uncatalogued(mutation)
            if missing:
                raise ValueError(f"services not in the catalogue: {', '.join(missing)}")
        started = time.monotonic()
        previous = self.mutation
        self.set_state(State.INACTIVE_MUTATING, reason=f"transmutation to {mutation or '-'}",
                       force=True)
        self.publish_record()
        for spec in reversed(self.mutation_specs(previous)):
            await self.runner.run(spec, "unbuild")
            self._withdraw(spec.name)
        self.mutation = mutation
        self.publish_record()
        self.refresh_interface()  # the areas changed with the mutation
        await self.request_management_ids()
        # No build without a management id for every service of a new area
        # [ARCH 11.4, 12.3].
        missing_ids = [s for s in self.my_area_services() if s not in self.management]
        ok = not missing_ids
        if missing_ids:
            self.event(f"No management id for {missing_ids}: build refused", logging.ERROR)
        for spec in (self.mutation_specs(mutation) if ok else []):
            if not (await self.runner.run(spec, "build")).ok:
                ok = False
                break
        if ok:
            for spec in self.mutation_specs(mutation):
                if (await self.runner.run(spec, "check_health")).ok:
                    self._host(spec.name)
                else:
                    ok = False
        duration = time.monotonic() - started
        self.transmutations.append({"from": previous, "to": mutation, "ok": ok,
                                    "seconds": round(duration, 1), "reason": reason,
                                    "at": time.strftime("%Y-%m-%d %H:%M:%S")})
        self.set_state(State.ACTIVE if ok else State.INACTIVE_EMERGENCY_HEALTH_CHECK,
                       reason="transmutation " + ("done" if ok else "failed"))
        self.publish_record()
        self.event(f"Transmutation {previous or '-'} -> {mutation or '-'}: "
                   f"{'ok' if ok else 'failed'} ({duration:.1f}s)")
        problem = self.sp_problem() if ok and self.hosted else ""
        if problem:
            self.event(f"Services of {mutation} built, but no client can reach them: {problem}",
                       logging.WARNING)
        if not ok:
            await self.emergency(State.INACTIVE_EMERGENCY_HEALTH_CHECK)
        return ok

    def service_address(self, name: str) -> int | None:
        """This node's SP address for a service, None without a management id."""
        entry = self.signed.service_by_name(name)
        if entry is None or entry.service_id not in self.management:
            return None
        return addresses.pack(entry.service_id, self.management[entry.service_id])

    def service_data_dir(self, name: str) -> Path:
        """Kept across unbuilds and transmutations [ARCH-03 8.7]."""
        configured = self.settings.service_data.get(name)
        return Path(configured) if configured else self.state_dir.path("services", name)

    def service_files_dir(self, name: str) -> Path:
        """Where the files delivered with a service are written; rewritten from
        the signed mutation before each sequence, so nothing kept here."""
        return self.state_dir.path("service-files", name)

    def sequence_environment(self, spec: ServiceSpec, sequence: str) -> dict[str, str] | None:
        """The runner's environment: the service's files in place, then its variables."""
        env = self.service_environment(spec, sequence)
        if env is not None or sequence not in ("build", "update", "check_health"):
            try:
                write_files(self.service_files_dir(spec.name), spec.files)
            except OSError as exc:
                self.event(f"Files of {spec.name} could not be written: {exc}", logging.ERROR)
        return env

    def service_environment(self, spec: ServiceSpec, sequence: str) -> dict[str, str] | None:
        """The ``USMD_*`` variables of a sequence; None without an SP address
        [ARCH-03 8.7]."""
        address = self.service_address(spec.name)
        if address is None:
            return None
        entry = self.signed.service_by_name(spec.name)
        areas = {a.area_id: a.name for a in (self.signed.usd.areas if self.signed.usd else [])}
        data = self.service_data_dir(spec.name)
        data.mkdir(parents=True, exist_ok=True)
        return {
            "USMD_SERVICE": spec.name,
            "USMD_SERVICE_ID": f"{entry.service_id:03x}",
            "USMD_MANAGEMENT_ID": f"{address & 0xFFFF:04x}",
            "USMD_SP_ADDRESS": addresses.to_text(address),
            "USMD_DATA_ID_PREFIX": dataid.prefix(address),
            "USMD_VIP": entry.vip,
            "USMD_GROUP": "" if entry.group == "0.0.0.0" else entry.group,
            "USMD_AREA": areas.get(entry.area_id, ""),
            "USMD_USDN": self.signed.usd.usdn if self.signed.usd else "",
            "USMD_NODE_ID": self.node_id,
            "USMD_MUTATION": self.mutation,
            "USMD_SEQUENCE": sequence,
            "USMD_DATA_DIR": str(data.resolve()),
            "USMD_FILES_DIR": str(self.service_files_dir(spec.name).resolve()),
        }

    def _host(self, name: str) -> None:
        entry = self.signed.service_by_name(name)
        if entry is None:
            return
        new = entry.service_id not in self.hosted
        self.hosted.add(entry.service_id)
        if entry.service_id in self.management and self.nndp:
            self.nndp.services.set_local(addresses.pack(entry.service_id,
                                                        self.management[entry.service_id]),
                                         self.load.reference)
            if new:
                self.nndp.trigger()  # anticipated HIA only when hosting changed [NNDP 6.1]
        self.refresh_interface()

    def refresh_interface(self) -> None:
        """VIPs of hosted services only, routes of our areas only [SP 5.1]."""
        if self.tun:
            self.tun.configure(self.sp_vips(), self.sp_routes(), self.sp_groups())

    def _withdraw(self, name: str) -> None:
        entry = self.signed.service_by_name(name)
        if entry is None or entry.service_id not in self.hosted:
            return
        self.hosted.discard(entry.service_id)
        if entry.service_id in self.management and self.nndp:
            self.nndp.services.withdraw_local(addresses.pack(entry.service_id,
                                                             self.management[entry.service_id]))
            self.nndp.trigger()
        self.refresh_interface()

    async def apply_mutation_update(self, mutation: str,
                                    previous: MutationProperties | None) -> bool:
        """[ARCH 8.5]: a host runs ``update`` then ``check_health`` on the new
        version before keeping (and propagating) it. On failure the previous
        version is put back and rebuilt; if that fails too, 0x3304."""
        if mutation != self.mutation or previous is None:
            return True
        self.updating[mutation] = previous  # pushed instead of the new one meanwhile
        try:
            return await self._run_update(mutation, previous)
        finally:
            self.updating.pop(mutation, None)

    async def _run_update(self, mutation: str, previous: MutationProperties) -> bool:
        updated = []
        for spec in self.mutation_specs(mutation):
            if not spec.sequences.get("update"):
                continue
            updated.append(spec.name)
            ok = (await self.runner.run(spec, "update")).ok and \
                (await self.runner.run(spec, "check_health")).ok
            if ok:
                continue
            self.event(f"Update of {spec.name} failed: previous version kept, not propagated",
                       logging.ERROR)
            self.signed.mutations[mutation] = previous
            self.save_signed()
            old = {s.name: s for s in self.mutation_specs(mutation)}
            rebuilt = True
            for name in updated:  # every service already updated goes back [ARCH 8.5]
                if name in old:
                    rebuilt &= (await self.runner.run(old[name], "build")).ok
            if not rebuilt:
                self.set_state(State.INACTIVE_EMERGENCY_UPDATE, reason="update failed",
                               force=True)
                self.publish_record()
                await self.emergency(State.INACTIVE_EMERGENCY_UPDATE)
            return False
        return True

    async def offer_mutation(self, obj: MutationProperties) -> bool:
        """Apply a received mutation object; a host updates before keeping it."""
        previous = self.signed.mutations.get(obj.name)
        if not self.signed.offer_mutation(obj, self.usc_key or bytes(32)):
            return False
        if obj.name == self.mutation:
            return await self.apply_mutation_update(obj.name, previous)
        return True

    async def _health_loop(self) -> None:
        while True:
            await asyncio.sleep(parameter(self.signed.usd, 0x000C) or 30)
            if self.state != State.ACTIVE or not self.mutation:
                continue
            failed = False
            for spec in self.mutation_specs(self.mutation):
                if not (await self.runner.run(spec, "check_health")).ok:
                    failed = True
                    self._withdraw(spec.name)
                else:
                    self._host(spec.name)
            self.delegation.health_failures = self.delegation.health_failures + 1 if failed else 0
            if self.delegation.health_failures >= 3:
                self.delegation.health_failures = 0
                self.set_state(State.INACTIVE_EMERGENCY_HEALTH_CHECK,
                               reason="three failed health checks")
                self.publish_record()
                await self.emergency(State.INACTIVE_EMERGENCY_HEALTH_CHECK)

    async def _dependency_loop(self) -> None:
        """[ARCH 8.4]: K least loaded active hosts per dependency, else 0x3302."""
        while True:
            await asyncio.sleep(parameter(self.signed.usd, 0x0009) or 30)
            if self.state != State.ACTIVE or not self.mutation:
                continue
            for spec in self.mutation_specs(self.mutation):
                for dependency in spec.dependencies:
                    entry = self.signed.service_by_name(dependency)
                    if entry is None:
                        continue
                    reachable = entry.service_id in self.hosted or (
                        self.nndp is not None and self.nndp.services.best(entry.service_id))
                    if not reachable and self.state == State.ACTIVE:
                        self.set_state(State.INACTIVE_EMERGENCY_DEPENDENCIES,
                                       reason=f"no active host of {dependency}")
                        self.publish_record()
                        await self.emergency(State.INACTIVE_EMERGENCY_DEPENDENCIES)

    async def check_weakness(self) -> None:
        """[ARCH 7.1]."""
        usd = self.signed.usd
        weak, urgent = parameter(usd, 0x0004) or 800, parameter(usd, 0x0005) or 950
        if not self.mutation:
            return
        if self.load.emergency(urgent) and self.state == State.ACTIVE:
            self.set_state(State.INACTIVE_EMERGENCY_RESOURCES, reason="reference load")
            self.publish_record()
            await self.emergency(State.INACTIVE_EMERGENCY_RESOURCES)
            return
        props = self.signed.mutations.get(self.mutation)
        tm = self.useful_transmutation_time(props)
        if self.load.weakened(weak, transmutation_s=tm) and self.state == State.ACTIVE \
                and time.monotonic() - self.delegation.last_request > 60:
            self.delegation.weakened = True
            await self.request_help()

    def useful_transmutation_time(self, props: MutationProperties | None) -> float | None:
        """Tm = Tmoy + V / D for a mutation with a dynamic service, None otherwise
        [ARCH 7.1]: V is the size of the service's data path (local setting
        ``service_data``), D the measured transfer rate (link speed otherwise)."""
        from usmd_rdsh.node.load import useful_transmutation_time  # pylint: disable=import-outside-toplevel

        if props is None:
            return None
        dynamic = [s for s in self.mutation_specs(props.name) if s.type == "dynamic"]
        if not dynamic:
            return None
        volume = sum(_directory_size(self.settings.service_data.get(s.name, ""))
                     for s in dynamic)
        rate = self.transfer_rate or _link_rate(self.settings.address)
        return useful_transmutation_time(props.average_transmutation_ms / 1000, volume, rate)

    def _solicited(self) -> list[str]:
        count = parameter(self.signed.usd, 0x0003) or 5
        by_distance = sorted(self.references, key=lambda n: self.distances.get(n, 9e9))
        return by_distance[:count]

    async def request_help(self) -> list[str]:
        """[ARCH 7.2]: preventive delegation; the weakened node stays active."""
        self.delegation.last_request = time.monotonic()
        solicited = self._solicited()
        favourable = await self._ask(Command.REQUEST_HELP, 0x0000, solicited)
        if favourable:
            best = min(favourable, key=lambda n: self.distances.get(n, 9e9))
            await self._quiet(self.call(best, Command.CONFIRM_DELEGATION,
                                        Writer().string(self.mutation).u16(0).bytes()))
            self.event(f"Help: {best} takes an extra instance of {self.mutation}")
        return favourable

    async def _ask(self, command: Command, reason: int, solicited: list[str]) -> list[str]:
        from usmd_rdsh.node.ncp.codec import ids  # pylint: disable=import-outside-toplevel

        body = Writer().u16(reason).raw(ids(solicited)).u16(self.load.reference).bytes()
        answers = await asyncio.gather(*(self._quiet(self.call(n, command, body))
                                         for n in solicited))
        favourable: list[str] = []
        for node_id, answer in zip(solicited, answers):
            if answer is None:
                continue
            reader = Reader(answer)
            if reader.boolean():
                favourable.append(node_id)
            favourable.extend(i for i in [reader.ident() for _ in range(reader.u16())]
                              if i not in favourable)
        self.delegation.favourable[self.mutation] = favourable
        return favourable

    async def emergency(self, reason: State) -> None:
        """[ARCH 7.3, 7.4]: emergency request, switch-over, declare, stop."""
        if not self.mutation:
            return
        self.delegation.emergency = reason
        favourable = await self._ask(Command.REQUEST_EMERGENCY, int(reason), self._solicited())
        await self.delegate_all(reason, favourable)

    async def delegate_all(self, reason: State, favourable: list[str] | None = None) -> None:
        favourable = favourable if favourable is not None else self._solicited()
        mutation = self.mutation
        for node_id in favourable:
            try:
                answer = await self.call(node_id, Command.CONFIRM_DELEGATION,
                                         Writer().string(mutation).u16(int(reason)).bytes())
            except (NcpTimeout, NcpRemoteError):
                continue
            if Reader(answer).boolean():
                self.event(f"Delegated {mutation} to {node_id}")
                break
        body = Writer().u16(int(State.INACTIVE)).bytes()
        await asyncio.gather(*(self._quiet(self.call(n, Command.DECLARE_STATE, body))
                               for n in self.references))
        for spec in reversed(self.mutation_specs(mutation)):
            await self.runner.run(spec, "emergency")
            # The services of the mutation are cut [ARCH 7.4]; an emergency
            # sequence that already unbuilds is not repeated.
            if not any(step.action == "unbuild" for step in spec.sequences.get("emergency", [])):
                await self.runner.run(spec, "unbuild")
            self._withdraw(spec.name)
        self.mutation = ""
        self.delegation.handed_over = reason != State.INACTIVE  # a retirement stays down
        self.set_state(State.INACTIVE if reason == State.INACTIVE else reason,
                       reason="services handed over", force=True)
        self.publish_record()

    def instance_count(self, mutation: str) -> int:
        return sum(1 for e in self.tables.nodes.entries.values()
                   if e.record.mutation == mutation and self.peer_state(e.key) == State.ACTIVE)

    async def enforce_instance_bounds(self) -> None:
        """[ARCH 8.6]: after healing, excess instances with the largest ids unbuild."""
        props = self.signed.mutations.get(self.mutation) if self.mutation else None
        if props is None or not props.max_instances:
            return
        holders = sorted(e.record.node_id for e in self.tables.nodes.entries.values()
                         if e.record.mutation == self.mutation
                         and self.peer_state(e.key) == State.ACTIVE)
        if self.node_id in holders[props.max_instances:]:
            self.event(f"Above max instances of {self.mutation}: unbuilding")
            await self.transmute("", reason="instance bound")

    # ------------------------------------------------------------------
    # SP plumbing [SP-01]
    # ------------------------------------------------------------------

    def sp_problem(self) -> str:
        """Why the hosted services cannot be reached through SP, "" when they can."""
        if parameter(self.signed.usd, 0x0010) is None:
            return "no SP port in the USD (config usd / set sp-port): SP is not started"
        if self.sp is None or self.tun is None:
            return "SP is not running (see 'show logging')"
        if self.tun.kind == "memory" and self.tun.reason:
            return f"SP interface simulated in memory: {self.tun.reason}"
        return ""

    def sp_vips(self) -> list[str]:
        catalog = self.signed.catalog()
        return [catalog[s].vip for s in self.hosted if s in catalog]

    def sp_groups(self) -> list[str]:
        catalog = self.signed.catalog()
        return [catalog[s].group for s in self.hosted
                if s in catalog and catalog[s].group != "0.0.0.0"]

    def sp_routes(self) -> list[str]:
        """Our areas' prefixes, minus any that collides [SP 4.1], plus 239/8
        when a service of our areas has a group address [SP 5.1]."""
        areas = self.signed.areas()
        routes = []
        for area in self.my_areas():
            if area not in areas:
                continue
            problem = self.prefix_conflict(areas[area])
            if problem:
                self.event(f"Area prefix {areas[area]} not routed: {problem}", logging.ERROR)
                continue
            routes.append(str(areas[area]))
        catalog = self.signed.catalog()
        if any(catalog[s].group != "0.0.0.0" for s in self.my_area_services() if s in catalog):
            routes.append("239.0.0.0/8")
        return routes

    def prefix_conflict(self, network) -> str:
        """Why an area prefix may not be used here, or "" [SP 4.1]."""
        known = [self.settings.address] + [a for e in self.tables.nit.entries.values()
                                           for a in e.addresses]
        for address in known:
            try:
                if address and ipaddress.IPv4Address(address) in network:
                    return f"contains node address {address}"
            except ValueError:
                continue
        ours = set(self.tun.routes) if self.tun is not None else set()
        for route in system_routes():
            if str(route) in ours:
                continue  # the route we put on the SP interface ourselves
            if route.overlaps(network):
                return f"overlaps system route {route}"
        return ""

    async def start_sp(self) -> None:
        port = parameter(self.signed.usd, 0x0010)
        if port is None or self.sp is not None:
            return
        from usmd_rdsh.node.sp.tun import open_tun  # pylint: disable=import-outside-toplevel

        loop = asyncio.get_running_loop()
        context = _NodeSpContext(self)
        holder: dict[str, Any] = {}

        def send_udp(data: bytes, ip: str, tos: int) -> None:
            sock = holder.get("sock")
            if sock is None:
                return
            # Inner ECN copied to the outer header, DSCP too [SP 9.2].
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
            except OSError:
                pass
            try:
                sock.sendto(data, (ip, port))
            except OSError:
                pass

        self.tun = open_tun(mtu=parameter(self.signed.usd, 0x0013) or 1412,
                            on_packet=lambda raw: self.sp.from_tun(raw) if self.sp else None)
        if self.tun.kind == "memory" and self.tun.reason:
            self.event(f"SP interface simulated in memory, hosted services unreachable: "
                       f"{self.tun.reason}", logging.ERROR)
        s = self.settings
        self.sp = SpEngine(context, self.identity.signing, self.identity.agreement,
                           send_udp=send_udp, write_tun=self.tun.write, port=port,
                           mtu=parameter(self.signed.usd, 0x0013) or 1412,
                           selection_margin=s.sp_margin, pending_per_peer=s.sp_pending,
                           ineligible_s=s.sp_ineligible, replay_window=s.sp_replay_window,
                           flow_idle_s=s.sp_flow_idle, broadcast_rate=s.sp_broadcast_rate,
                           local_address=s.address or s.bind_address)
        if not self._check_mtu():
            # [SP 9.1] the SP MTU DOIT fit the path MTU minus 82: no SP until fixed.
            await self.stop_sp()
            return
        engine = self.sp

        class _Protocol(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):  # type: ignore[override]
                engine.from_udp(data, addr[0], addr[1])

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _set_dont_fragment(sock)
        try:
            sock.bind((self.settings.bind_address, port))
        except OSError as exc:
            self.event(f"SP could not bind UDP {port}: {exc}", logging.ERROR)
            return
        holder["sock"] = sock
        if hasattr(socket, "IP_RECVTOS") and hasattr(sock, "recvmsg"):
            # Linux: read the outer ECN of each datagram [SP 9.2].
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
            sock.setblocking(False)

            def readable() -> None:
                while True:
                    try:
                        data, ancillary, _flags, addr = sock.recvmsg(65535, socket.CMSG_SPACE(1))
                    except OSError:
                        return
                    ecn = 0
                    for level, kind, value in ancillary:
                        if level == socket.IPPROTO_IP and kind == socket.IP_TOS and value:
                            ecn = value[0] & 0x03
                    engine.from_udp(data, addr[0], addr[1], ecn)

            loop.add_reader(sock.fileno(), readable)
            self._sp_reader = sock
        else:
            # Windows: asyncio exposes no recvmsg; the outer ECN reads Not-ECT.
            transport, _ = await loop.create_datagram_endpoint(_Protocol, sock=sock)
            self._sp_transport = transport
        self.tun.configure(self.sp_vips(), self.sp_routes(), self.sp_groups())
        await self.tun.start()

    async def stop_sp(self) -> None:
        if self._sp_transport is not None:
            self._sp_transport.close()
            self._sp_transport = None
        reader = getattr(self, "_sp_reader", None)
        if reader is not None:
            asyncio.get_running_loop().remove_reader(reader.fileno())
            reader.close()
            self._sp_reader = None
        if self.tun is not None:
            await self.tun.stop()
            self.tun = None
        self.sp = None

    def _check_mtu(self) -> bool:
        """SP MTU + 82 must fit the path MTU [SP 9.1]; the local link bounds it."""
        import psutil  # pylint: disable=import-outside-toplevel

        mtu = parameter(self.signed.usd, 0x0013) or 1412
        self.link_mtu = None
        for name, addrs in psutil.net_if_addrs().items():
            if any(a.address == self.settings.address for a in addrs):
                link = psutil.net_if_stats().get(name)
                self.link_mtu = link.mtu if link else None
                if link and link.mtu and mtu + 82 > link.mtu:
                    self.event(f"SP not started: MTU {mtu} + 82 exceeds the MTU {link.mtu} "
                               f"of {name} [SP 9.1]", logging.ERROR)
                    return False
        return True

    async def restart_sp(self) -> None:
        await self.stop_sp()
        await self.start_sp()


def _permille(reader: Reader) -> int:
    """A per-mille field: 0..1000 [NCP 6.1]."""
    reader_permille = getattr(reader, "permille", None)
    if reader_permille is not None:
        return reader_permille()
    value = reader.u16()
    if value > 1000:
        raise WireError("per mille above 1000")
    return value


def parse_edb(text: str) -> list[str]:
    """``<ULID>: <IPv4>`` lines, comments after '#' [ARCH 3.4]; others skipped."""
    from usmd_rdsh.node.wire import is_ulid  # pylint: disable=import-outside-toplevel

    found = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        node_id, _, address = line.partition(":")
        try:
            ipaddress.IPv4Address(address.strip())
        except ValueError:
            continue
        if is_ulid(node_id.strip()):
            found.append(address.strip())
    return found


def _directory_size(path: str) -> int:
    if not path or not os.path.exists(path):
        return 0
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for folder, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(folder, name))
            except OSError:
                continue
    return total


def _link_rate(address: str) -> float:
    """Nominal speed of the interface carrying *address*, bytes/s."""
    import psutil  # pylint: disable=import-outside-toplevel

    for name, addrs in psutil.net_if_addrs().items():
        if any(a.address == address for a in addrs):
            stats = psutil.net_if_stats().get(name)
            if stats and stats.speed:
                return stats.speed * 1_000_000 / 8
    return 125_000_000.0  # 1 Gbit/s when unknown


def system_routes() -> list:
    """The host's routes outside the SP interface, best effort [SP 4.1]."""
    import subprocess  # pylint: disable=import-outside-toplevel
    import sys  # pylint: disable=import-outside-toplevel

    out = []
    try:
        if sys.platform.startswith("linux"):
            text = subprocess.run(["ip", "-4", "route", "show"], capture_output=True,
                                  text=True, timeout=3, check=False).stdout
            for line in text.splitlines():
                words = line.split()
                if not words or "usmd-sp" in words or words[0] == "default":
                    continue
                first = words[0] if "/" in words[0] else words[0] + "/32"
                out.append(ipaddress.IPv4Network(first, strict=False))
        elif sys.platform == "win32":
            text = subprocess.run(["route", "print", "-4"], capture_output=True, text=True,
                                  timeout=3, check=False).stdout
            for line in text.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0].count(".") == 3 and parts[1].count(".") == 3:
                    try:
                        net = ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
                    except ValueError:
                        continue
                    if 0 < net.prefixlen < 32 and not net.is_multicast and not net.is_loopback:
                        out.append(net)
    except (OSError, subprocess.SubprocessError, ValueError):
        return []
    return out


def _set_dont_fragment(sock: socket.socket) -> None:
    """SP datagrams carry DF [SP 7.1]."""
    try:
        if hasattr(socket, "IP_MTU_DISCOVER"):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MTU_DISCOVER, 2)  # IP_PMTUDISC_DO
        else:
            sock.setsockopt(socket.IPPROTO_IP, 14, 1)  # IP_DONTFRAGMENT (Windows)
    except OSError:
        pass


class _NodeSpContext:
    """The node seen through the :class:`SpContext` protocol."""

    def __init__(self, node: Node) -> None:
        self.node = node

    def catalog(self) -> dict[int, CatalogService]:
        areas = {a.area_id: a.name for a in (self.node.signed.usd.areas if self.node.signed.usd
                                             else [])}
        return {
            e.service_id: CatalogService(e.service_id, areas.get(e.area_id, str(e.area_id)), e.vip,
                                         None if e.group == "0.0.0.0" else e.group)
            for e in self.node.signed.catalog().values()
        }

    def area_networks(self):
        return {str(k): v for k, v in self.node.signed.areas().items()}

    def management_id(self, service_id: int) -> int | None:
        return self.node.management.get(service_id)

    def hosted_services(self) -> set[int]:
        return set(self.node.hosted)

    def owner(self, sp_address: int) -> bytes | None:
        """The node an SP address is attributed to [SP 4.3].

        Two records claiming one address [ARCH 14]: a voter settles it with the
        master's replicated table; otherwise the address is unusable and said so.
        """
        claims = [e.key for e in self.node.tables.nodes.entries.values()
                  if sp_address in e.record.sp_addresses]
        if len(claims) <= 1:
            return claims[0] if claims else None
        raft = self.node.raft
        if raft is not None and raft.is_voter:
            assigned = raft.state.assignments.get(((sp_address >> 16) & 0xFFF,
                                                   sp_address & 0xFFFF))
            if assigned is not None and assigned.key in claims:
                return assigned.key
        self.node.event(f"SP address {addresses.to_text(sp_address)} claimed by "
                        f"{len(claims)} nodes: not used", logging.WARNING)
        return None

    def peer(self, key: bytes) -> Peer | None:
        node = self.node
        entry = node.tables.nodes.get(key)
        address = node.tables.nit.address_of(key)
        if entry is None or address is None or node.tables.exclusions.is_excluded(key):
            return None  # an excluded peer loses its sessions and eligibility [SP 7.6]
        hia = None
        if node.nndp is not None:
            heard = [n for n in node.nndp.neighbors.values() if n.public_key == key]
            if heard:
                hia = frozenset(heard[-1].hosted)
        mutation_services = {
            s.service_id for name in node.signed.mutation_services(entry.record.mutation)
            if (s := node.signed.service_by_name(name)) is not None
        }
        return Peer(key, entry.record.x25519, address, node.peer_state(key) == State.ACTIVE,
                    hia, frozenset(mutation_services))

    def peers(self) -> list[Peer]:
        return [p for k in self.node.tables.nodes.entries if k != self.node.key
                if (p := self.peer(k)) is not None]

    def nearest(self, service_id: int) -> list[tuple[int, int]]:
        if self.node.nndp is None:
            return []
        return [(e.address, e.distance)
                for e in self.node.nndp.services.entries.get(service_id, [])
                if e.learned_from is not None]

    def initiator_allowed(self, key: bytes, address: str) -> bool:
        return not self.node.tables.exclusions.is_excluded(key) and \
            self.node.tables.nit.associated(key, address) and \
            self.node.tables.nal.allows(key, Role.NODE_EXECUTOR)

    def address_known(self, address: str) -> bool:
        return self.node.tables.nit.address_known(address)


__all__ = ["LocalSettings", "Node"]
