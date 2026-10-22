"""Trust tables [ARCH-02 4.3, NCP-02 7]: NIT, NAL, NEL, node table, exclusions.

    NIT         key -> addresses, X25519 key, TTL (300 s by default)
    NAL         key -> roles; trust anchors are permanent
    NEL         endorsement packets this node issued
    node table  key -> (creation token, latest node record), the USD's roster
    exclusions  key -> family 0x4000 state, permanent or until a date
"""

from __future__ import annotations

from dataclasses import dataclass, field

from usmd_rdsh.node.ncp.codec import CreationToken, EndorsementPacket, NodeRecord, Role
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import now_ms

NIT_TTL_MS = 300_000


@dataclass(slots=True)
class NitEntry:
    ed25519: bytes
    node_id: str
    addresses: dict[str, int]  # address -> expiry (ms); 0 = no expiry (node table)
    x25519: bytes


class Nit:
    """Node Identity Table: one key may have several addresses and vice versa."""

    def __init__(self) -> None:
        self.entries: dict[bytes, NitEntry] = {}

    def associate(self, key: bytes, node_id: str, address: str, x25519: bytes, *,
                  ttl_ms: int | None = NIT_TTL_MS, now: int | None = None) -> None:
        current = now_ms() if now is None else now
        entry = self.entries.get(key)
        if entry is None:
            entry = self.entries[key] = NitEntry(key, node_id, {}, x25519)
        entry.node_id, entry.x25519 = node_id, x25519
        entry.addresses[address] = 0 if ttl_ms is None else current + ttl_ms

    def knows(self, key: bytes) -> bool:
        return key in self.entries

    def accepts(self, key: bytes, address: str, now: int | None = None) -> bool:
        """True for an unknown key or a known (key, address) pair [7.6]."""
        entry = self.entries.get(key)
        if entry is None:
            return True
        expiry = entry.addresses.get(address)
        current = now_ms() if now is None else now
        return expiry is not None and (expiry == 0 or expiry > current)

    def associated(self, key: bytes, address: str) -> bool:
        return self.knows(key) and self.accepts(key, address)

    def address_known(self, address: str) -> bool:
        return any(address in e.addresses for e in self.entries.values())

    def address_of(self, key: bytes) -> str | None:
        entry = self.entries.get(key)
        if not entry or not entry.addresses:
            return None
        return max(entry.addresses, key=lambda a: entry.addresses[a] or 1 << 62)

    def x25519_of(self, key: bytes) -> bytes | None:
        entry = self.entries.get(key)
        return entry.x25519 if entry else None

    def by_id(self, node_id: str) -> NitEntry | None:
        return next((e for e in self.entries.values() if e.node_id == node_id), None)

    def remove(self, key: bytes) -> None:
        self.entries.pop(key, None)

    def expire(self, now: int | None = None) -> None:
        current = now_ms() if now is None else now
        for key, entry in list(self.entries.items()):
            entry.addresses = {a: t for a, t in entry.addresses.items() if t == 0 or t > current}
            if not entry.addresses:
                del self.entries[key]


class Nal:
    """Node Access List [7.3]."""

    def __init__(self) -> None:
        self.roles: dict[bytes, set[int]] = {}
        self.anchors: set[bytes] = set()

    def grant(self, key: bytes, roles: list[int] | set[int], *, anchor: bool = False) -> None:
        self.roles.setdefault(key, set()).update(roles)
        if anchor:
            self.anchors.add(key)

    def revoke(self, key: bytes) -> None:
        if key not in self.anchors:
            self.roles.pop(key, None)

    def of(self, key: bytes) -> set[int]:
        return self.roles.get(key, set())

    def allows(self, key: bytes, minimum: Role) -> bool:
        return any(0 < r <= minimum for r in self.of(key))


@dataclass(slots=True)
class Entry:
    """One node-table entry."""

    token: CreationToken
    record: NodeRecord
    modified: bool = False

    @property
    def key(self) -> bytes:
        return self.token.node_key

    def encode(self) -> bytes:
        """Token || record, as Send_node_table carries it [6.14]."""
        return self.token.encode() + self.record.encode()


class NodeTable:
    """The USD's nodes: (token, latest record) per node key [7.8, 7.9]."""

    def __init__(self) -> None:
        self.entries: dict[bytes, Entry] = {}

    def by_id(self, node_id: str) -> Entry | None:
        return next((e for e in self.entries.values() if e.record.node_id == node_id), None)

    def get(self, key: bytes) -> Entry | None:
        return self.entries.get(key)

    def sorted(self) -> list[Entry]:
        return sorted(self.entries.values(), key=lambda e: e.record.node_id)

    def merge(self, token: CreationToken, record: NodeRecord) -> bool:
        """Apply the replacement rules of [7.9]; True when the table changed.

        Verification (token, record, exclusion) is the caller's.
        """
        key = token.node_key
        clash = self.by_id(record.node_id)
        if clash is not None and clash.key != key:
            if token.issued >= clash.token.issued:
                return False  # the older token keeps the identifier
            del self.entries[clash.key]
        held = self.entries.get(key)
        if held is not None and record.date <= held.record.date:
            return False
        self.entries[key] = Entry(token, record, modified=True)
        return True

    def take_modified(self) -> list[Entry]:
        out = [e for e in self.entries.values() if e.modified]
        for entry in out:
            entry.modified = False
        return out


@dataclass(slots=True)
class Exclusion:
    state: State
    since: int
    until: int | None  # None: permanent


class Exclusions:
    """Local family-0x4000 verdicts, never announced [ARCH 5.5]."""

    def __init__(self) -> None:
        self.by_key: dict[bytes, Exclusion] = {}

    def exclude(self, key: bytes, state: State, *, duration_ms: int | None = None,
                now: int | None = None) -> None:
        current = now_ms() if now is None else now
        self.by_key[key] = Exclusion(state, current,
                                     None if duration_ms is None else current + duration_ms)

    def is_excluded(self, key: bytes, now: int | None = None) -> bool:
        verdict = self.by_key.get(key)
        if verdict is None:
            return False
        current = now_ms() if now is None else now
        if verdict.until is not None and verdict.until <= current:
            del self.by_key[key]  # temporary exclusion over: eligible again [5.6]
            return False
        return True


@dataclass
class Tables:
    """All trust tables of one node."""

    nit: Nit = field(default_factory=Nit)
    nal: Nal = field(default_factory=Nal)
    nel: list[EndorsementPacket] = field(default_factory=list)
    nodes: NodeTable = field(default_factory=NodeTable)
    exclusions: Exclusions = field(default_factory=Exclusions)
    # Peers' endorsement packets, checked per [NCP 7.4].
    endorsements: dict[bytes, EndorsementPacket] = field(default_factory=dict)
