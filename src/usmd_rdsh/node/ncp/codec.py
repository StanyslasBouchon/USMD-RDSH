"""NCP message and body formats [NCP-02 5.6, 6, 7].

Every object that is signed carries its own signature and knows the exact
bytes it covers; ``verify`` methods raise CryptoError, ``decode`` methods
raise WireError. Integers are big-endian (``wire.Writer``/``wire.Reader``).
"""

from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass, field
from enum import IntEnum

from usmd_rdsh.node.crypto import SigningKey, verify
from usmd_rdsh.node.wire import Reader, WireError, Writer

CONTEXT = b"USMD-NCP-v1"


class Command(IntEnum):
    """The twenty-one commands [6.1], Send_operators and Operate [ARCH 12.4, 12.5]."""

    GET_STATUS = 0x0001
    CHECK_DISTANCE_TO_NODE = 0x0002
    REQUEST_EMERGENCY = 0x0003
    REQUEST_HELP = 0x0004
    REQUEST_APPROVAL = 0x0005
    SEND_USC_PROPERTIES = 0x0006
    SEND_USD_PROPERTIES = 0x0007
    SEND_MUTATION_PROPERTIES = 0x0008
    INFORM_REFERENCE_NODE = 0x0009
    ENDORSEMENT_CHECK_REQUIRED = 0x000A
    VERIFY_ENDORSEMENT = 0x000B
    NOTIFY_END_OF_SERVICE = 0x000C
    REQUEST_REVOCATION = 0x000D
    CONFIRM_DELEGATION = 0x000E
    DECLARE_STATE = 0x000F
    SEND_NODE_TABLE = 0x0010
    REQUEST_MANAGEMENT_ID = 0x0011
    RAFT_REQUEST_VOTE = 0x0012
    RAFT_APPEND_ENTRIES = 0x0013
    RAFT_INSTALL_SNAPSHOT = 0x0014
    SEND_OPERATORS = 0x0015
    OPERATE = 0x0016  # [ARCH 12.5], outside the drafts


class MessageType(IntEnum):
    """[5.6]."""

    REQUEST = 0x00
    RESPONSE = 0x01
    ERROR = 0x02
    FRAGMENT_ACK = 0x03


class ErrorCode(IntEnum):
    """[9]."""

    NOT_AUTHORISED = 0x0001
    STALE_TIMESTAMP = 0x0002
    MALFORMED = 0x0003
    BUSY = 0x0004
    UNKNOWN_KEY = 0x0005
    OBSOLETE_OR_UNSIGNED = 0x0006
    BAD_CREATION_TOKEN = 0x0007
    ID_IN_USE = 0x0008
    BAD_NODE_RECORD = 0x0009
    VOTERS_ONLY = 0x000A
    UNKNOWN_SERVICE = 0x000B


class Role(IntEnum):
    """NAL roles [7.3]."""

    USC_OPERATOR = 0x01
    USD_OPERATOR = 0x02
    NODE_OPERATOR = 0x03
    NODE_EXECUTOR = 0x04


#: The roles the USD master elects among the nodes authorised for them [ARCH 12.4].
OPERATOR_ROLES = (Role.USC_OPERATOR, Role.USD_OPERATOR, Role.NODE_OPERATOR)
#: Node-record flag of each elected role [7.8].
OPERATOR_FLAGS = {Role.USC_OPERATOR: 0x40, Role.USD_OPERATOR: 0x20, Role.NODE_OPERATOR: 0x10}


def role_allows(roles: set[int], wanted: Role) -> bool:
    """Roles add up, none includes another; every node is at least an
    executor, whatever else it holds [7.3]."""
    if wanted == Role.NODE_EXECUTOR:
        return any(r in (1, 2, 3, 4) for r in roles)
    return int(wanted) in roles


# ---------------------------------------------------------------------------
# Message [5.6]
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Message:
    """The reassembled plaintext."""

    event: int
    type: int
    request_id: int
    timestamp: int
    sender: bytes
    body: bytes
    signature: bytes = b""

    def signed_bytes(self, recipient: bytes) -> bytes:
        return (CONTEXT + self.event.to_bytes(2, "big") + recipient + bytes([self.type])
                + self.request_id.to_bytes(8, "big") + self.timestamp.to_bytes(8, "big")
                + self.sender + self.body)

    def encode(self, key: SigningKey, recipient: bytes) -> bytes:
        """Sign for *recipient* and serialise."""
        signature = key.sign(self.signed_bytes(recipient))
        return (bytes([self.type]) + self.request_id.to_bytes(8, "big")
                + self.timestamp.to_bytes(8, "big") + self.sender + self.body + signature)

    @classmethod
    def decode(cls, event: int, plaintext: bytes) -> "Message":
        if len(plaintext) < 49 + 64:
            raise WireError("message shorter than its fixed fields")
        if plaintext[0] > 0x03:
            raise WireError("unknown message type")
        return cls(
            event=event,
            type=plaintext[0],
            request_id=int.from_bytes(plaintext[1:9], "big"),
            timestamp=int.from_bytes(plaintext[9:17], "big"),
            sender=plaintext[17:49],
            body=plaintext[49:-64],
            signature=plaintext[-64:],
        )

    def verify(self, recipient: bytes) -> None:
        verify(self.sender, self.signature, self.signed_bytes(recipient))


def error_body(code: int, text: str = "") -> bytes:
    out = Writer().u16(code)
    if text:
        out.string(text)
    return out.bytes()


def parse_error(body: bytes) -> tuple[int, str]:
    reader = Reader(body)
    code = reader.u16()
    text = reader.string() if reader.remaining else ""
    reader.end()
    return code, text


def ack_body(result: bool, version: int | None = None) -> bytes:
    """Generic acknowledgement [6.12]."""
    out = Writer().boolean(result)
    if version is not None:
        out.u64(version)
    return out.bytes()


def parse_ack(body: bytes) -> tuple[bool, int | None]:
    reader = Reader(body)
    result = reader.boolean()
    version = reader.u64() if reader.remaining == 8 else None
    reader.end()
    return result, version


def fragment_ack_body(salt: bytes, count: int, received: set[int]) -> bytes:
    """[5.7]: salt, count, bitfield (bit i = fragment i; MSB first)."""
    bits = bytearray((count + 7) // 8)
    for index in received:
        bits[index // 8] |= 0x80 >> (index % 8)
    return salt + count.to_bytes(2, "big") + bytes(bits)


def parse_fragment_ack(body: bytes) -> tuple[bytes, int, set[int]]:
    reader = Reader(body)
    salt, count = reader.raw(16), reader.u16()
    bits = reader.raw((count + 7) // 8)
    reader.end()
    return salt, count, {i for i in range(count) if bits[i // 8] & (0x80 >> (i % 8))}


# ---------------------------------------------------------------------------
# Signed objects [7]
# ---------------------------------------------------------------------------


def _roles(writer: Writer, roles: list[int]) -> None:
    writer.u16(len(roles))
    for role in roles:
        writer.u8(role)


def _read_roles(reader: Reader) -> list[int]:
    roles = [reader.u8() for _ in range(reader.u16())]
    if any(r not in (1, 2, 3, 4) for r in roles):
        raise WireError("unknown role")
    return roles


@dataclass(slots=True)
class CreationToken:  # pylint: disable=too-many-instance-attributes
    """[7.7]: signed by the USD key, bound to the node's Ed25519 key."""

    usdn: str
    node_key: bytes
    roles: list[int]
    issued: int
    expires: int
    issuer: bytes
    founder: bool = False
    serial: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    signature: bytes = b""
    version: int = 1

    def _unsigned(self) -> bytes:
        out = Writer().u8(self.version).u8(0x80 if self.founder else 0).ident(self.usdn)
        out.raw(self.node_key)
        _roles(out, self.roles)
        out.u64(self.issued).u64(self.expires).raw(self.serial).raw(self.issuer)
        return out.bytes()

    def sign(self, key: SigningKey) -> "CreationToken":
        self.issuer = key.public
        self.signature = key.sign(b"USMD-NCP-v1-creation-token" + self._unsigned())
        return self

    def encode(self) -> bytes:
        return self._unsigned() + self.signature

    def verify(self) -> None:
        verify(self.issuer, self.signature, b"USMD-NCP-v1-creation-token" + self._unsigned())

    @classmethod
    def read(cls, reader: Reader) -> "CreationToken":
        version = reader.u8()
        if version != 1:
            raise WireError("unknown creation token version")
        flags = reader.u8()
        if flags & 0x7F:
            raise WireError("reserved token flags set")
        usdn, node_key = reader.ident(), reader.raw(32)
        roles = _read_roles(reader)
        issued, expires, serial, issuer = reader.u64(), reader.u64(), reader.raw(16), reader.raw(32)
        return cls(usdn, node_key, roles, issued, expires, issuer, bool(flags & 0x80),
                   serial, reader.raw(64), version)


@dataclass(slots=True)
class NodeRecord:  # pylint: disable=too-many-instance-attributes
    """[7.8]: signed by the node it describes."""

    node_id: str
    address: str
    x25519: bytes
    state: int
    date: int
    mutation: str = ""
    reference_nodes: list[str] = field(default_factory=list)
    sp_addresses: list[int] = field(default_factory=list)
    voter: bool = False
    signature: bytes = b""
    operators: list[int] = field(default_factory=list)  # roles the master elected it to

    @property
    def flags(self) -> int:
        flags = 0x80 if self.voter else 0
        for role in self.operators:
            flags |= OPERATOR_FLAGS.get(Role(role), 0)
        return flags

    def _unsigned(self) -> bytes:
        out = Writer().ident(self.node_id).raw(ipaddress.IPv4Address(self.address).packed)
        out.raw(self.x25519).u16(self.state).u8(self.flags).u64(self.date)
        out.string(self.mutation).u16(len(self.reference_nodes))
        for ref in self.reference_nodes:
            out.ident(ref)
        out.u16(len(self.sp_addresses))
        for address in self.sp_addresses:
            out.u32(address)
        return out.bytes()

    def signed_bytes(self, node_key: bytes) -> bytes:
        return b"USMD-NCP-v1-node-record" + node_key + self._unsigned()

    def sign(self, key: SigningKey) -> "NodeRecord":
        self.signature = key.sign(self.signed_bytes(key.public))
        return self

    def encode(self) -> bytes:
        return self._unsigned() + self.signature

    def verify(self, node_key: bytes) -> None:
        verify(node_key, self.signature, self.signed_bytes(node_key))

    @classmethod
    def read(cls, reader: Reader) -> "NodeRecord":
        node_id = reader.ident()
        address = str(ipaddress.IPv4Address(reader.raw(4)))
        x25519, state = reader.raw(32), reader.u16()
        flags = reader.u8()
        if flags & 0x0F:
            raise WireError("reserved record flags set")
        date, mutation = reader.u64(), reader.string()
        refs = [reader.ident() for _ in range(reader.u16())]
        sp = [reader.u32() for _ in range(reader.u16())]
        operators = [int(r) for r, bit in OPERATOR_FLAGS.items() if flags & bit]
        return cls(node_id, address, x25519, state, date, mutation, refs, sp,
                   bool(flags & 0x80), reader.raw(64), operators)


@dataclass(slots=True)
class TableEntry:
    """Creation token + latest node record [6.14]."""

    token: CreationToken
    record: NodeRecord

    def encode(self) -> bytes:
        return self.token.encode() + self.record.encode()

    @classmethod
    def read(cls, reader: Reader) -> "TableEntry":
        return cls(CreationToken.read(reader), NodeRecord.read(reader))

    def verify(self, usd_key: bytes) -> None:
        """Token signed by the USD key, record by the token's node key [7.9]."""
        if self.token.issuer != usd_key:
            raise WireError("token not issued by this USD's key")
        self.token.verify()
        self.record.verify(self.token.node_key)


@dataclass(slots=True)
class EndorsementPacket:  # pylint: disable=too-many-instance-attributes
    """[7.1]: 202 + k bytes."""

    endorser: bytes
    node_id: str
    node_key: bytes
    node_x25519: bytes
    roles: list[int]
    expiration: int
    serial: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    signature: bytes = b""

    def _unsigned(self) -> bytes:
        out = Writer().raw(self.endorser).ident(self.node_id).raw(self.node_key)
        out.raw(self.node_x25519)
        _roles(out, self.roles)
        out.raw(self.serial).u64(self.expiration)
        return out.bytes()

    def sign(self, key: SigningKey) -> "EndorsementPacket":
        self.endorser = key.public
        self.signature = key.sign(b"USMD-NCP-v1-endorsement" + self._unsigned())
        return self

    def encode(self) -> bytes:
        return self._unsigned() + self.signature

    def verify(self) -> None:
        verify(self.endorser, self.signature, b"USMD-NCP-v1-endorsement" + self._unsigned())

    @classmethod
    def read(cls, reader: Reader) -> "EndorsementPacket":
        endorser, node_id, node_key, x25519 = (reader.raw(32), reader.ident(),
                                               reader.raw(32), reader.raw(32))
        roles = _read_roles(reader)
        serial, expiration = reader.raw(16), reader.u64()
        return cls(endorser, node_id, node_key, x25519, roles, expiration, serial, reader.raw(64))

    @classmethod
    def decode(cls, data: bytes) -> "EndorsementPacket":
        reader = Reader(data)
        packet = cls.read(reader)
        reader.end()
        return packet


# ---------------------------------------------------------------------------
# Configuration objects [6.8 - 6.10], signed by the authority (USC key)
# ---------------------------------------------------------------------------


LABEL_MAX = 64


def check_label(label: str) -> None:
    """[NCP-03 6.8]: 0 to 64 bytes of UTF-8, no control character."""
    if len(label.encode("utf-8")) > LABEL_MAX:
        raise WireError(f"a label is at most {LABEL_MAX} bytes of UTF-8")
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in label):
        raise WireError("a label holds no control character")


@dataclass(slots=True)
class UscProperties:
    uscn: str
    version: int
    public_key: bytes
    usd: list[str]
    signature: bytes = b""
    #: Readable name chosen by the authority; signed, identifies nothing [NCP-03 6.8].
    label: str = ""

    def _unsigned(self) -> bytes:
        out = Writer().ident(self.uscn).string(self.label).u64(self.version)
        out.raw(self.public_key).u16(len(self.usd))
        for usdn in self.usd:
            out.ident(usdn)
        return out.bytes()

    def validate(self) -> None:
        """Error 0x0003 when the label is too long or holds a control character."""
        check_label(self.label)

    def sign(self, key: SigningKey) -> "UscProperties":
        self.signature = key.sign(self._unsigned())
        return self

    def verify(self, authority: bytes) -> None:
        verify(authority, self.signature, self._unsigned())

    def encode(self) -> bytes:
        return self._unsigned() + self.signature

    @classmethod
    def decode(cls, data: bytes) -> "UscProperties":
        reader = Reader(data)
        uscn, label, version, key = reader.ident(), reader.string(), reader.u64(), reader.raw(32)
        usd = [reader.ident() for _ in range(reader.u16())]
        obj = cls(uscn, version, key, usd, reader.raw(64), label)
        reader.end()
        return obj


@dataclass(frozen=True, slots=True)
class Area:
    area_id: int
    name: str
    prefix: str
    length: int


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    service_id: int
    name: str
    area_id: int
    vip: str
    group: str  # "0.0.0.0" when none


@dataclass(slots=True)
class UsdProperties:  # pylint: disable=too-many-instance-attributes
    usdn: str
    version: int
    public_key: bytes
    areas: list[Area]
    catalog: list[CatalogEntry]
    parameters: dict[int, int]
    signature: bytes = b""
    #: Readable name chosen by the authority; signed, identifies nothing [NCP-03 6.9].
    label: str = ""

    def _unsigned(self) -> bytes:
        out = Writer().ident(self.usdn).string(self.label).u64(self.version).raw(self.public_key)
        out.u16(len(self.areas))
        for area in self.areas:
            out.u8(area.area_id).string(area.name)
            out.raw(ipaddress.IPv4Address(area.prefix).packed).u8(area.length)
        out.u16(len(self.catalog))
        for entry in self.catalog:
            out.u16(entry.service_id).string(entry.name).u8(entry.area_id)
            out.raw(ipaddress.IPv4Address(entry.vip).packed)
            out.raw(ipaddress.IPv4Address(entry.group).packed)
        out.u16(len(self.parameters))
        for code in sorted(self.parameters):
            out.u16(code).u32(self.parameters[code])
        return out.bytes()

    def sign(self, key: SigningKey) -> "UsdProperties":
        self.signature = key.sign(self._unsigned())
        return self

    def verify(self, authority: bytes) -> None:
        verify(authority, self.signature, self._unsigned())

    def encode(self) -> bytes:
        return self._unsigned() + self.signature

    @classmethod
    def decode(cls, data: bytes) -> "UsdProperties":
        reader = Reader(data)
        usdn, label, version, key = reader.ident(), reader.string(), reader.u64(), reader.raw(32)
        areas = []
        for _ in range(reader.u16()):
            area_id, name = reader.u8(), reader.string()
            prefix, length = str(ipaddress.IPv4Address(reader.raw(4))), reader.u8()
            if not 8 <= length <= 32:
                raise WireError("area mask length out of 8..32")
            areas.append(Area(area_id, name, prefix, length))
        catalog = []
        for _ in range(reader.u16()):
            service_id, name, area_id = reader.u16(), reader.string(), reader.u8()
            vip = str(ipaddress.IPv4Address(reader.raw(4)))
            group = str(ipaddress.IPv4Address(reader.raw(4)))
            catalog.append(CatalogEntry(service_id, name, area_id, vip, group))
        parameters = {}
        for _ in range(reader.u16()):
            code = reader.u16()
            parameters[code] = reader.u32()
        obj = cls(usdn, version, key, areas, catalog, parameters, reader.raw(64), label)
        reader.end()
        return obj

    def validate(self) -> None:
        """Validity rules of [ARCH 11.1, 11.2] (error 0x0003 when broken).

        A USD contains one or more service areas, each with a mask length of
        8..32 [ARCH 11.2] - the same range the decoder enforces.
        """
        check_label(self.label)
        if not self.areas:
            raise WireError("a USD contains at least one service area [ARCH 11.2]")
        ids, names, nets = set(), set(), []
        for area in self.areas:
            if not 8 <= area.length <= 32:
                raise WireError("area mask length out of 8..32")
            if area.area_id in ids or area.name in names:
                raise WireError("duplicate area")
            ids.add(area.area_id)
            names.add(area.name)
            net = ipaddress.IPv4Network(f"{area.prefix}/{area.length}", strict=False)
            if any(net.overlaps(other) for other in nets):
                raise WireError("overlapping area prefixes")
            nets.append(net)
        by_id = {a.area_id: ipaddress.IPv4Network(f"{a.prefix}/{a.length}", strict=False)
                 for a in self.areas}
        seen_ids, seen_names, seen_vips, seen_groups = set(), set(), set(), set()
        for entry in self.catalog:
            if entry.vip in seen_vips or (entry.group != "0.0.0.0" and entry.group in seen_groups):
                raise WireError("a VIP or group address is used by two services [SP 4.2]")
            seen_vips.add(entry.vip)
            seen_groups.add(entry.group)
            if not 0x001 <= entry.service_id <= 0xFFE or entry.service_id in seen_ids \
                    or entry.name in seen_names:
                raise WireError("invalid or duplicate service identifier or name")
            seen_ids.add(entry.service_id)
            seen_names.add(entry.name)
            if entry.area_id not in by_id or \
                    ipaddress.IPv4Address(entry.vip) not in by_id[entry.area_id]:
                raise WireError("service VIP outside its area")
            if entry.group != "0.0.0.0" and \
                    ipaddress.IPv4Address(entry.group) not in ipaddress.IPv4Network("239.0.0.0/8"):
                raise WireError("group address outside 239.0.0.0/8")


@dataclass(slots=True)
class MutationProperties:  # pylint: disable=too-many-instance-attributes
    name: str
    version: int
    average_transmutation_ms: int
    min_instances: int
    max_instances: int
    service_file: bytes
    signature: bytes = b""

    def _unsigned(self) -> bytes:
        return (Writer().string(self.name).u64(self.version).u32(self.average_transmutation_ms)
                .u16(self.min_instances).u16(self.max_instances)
                .u32(len(self.service_file)).raw(self.service_file).bytes())

    def sign(self, key: SigningKey) -> "MutationProperties":
        self.signature = key.sign(self._unsigned())
        return self

    def verify(self, authority: bytes) -> None:
        verify(authority, self.signature, self._unsigned())

    def encode(self) -> bytes:
        return self._unsigned() + self.signature

    @classmethod
    def read(cls, reader: Reader) -> "MutationProperties":
        name, version = reader.string(), reader.u64()
        average, low, high = reader.u32(), reader.u16(), reader.u16()
        service_file = reader.raw(reader.u32())
        return cls(name, version, average, low, high, service_file, reader.raw(64))


def encode_mutations(mutations: list[MutationProperties]) -> bytes:
    return Writer().u16(len(mutations)).raw(b"".join(m.encode() for m in mutations)).bytes()


def decode_mutations(body: bytes) -> list[MutationProperties]:
    reader = Reader(body)
    out = [MutationProperties.read(reader) for _ in range(reader.u16())]
    reader.end()
    return out


# ---------------------------------------------------------------------------
# Raft records [6.16 - 6.18]
# ---------------------------------------------------------------------------


class RecordType(IntEnum):
    ASSIGN = 0x01
    RELEASE = 0x02
    ADD_VOTER = 0x03
    REMOVE_VOTER = 0x04
    NOOP = 0x05
    ELECT_OPERATOR = 0x06
    DEPOSE_OPERATOR = 0x07


@dataclass(frozen=True, slots=True)
class LogRecord:
    term: int
    type: int
    data: bytes

    def encode(self) -> bytes:
        return Writer().u64(self.term).u8(self.type).blob(self.data).bytes()

    @classmethod
    def read(cls, reader: Reader) -> "LogRecord":
        term, kind, data = reader.u64(), reader.u8(), reader.blob()
        expected = {1: 62, 2: 4, 3: 58, 4: 26, 5: 0, 6: 27, 7: 27}.get(kind)
        if expected is None or len(data) != expected:
            raise WireError("malformed Raft record")
        return cls(term, kind, data)


# ---------------------------------------------------------------------------
# Operate [ARCH 12.5]
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class OperateRequest:  # pylint: disable=too-many-instance-attributes
    """One console exchange from an elected operator::

        flags (8: 0x80 credentials, 0x40 target) ‖ session (64)
        ‖ [target (Identifiant)] ‖ length (32) ‖ JSON (UTF-8)
        ‖ [length (32) ‖ USD properties ‖ creation token ‖ X25519 (32)]

    The JSON is the local console's (``line`` / ``confirm``, ``complete``...).
    An operator of another USD of the USC adds its credentials: its USD
    properties, signed by the USC, and its creation token, signed by that
    USD's key; ``target`` asks the receiver to relay to a node of its USD.
    """

    session: int
    payload: bytes
    target: str = ""
    usd: UsdProperties | None = None
    token: CreationToken | None = None
    x25519: bytes = b""

    def encode(self) -> bytes:
        foreign = self.token is not None and self.usd is not None
        out = Writer().u8((0x80 if foreign else 0) | (0x40 if self.target else 0))
        out.u64(self.session)
        if self.target:
            out.ident(self.target)
        out.u32(len(self.payload)).raw(self.payload)
        if foreign:
            usd = self.usd.encode()
            out.u32(len(usd)).raw(usd).raw(self.token.encode()).raw(self.x25519)
        return out.bytes()

    @classmethod
    def decode(cls, body: bytes) -> "OperateRequest":
        reader = Reader(body)
        flags = reader.u8()
        if flags & 0x3F:
            raise WireError("reserved Operate flags set")
        session = reader.u64()
        target = reader.ident() if flags & 0x40 else ""
        payload = reader.raw(reader.u32())
        usd = token = None
        x25519 = b""
        if flags & 0x80:
            usd = UsdProperties.decode(reader.raw(reader.u32()))
            token = CreationToken.read(reader)
            x25519 = reader.raw(32)
        reader.end()
        return cls(session, payload, target, usd, token, x25519)


def read_list(reader: Reader, item) -> list:
    return [item(reader) for _ in range(reader.u16())]


def ids(values: list[str]) -> bytes:
    out = Writer().u16(len(values))
    for value in values:
        out.ident(value)
    return out.bytes()


def read_ids(reader: Reader) -> list[str]:
    return [reader.ident() for _ in range(reader.u16())]
