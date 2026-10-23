"""Dissectors: NNDP, NCP and SP frames as trees of named fields.

Each ``dissect_*`` function returns the summary line and the
:class:`~usmd_rdsh.node.capture.Dissection` of one frame; the protocol
services call them only when the capture wants their frames. A dissector
never raises: what does not decode ends the tree with a "malformed" line,
the way Wireshark marks a short frame.

NCP travels encrypted; its messages are dissected after reassembly and
decryption, the plaintext being a second byte view of the packet.
"""

from __future__ import annotations

import ipaddress
import struct
import time
from typing import Any, Callable

from usmd_rdsh.node import addresses
from usmd_rdsh.node.capture import Dissection, Item, register
from usmd_rdsh.node.ncp.codec import (
    Command,
    ErrorCode,
    MessageType,
    UscProperties,
    UsdProperties,
    decode_mutations,
)
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import HEADER_SIZE, MAGIC, Reader, WireError

register({
    "usmd": "USMD-RDSH frame header",
    "usmd.magic": "Magic",
    "usmd.version": "Version",
    "usmd.event": "Event",
    "usmd.length": "Length",
    "malformed": "Malformed frame",
    # NNDP-01 5.2, 5.4
    "nndp": "Neighbor Node Discovery Protocol",
    "nndp.public_key": "Ed25519 public key",
    "nndp.signature": "Signature",
    "nndp.id_length": "Identifier length",
    "nndp.node_id": "Node ID",
    "nndp.next_emission": "Next emission",
    "nndp.interval": "Announced interval (ms)",
    "nndp.state": "State",
    "nndp.timestamp": "Timestamp",
    "nndp.x25519": "X25519 public key",
    "nndp.hosted_count": "Hosted services",
    "nndp.hosted": "Hosted SP address",
    "nndp.vector_count": "Vector entries",
    "nndp.vector.address": "SP address",
    "nndp.vector.distance": "Distance (permille)",
    "nndp.vector.hops": "Hops",
    # NCP-02 5.2 - 5.7
    "ncp": "Node Control Protocol",
    "ncp.command": "Command",
    "ncp.fragments": "Fragments",
    "ncp.ephemeral": "Ephemeral X25519 key",
    "ncp.salt": "Salt",
    "ncp.nonce": "Nonce",
    "ncp.fragment.index": "Fragment index",
    "ncp.fragment.count": "Fragment count",
    "ncp.sealed": "Sealed data",
    "ncp.type": "Message type",
    "ncp.request_id": "Request ID",
    "ncp.timestamp": "Timestamp",
    "ncp.sender": "Sender Ed25519 key",
    "ncp.body": "Body",
    "ncp.signature": "Signature",
    "ncp.error.code": "Error code",
    "ncp.error.text": "Error text",
    "ncp.ack.salt": "Acknowledged salt",
    "ncp.ack.count": "Fragment count",
    "ncp.ack.received": "Fragments received",
    "ncp.result": "Result",
    "ncp.version": "Version held",
    "ncp.sent_at": "Sent at",
    "ncp.reason": "Reason",
    "ncp.load": "Load (permille)",
    "ncp.node_id": "Node ID",
    "ncp.state": "State",
    "ncp.validity": "Validity",
    "ncp.mutation": "Mutation",
    "ncp.service": "Service",
    "ncp.table.mode": "Mode",
    "ncp.table.page": "Page",
    "ncp.table.pages": "Pages",
    "ncp.table.entries": "Entries",
    "ncp.address": "Address",
    "ncp.object.name": "Identifier",
    "ncp.object.version": "Version",
    # SP-01 7.3 - 7.6
    "sp": "Service Protocol",
    "sp.frame": "Frame type",
    "sp.index_i": "Initiator index",
    "sp.index_r": "Responder index",
    "sp.ephemeral": "Ephemeral X25519 key",
    "sp.timestamp": "Timestamp",
    "sp.sealed": "Sealed identity",
    "sp.receiver_index": "Receiver index",
    "sp.counter": "Counter",
    "sp.ciphertext": "Ciphertext",
    "sp.keepalive": "Keepalive",
    "sp.source": "SP source",
    "sp.destination": "SP destination",
    "sp.broadcast_id": "Broadcast ID",
    "inner": "Inner IPv4 packet",
    "inner.src": "Source",
    "inner.dst": "Destination",
    "inner.proto": "Protocol",
    "inner.ttl": "Time to live",
    "inner.len": "Total length",
    "inner.dscp": "DSCP",
    "inner.ecn": "ECN",
    "inner.srcport": "Source port",
    "inner.dstport": "Destination port",
})

NNDP_EVENTS = {0x0001: "Here I am"}
SP_EVENTS = {0x0001: "Initiation", 0x0002: "Response", 0x0003: "Data"}
_INNER_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Cursor:
    """Reads big-endian fields, remembering where each one was."""

    def __init__(self, data: bytes, at: int = 0, end: int | None = None) -> None:
        self.data = data
        self.at = at
        self.end = len(data) if end is None else end

    def take(self, size: int) -> tuple[int, bytes]:
        if size < 0 or self.at + size > self.end:
            raise WireError("truncated field")
        start = self.at
        self.at += size
        return start, self.data[start:self.at]

    def add_int(self, item: Item, name: str, size: int, *,
                fmt: Callable[[int], str] | None = None,
                alias: Callable[[int], str | None] | None = None) -> tuple[int, Item]:
        start, raw = self.take(size)
        value = int.from_bytes(raw, "big")
        child = item.add(name, value=value, shown=fmt(value) if fmt else str(value),
                         alias=alias(value) if alias else None, at=start, size=size)
        return value, child

    def add_bytes(self, item: Item, name: str, size: int, **kwargs: Any) -> tuple[bytes, Item]:
        start, raw = self.take(size)
        return raw, item.add(name, value=raw, at=start, size=size, **kwargs)

    def add_ident(self, item: Item, name: str) -> tuple[str, Item]:
        start, raw = self.take(26)
        text = raw.decode("ascii", errors="replace")
        return text, item.add(name, value=text, at=start, size=26)


def _hex16(value: int) -> str:
    return f"0x{value:04X}"


def state_name(value: int) -> str | None:
    try:
        return State(value).name
    except ValueError:
        return None


def _state(value: int) -> str:
    name = state_name(value)
    return f"{name} (0x{value:04X})" if name else f"0x{value:04X}"


def _when(ms: int) -> str:
    if not 0 < ms < 1 << 50:
        return str(ms)
    stamp = ms / 1000
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stamp)) + f".{ms % 1000:03d}"


def _command(value: int) -> str | None:
    try:
        return Command(value).name
    except ValueError:
        return None


def _enum_name(enum, value: int) -> str | None:
    try:
        return enum(value).name
    except ValueError:
        return None


def sp_address(value: int) -> str:
    try:
        return addresses.to_text(value)
    except ValueError:
        return f"0x{value:08X}"


def _short(key: bytes) -> str:
    return key.hex()[:12]


def _header(root: Item, data: bytes, at: int, names: dict[int, str]) -> tuple[int, int]:
    """The 9 common bytes [ARCH-02 10.1]; (event, length)."""
    cursor = _Cursor(data, at)
    head = root.add("usmd", value=True, shown="", at=at, size=HEADER_SIZE)
    cursor.add_int(head, "usmd.magic", 2,
                   fmt=lambda v: f"0x{v:04X}" + ("" if v == MAGIC else " (wrong)"))
    cursor.add_int(head, "usmd.version", 1)
    event, _ = cursor.add_int(head, "usmd.event", 2,
                              fmt=lambda v: f"{names.get(v, 'unknown')} (0x{v:04X})",
                              alias=lambda v: names.get(v))
    length, _ = cursor.add_int(head, "usmd.length", 4)
    return event, length


def _malformed(item: Item, exc: Exception) -> None:
    item.add("malformed", value=True, shown=f"[Malformed frame: {exc}]")


# ---------------------------------------------------------------------------
# NNDP [NNDP-01 5.2, 5.4]
# ---------------------------------------------------------------------------


def dissect_nndp(data: bytes) -> tuple[str, Dissection]:
    """One NNDP datagram: key | signature | header | HIA payload."""
    dissection = Dissection()
    root = dissection.root.add("nndp", value=True, shown="Here I am")
    info = "HIA"
    cursor = _Cursor(data)
    try:
        key, _ = cursor.add_bytes(root, "nndp.public_key", 32)
        cursor.add_bytes(root, "nndp.signature", 64)
        event, _length = _header(root, data, 96, NNDP_EVENTS)
        cursor.at = 96 + HEADER_SIZE
        if event != 0x0001:
            info = f"Unknown event 0x{event:04X}"
            raise WireError("not a Here I am")
        cursor.add_int(root, "nndp.id_length", 2)
        node_id, _ = cursor.add_ident(root, "nndp.node_id")
        next_emission, _ = cursor.add_int(root, "nndp.next_emission", 8, fmt=_when)
        state, _ = cursor.add_int(root, "nndp.state", 2, fmt=_state, alias=state_name)
        timestamp, _ = cursor.add_int(root, "nndp.timestamp", 8, fmt=_when)
        root.add("nndp.interval", value=next_emission - timestamp)
        cursor.add_bytes(root, "nndp.x25519", 32)
        count, hosted_item = cursor.add_int(root, "nndp.hosted_count", 2)
        hosted = []
        for _ in range(min(count, 64)):
            value, _ = cursor.add_int(hosted_item, "nndp.hosted", 4, fmt=sp_address,
                                      alias=sp_address)
            hosted.append(sp_address(value))
        count, vector_item = cursor.add_int(root, "nndp.vector_count", 2)
        for index in range(min(count, 240)):
            start = cursor.at
            entry = vector_item.text(f"Entry {index}", at=start, size=7)
            address, _ = cursor.add_int(entry, "nndp.vector.address", 4, fmt=sp_address,
                                        alias=sp_address)
            distance, _ = cursor.add_int(entry, "nndp.vector.distance", 2,
                                         fmt=lambda v: "65535 (unreachable)" if v == 65535
                                         else str(v))
            hops, _ = cursor.add_int(entry, "nndp.vector.hops", 1)
            entry.node["l"] = f"Entry {index}: {sp_address(address)} D={distance} hops={hops}"
        info = (f"HIA {node_id} {state_name(state) or _hex16(state)}, "
                f"{len(hosted)} hosted, {count} vector, I={(next_emission - timestamp) // 1000} s")
        root.node["v"] = f"Here I am from {node_id} (key {_short(key)})"
    except WireError as exc:
        _malformed(root, exc)
    return info, dissection


# ---------------------------------------------------------------------------
# NCP [NCP-02 5.2 - 5.7, 6]
# ---------------------------------------------------------------------------


def _command_text(event: int) -> str:
    return _command(event) or f"0x{event:04X}"


def dissect_ncp_fragment(data: bytes) -> tuple[str, Dissection]:
    """An NCP datagram that could not be opened: only its clear envelope."""
    dissection = Dissection()
    root = dissection.root.add("ncp", value=True, shown="fragment (not decrypted)")
    info = "NCP fragment"
    try:
        event, _ = _header(root, data, 0, {c.value: c.name for c in Command})
        root.add("ncp.command", value=event, shown=_command_text(event), alias=_command(event))
        cursor = _Cursor(data, HEADER_SIZE)
        cursor.add_bytes(root, "ncp.ephemeral", 32)
        cursor.add_bytes(root, "ncp.salt", 16)
        cursor.add_bytes(root, "ncp.nonce", 12)
        index, _ = cursor.add_int(root, "ncp.fragment.index", 2)
        count, _ = cursor.add_int(root, "ncp.fragment.count", 2)
        cursor.add_bytes(root, "ncp.sealed", len(data) - cursor.at)
        info = f"{_command_text(event)} fragment {index + 1}/{count} (encrypted)"
    except WireError as exc:
        _malformed(root, exc)
    return info, dissection


def dissect_ncp(event: int, plaintext: bytes, *, fragments: int = 1) -> tuple[str, Dissection]:
    """A reassembled, decrypted NCP message [5.6]."""
    dissection = Dissection()
    buf = dissection.buffer("Déchiffré", plaintext)
    root = dissection.root.add("ncp", value=True, shown=_command_text(event), buffer=buf)
    root.add("ncp.command", value=event, shown=f"{_command_text(event)} (0x{event:04X})",
             alias=_command(event))
    root.add("ncp.fragments", value=fragments)
    info = _command_text(event)
    cursor = _Cursor(plaintext)
    try:
        kind, _ = cursor.add_int(root, "ncp.type", 1,
                                 fmt=lambda v: f"{_enum_name(MessageType, v) or '?'} ({v})",
                                 alias=lambda v: _enum_name(MessageType, v))
        request_id, _ = cursor.add_int(root, "ncp.request_id", 8, fmt=lambda v: f"0x{v:016x}")
        cursor.add_int(root, "ncp.timestamp", 8, fmt=_when)
        sender, _ = cursor.add_bytes(root, "ncp.sender", 32)
        if len(plaintext) < cursor.at + 64:
            raise WireError("message shorter than its signature")
        body_end = len(plaintext) - 64
        body = plaintext[cursor.at:body_end]
        body_item = root.add("ncp.body", value=body, shown=f"{len(body)} bytes",
                             at=cursor.at, size=len(body))
        root.add("ncp.signature", value=plaintext[body_end:], at=body_end, size=64)
        kind_name = _enum_name(MessageType, kind) or "?"
        info = f"{_command_text(event)} {kind_name.title().replace('_', ' ')}"
        if kind != MessageType.FRAGMENT_ACK:
            info += f" id={request_id:x}"
        detail = _ncp_body(event, kind, _Cursor(plaintext, cursor.at, body_end), body_item)
        if detail:
            info += f" {detail}"
        info += f" from {_short(sender)}"
        if fragments > 1:
            info += f" [{fragments} fragments]"
    except WireError as exc:
        _malformed(root, exc)
    return info, dissection


def _ncp_body(event: int, kind: int, cursor: _Cursor, item: Item) -> str:
    """The body of one message; the text appended to the summary."""
    try:
        if kind == MessageType.ERROR:
            code, _ = cursor.add_int(item, "ncp.error.code", 2,
                                     fmt=lambda v: f"{_enum_name(ErrorCode, v) or '?'} "
                                                   f"(0x{v:04X})",
                                     alias=lambda v: _enum_name(ErrorCode, v))
            text = ""
            if cursor.end - cursor.at >= 2:
                length = int.from_bytes(cursor.data[cursor.at:cursor.at + 2], "big")
                cursor.take(2)
                start, raw = cursor.take(length)
                text = raw.decode("utf-8", errors="replace")
                item.add("ncp.error.text", value=text, at=start, size=length)
            return f"0x{code:04X} {_enum_name(ErrorCode, code) or ''} {text}".rstrip()
        if kind == MessageType.FRAGMENT_ACK:
            cursor.add_bytes(item, "ncp.ack.salt", 16)
            count, _ = cursor.add_int(item, "ncp.ack.count", 2)
            start, bits = cursor.take((count + 7) // 8)
            received = sum(1 for i in range(count) if bits[i // 8] & (0x80 >> (i % 8)))
            item.add("ncp.ack.received", value=received, shown=f"{received}/{count}",
                     at=start, size=len(bits))
            return f"{received}/{count}"
        if kind == MessageType.RESPONSE:
            return _ncp_response(cursor, item)
        handler = _REQUESTS.get(event)
        return handler(cursor, item) if handler else ""
    except (WireError, ValueError) as exc:
        _malformed(item, exc)
        return ""


def _ncp_response(cursor: _Cursor, item: Item) -> str:
    size = cursor.end - cursor.at
    if size not in (1, 9) or cursor.data[cursor.at] > 1:
        return ""
    result, _ = cursor.add_int(item, "ncp.result", 1, fmt=lambda v: "true" if v else "false")
    if size == 9:
        cursor.add_int(item, "ncp.version", 8)
    return "result=" + ("true" if result else "false")


def _ids(cursor: _Cursor, item: Item) -> list[str]:
    count = int.from_bytes(cursor.take(2)[1], "big")
    return [cursor.add_ident(item, "ncp.node_id")[0] for _ in range(min(count, 256))]


def _req_check_distance(cursor: _Cursor, item: Item) -> str:
    cursor.add_int(item, "ncp.sent_at", 8, fmt=_when)
    return ""


def _req_help(cursor: _Cursor, item: Item) -> str:
    reason, _ = cursor.add_int(item, "ncp.reason", 2, fmt=_hex16)
    nodes = _ids(cursor, item)
    load, _ = cursor.add_int(item, "ncp.load", 2)
    return f"reason=0x{reason:04X} load={load} nodes={len(nodes)}"


def _req_confirm_delegation(cursor: _Cursor, item: Item) -> str:
    length = int.from_bytes(cursor.take(2)[1], "big")
    start, raw = cursor.take(length)
    mutation = raw.decode("utf-8", errors="replace")
    item.add("ncp.mutation", value=mutation, at=start, size=length)
    reason, _ = cursor.add_int(item, "ncp.reason", 2, fmt=_hex16)
    return f"{mutation} reason=0x{reason:04X}"


def _req_declare_state(cursor: _Cursor, item: Item) -> str:
    state, _ = cursor.add_int(item, "ncp.state", 2, fmt=_state, alias=state_name)
    if cursor.end - cursor.at == 8:
        cursor.add_int(item, "ncp.validity", 8, fmt=_when)
    return state_name(state) or _hex16(state)


def _req_management_id(cursor: _Cursor, item: Item) -> str:
    count = int.from_bytes(cursor.take(2)[1], "big")
    services = [cursor.add_int(item, "ncp.service", 2, fmt=lambda v: f"{v:03x}")[0]
                for _ in range(min(count, 512))]
    return " ".join(f"{s:03x}" for s in services)


def _req_node_id(cursor: _Cursor, item: Item) -> str:
    return cursor.add_ident(item, "ncp.node_id")[0]


def _object(cursor: _Cursor) -> bytes:
    return cursor.data[cursor.at:cursor.end]


def _req_usc(cursor: _Cursor, item: Item) -> str:
    usc = UscProperties.decode(_object(cursor))
    item.add("ncp.object.name", value=usc.uscn)
    item.add("ncp.object.version", value=usc.version)
    for usdn in usc.usd:
        item.add("ncp.node_id", "USD", value=usdn)
    return f"USC {usc.uscn} v{usc.version}"


def _req_usd(cursor: _Cursor, item: Item) -> str:
    usd = UsdProperties.decode(_object(cursor))
    item.add("ncp.object.name", value=usd.usdn)
    item.add("ncp.object.version", value=usd.version)
    for area in usd.areas:
        item.text(f"Area {area.area_id} {area.name}: {area.prefix}/{area.length}")
    for entry in usd.catalog:
        item.add("ncp.service", value=entry.service_id,
                 shown=f"{entry.service_id:03x} {entry.name} (area {entry.area_id}, "
                       f"VIP {entry.vip})", alias=entry.name)
    for code, value in sorted(usd.parameters.items()):
        item.text(f"Parameter 0x{code:04X} = {value}")
    return f"USD {usd.usdn} v{usd.version}"


def _req_mutations(cursor: _Cursor, item: Item) -> str:
    mutations = decode_mutations(_object(cursor))
    for mutation in mutations:
        child = item.add("ncp.mutation", value=mutation.name,
                         shown=f"{mutation.name} v{mutation.version} "
                               f"({mutation.min_instances}..{mutation.max_instances} instances)")
        child.add("ncp.object.version", value=mutation.version)
    return ", ".join(m.name for m in mutations)


def _req_node_table(cursor: _Cursor, item: Item) -> str:
    from usmd_rdsh.node.ncp.codec import TableEntry  # pylint: disable=import-outside-toplevel

    mode, _ = cursor.add_int(item, "ncp.table.mode", 1)
    page, _ = cursor.add_int(item, "ncp.table.page", 2)
    pages, _ = cursor.add_int(item, "ncp.table.pages", 2)
    reader = Reader(cursor.data[cursor.at:cursor.end])
    count = reader.u16()
    entries = item.add("ncp.table.entries", value=count)
    for _ in range(min(count, 512)):
        entry = TableEntry.read(reader)
        record = entry.record
        child = entries.add("ncp.node_id", value=record.node_id,
                            shown=f"{record.node_id} {record.address} {_state(record.state)}")
        child.add("ncp.address", value=record.address)
        child.add("ncp.state", value=record.state, shown=_state(record.state),
                  alias=state_name(record.state))
    return f"mode={mode} page {page + 1}/{max(pages, 1)} entries={count}"


_REQUESTS: dict[int, Callable[[_Cursor, Item], str]] = {
    Command.CHECK_DISTANCE_TO_NODE: _req_check_distance,
    Command.REQUEST_HELP: _req_help,
    Command.REQUEST_EMERGENCY: _req_help,
    Command.CONFIRM_DELEGATION: _req_confirm_delegation,
    Command.DECLARE_STATE: _req_declare_state,
    Command.REQUEST_MANAGEMENT_ID: _req_management_id,
    Command.NOTIFY_END_OF_SERVICE: _req_node_id,
    Command.REQUEST_REVOCATION: _req_node_id,
    Command.SEND_USC_PROPERTIES: _req_usc,
    Command.SEND_USD_PROPERTIES: _req_usd,
    Command.SEND_MUTATION_PROPERTIES: _req_mutations,
    Command.SEND_NODE_TABLE: _req_node_table,
}


# ---------------------------------------------------------------------------
# SP [SP-01 7.3 - 7.6]
# ---------------------------------------------------------------------------


def dissect_sp(data: bytes, payload: Any = None) -> tuple[str, Dissection]:
    """An SP frame; *payload* is the decrypted :class:`Payload` of a data frame."""
    dissection = Dissection()
    root = dissection.root.add("sp", value=True, shown="")
    info = "SP"
    try:
        event, _ = _header(root, data, 0, SP_EVENTS)
        name = SP_EVENTS.get(event, f"0x{event:04X}")
        root.node["v"] = name
        root.add("sp.frame", value=event, shown=f"{name} (0x{event:04X})",
                 alias=SP_EVENTS.get(event))
        cursor = _Cursor(data, HEADER_SIZE)
        if event == 0x0001:
            index, _ = cursor.add_int(root, "sp.index_i", 4, fmt=lambda v: f"0x{v:08x}")
            cursor.add_bytes(root, "sp.ephemeral", 32)
            cursor.add_int(root, "sp.timestamp", 8, fmt=_when)
            cursor.add_bytes(root, "sp.sealed", len(data) - cursor.at)
            info = f"Handshake Initiation index_I=0x{index:08x}"
        elif event == 0x0002:
            index_r, _ = cursor.add_int(root, "sp.index_r", 4, fmt=lambda v: f"0x{v:08x}")
            index_i, _ = cursor.add_int(root, "sp.index_i", 4, fmt=lambda v: f"0x{v:08x}")
            cursor.add_bytes(root, "sp.ephemeral", 32)
            cursor.add_bytes(root, "sp.sealed", len(data) - cursor.at)
            info = f"Handshake Response index_R=0x{index_r:08x} index_I=0x{index_i:08x}"
        elif event == 0x0003:
            index, _ = cursor.add_int(root, "sp.receiver_index", 4, fmt=lambda v: f"0x{v:08x}")
            counter, _ = cursor.add_int(root, "sp.counter", 8)
            cursor.add_bytes(root, "sp.ciphertext", len(data) - cursor.at,
                             shown=f"{len(data) - cursor.at} bytes")
            info = f"Data index=0x{index:08x} ctr={counter}"
            if payload is not None:
                info += " " + _sp_payload(dissection, root, payload)
            else:
                info += " (not decrypted)"
        else:
            info = f"Unknown SP event 0x{event:04X}"
    except WireError as exc:
        _malformed(root, exc)
    return info, dissection


def _sp_payload(dissection: Dissection, root: Item, payload: Any) -> str:
    root.add("sp.keepalive", value=bool(payload.keepalive))
    if payload.keepalive:
        return "Keepalive"
    root.add("sp.source", value=payload.source, shown=sp_address(payload.source),
             alias=sp_address(payload.source))
    root.add("sp.destination", value=payload.destination, shown=sp_address(payload.destination),
             alias=sp_address(payload.destination))
    if payload.broadcast_id is not None:
        root.add("sp.broadcast_id", value=payload.broadcast_id,
                 shown=f"0x{payload.broadcast_id:016x}")
    text = f"{sp_address(payload.source)} → {sp_address(payload.destination)}"
    packet = payload.packet
    buf = dissection.buffer("Paquet interne", packet)
    try:
        if len(packet) < 20:
            raise WireError("inner packet shorter than an IPv4 header")
        ihl = (packet[0] & 0x0F) * 4
        tos, total = packet[1], struct.unpack_from("!H", packet, 2)[0]
        ttl, proto = packet[8], packet[9]
        src = str(ipaddress.IPv4Address(packet[12:16]))
        dst = str(ipaddress.IPv4Address(packet[16:20]))
        proto_name = _INNER_PROTOCOLS.get(proto, str(proto))
        inner = root.add("inner", value=True, shown=f"{src} → {dst} {proto_name}", buffer=buf,
                         at=0, size=ihl)
        inner.add("inner.len", value=total, at=2, size=2)
        inner.add("inner.dscp", value=tos >> 2, at=1, size=1)
        inner.add("inner.ecn", value=tos & 0x03, at=1, size=1)
        inner.add("inner.ttl", value=ttl, at=8, size=1)
        inner.add("inner.proto", value=proto, shown=f"{proto_name} ({proto})", alias=proto_name,
                  at=9, size=1)
        inner.add("inner.src", value=src, at=12, size=4)
        inner.add("inner.dst", value=dst, at=16, size=4)
        text += f" {proto_name} {src}"
        offset = struct.unpack_from("!H", packet, 6)[0] & 0x1FFF
        if proto in (6, 17) and offset == 0 and len(packet) >= ihl + 4:
            sport, dport = struct.unpack_from("!HH", packet, ihl)
            inner.add("inner.srcport", value=sport, at=ihl, size=2)
            inner.add("inner.dstport", value=dport, at=ihl + 2, size=2)
            text += f":{sport} → {dst}:{dport}"
        else:
            text += f" → {dst}"
    except (WireError, ValueError, struct.error) as exc:
        _malformed(root, exc)
    return text
