"""SP sessions: data frames, counters, anti-replay, lifetimes [SP-01 7.5, 7.6].

Data frame (event 0x0003)::

    header (9) | receiver index (4) | counter (8) | AEAD(k_dir, plaintext)
    nonce = 0x00000000 || counter,  AAD = header || index || counter

Plaintext::

    flags (1: 0x80 = keepalive) [| SP source (4) | SP destination (4)
    [| broadcast id (8), when destination is sss.ffff] | inner IPv4 packet]
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from usmd_rdsh.node import addresses
from usmd_rdsh.node.crypto import open_sealed, seal
from usmd_rdsh.node.sp.handshake import EVENT_DATA, SessionKeys
from usmd_rdsh.node.wire import HEADER_SIZE, FrameHeader, WireError

FLAG_KEEPALIVE = 0x80
REPLAY_WINDOW = 2048
REKEY_AFTER_S = 120.0
REKEY_AFTER_FRAMES = 1 << 60
SEND_LIMIT_S = 180.0
RECEIVE_LIMIT_S = 240.0
IDLE_LIMIT_S = 180.0
KEEPALIVE_S = 10.0
_COUNTER_MAX = (1 << 64) - 1


@dataclass(frozen=True, slots=True)
class Payload:
    """A decrypted data frame."""

    keepalive: bool
    source: int = 0
    destination: int = 0
    broadcast_id: int | None = None
    packet: bytes = b""


def encode_payload(payload: Payload) -> bytes:
    if payload.keepalive:
        return bytes([FLAG_KEEPALIVE])
    if payload.destination & 0xFFFF == addresses.ANY_INSTANCE:
        raise WireError("sss.0000 never travels: resolve it first [ARCH 11.3]")
    out = bytes([0]) + struct.pack("!II", payload.source, payload.destination)
    if payload.destination & 0xFFFF == addresses.ALL_INSTANCES:
        if payload.broadcast_id is None:
            raise WireError("a broadcast carries a 64-bit identifier")
        out += struct.pack("!Q", payload.broadcast_id)
    return out + payload.packet


def decode_payload(data: bytes) -> Payload:
    if not data:
        raise WireError("empty plaintext")
    if data[0] & FLAG_KEEPALIVE:  # reserved bits are ignored
        return Payload(keepalive=True)
    if len(data) < 9:
        raise WireError("plaintext too short")
    source, destination = struct.unpack_from("!II", data, 1)
    addresses.unpack(source)
    addresses.unpack(destination)
    if destination & 0xFFFF == addresses.ANY_INSTANCE:
        raise WireError("sss.0000 in a frame")
    if destination & 0xFFFF == addresses.ALL_INSTANCES:
        if len(data) < 17:
            raise WireError("broadcast without its identifier")
        (bid,) = struct.unpack_from("!Q", data, 9)
        return Payload(False, source, destination, bid, data[17:])
    return Payload(False, source, destination, None, data[9:])


class ReplayWindow:
    """Sliding window of at least 2048 counters [7.5]."""

    def __init__(self, size: int = REPLAY_WINDOW) -> None:
        self.size = max(size, REPLAY_WINDOW)
        self.highest = -1
        self._bits = 0

    def check(self, counter: int) -> bool:
        """Whether *counter* is new and inside the window (does not record)."""
        if counter > self.highest:
            return True
        offset = self.highest - counter
        return offset < self.size and not self._bits >> offset & 1

    def record(self, counter: int) -> None:
        if counter > self.highest:
            shift = counter - self.highest
            self._bits = ((self._bits << shift) | 1) & ((1 << self.size) - 1)
            self.highest = counter
        else:
            self._bits |= 1 << (self.highest - counter)


@dataclass
class Session:  # pylint: disable=too-many-instance-attributes
    """One established session with a peer."""

    keys: SessionKeys
    peer_address: str
    established: float
    send_counter: int = 0
    last_sent: float = 0.0
    last_received: float = 0.0
    last_data_received: float = 0.0
    confirmed: bool = False  # responder: first frame from I authenticated
    window: ReplayWindow = field(default_factory=ReplayWindow)

    @property
    def local_index(self) -> int:
        return self.keys.local_index

    @property
    def peer(self) -> bytes:
        return self.keys.peer_ed25519

    def can_send(self, now: float) -> bool:
        """Not past 180 s nor the counter limit; R waits for I's first frame."""
        if now - self.established > SEND_LIMIT_S or self.send_counter >= _COUNTER_MAX:
            return False
        return self.keys.initiator or self.confirmed

    def can_receive(self, now: float) -> bool:
        return now - self.established <= RECEIVE_LIMIT_S

    def needs_rekey(self, now: float) -> bool:
        return (now - self.established >= REKEY_AFTER_S
                or self.send_counter >= REKEY_AFTER_FRAMES)

    def idle(self, now: float) -> bool:
        last = max(self.last_sent, self.last_received, self.established)
        return now - last > IDLE_LIMIT_S

    def seal(self, payload: Payload, now: float) -> bytes:
        """A data frame for the peer."""
        if not self.can_send(now):
            raise WireError("session may no longer send")
        plaintext = encode_payload(payload)
        counter = self.send_counter
        self.send_counter += 1
        header = FrameHeader(EVENT_DATA, 12 + len(plaintext) + 16).encode()
        aad = header + struct.pack("!IQ", self.keys.remote_index, counter)
        nonce = bytes(4) + struct.pack("!Q", counter)
        self.last_sent = now
        return aad + seal(self.keys.send_key, nonce, plaintext, aad)

    def open(self, data: bytes, now: float) -> Payload:
        """Authenticate and decrypt a frame addressed to this session."""
        if not self.can_receive(now):
            raise WireError("session expired for reception")
        index, counter = struct.unpack_from("!IQ", data, HEADER_SIZE)
        if index != self.local_index:
            raise WireError("frame for another session")
        if not self.window.check(counter):
            raise WireError("replayed or too old counter")
        aad = data[:21]
        nonce = bytes(4) + struct.pack("!Q", counter)
        plaintext = open_sealed(self.keys.receive_key, nonce, data[21:], aad)
        self.window.record(counter)
        self.last_received = now
        self.confirmed = True
        return decode_payload(plaintext)


def data_frame_index(data: bytes) -> int:
    """The receiver index of a data frame, after the format checks."""
    header = FrameHeader.decode(data)
    if header.event != EVENT_DATA or len(data) < HEADER_SIZE + 12 + 1 + 16:
        raise WireError("not a data frame")
    return struct.unpack_from("!I", data, HEADER_SIZE)[0]
