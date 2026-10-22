"""NNDP Here I Am (HIA) packet for USMD-RDSH.

The HIA packet is broadcast via UDP (source port 5222, destination port 5221)
and is signed with Ed25519. All packets must be signed — no exceptions.

Binary layout:

.. code-block:: text

    [NNDP Version: 4 bytes]
    [Ed25519 Public Key: 32 bytes]
    [HIA Data: 24 bytes]
      - TTL: 8 bytes (big-endian uint64, seconds)
      - TIMESTAMP_64: 8 bytes (big-endian uint64, UNIX ms)
      - NONCE_32: 8 bytes (derived from TIMESTAMP_64)
    [Ed25519 Signature: 64 bytes]

Total: 4 + 32 + 24 + 64 = 124 bytes.

Examples:
    >>> priv, pub = Ed25519Pair.generate()
    >>> pkt = HereIAmPacket.build(
    ...     sender_name=1710000000,
    ...     sender_pub_key=pub,
    ...     sender_priv_key=priv,
    ...     ttl=30,
    ...     state=NodeState.ACTIVE,
    ... )
    >>> HereIAmPacket.verify_and_parse(pkt.to_bytes(), pub).is_ok()
    True
"""

import struct
import time
from dataclasses import dataclass

from ...node.state import NodeState
from ...security.crypto import Ed25519Pair
from ...utils.errors import Error, ErrorKind
from ...utils.result import Result

# NNDP version: 4 bytes (same versioning scheme as NCP)
NNDP_VERSION = bytes([1, 0, 0, 0])

# Packet structure constants
_VER_OFFSET = 0
_VER_SIZE = 4
_KEY_OFFSET = _VER_SIZE
_KEY_SIZE = 32
_DATA_OFFSET = _KEY_OFFSET + _KEY_SIZE   # 36
_TTL_SIZE = 8
_TS_SIZE = 8
_NONCE_SIZE = 8
_DATA_SIZE = _TTL_SIZE + _TS_SIZE + _NONCE_SIZE  # 24
_SIG_OFFSET = _DATA_OFFSET + _DATA_SIZE  # 60
_SIG_SIZE = 64
PACKET_SIZE = _SIG_OFFSET + _SIG_SIZE  # 124


@dataclass
class HiaData:
    """The data payload of a Here I Am packet.

    Attributes:
        ttl: Liveness interval in seconds. Peers expect the next HIA within ttl×2.
        timestamp_ms: UNIX timestamp in milliseconds at time of sending.
        nonce: 8-byte value derived from timestamp_ms (XOR with a fixed pattern).

    Examples:
        >>> data = HiaData(ttl=30, timestamp_ms=1710000000000, nonce=b"\\x00"*8)
        >>> data.ttl
        30
    """

    ttl: int
    timestamp_ms: int
    nonce: bytes

    @staticmethod
    def build(ttl: int) -> "HiaData":
        """Build HiaData with a fresh timestamp and derived nonce.

        Args:
            ttl: Liveness interval in seconds.

        Returns:
            HiaData: Ready-to-sign data.

        Example:
            >>> data = HiaData.build(ttl=30)
            >>> data.ttl
            30
            >>> len(data.nonce)
            8
        """
        ts_ms = int(time.time() * 1000)
        # Nonce derived from lower 8 bytes of timestamp XOR'd with 0xA5 pattern
        nonce = bytes([(ts_ms >> (8 * i)) & 0xFF ^ 0xA5 for i in range(8)])
        return HiaData(ttl=ttl, timestamp_ms=ts_ms, nonce=nonce)

    def to_bytes(self) -> bytes:
        """Serialise HIA data to 24 bytes.

        Returns:
            bytes: 24 bytes of data.
        """
        return struct.pack("!QQ", self.ttl, self.timestamp_ms) + self.nonce

    @staticmethod
    def from_bytes(data: bytes) -> Result["HiaData", Error]:
        """Deserialise HIA data from 24 bytes.

        Args:
            data: Exactly 24 bytes.

        Returns:
            Result[HiaData, Error]: Ok or Err.
        """
        if len(data) < _DATA_SIZE:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"HIA data needs {_DATA_SIZE} bytes, got {len(data)}",
                )
            )
        ttl, ts_ms = struct.unpack_from("!QQ", data)
        nonce = data[16:24]
        return Result.Ok(HiaData(ttl=int(ttl), timestamp_ms=int(ts_ms), nonce=nonce))


@dataclass
class HereIAmPacket:
    """A complete NNDP Here I Am packet, ready for broadcast.

    Attributes:
        sender_pub_key: Ed25519 public key of the sender (32 bytes).
        data: HIA payload data (TTL, timestamp, nonce).
        signature: Ed25519 signature over (version + pub_key + data) (64 bytes).
        sender_name: UNIX-timestamp name of the sending node.
        state: Current NodeState of the sender.

    Examples:
        >>> priv, pub = Ed25519Pair.generate()
        >>> pkt = HereIAmPacket.build(1710000000, pub, priv, ttl=30,
        ...                           state=NodeState.ACTIVE)
        >>> len(pkt.to_bytes())
        124
    """

    sender_pub_key: bytes
    data: HiaData
    signature: bytes
    sender_name: int
    state: NodeState

    def _signable(self) -> bytes:
        """Return the bytes that are signed (version + pub_key + data)."""
        return NNDP_VERSION + self.sender_pub_key + self.data.to_bytes()

    def to_bytes(self) -> bytes:
        """Serialise the packet to 124 bytes for broadcast.

        Returns:
            bytes: Full 124-byte packet.

        Example:
            >>> priv, pub = Ed25519Pair.generate()
            >>> pkt = HereIAmPacket.build(0, pub, priv, 30, NodeState.ACTIVE)
            >>> len(pkt.to_bytes())
            124
        """
        return (
            NNDP_VERSION
            + self.sender_pub_key
            + self.data.to_bytes()
            + self.signature
        )

    @staticmethod
    def build(
        sender_name: int,
        sender_pub_key: bytes,
        sender_priv_key: bytes,
        ttl: int,
        state: NodeState,
    ) -> "HereIAmPacket":
        """Build and sign a new HIA packet.

        Args:
            sender_name: UNIX-timestamp name of the sender.
            sender_pub_key: Ed25519 public key (32 bytes).
            sender_priv_key: Ed25519 private key for signing (32 bytes).
            ttl: Liveness interval (seconds).
            state: Current state of the sending node.

        Returns:
            HereIAmPacket: Signed, ready-to-broadcast packet.

        Example:
            >>> priv, pub = Ed25519Pair.generate()
            >>> pkt = HereIAmPacket.build(1710000000, pub, priv, 30, NodeState.ACTIVE)
            >>> HereIAmPacket.verify_and_parse(pkt.to_bytes(), pub).is_ok()
            True
        """
        data = HiaData.build(ttl=ttl)
        signable = NNDP_VERSION + sender_pub_key + data.to_bytes()
        signature = Ed25519Pair.sign(sender_priv_key, signable)
        return HereIAmPacket(
            sender_pub_key=sender_pub_key,
            data=data,
            signature=signature,
            sender_name=sender_name,
            state=state,
        )

    @staticmethod
    def verify_and_parse(
        raw: bytes, expected_pub_key: bytes
    ) -> Result["HereIAmPacket", Error]:
        """Parse and verify the signature of a raw HIA packet.

        Args:
            raw: 124-byte raw packet from the network.
            expected_pub_key: Ed25519 public key expected from this sender.

        Returns:
            Result[HereIAmPacket, Error]: Ok with parsed packet, or Err.

        Example:
            >>> priv, pub = Ed25519Pair.generate()
            >>> pkt = HereIAmPacket.build(0, pub, priv, 30, NodeState.ACTIVE)
            >>> HereIAmPacket.verify_and_parse(pkt.to_bytes(), pub).is_ok()
            True
        """
        if len(raw) < PACKET_SIZE:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"HIA packet too short: {len(raw)} bytes, need {PACKET_SIZE}",
                )
            )

        pub_key = raw[_KEY_OFFSET: _KEY_OFFSET + _KEY_SIZE]
        if pub_key != expected_pub_key:
            return Result.Err(
                Error.new(
                    ErrorKind.INVALID_NIT_ASSOCIATION,
                    "HIA packet public key mismatch",
                )
            )

        data_bytes = raw[_DATA_OFFSET: _DATA_OFFSET + _DATA_SIZE]
        signature = raw[_SIG_OFFSET: _SIG_OFFSET + _SIG_SIZE]
        signable = raw[:_SIG_OFFSET]  # version + pub_key + data

        sig_result = Ed25519Pair.verify(pub_key, signable, signature)
        if sig_result.is_err():
            return Result.Err(sig_result.unwrap_err())

        data_result = HiaData.from_bytes(data_bytes)
        if data_result.is_err():
            return Result.Err(data_result.unwrap_err())

        data = data_result.unwrap()
        return Result.Ok(
            HereIAmPacket(
                sender_pub_key=pub_key,
                data=data,
                signature=signature,
                sender_name=0,   # Not encoded in packet — resolved via NIT
                state=NodeState.ACTIVE,  # State carried separately via NCP
            )
        )
