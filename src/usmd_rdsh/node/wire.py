"""Byte-level helpers and the frame header common to NNDP, NCP and SP.

[ARCH-02 10.1]: every frame starts with 9 bytes, integers in network order::

    Magic (16) = 0xD5C1 | Version (8) | Event (16) | Length (32)

``Length`` counts the bytes that follow the header. The protocol of a frame
is given by the port it arrives on, not by the header.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

MAGIC = 0xD5C1
VERSION = 1
HEADER = struct.Struct("!HBHI")
HEADER_SIZE = HEADER.size  # 9


class WireError(ValueError):
    """A frame or field that does not decode; the frame is dropped."""


def now_ms() -> int:
    """Milliseconds since the Unix epoch, the time unit of every protocol."""
    return int(time.time() * 1000)


@dataclass(frozen=True, slots=True)
class FrameHeader:
    """The decoded common header."""

    event: int
    length: int
    version: int = VERSION

    def encode(self) -> bytes:
        """The 9 header bytes."""
        return HEADER.pack(MAGIC, self.version, self.event, self.length)

    @classmethod
    def decode(cls, data: bytes, *, expect_exact: bool = True) -> "FrameHeader":
        """Read and check a header [ARCH 10.1, NNDP-01 5.3].

        Raises WireError for a wrong magic, an unsupported version, or (with
        ``expect_exact``) a length that does not match what follows.
        """
        if len(data) < HEADER_SIZE:
            raise WireError("frame shorter than its header")
        magic, version, event, length = HEADER.unpack_from(data)
        if magic != MAGIC:
            raise WireError(f"bad magic 0x{magic:04X}")
        if version != VERSION:
            raise WireError(f"unsupported version {version}")
        if expect_exact and length != len(data) - HEADER_SIZE:
            raise WireError("declared length does not match the payload")
        return cls(event=event, length=length, version=version)


def frame(event: int, payload: bytes) -> bytes:
    """Header plus payload."""
    return FrameHeader(event, len(payload)).encode() + payload


class Writer:
    """Big-endian serialiser [NCP-02 6.1 types]."""

    def __init__(self) -> None:
        self._parts: list[bytes] = []

    def u8(self, value: int) -> "Writer":
        self._parts.append(struct.pack("!B", value))
        return self

    def u16(self, value: int) -> "Writer":
        self._parts.append(struct.pack("!H", value))
        return self

    def u32(self, value: int) -> "Writer":
        self._parts.append(struct.pack("!I", value))
        return self

    def u64(self, value: int) -> "Writer":
        self._parts.append(struct.pack("!Q", value))
        return self

    def boolean(self, value: bool) -> "Writer":
        return self.u8(1 if value else 0)

    def raw(self, value: bytes) -> "Writer":
        self._parts.append(bytes(value))
        return self

    def string(self, value: str) -> "Writer":
        """16-bit length, then UTF-8."""
        data = value.encode("utf-8")
        if len(data) > 0xFFFF:
            raise WireError("string too long")
        return self.u16(len(data)).raw(data)

    def blob(self, value: bytes) -> "Writer":
        """16-bit length, then the bytes."""
        if len(value) > 0xFFFF:
            raise WireError("blob too long")
        return self.u16(len(value)).raw(value)

    def ident(self, node_id: str) -> "Writer":
        """26 ASCII bytes: a ULID [NCP-02 6.1]."""
        data = node_id.encode("ascii")
        if len(data) != 26:
            raise WireError("a node identifier is 26 characters")
        return self.raw(data)

    def bytes(self) -> bytes:
        return b"".join(self._parts)


class Reader:
    """Big-endian deserialiser; every read past the end raises WireError."""

    def __init__(self, data: bytes, offset: int = 0) -> None:
        self._data = memoryview(data)
        self._offset = offset

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset

    def _take(self, size: int) -> bytes:
        if size < 0 or self._offset + size > len(self._data):
            raise WireError("truncated field")
        chunk = bytes(self._data[self._offset:self._offset + size])
        self._offset += size
        return chunk

    def u8(self) -> int:
        return self._take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self._take(2))[0]

    def u32(self) -> int:
        return struct.unpack("!I", self._take(4))[0]

    def u64(self) -> int:
        return struct.unpack("!Q", self._take(8))[0]

    def permille(self) -> int:
        """16 bits, from 0 to 1000 [NCP-02 6.1 "Pour mille"]."""
        value = self.u16()
        if value > 1000:
            raise WireError(f"per-mille value {value} above 1000")
        return value

    def boolean(self) -> bool:
        value = self.u8()
        if value > 1:
            raise WireError("boolean is 0x00 or 0x01")
        return value == 1

    def raw(self, size: int) -> bytes:
        return self._take(size)

    def string(self) -> str:
        try:
            return self._take(self.u16()).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WireError("invalid UTF-8") from exc

    def blob(self) -> bytes:
        return self._take(self.u16())

    def ident(self) -> str:
        text = self._take(26).decode("ascii", errors="replace")
        if not is_ulid(text):
            raise WireError("invalid node identifier")
        return text

    def rest(self) -> bytes:
        return self._take(self.remaining)

    def end(self) -> None:
        """Refuse trailing bytes."""
        if self.remaining:
            raise WireError(f"{self.remaining} unexpected trailing bytes")


_CROCKFORD = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")


def is_ulid(text: str) -> bool:
    """26 Crockford base-32 characters whose first is at most 7 [ULID]."""
    return len(text) == 26 and set(text) <= _CROCKFORD and text[0] <= "7"
