"""SP addresses ``sss.nnnn`` [ARCH-02 11.3].

32 bits on the wire: 4 reserved zero bits, a 12-bit service identifier, a
16-bit management identifier. ``sss.0000`` is the nearest instance (the VIP),
``sss.ffff`` every instance (the group address); neither of the two service
values 0x000 and 0xFFF names a service.
"""

from __future__ import annotations

import re

ANY_INSTANCE = 0x0000
ALL_INSTANCES = 0xFFFF
_TEXT = re.compile(r"^([0-9a-f]{3})\.([0-9a-f]{4})$")


def service_id_valid(service: int) -> bool:
    """0x001 to 0xFFE [ARCH 11.1]."""
    return 0x001 <= service <= 0xFFE


def pack(service: int, management: int) -> int:
    """The 32-bit form."""
    if not 0 <= service <= 0xFFF or not 0 <= management <= 0xFFFF:
        raise ValueError("service is 12 bits, management id 16 bits")
    return (service << 16) | management


def unpack(address: int) -> tuple[int, int]:
    """(service, management); ValueError when the 4 reserved bits are set."""
    if address >> 28:
        raise ValueError("the 4 high bits of an SP address are 0")
    return (address >> 16) & 0xFFF, address & 0xFFFF


def service_of(address: int) -> int:
    return (address >> 16) & 0xFFF


def to_text(address: int) -> str:
    """``0a1.5d68``."""
    service, management = unpack(address)
    return f"{service:03x}.{management:04x}"


def from_text(text: str) -> int:
    """Inverse of :func:`to_text`."""
    match = _TEXT.match(text.strip().lower())
    if not match:
        raise ValueError(f"'{text}' is not an SP address (sss.nnnn)")
    return pack(int(match.group(1), 16), int(match.group(2), 16))
