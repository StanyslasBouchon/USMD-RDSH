"""Data identifiers of the services [ARCH-03 11.6].

A Snowflake-like UUID (version 8, RFC 9562) whose first 32 bits are the SP
address of the instance that created it, so its text starts with it::

    00b20003-0192-8d3a-...    created by instance 0b2.0003

    bits   0-31   SP address (4 zero bits, service, management id)
          32-47   timestamp, high 16 bits   (milliseconds since 1970, 48 bits)
          48-51   version 8
          52-63   timestamp, next 12 bits
          64-65   variant 0b10
          66-85   timestamp, low 20 bits
         86-101   sequence (16 bits)
        102-127   random (26 bits)

Sorting identifiers groups the data of each instance, then by creation time.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass

from usmd_rdsh.node import addresses

VERSION = 8
SEQUENCE_MAX = 0xFFFF
RANDOM_BITS = 26


@dataclass(frozen=True, slots=True)
class DataId:
    """What an identifier tells: who created it, and when."""

    sp_address: int
    timestamp_ms: int
    sequence: int
    random: int

    @property
    def service_id(self) -> int:
        return addresses.service_of(self.sp_address)

    @property
    def management_id(self) -> int:
        return self.sp_address & 0xFFFF

    @property
    def sp_text(self) -> str:
        return addresses.to_text(self.sp_address)

    @property
    def created(self) -> str:
        """UTC date of creation, to the millisecond."""
        seconds, ms = divmod(self.timestamp_ms, 1000)
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(seconds)) + f".{ms:03d} UTC"


def check_address(sp_address: int) -> None:
    """An instance address: service 001..ffe, management id 0001..fffe."""
    service, management = addresses.unpack(sp_address)
    if not addresses.service_id_valid(service):
        raise ValueError(f"service id {service:03x} names no service")
    if management in (addresses.ANY_INSTANCE, addresses.ALL_INSTANCES):
        raise ValueError(f"{addresses.to_text(sp_address)} is not an instance address")


def prefix(sp_address: int) -> str:
    """The 8 hexadecimal digits every identifier of the instance starts with."""
    return f"{sp_address:08x}"


def encode(sp_address: int, timestamp_ms: int, sequence: int, rnd: int) -> uuid.UUID:
    check_address(sp_address)
    if not 0 <= timestamp_ms < 1 << 48 or not 0 <= sequence <= SEQUENCE_MAX \
            or not 0 <= rnd < 1 << RANDOM_BITS:
        raise ValueError("timestamp 48 bits, sequence 16 bits, random 26 bits")
    value = sp_address << 96
    value |= (timestamp_ms >> 32) << 80
    value |= VERSION << 76
    value |= ((timestamp_ms >> 20) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= (timestamp_ms & 0xFFFFF) << 42
    value |= sequence << RANDOM_BITS
    value |= rnd
    return uuid.UUID(int=value)


def decode(value: uuid.UUID | str) -> DataId:
    """ValueError when it is not a USMD-RDSH data identifier."""
    number = (value if isinstance(value, uuid.UUID) else uuid.UUID(str(value).strip())).int
    if (number >> 76) & 0xF != VERSION or (number >> 62) & 0b11 != 0b10:
        raise ValueError("not a version 8 UUID of variant 0b10")
    sp_address = number >> 96
    if sp_address >> 28:
        raise ValueError("the 4 high bits of a data identifier are 0")
    timestamp = (((number >> 80) & 0xFFFF) << 32) | (((number >> 64) & 0xFFF) << 20) \
        | ((number >> 42) & 0xFFFFF)
    return DataId(sp_address, timestamp, (number >> RANDOM_BITS) & SEQUENCE_MAX,
                  number & ((1 << RANDOM_BITS) - 1))


class DataIdGenerator:
    """Identifiers of one instance: never decreasing time, sequence per ms."""

    def __init__(self, sp_address: int, *, clock=None) -> None:
        check_address(sp_address)
        self.sp_address = sp_address
        self._clock = clock or (lambda: time.time_ns() // 1_000_000)
        self._lock = threading.Lock()
        self._last = -1
        self._sequence = 0

    def next(self) -> uuid.UUID:
        with self._lock:
            now = self._clock()
            if now > self._last:
                self._last = now
                self._sequence = secrets.randbelow(0x8000)
            else:  # same millisecond, or the clock went back: keep the last one
                self._sequence += 1
                if self._sequence > SEQUENCE_MAX:
                    self._last += 1
                    self._sequence = 0
            return encode(self.sp_address, self._last, self._sequence,
                          secrets.randbits(RANDOM_BITS))


POSTGRESQL = """\
-- USMD-RDSH data identifiers [draft-usmd-rdsh-architecture-03, 11.6]
-- The instance's prefix is set by its build sequence:
--   ALTER DATABASE app SET usmd.data_id_prefix = '$USMD_DATA_ID_PREFIX';
-- then: id uuid PRIMARY KEY DEFAULT usmd_id()
CREATE SEQUENCE IF NOT EXISTS usmd_id_seq MINVALUE 0 MAXVALUE 65535 CYCLE;
CREATE OR REPLACE FUNCTION usmd_id() RETURNS uuid LANGUAGE plpgsql VOLATILE AS $$
DECLARE
  prefix text   := current_setting('usmd.data_id_prefix');
  ms     bigint := floor(extract(epoch FROM clock_timestamp()) * 1000);
  seq    bigint := nextval('usmd_id_seq');
  rnd    bigint := floor(random() * 67108864);
BEGIN
  IF prefix !~ '^0[0-9a-f]{7}$' THEN
    RAISE EXCEPTION 'usmd.data_id_prefix: 8 hexadecimal digits';
  END IF;
  RETURN (prefix
    || lpad(to_hex((ms >> 32) & 65535), 4, '0')
    || '8' || lpad(to_hex((ms >> 20) & 4095), 3, '0')
    || lpad(to_hex((2::bigint << 30) | ((ms & 1048575) << 10)
                   | (seq >> 6)), 8, '0')
    || lpad(to_hex(((seq & 63) << 26) | rnd), 8, '0'))::uuid;
END $$;
-- The SP address (sss.nnnn) and creation time of an identifier.
CREATE OR REPLACE FUNCTION usmd_id_sp_address(id uuid) RETURNS text
  LANGUAGE sql IMMUTABLE AS $$
  SELECT substr(id::text, 2, 3) || '.' || substr(id::text, 5, 4) $$;
CREATE OR REPLACE FUNCTION usmd_id_created(id uuid) RETURNS timestamptz
  LANGUAGE sql IMMUTABLE AS $$
  SELECT to_timestamp((('x' || lpad(substr(replace(id::text, '-', ''), 9, 4)
                         || substr(replace(id::text, '-', ''), 14, 3), 16, '0'))::bit(64)::bigint
                       * 1048576
                       + ((('x' || substr(replace(id::text, '-', ''), 17, 8))::bit(32)::bigint
                           >> 10) & 1048575)) / 1000.0) $$;
"""


def postgresql(sp_address: int | None = None, database: str = "app") -> str:
    """The generator's SQL; with an address, the line that sets the prefix."""
    if sp_address is None:
        return POSTGRESQL
    check_address(sp_address)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", database):
        raise ValueError(f"'{database}' is not a plain PostgreSQL identifier")
    return (POSTGRESQL + f"ALTER DATABASE {database} SET usmd.data_id_prefix = "
            f"'{prefix(sp_address)}';\n")
