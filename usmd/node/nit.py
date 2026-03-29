"""Node Identity Table (NIT) for USMD-RDSH.

The NIT associates each known node's Ed25519 public key with its network address
and a TTL (Time To Live). It is used to validate the origin of every incoming
NCP packet: if the (address, public_key) pair does not match a NIT entry, the
packet is silently dropped and the sender is excluded.

Rules (from the spec):
    - One public key → at most one address.
    - One address → may have several public keys.
    - If a packet's (address, public_key) pair is not in the NIT the sender
      is excluded permanently.

Examples:
    >>> nit = NodeIdentityTable()
    >>> pub_key = b"\\x01" * 32
    >>> nit.register("192.168.1.10", pub_key, ttl=3600)
    >>> nit.validate("192.168.1.10", pub_key).is_ok()
    True
    >>> nit.validate("192.168.1.99", pub_key).is_err()
    True
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Iterator, Optional

from ..utils.errors import Error, ErrorKind
from ..utils.result import Result


@dataclass
class NitEntry:
    """A single entry in the Node Identity Table.

    Attributes:
        address: IPv4 or IPv6 address of the node.
        public_key: Ed25519 public key bytes (32 bytes).
        ttl: Seconds this entry remains valid after ``registered_at``.
        registered_at: UNIX timestamp (float) when the entry was created.

    Examples:
        >>> entry = NitEntry(address="10.0.0.1", public_key=b"\\x00" * 32, ttl=3600)
        >>> entry.is_expired()
        False
    """

    address: str
    public_key: bytes
    ttl: int
    registered_at: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        """Return True if the TTL has elapsed since registration.

        Example:
            >>> import time
            >>> entry = NitEntry("10.0.0.1", b"\\x00"*32, ttl=1,
            ...                  registered_at=time.time() - 10)
            >>> entry.is_expired()
            True
        """
        return (time.time() - self.registered_at) > self.ttl


class NodeIdentityTable:
    """Manages the mapping of public keys to network addresses with TTL support.

    Internally the table is keyed by ``public_key`` (bytes) for fast lookup
    on incoming packets. The inverse index (``address → [keys]``) is maintained
    separately for diagnostics.

    Attributes:
        _entries: Mapping of public_key → NitEntry.

    Examples:
        >>> nit = NodeIdentityTable()
        >>> key = b"k" * 32
        >>> nit.register("10.0.0.1", key, ttl=3600)
        >>> nit.validate("10.0.0.1", key).is_ok()
        True
        >>> nit.validate("10.0.0.2", key).is_err()
        True
    """

    def __init__(self) -> None:
        self._entries: dict[bytes, NitEntry] = {}

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def register(self, address: str, public_key: bytes, ttl: int = 3600) -> None:
        """Add or refresh an entry in the NIT.

        Args:
            address: IPv4 or IPv6 address of the node.
            public_key: Ed25519 public key (32 bytes).
            ttl: Validity duration in seconds. Defaults to 3 600 (1 hour).

        Example:
            >>> nit = NodeIdentityTable()
            >>> nit.register("10.0.0.5", b"k" * 32, ttl=7200)
        """
        self._entries[public_key] = NitEntry(
            address=address,
            public_key=public_key,
            ttl=ttl,
        )
        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NIT register: %s ↔ %s (ttl=%ds)",
            address,
            public_key.hex()[:16] + "…",
            ttl,
        )

    def remove(self, public_key: bytes) -> None:
        """Remove an entry from the NIT.

        Args:
            public_key: Ed25519 public key to remove.

        Example:
            >>> nit = NodeIdentityTable()
            >>> key = b"x" * 32
            >>> nit.register("10.0.0.1", key)
            >>> nit.remove(key)
            >>> nit.get_address(key) is None
            True
        """
        self._entries.pop(public_key, None)

    def purge_expired(self) -> int:
        """Remove all entries whose TTL has elapsed.

        Returns:
            int: Number of entries removed.

        Example:
            >>> nit = NodeIdentityTable()
            >>> nit.purge_expired()
            0
        """
        expired = [k for k, e in self._entries.items() if e.is_expired()]
        for key in expired:
            del self._entries[key]
        return len(expired)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def validate(self, address: str, public_key: bytes) -> Result[None, Error]:
        """Verify that the given (address, public_key) pair is registered and valid.

        According to the spec, if the pair does not match an entry the sender
        must be excluded permanently.

        Args:
            address: Source IP address of the incoming packet.
            public_key: Ed25519 public key claimed by the sender.

        Returns:
            Result[None, Error]: Ok(None) if valid, Err if unknown or expired.

        Examples:
            >>> nit = NodeIdentityTable()
            >>> key = b"k" * 32
            >>> nit.register("10.0.0.1", key)
            >>> nit.validate("10.0.0.1", key).is_ok()
            True
            >>> nit.validate("10.0.0.9", key).is_err()
            True
        """
        entry = self._entries.get(public_key)
        if entry is None:
            return Result.Err(
                Error.new(
                    ErrorKind.INVALID_NIT_ASSOCIATION,
                    f"No NIT entry for key {public_key.hex()[:16]}…",
                )
            )
        if entry.is_expired():
            self.remove(public_key)
            return Result.Err(
                Error.new(
                    ErrorKind.INVALID_NIT_ASSOCIATION,
                    f"NIT entry expired for key {public_key.hex()[:16]}…",
                )
            )
        if entry.address != address:
            return Result.Err(
                Error.new(
                    ErrorKind.INVALID_NIT_ASSOCIATION,
                    f"NIT address mismatch: expected {entry.address}, got {address}",
                )
            )
        return Result.Ok(None)

    def get_address(self, public_key: bytes) -> Optional[str]:
        """Return the address associated with a public key, or None if absent.

        Args:
            public_key: Ed25519 public key to look up.

        Returns:
            str | None: The address, or None.

        Example:
            >>> nit = NodeIdentityTable()
            >>> key = b"k" * 32
            >>> nit.register("10.0.0.3", key)
            >>> nit.get_address(key)
            '10.0.0.3'
        """
        entry = self._entries.get(public_key)
        return entry.address if entry else None

    def get_keys_for_address(self, address: str) -> list[bytes]:
        """Return all public keys registered for a given address.

        Args:
            address: IPv4 or IPv6 address to look up.

        Returns:
            list[bytes]: List of public keys (may be empty).

        Example:
            >>> nit = NodeIdentityTable()
            >>> nit.register("10.0.0.1", b"a" * 32)
            >>> nit.register("10.0.0.1", b"b" * 32)
            >>> len(nit.get_keys_for_address("10.0.0.1"))
            2
        """
        return [e.public_key for e in self._entries.values() if e.address == address]

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"NodeIdentityTable({len(self)} entries)"

    def iter_all_entries(self) -> Iterator[NitEntry]:
        """Iterate over all registered NIT entries (including expired ones).

        Returns:
            Iterator[NitEntry]: All current entries in insertion order.

        Example:
            >>> nit = NodeIdentityTable()
            >>> nit.register("10.0.0.1", b"k" * 32)
            >>> list(nit.iter_all_entries())[0].address
            '10.0.0.1'
        """
        return iter(self._entries.values())
