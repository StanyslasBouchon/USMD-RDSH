"""Node Reference Table (NRT) for USMD-RDSH.

Stores the last computed distance *d* to each neighbouring node, as returned
by a CHECK_DISTANCE NCP request sent immediately after a HIA packet is received.

The distance formula is:

    d = (t / T) + c + p + n  ∈ [0; 5]

where:
    - t  : measured round-trip ping to the neighbour (ms)
    - T  : maximum tolerated ping from the USD config (ms)
    - c  : neighbour's reference load ∈ [0, 1]
    - p  : 1 if the neighbour hosts the same service, 0 otherwise
    - n  : 2 if the neighbour already has us as a reference node, 0 otherwise

An entry is considered stale after _MAX_AGE seconds without a refresh.

Examples:
    >>> nrt = NodeReferenceTable()
    >>> nrt.update("10.0.0.1", distance=1.25, ping_ms=42.0)
    >>> len(nrt)
    1
    >>> nrt.get("10.0.0.1").distance
    1.25
    >>> nrt.remove("10.0.0.1")
    >>> len(nrt)
    0
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

_MAX_AGE: float = 3600.0  # seconds before an entry is considered stale


@dataclass
class NrtEntry:
    """A single entry in the Node Reference Table.

    Attributes:
        address: IPv4 or IPv6 address of the neighbouring node.
        distance: Computed distance d ∈ [0, 5].
        ping_ms: Measured round-trip time in milliseconds.
        updated_at: UNIX timestamp of the last successful update.

    Examples:
        >>> e = NrtEntry(address="10.0.0.1", distance=0.5, ping_ms=10.0)
        >>> e.is_stale()
        False
    """

    address: str
    distance: float
    ping_ms: float
    updated_at: float = field(default_factory=time.time)

    def is_stale(self) -> bool:
        """Return True if the entry has not been refreshed within _MAX_AGE seconds.

        Example:
            >>> import time
            >>> e = NrtEntry("10.0.0.1", 1.0, 20.0,
            ...               updated_at=time.time() - 7200)
            >>> e.is_stale()
            True
        """
        return (time.time() - self.updated_at) > _MAX_AGE


class NodeReferenceTable:
    """Maintains the last known distance to each neighbouring node.

    Entries are created or refreshed via :meth:`update` (called after a
    successful CHECK_DISTANCE NCP exchange) and removed via :meth:`remove`
    (called when a node becomes inactive or its NIT entry expires).

    Examples:
        >>> nrt = NodeReferenceTable()
        >>> nrt.update("10.0.0.2", distance=2.0, ping_ms=80.0)
        >>> nrt.get("10.0.0.2").ping_ms
        80.0
    """

    def __init__(self) -> None:
        self._entries: dict[str, NrtEntry] = {}

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def update(self, address: str, distance: float, ping_ms: float) -> None:
        """Insert or refresh the NRT entry for *address*.

        Args:
            address: IPv4 or IPv6 address of the neighbouring node.
            distance: Computed distance d ∈ [0, 5].
            ping_ms: Measured round-trip time in milliseconds.

        Example:
            >>> nrt = NodeReferenceTable()
            >>> nrt.update("10.0.0.1", 0.75, 15.0)
            >>> nrt.get("10.0.0.1").distance
            0.75
        """
        self._entries[address] = NrtEntry(
            address=address,
            distance=round(distance, 4),
            ping_ms=round(ping_ms, 2),
        )

    def remove(self, address: str) -> None:
        """Remove the NRT entry for *address* if present.

        Args:
            address: IPv4 or IPv6 address to remove.

        Example:
            >>> nrt = NodeReferenceTable()
            >>> nrt.update("10.0.0.1", 1.0, 10.0)
            >>> nrt.remove("10.0.0.1")
            >>> nrt.get("10.0.0.1") is None
            True
        """
        self._entries.pop(address, None)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(self, address: str) -> Optional[NrtEntry]:
        """Return the NRT entry for *address*, or None if absent.

        Args:
            address: IPv4 or IPv6 address to look up.

        Example:
            >>> nrt = NodeReferenceTable()
            >>> nrt.get("10.0.0.99") is None
            True
        """
        return self._entries.get(address)

    def get_all(self) -> list[dict]:
        """Return all NRT entries as serialisable dicts, sorted by distance.

        Returns:
            list[dict]: Each dict has keys address, distance, ping_ms,
                updated_at, updated_at_str, stale.

        Example:
            >>> nrt = NodeReferenceTable()
            >>> nrt.update("10.0.0.1", 1.0, 20.0)
            >>> nrt.get_all()[0]["address"]
            '10.0.0.1'
        """
        import datetime  # pylint: disable=import-outside-toplevel

        rows = []
        for e in self._entries.values():
            rows.append({
                "address":       e.address,
                "distance":      e.distance,
                "ping_ms":       e.ping_ms,
                "updated_at":    e.updated_at,
                "updated_at_str": datetime.datetime.fromtimestamp(
                    e.updated_at
                ).strftime("%d/%m/%Y %H:%M:%S"),
                "stale":         e.is_stale(),
            })
        rows.sort(key=lambda r: r["distance"])
        return rows

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"NodeReferenceTable({len(self)} entries)"
