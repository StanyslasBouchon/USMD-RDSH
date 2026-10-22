"""Node Reference List (NRL) for USMD-RDSH.

Tracks which peer nodes have declared *this* node as one of their reference
nodes by sending an ``INFORM_REFERENCE_NODE`` NCP request that includes our
name in the payload.

Terminology:
    mandator - a node that has chosen us as one of its reference nodes.

Each entry is refreshed every time the mandator resends
``INFORM_REFERENCE_NODE`` (which happens whenever its NRT-based selection
changes).  Entries that stop sending can be detected via ``declared_at``.

Examples:
    >>> nrl = NodeReferenceList()
    >>> nrl.add(mandator_name=1710000001, mandator_address="10.0.0.2")
    >>> len(nrl)
    1
    >>> nrl.get_all_dicts()[0]["address"]
    '10.0.0.2'
    >>> nrl.remove(1710000001)
    >>> len(nrl)
    0
"""

from __future__ import annotations

import datetime
import time
from typing import Optional


class NrlEntry:
    """A single entry in the Node Reference List.

    Attributes:
        mandator_name: UNIX-timestamp name of the node that chose us.
        mandator_address: IP address of that node.
        declared_at: UNIX timestamp of the last ``INFORM_REFERENCE_NODE``
            received from this mandator.

    Examples:
        >>> e = NrlEntry(1710000001, "10.0.0.2", 0.0)
        >>> e.declared_at_str  # doctest: +ELLIPSIS
        '...'
    """

    def __init__(
        self,
        mandator_name: int,
        mandator_address: str,
        declared_at: float,
    ) -> None:
        self.mandator_name = mandator_name
        self.mandator_address = mandator_address
        self.declared_at = declared_at

    @property
    def declared_at_str(self) -> str:
        """Human-readable local datetime string."""
        return datetime.datetime.fromtimestamp(self.declared_at).strftime(
            "%d/%m/%Y %H:%M:%S"
        )

    def to_dict(self) -> dict:
        """Serialise the entry to a JSON-compatible dict.

        Returns:
            dict: With keys name, address, declared_at, declared_at_str.

        Example:
            >>> e = NrlEntry(123, "1.2.3.4", 0.0)
            >>> e.to_dict()["name"]
            123
        """
        return {
            "name": self.mandator_name,
            "address": self.mandator_address,
            "declared_at": self.declared_at,
            "declared_at_str": self.declared_at_str,
        }


class NodeReferenceList:
    """Maintains the list of nodes that have chosen us as a reference peer.

    Updated by the NCP handler whenever an ``INFORM_REFERENCE_NODE`` request
    arrives and the receiver discovers its own name in the sender's reference
    list.

    Examples:
        >>> nrl = NodeReferenceList()
        >>> nrl.add(1710000001, "10.0.0.2")
        >>> len(nrl)
        1
        >>> nrl.add(1710000001, "10.0.0.2")  # refresh — no duplicate
        >>> len(nrl)
        1
        >>> nrl.remove(1710000001)
        >>> len(nrl)
        0
    """

    def __init__(self) -> None:
        self._entries: dict[int, NrlEntry] = {}

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, mandator_name: int, mandator_address: str) -> None:
        """Add or refresh the NRL entry for *mandator_name*.

        Args:
            mandator_name: UNIX-timestamp name of the mandating node.
            mandator_address: IP address of the mandating node.

        Example:
            >>> nrl = NodeReferenceList()
            >>> nrl.add(1, "10.0.0.1")
            >>> len(nrl)
            1
        """
        self._entries[mandator_name] = NrlEntry(
            mandator_name=mandator_name,
            mandator_address=mandator_address,
            declared_at=time.time(),
        )

    def remove(self, mandator_name: int) -> None:
        """Remove the NRL entry for *mandator_name* if present.

        Args:
            mandator_name: UNIX-timestamp name of the mandating node.

        Example:
            >>> nrl = NodeReferenceList()
            >>> nrl.add(1, "10.0.0.1")
            >>> nrl.remove(1)
            >>> len(nrl)
            0
        """
        self._entries.pop(mandator_name, None)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(self, mandator_name: int) -> Optional[NrlEntry]:
        """Return the NRL entry for *mandator_name*, or None if absent.

        Args:
            mandator_name: UNIX-timestamp name to look up.

        Example:
            >>> nrl = NodeReferenceList()
            >>> nrl.get(99) is None
            True
        """
        return self._entries.get(mandator_name)

    def get_all_dicts(self) -> list[dict]:
        """Return all NRL entries as serialisable dicts, sorted by name.

        Returns:
            list[dict]: Each dict has keys name, address, declared_at,
                declared_at_str.

        Example:
            >>> nrl = NodeReferenceList()
            >>> nrl.add(2, "10.0.0.2")
            >>> nrl.get_all_dicts()[0]["address"]
            '10.0.0.2'
        """
        return sorted(
            (e.to_dict() for e in self._entries.values()),
            key=lambda d: d["name"],
        )

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"NodeReferenceList({len(self)} mandators)"
