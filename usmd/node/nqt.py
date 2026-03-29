"""Node Quorum Table (NQT) for USMD-RDSH.

Keeps a persistent, ordered log of all quorum promotion events for this
USD cluster.  Each node maintains its own copy, synchronised with active
peers via the ``GET_NQT`` NCP command (id 12) so that nodes joining *after*
an election immediately know who the current operator is.

Each entry records:
    epoch       - election epoch number
    pub_key     - Ed25519 public key of the promoted node (32 bytes)
    address     - IP address of the promoted node
    promoted_at - UNIX timestamp of the promotion
    reason      - human-readable explanation (French)

The table is kept sorted by ``promoted_at`` descending (newest first) and
capped at ``_MAX_ENTRIES`` to avoid unbounded growth.

Examples:
    >>> nqt = NodeQuorumTable()
    >>> nqt.add(epoch=1, pub_key=b'k' * 32, address="10.0.0.1", reason="Élu")
    >>> len(nqt)
    1
    >>> nqt.get_latest().address
    '10.0.0.1'
    >>> nqt.get_latest().epoch
    1
"""

from __future__ import annotations

import datetime
import time
from typing import Optional

_MAX_ENTRIES: int = 50


class NqtEntry:
    """A single quorum promotion record.

    Attributes:
        epoch: Election epoch of the promotion.
        pub_key: Ed25519 public key of the promoted node (32 bytes).
        address: IP address of the promoted node.
        promoted_at: UNIX timestamp of the promotion.
        reason: Human-readable explanation (French).

    Examples:
        >>> e = NqtEntry(epoch=1, pub_key=b'k'*32,
        ...              address="10.0.0.2", promoted_at=0.0, reason="Test")
        >>> e.pub_key_short.endswith("…")
        True
    """

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        epoch: int,
        pub_key: bytes,
        address: str,
        promoted_at: float,
        reason: str,
    ) -> None:
        self.epoch = epoch
        self.pub_key = pub_key
        self.address = address
        self.promoted_at = promoted_at
        self.reason = reason

    @property
    def pub_key_short(self) -> str:
        """Return the first 20 hex characters of the public key with a trailing ellipsis."""
        return self.pub_key.hex()[:20] + "…"

    @property
    def promoted_at_str(self) -> str:
        """Return a human-readable local datetime string for the promotion timestamp."""
        return datetime.datetime.fromtimestamp(self.promoted_at).strftime(
            "%d/%m/%Y %H:%M:%S"
        )

    def to_dict(self) -> dict:
        """Serialise the entry to a JSON-compatible dict.

        Returns:
            dict: With keys epoch, address, pub_key, pub_key_hex,
                  promoted_at, promoted_at_str, reason.

        Example:
            >>> e = NqtEntry(1, b'k'*32, "1.2.3.4", 0.0, "Élu")
            >>> e.to_dict()["epoch"]
            1
        """
        return {
            "epoch": self.epoch,
            "address": self.address,
            "pub_key": self.pub_key_short,
            "pub_key_hex": self.pub_key.hex(),
            "promoted_at": self.promoted_at,
            "promoted_at_str": self.promoted_at_str,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NqtEntry":
        """Reconstruct an NqtEntry from a serialised dict.

        Args:
            data: Dict as produced by :meth:`to_dict`.

        Returns:
            NqtEntry: Reconstructed entry.

        Example:
            >>> e = NqtEntry(2, b'x'*32, "5.5.5.5", 1.0, "Sync")
            >>> NqtEntry.from_dict(e.to_dict()).epoch
            2
        """
        raw_hex = data.get("pub_key_hex", "")
        try:
            pub_key = bytes.fromhex(raw_hex) if raw_hex else b"\x00" * 32
        except ValueError:
            pub_key = b"\x00" * 32
        return cls(
            epoch=int(data.get("epoch", 0)),
            pub_key=pub_key,
            address=str(data.get("address", "")),
            promoted_at=float(data.get("promoted_at", time.time())),
            reason=str(data.get("reason", "")),
        )


class NodeQuorumTable:
    """Ordered log of quorum election results for this USD cluster.

    Entries are added via :meth:`add` (called when a promotion is recorded
    locally or received from a peer via ``ANNOUNCE_PROMOTION``) and
    synchronised from peers via :meth:`merge_from_dicts` (called after
    receiving a ``GET_NQT`` response).

    Examples:
        >>> nqt = NodeQuorumTable()
        >>> nqt.add(1, b'k'*32, "10.0.0.1", "Élu")
        >>> nqt.get_latest().address
        '10.0.0.1'
        >>> nqt.merge_from_dicts([])
        0
    """

    def __init__(self) -> None:
        self._entries: list[NqtEntry] = []

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, epoch: int, pub_key: bytes, address: str, reason: str) -> None:
        """Prepend a new promotion record.

        If an entry with the same (epoch, address) already exists it is
        **not** duplicated.

        Args:
            epoch: Election epoch of the promotion.
            pub_key: Ed25519 public key (32 bytes).
            address: IP address of the promoted node.
            reason: Human-readable explanation (French).

        Example:
            >>> nqt = NodeQuorumTable()
            >>> nqt.add(1, b'k'*32, "10.0.0.1", "Élu")
            >>> len(nqt)
            1
            >>> nqt.add(1, b'k'*32, "10.0.0.1", "Élu")  # duplicate → ignored
            >>> len(nqt)
            1
        """
        existing_keys = {(e.epoch, e.address) for e in self._entries}
        if (epoch, address) in existing_keys:
            return
        entry = NqtEntry(
            epoch=epoch,
            pub_key=pub_key,
            address=address,
            promoted_at=time.time(),
            reason=reason,
        )
        self._entries.insert(0, entry)
        if len(self._entries) > _MAX_ENTRIES:
            self._entries = self._entries[:_MAX_ENTRIES]

    def merge_from_dicts(self, dicts: list[dict]) -> int:
        """Merge NQT entries received from a peer, skipping duplicates.

        After merging, entries are re-sorted by ``promoted_at`` descending
        and capped at ``_MAX_ENTRIES``.

        Args:
            dicts: List of dicts as returned by :meth:`get_all_dicts`.

        Returns:
            int: Number of new entries added.

        Example:
            >>> nqt = NodeQuorumTable()
            >>> added = nqt.merge_from_dicts([
            ...     {"epoch": 1, "address": "10.0.0.1", "pub_key_hex": "aa"*32,
            ...      "promoted_at": 1.0, "reason": "Test", "pub_key": "…",
            ...      "promoted_at_str": ""}])
            >>> added
            1
            >>> nqt.merge_from_dicts([
            ...     {"epoch": 1, "address": "10.0.0.1", "pub_key_hex": "aa"*32,
            ...      "promoted_at": 1.0, "reason": "Test", "pub_key": "…",
            ...      "promoted_at_str": ""}])
            0
        """
        existing = {(e.epoch, e.address) for e in self._entries}
        added = 0
        for data in dicts:
            entry = NqtEntry.from_dict(data)
            key = (entry.epoch, entry.address)
            if key not in existing:
                self._entries.append(entry)
                existing.add(key)
                added += 1
        if added:
            self._entries.sort(key=lambda e: e.promoted_at, reverse=True)
            if len(self._entries) > _MAX_ENTRIES:
                self._entries = self._entries[:_MAX_ENTRIES]
        return added

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_latest(self) -> Optional[NqtEntry]:
        """Return the most recent promotion entry, or None if the table is empty.

        Example:
            >>> nqt = NodeQuorumTable()
            >>> nqt.get_latest() is None
            True
        """
        return self._entries[0] if self._entries else None

    def get_all_entries(self) -> list[NqtEntry]:
        """Return a shallow copy of all entries (newest first).

        Example:
            >>> nqt = NodeQuorumTable()
            >>> nqt.add(1, b'k'*32, "10.0.0.1", "Élu")
            >>> len(nqt.get_all_entries())
            1
        """
        return list(self._entries)

    def get_all_dicts(self) -> list[dict]:
        """Return all entries serialised as dicts (newest first).

        Suitable for JSON serialisation in snapshots and GET_NQT responses.

        Example:
            >>> nqt = NodeQuorumTable()
            >>> nqt.add(1, b'k'*32, "10.0.0.1", "Élu")
            >>> nqt.get_all_dicts()[0]["epoch"]
            1
        """
        return [e.to_dict() for e in self._entries]

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"NodeQuorumTable({len(self)} entries)"
