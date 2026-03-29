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
    role_name   - name of the elected role (e.g. ``"node_operator"``)

The table is kept sorted by ``promoted_at`` descending (newest first) and
capped at ``_MAX_ENTRIES`` to avoid unbounded growth.

Examples:
    >>> nqt = NodeQuorumTable()
    >>> nqt.add(epoch=1, pub_key=b'k' * 32, address="10.0.0.1",
    ...          reason="Élu", role_name="node_operator")
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
from dataclasses import dataclass, field
from typing import Optional

_MAX_ENTRIES: int = 50


@dataclass
class NqtEntry:
    """A single quorum promotion record.

    Attributes:
        epoch: Election epoch of the promotion.
        pub_key: Ed25519 public key of the promoted node (32 bytes).
        address: IP address of the promoted node.
        promoted_at: UNIX timestamp of the promotion.
        reason: Human-readable explanation (French).
        role_name: Name of the elected role (e.g. ``"node_operator"``).

    Examples:
        >>> e = NqtEntry(epoch=1, pub_key=b'k'*32, address="10.0.0.2",
        ...              promoted_at=0.0, reason="Test",
        ...              role_name="usd_operator")
        >>> e.pub_key_short.endswith("…")
        True
        >>> e.role_name
        'usd_operator'
    """

    epoch: int
    pub_key: bytes
    address: str
    promoted_at: float = field(default_factory=time.time)
    reason: str = ""
    role_name: str = "node_operator"

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
                  promoted_at, promoted_at_str, reason, role_name.

        Example:
            >>> e = NqtEntry(1, b'k'*32, "1.2.3.4", 0.0, "Élu", "node_operator")
            >>> e.to_dict()["epoch"]
            1
            >>> e.to_dict()["role_name"]
            'node_operator'
        """
        return {
            "epoch":          self.epoch,
            "address":        self.address,
            "pub_key":        self.pub_key.hex(),
            "pub_key_hex":    self.pub_key.hex(),
            "promoted_at":    self.promoted_at,
            "promoted_at_str": self.promoted_at_str,
            "reason":         self.reason,
            "role_name":      self.role_name,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NqtEntry":
        """Reconstruct an NqtEntry from a serialised dict.

        Args:
            data: Dict as produced by :meth:`to_dict`.

        Returns:
            NqtEntry: Reconstructed entry.

        Example:
            >>> e = NqtEntry(2, b'x'*32, "5.5.5.5", 1.0, "Sync", "ucd_operator")
            >>> NqtEntry.from_dict(e.to_dict()).role_name
            'ucd_operator'
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
            role_name=str(data.get("role_name", "node_operator")),
        )


class NodeQuorumTable:
    """Ordered log of quorum election results for this USD cluster.

    Entries are added via :meth:`add` (called when a promotion is recorded
    locally or received from a peer via ``ANNOUNCE_PROMOTION``) and
    synchronised from peers via :meth:`merge_from_dicts` (called after
    receiving a ``GET_NQT`` response).

    Examples:
        >>> nqt = NodeQuorumTable()
        >>> nqt.add(1, b'k'*32, "10.0.0.1", "Élu", "node_operator")
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

    def add(
        self,
        epoch: int,
        pub_key: bytes,
        address: str,
        reason: str,
        role_name: str = "node_operator",
    ) -> None:
        """Prepend a new promotion record.

        If an entry with the same (epoch, address, role_name) already exists
        it is **not** duplicated.

        Args:
            epoch: Election epoch of the promotion.
            pub_key: Ed25519 public key (32 bytes).
            address: IP address of the promoted node.
            reason: Human-readable explanation (French).
            role_name: Name of the elected role.

        Example:
            >>> nqt = NodeQuorumTable()
            >>> nqt.add(1, b'k'*32, "10.0.0.1", "Élu", "usd_operator")
            >>> len(nqt)
            1
            >>> nqt.add(1, b'k'*32, "10.0.0.1", "Élu", "usd_operator")  # duplicate
            >>> len(nqt)
            1
        """
        existing_keys = {(e.epoch, e.address, e.role_name) for e in self._entries}
        if (epoch, address, role_name) in existing_keys:
            return
        entry = NqtEntry(
            epoch=epoch,
            pub_key=pub_key,
            address=address,
            promoted_at=time.time(),
            reason=reason,
            role_name=role_name,
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
            ...      "promoted_at_str": "", "role_name": "node_operator"}])
            >>> added
            1
            >>> nqt.merge_from_dicts([
            ...     {"epoch": 1, "address": "10.0.0.1", "pub_key_hex": "aa"*32,
            ...      "promoted_at": 1.0, "reason": "Test", "pub_key": "…",
            ...      "promoted_at_str": "", "role_name": "node_operator"}])
            0
        """
        existing = {(e.epoch, e.address, e.role_name) for e in self._entries}
        added = 0
        for data in dicts:
            entry = NqtEntry.from_dict(data)
            key = (entry.epoch, entry.address, entry.role_name)
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

    def get_latest_for_role(self, role_name: str) -> Optional[NqtEntry]:
        """Return the most recent promotion for a specific role, or None.

        Args:
            role_name: Role name to filter by (e.g. ``"usd_operator"``).

        Returns:
            Optional[NqtEntry]: Most recent matching entry, or None.

        Example:
            >>> nqt = NodeQuorumTable()
            >>> nqt.add(1, b'k'*32, "10.0.0.1", "Élu", "usd_operator")
            >>> nqt.get_latest_for_role("usd_operator").address
            '10.0.0.1'
            >>> nqt.get_latest_for_role("node_operator") is None
            True
        """
        for entry in self._entries:
            if entry.role_name == role_name:
                return entry
        return None

    def get_all_entries(self) -> list[NqtEntry]:
        """Return a shallow copy of all entries (newest first).

        Example:
            >>> nqt = NodeQuorumTable()
            >>> nqt.add(1, b'k'*32, "10.0.0.1", "Élu", "node_operator")
            >>> len(nqt.get_all_entries())
            1
        """
        return list(self._entries)

    def get_all_dicts(self) -> list[dict]:
        """Return all entries serialised as dicts (newest first).

        Suitable for JSON serialisation in snapshots and GET_NQT responses.

        Example:
            >>> nqt = NodeQuorumTable()
            >>> nqt.add(1, b'k'*32, "10.0.0.1", "Élu", "usd_operator")
            >>> nqt.get_all_dicts()[0]["role_name"]
            'usd_operator'
        """
        return [e.to_dict() for e in self._entries]

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"NodeQuorumTable({len(self)} entries)"
