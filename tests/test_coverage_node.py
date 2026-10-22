"""Coverage tests for node data structures.

Covers:
- usmd/node/nqt.py   (NqtEntry, NodeQuorumTable)
- usmd/node/nrl.py   (NrlEntry, NodeReferenceList)
- usmd/node/nrt.py   (NrtEntry, NodeReferenceTable)
"""

from __future__ import annotations

import time

import pytest

from usmd.node.nqt import NqtEntry, NodeQuorumTable
from usmd.node.nrl import NrlEntry, NodeReferenceList
from usmd.node.nrt import NrtEntry, NodeReferenceTable


# ===========================================================================
# node/nqt.py
# ===========================================================================


class TestNqtEntry:
    def _make(self, epoch=1, address="10.0.0.1"):
        return NqtEntry(
            epoch=epoch,
            pub_key=b"k" * 32,
            address=address,
            promoted_at=1_000_000.0,
            reason="Elected",
            role_name="node_operator",
        )

    def test_pub_key_short(self):
        e = self._make()
        short = e.pub_key_short
        assert short.endswith("…")
        assert len(short) == 21  # 20 hex chars + "…"

    def test_promoted_at_str(self):
        e = self._make()
        s = e.promoted_at_str
        assert isinstance(s, str)
        assert "/" in s  # date format dd/mm/yyyy

    def test_to_dict_keys(self):
        e = self._make()
        d = e.to_dict()
        for key in ("epoch", "address", "pub_key", "pub_key_hex", "promoted_at",
                    "promoted_at_str", "reason", "role_name"):
            assert key in d

    def test_to_dict_values(self):
        e = self._make(epoch=7, address="1.2.3.4")
        d = e.to_dict()
        assert d["epoch"] == 7
        assert d["address"] == "1.2.3.4"
        assert d["role_name"] == "node_operator"

    def test_from_dict_roundtrip(self):
        e = self._make(epoch=3)
        d = e.to_dict()
        e2 = NqtEntry.from_dict(d)
        assert e2.epoch == 3
        assert e2.pub_key == b"k" * 32
        assert e2.address == "10.0.0.1"
        assert e2.role_name == "node_operator"

    def test_from_dict_invalid_hex(self):
        d = {
            "epoch": 1,
            "address": "10.0.0.1",
            "pub_key_hex": "not-valid-hex",
            "promoted_at": 0.0,
            "reason": "",
            "role_name": "node_operator",
        }
        e = NqtEntry.from_dict(d)
        assert e.pub_key == b"\x00" * 32

    def test_from_dict_missing_hex(self):
        d = {
            "epoch": 2,
            "address": "10.0.0.2",
            "promoted_at": 0.0,
            "reason": "",
            "role_name": "usd_operator",
        }
        e = NqtEntry.from_dict(d)
        assert e.pub_key == b"\x00" * 32
        assert e.role_name == "usd_operator"


class TestNodeQuorumTable:
    def test_empty_table(self):
        nqt = NodeQuorumTable()
        assert len(nqt) == 0
        assert nqt.get_latest() is None

    def test_add_entry(self):
        nqt = NodeQuorumTable()
        nqt.add(1, b"k" * 32, "10.0.0.1", "Elected", "node_operator")
        assert len(nqt) == 1
        entry = nqt.get_latest()
        assert entry.epoch == 1
        assert entry.address == "10.0.0.1"

    def test_add_no_duplicate(self):
        nqt = NodeQuorumTable()
        nqt.add(1, b"k" * 32, "10.0.0.1", "Elected", "node_operator")
        nqt.add(1, b"k" * 32, "10.0.0.1", "Elected", "node_operator")
        assert len(nqt) == 1

    def test_add_different_epochs(self):
        nqt = NodeQuorumTable()
        nqt.add(1, b"k" * 32, "10.0.0.1", "Elected", "node_operator")
        nqt.add(2, b"k" * 32, "10.0.0.1", "Elected 2", "node_operator")
        assert len(nqt) == 2

    def test_get_latest_for_role(self):
        nqt = NodeQuorumTable()
        nqt.add(1, b"k" * 32, "10.0.0.1", "Elected", "node_operator")
        nqt.add(2, b"k" * 32, "10.0.0.2", "Elected USD", "usd_operator")
        entry = nqt.get_latest_for_role("usd_operator")
        assert entry is not None
        assert entry.address == "10.0.0.2"

    def test_get_latest_for_role_not_found(self):
        nqt = NodeQuorumTable()
        nqt.add(1, b"k" * 32, "10.0.0.1", "Elected", "node_operator")
        assert nqt.get_latest_for_role("ucd_operator") is None

    def test_get_all_entries(self):
        nqt = NodeQuorumTable()
        nqt.add(1, b"k" * 32, "10.0.0.1", "Elected", "node_operator")
        entries = nqt.get_all_entries()
        assert len(entries) == 1
        assert isinstance(entries[0], NqtEntry)

    def test_get_all_dicts(self):
        nqt = NodeQuorumTable()
        nqt.add(1, b"k" * 32, "10.0.0.1", "Elected", "usd_operator")
        dicts = nqt.get_all_dicts()
        assert len(dicts) == 1
        assert dicts[0]["role_name"] == "usd_operator"

    def test_merge_from_dicts_adds_new(self):
        nqt = NodeQuorumTable()
        data = [
            {
                "epoch": 1,
                "address": "10.0.0.1",
                "pub_key_hex": "aa" * 32,
                "promoted_at": 1.0,
                "reason": "Test",
                "pub_key": "...",
                "promoted_at_str": "",
                "role_name": "node_operator",
            }
        ]
        added = nqt.merge_from_dicts(data)
        assert added == 1
        assert len(nqt) == 1

    def test_merge_from_dicts_skips_duplicates(self):
        nqt = NodeQuorumTable()
        nqt.add(1, b"aa" * 16, "10.0.0.1", "Test", "node_operator")
        data = [
            {
                "epoch": 1,
                "address": "10.0.0.1",
                "pub_key_hex": "aa" * 32,
                "promoted_at": 1.0,
                "reason": "Test",
                "pub_key": "...",
                "promoted_at_str": "",
                "role_name": "node_operator",
            }
        ]
        added = nqt.merge_from_dicts(data)
        assert added == 0

    def test_merge_from_dicts_empty(self):
        nqt = NodeQuorumTable()
        assert nqt.merge_from_dicts([]) == 0

    def test_repr(self):
        nqt = NodeQuorumTable()
        assert "0" in repr(nqt)


# ===========================================================================
# node/nrl.py
# ===========================================================================


class TestNrlEntry:
    def test_declared_at_str(self):
        e = NrlEntry(mandator_name=1, mandator_address="10.0.0.1", declared_at=1_000_000.0)
        s = e.declared_at_str
        assert isinstance(s, str)
        assert "/" in s

    def test_to_dict(self):
        e = NrlEntry(mandator_name=123, mandator_address="1.2.3.4", declared_at=0.0)
        d = e.to_dict()
        assert d["name"] == 123
        assert d["address"] == "1.2.3.4"
        assert "declared_at" in d
        assert "declared_at_str" in d


class TestNodeReferenceList:
    def test_empty(self):
        nrl = NodeReferenceList()
        assert len(nrl) == 0

    def test_add_entry(self):
        nrl = NodeReferenceList()
        nrl.add(1710000001, "10.0.0.2")
        assert len(nrl) == 1

    def test_add_refreshes_existing(self):
        nrl = NodeReferenceList()
        nrl.add(1, "10.0.0.1")
        nrl.add(1, "10.0.0.1")
        assert len(nrl) == 1

    def test_remove_existing(self):
        nrl = NodeReferenceList()
        nrl.add(1, "10.0.0.1")
        nrl.remove(1)
        assert len(nrl) == 0

    def test_remove_nonexistent(self):
        nrl = NodeReferenceList()
        nrl.remove(9999)  # Should not raise
        assert len(nrl) == 0

    def test_get_existing(self):
        nrl = NodeReferenceList()
        nrl.add(42, "10.0.0.42")
        entry = nrl.get(42)
        assert entry is not None
        assert entry.mandator_address == "10.0.0.42"

    def test_get_nonexistent(self):
        nrl = NodeReferenceList()
        assert nrl.get(999) is None

    def test_get_all_dicts_sorted(self):
        nrl = NodeReferenceList()
        nrl.add(3, "10.0.0.3")
        nrl.add(1, "10.0.0.1")
        nrl.add(2, "10.0.0.2")
        dicts = nrl.get_all_dicts()
        assert [d["name"] for d in dicts] == [1, 2, 3]

    def test_repr(self):
        nrl = NodeReferenceList()
        nrl.add(1, "10.0.0.1")
        r = repr(nrl)
        assert "1" in r


# ===========================================================================
# node/nrt.py
# ===========================================================================


class TestNrtEntry:
    def test_not_stale_fresh(self):
        e = NrtEntry(address="10.0.0.1", distance=0.5, ping_ms=10.0)
        assert e.is_stale() is False

    def test_stale_old_entry(self):
        e = NrtEntry(
            address="10.0.0.1",
            distance=1.0,
            ping_ms=20.0,
            updated_at=time.time() - 7200,  # 2 hours ago
        )
        assert e.is_stale() is True


class TestNodeReferenceTable:
    def test_empty(self):
        nrt = NodeReferenceTable()
        assert len(nrt) == 0

    def test_update_and_get(self):
        nrt = NodeReferenceTable()
        nrt.update("10.0.0.1", 1.25, 42.0)
        entry = nrt.get("10.0.0.1")
        assert entry is not None
        assert entry.distance == 1.25
        assert entry.ping_ms == 42.0

    def test_update_overwrites(self):
        nrt = NodeReferenceTable()
        nrt.update("10.0.0.1", 1.0, 20.0)
        nrt.update("10.0.0.1", 2.0, 30.0)
        entry = nrt.get("10.0.0.1")
        assert entry.distance == 2.0

    def test_get_nonexistent(self):
        nrt = NodeReferenceTable()
        assert nrt.get("10.0.0.99") is None

    def test_remove_existing(self):
        nrt = NodeReferenceTable()
        nrt.update("10.0.0.1", 1.0, 10.0)
        nrt.remove("10.0.0.1")
        assert nrt.get("10.0.0.1") is None

    def test_remove_nonexistent(self):
        nrt = NodeReferenceTable()
        nrt.remove("10.0.0.99")  # should not raise

    def test_get_all_sorted_by_distance(self):
        nrt = NodeReferenceTable()
        nrt.update("10.0.0.3", 3.0, 30.0)
        nrt.update("10.0.0.1", 1.0, 10.0)
        nrt.update("10.0.0.2", 2.0, 20.0)
        rows = nrt.get_all()
        assert [r["address"] for r in rows] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_get_all_keys(self):
        nrt = NodeReferenceTable()
        nrt.update("10.0.0.1", 1.0, 10.0)
        row = nrt.get_all()[0]
        for key in ("address", "distance", "ping_ms", "updated_at",
                    "updated_at_str", "stale", "node_name"):
            assert key in row

    def test_get_all_node_name_is_none(self):
        nrt = NodeReferenceTable()
        nrt.update("10.0.0.1", 1.0, 10.0)
        assert nrt.get_all()[0]["node_name"] is None

    def test_len(self):
        nrt = NodeReferenceTable()
        nrt.update("10.0.0.1", 1.0, 10.0)
        nrt.update("10.0.0.2", 2.0, 20.0)
        assert len(nrt) == 2

    def test_repr(self):
        nrt = NodeReferenceTable()
        assert isinstance(repr(nrt), str)
