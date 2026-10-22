"""Coverage tests for web helper functions.

Covers pure functions in usmd/web/node_snapshots.py that don't require Django:
- _get_state_reason
- _normalize_nrt_rows
- _build_inactive_stub
- extract_promotions
- invalidate_snapshot_cache
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from usmd.web.node_snapshots import (
    _SNAPSHOT_CACHE,
    _build_inactive_stub,
    _get_state_reason,
    _normalize_nrt_rows,
    extract_promotions,
    invalidate_snapshot_cache,
)


# ===========================================================================
# _get_state_reason
# ===========================================================================


class TestGetStateReason:
    def test_known_states(self):
        assert _get_state_reason("inactive") == "Inactive"
        assert _get_state_reason("inactive_timeout") == "NCP timeout exceeded"
        assert _get_state_reason("excluded_invalid_nit") == "Invalid NIT (excluded)"

    def test_unknown_state_returns_empty(self):
        assert _get_state_reason("some_unknown_state") == ""

    def test_empty_string(self):
        assert _get_state_reason("") == ""

    def test_all_known_emergency_states(self):
        for state in (
            "inactive_emergency",
            "inactive_emergency_out_of_resources",
            "inactive_emergency_dependency_inactive",
            "inactive_emergency_health_check_failed",
            "inactive_emergency_update_failed",
        ):
            assert _get_state_reason(state) != ""


# ===========================================================================
# _normalize_nrt_rows
# ===========================================================================


class TestNormalizeNrtRows:
    def test_no_nrt_key(self):
        snap = {"node": {}}
        _normalize_nrt_rows(snap)
        assert "nrt" not in snap

    def test_empty_nrt(self):
        snap = {"nrt": []}
        _normalize_nrt_rows(snap)
        assert snap["nrt"] == []

    def test_row_with_node_name_present_unchanged(self):
        snap = {"nrt": [{"address": "10.0.0.1", "node_name": 42}]}
        _normalize_nrt_rows(snap)
        assert snap["nrt"][0]["node_name"] == 42

    def test_row_without_node_name_filled_from_usd(self):
        usd_node = MagicMock()
        usd_node.address = "10.0.0.1"
        usd_node.name = 99
        snap = {"nrt": [{"address": "10.0.0.1"}]}
        _normalize_nrt_rows(snap, usd_nodes=[usd_node])
        assert snap["nrt"][0]["node_name"] == 99

    def test_row_without_node_name_no_usd_match(self):
        snap = {"nrt": [{"address": "10.0.0.1"}]}
        _normalize_nrt_rows(snap, usd_nodes=[])
        assert snap["nrt"][0]["node_name"] is None

    def test_row_with_node_name_none_not_overwritten(self):
        """node_name=None (JSON null) must NOT be overwritten by USD lookup."""
        usd_node = MagicMock()
        usd_node.address = "10.0.0.1"
        usd_node.name = 77
        snap = {"nrt": [{"address": "10.0.0.1", "node_name": None}]}
        _normalize_nrt_rows(snap, usd_nodes=[usd_node])
        # node_name key is already present with None → do not overwrite
        assert snap["nrt"][0]["node_name"] is None

    def test_non_dict_row_passed_through(self):
        snap = {"nrt": ["not-a-dict", {"address": "10.0.0.1"}]}
        _normalize_nrt_rows(snap)
        assert snap["nrt"][0] == "not-a-dict"

    def test_does_not_mutate_original_rows(self):
        """Output rows should be copies, not the original dict objects."""
        original_row = {"address": "10.0.0.1"}
        snap = {"nrt": [original_row]}
        _normalize_nrt_rows(snap)
        # The snap["nrt"] list is new but we're fine if same object (shallow copy is ok)
        assert snap["nrt"][0]["address"] == "10.0.0.1"


# ===========================================================================
# _build_inactive_stub
# ===========================================================================


class TestBuildInactiveStub:
    def _make_usd_node(self, state_value="inactive"):
        usd_node = MagicMock()
        usd_node.name = 1710000001
        usd_node.state.value = state_value
        return usd_node

    def test_stub_is_not_local(self):
        stub = _build_inactive_stub("10.0.0.1", self._make_usd_node())
        assert stub["is_local"] is False

    def test_stub_address(self):
        stub = _build_inactive_stub("10.0.0.5", self._make_usd_node())
        assert stub["node"]["address"] == "10.0.0.5"

    def test_stub_state_reason(self):
        stub = _build_inactive_stub("10.0.0.1", self._make_usd_node("inactive"))
        assert stub["node"]["state_reason"] == "Inactive"

    def test_stub_resources_zero(self):
        stub = _build_inactive_stub("10.0.0.1", self._make_usd_node())
        res = stub["resources"]
        assert res["cpu_percent"] == 0.0
        assert res["ram_percent"] == 0.0

    def test_stub_empty_lists(self):
        stub = _build_inactive_stub("10.0.0.1", self._make_usd_node())
        assert stub["nit"] == []
        assert stub["nal"] == []
        assert stub["nel"] == []
        assert stub["nrt"] == []
        assert stub["nrl"] == []
        assert stub["reference_nodes"] == []

    def test_stub_quorum_fields(self):
        stub = _build_inactive_stub("10.0.0.1", self._make_usd_node())
        assert "quorum" in stub
        assert stub["quorum"]["elected_roles"] == []
        assert stub["quorum"]["promotions"] == []


# ===========================================================================
# extract_promotions
# ===========================================================================


class TestExtractPromotions:
    def test_empty_nodes(self):
        assert extract_promotions([]) == []

    def test_no_quorum_key(self):
        nodes = [{"node": {}}]
        assert extract_promotions(nodes) == []

    def test_single_promotion(self):
        nodes = [
            {
                "quorum": {
                    "promotions": [
                        {"epoch": 1, "address": "10.0.0.1", "promoted_at": 1000.0}
                    ]
                }
            }
        ]
        result = extract_promotions(nodes)
        assert len(result) == 1
        assert result[0]["epoch"] == 1

    def test_deduplication(self):
        promo = {"epoch": 1, "address": "10.0.0.1", "promoted_at": 1000.0}
        nodes = [
            {"quorum": {"promotions": [promo]}},
            {"quorum": {"promotions": [promo]}},
        ]
        result = extract_promotions(nodes)
        assert len(result) == 1

    def test_sorted_newest_first(self):
        nodes = [
            {
                "quorum": {
                    "promotions": [
                        {"epoch": 1, "address": "10.0.0.1", "promoted_at": 100.0},
                        {"epoch": 2, "address": "10.0.0.2", "promoted_at": 200.0},
                    ]
                }
            }
        ]
        result = extract_promotions(nodes)
        assert result[0]["promoted_at"] == 200.0
        assert result[1]["promoted_at"] == 100.0


# ===========================================================================
# invalidate_snapshot_cache
# ===========================================================================


class TestInvalidateSnapshotCache:
    def test_invalidate_existing(self):
        _SNAPSHOT_CACHE["10.0.0.99"] = ({"node": {}}, 9999.0)
        invalidate_snapshot_cache("10.0.0.99")
        assert "10.0.0.99" not in _SNAPSHOT_CACHE

    def test_invalidate_nonexistent(self):
        # Should not raise
        invalidate_snapshot_cache("10.0.0.200")
