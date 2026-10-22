"""Coverage tests for miscellaneous modules.

Covers:
- usmd/quorum/manager.py  (QuorumManager construction, accessors, liveness check,
                            should_grant_vote, on_promotion_announced)
- usmd/__main__.py         (_build_parser, _format_uptime indirectly)
"""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock, patch

import pytest

from usmd.config import NodeConfig
from usmd.node.nal import NodeAccessList
from usmd.node.nit import NodeIdentityTable
from usmd.node.nqt import NodeQuorumTable
from usmd.node.role import NodeRole
from usmd.quorum.manager import QuorumManager


# ===========================================================================
# QuorumManager
# ===========================================================================


def _make_qm(role="executor", node_address="10.0.0.1"):
    cfg = NodeConfig(role=role)
    return QuorumManager(
        node_address=node_address,
        ed_pub=b"k" * 32,
        nit=NodeIdentityTable(),
        nal=NodeAccessList(),
        nqt=NodeQuorumTable(),
        cfg=cfg,
    )


class TestQuorumManagerConstruction:
    def test_is_quorum_manager(self):
        qm = _make_qm()
        assert isinstance(qm, QuorumManager)

    def test_executor_is_not_operator(self):
        qm = _make_qm(role="executor")
        assert qm.is_operator is False

    def test_operator_role_seeded(self):
        qm = _make_qm(role="operator")
        assert qm.is_operator is True

    def test_usd_operator_role_seeded(self):
        qm = _make_qm(role="usd_operator")
        assert qm.is_operator is True

    def test_elected_roles_executor_empty(self):
        qm = _make_qm(role="executor")
        assert qm.elected_roles == []

    def test_elected_roles_operator(self):
        qm = _make_qm(role="operator")
        assert "node_operator" in qm.elected_roles


class TestQuorumManagerAccessors:
    def test_get_promotions_empty(self):
        qm = _make_qm()
        assert qm.get_promotions() == []

    def test_get_promotions_after_nqt_add(self):
        qm = _make_qm()
        qm._nqt.add(1, b"k" * 32, "10.0.0.1", "Elected", "node_operator")
        promos = qm.get_promotions()
        assert len(promos) == 1
        assert promos[0]["epoch"] == 1


class TestQuorumManagerLiveness:
    def test_no_live_role_empty_nit(self):
        qm = _make_qm()
        assert qm._has_live_role(NodeRole.NODE_OPERATOR) is False

    def test_live_peer_addresses_empty_nit(self):
        qm = _make_qm()
        assert qm._live_peer_addresses() == []


class TestShouldGrantVote:
    def test_grants_first_vote(self):
        qm = _make_qm()
        result = qm.should_grant_vote(
            epoch=1,
            candidate_address="10.0.0.2",
            role_name="node_operator",
        )
        assert result is True

    def test_rejects_second_vote_same_epoch(self):
        qm = _make_qm()
        qm.should_grant_vote(1, "10.0.0.2", "node_operator")
        result = qm.should_grant_vote(1, "10.0.0.2", "node_operator")
        assert result is False

    def test_grants_different_epoch(self):
        qm = _make_qm()
        qm.should_grant_vote(1, "10.0.0.2", "node_operator")
        result = qm.should_grant_vote(2, "10.0.0.2", "node_operator")
        assert result is True

    def test_rejects_unknown_role(self):
        qm = _make_qm()
        result = qm.should_grant_vote(1, "10.0.0.2", "unknown_role")
        assert result is False


class TestOnPromotionAnnounced:
    def test_on_promotion_announced(self):
        qm = _make_qm()
        pub_key = b"\xaa" * 32
        # Should not raise and should register NQT entry
        qm.on_promotion_announced(
            epoch=1,
            pub_key=pub_key,
            address="10.0.0.2",
            role_name="node_operator",
        )
        assert len(qm._nqt) == 1


# ===========================================================================
# __main__.py — _build_parser
# ===========================================================================


class TestBuildParser:
    def _parser(self):
        from usmd.__main__ import _build_parser
        return _build_parser()

    def test_parser_returns_argparse(self):
        parser = self._parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_default_config(self):
        parser = self._parser()
        args = parser.parse_args([])
        assert args.config == "usmd.yaml"

    def test_config_override(self):
        parser = self._parser()
        args = parser.parse_args(["--config", "my_config.yaml"])
        assert args.config == "my_config.yaml"

    def test_bootstrap_flag(self):
        parser = self._parser()
        args = parser.parse_args(["--bootstrap"])
        assert args.bootstrap is True

    def test_role_override(self):
        parser = self._parser()
        args = parser.parse_args(["--role", "operator"])
        assert args.role == "operator"

    def test_status_subcommand(self):
        parser = self._parser()
        args = parser.parse_args(["status"])
        assert args.command == "status"

    def test_status_json_flag(self):
        parser = self._parser()
        args = parser.parse_args(["status", "--json"])
        assert args.as_json is True

    def test_status_socket(self):
        parser = self._parser()
        args = parser.parse_args(["status", "--socket", "/tmp/usmd.sock"])
        assert args.socket == "/tmp/usmd.sock"

    def test_status_port(self):
        parser = self._parser()
        args = parser.parse_args(["status", "--port", "5627"])
        assert args.port == 5627

    def test_log_level_choices(self):
        parser = self._parser()
        for level in ("DEBUG", "INFO", "WARNING", "ERROR"):
            args = parser.parse_args(["--log-level", level])
            assert args.log_level == level

    def test_address_override(self):
        parser = self._parser()
        args = parser.parse_args(["--address", "192.168.1.50"])
        assert args.address == "192.168.1.50"
