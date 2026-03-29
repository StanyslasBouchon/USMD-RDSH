"""Tests for quorum/manager.py (QuorumManager) and quorum/_quorum_rpc.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from usmd.config import NodeConfig
from usmd.node.nal import NodeAccessList
from usmd.node.nit import NodeIdentityTable
from usmd.node.nqt import NodeQuorumTable
from usmd.node.role import NodeRole
from usmd.node.state import NodeState
from usmd.quorum._quorum_rpc import (
    QuorumOptions,
    announce_promotion,
    on_promotion_announced,
    promote_self,
    request_vote,
    should_grant_vote,
)
from usmd.quorum.manager import QuorumManager
from usmd.security.crypto import Ed25519Pair
from usmd.utils.result import Result
from usmd.utils.errors import Error, ErrorKind


def _err():
    return Result.Err(Error.new(ErrorKind.CONNECTION_ERROR, "mocked failure"))


def _ok(frame):
    return Result.Ok(frame)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_qm(*, node_address="10.0.0.1", node_role=NodeRole.NODE_EXECUTOR):
    ed_priv, ed_pub = Ed25519Pair.generate()
    # NodeConfig uses "operator"/"executor"/"usd_operator"/"ucd_operator" strings
    _role_str_map = {
        NodeRole.NODE_EXECUTOR: "executor",
        NodeRole.NODE_OPERATOR: "operator",
        NodeRole.USD_OPERATOR: "usd_operator",
        NodeRole.UCD_OPERATOR: "ucd_operator",
    }
    cfg = NodeConfig(bootstrap=True, role=_role_str_map[node_role])
    nit = NodeIdentityTable()
    nal = NodeAccessList()
    nqt = NodeQuorumTable()
    nit.register(node_address, ed_pub, ttl=86400)
    nal.grant(ed_pub, node_role, permanent=True)
    qm = QuorumManager(
        node_address=node_address,
        ed_pub=ed_pub,
        nit=nit,
        nal=nal,
        nqt=nqt,
        cfg=cfg,
        options=QuorumOptions(check_interval=0.01, ncp_port=5626, ncp_timeout=1.0),
    )
    return qm, nit, nal, nqt, ed_pub, cfg


# ===========================================================================
# QuorumOptions
# ===========================================================================


class TestQuorumOptions:
    def test_defaults(self):
        opts = QuorumOptions()
        assert opts.check_interval == 30.0
        assert opts.ncp_port == 5626
        assert opts.ncp_timeout == 5.0
        assert opts.on_ncp_failure is None
        assert opts.usd is None

    def test_custom_values(self):
        opts = QuorumOptions(check_interval=10.0, ncp_port=9999)
        assert opts.check_interval == 10.0
        assert opts.ncp_port == 9999


# ===========================================================================
# QuorumManager — construction and accessors
# ===========================================================================


class TestQuorumManagerInit:
    def test_basic_construction(self):
        qm, *_ = _make_qm()
        assert isinstance(qm, QuorumManager)

    def test_is_operator_false_for_executor(self):
        qm, *_ = _make_qm(node_role=NodeRole.NODE_EXECUTOR)
        assert qm.is_operator is False

    def test_is_operator_true_for_node_operator_role(self):
        qm, *_ = _make_qm(node_role=NodeRole.NODE_OPERATOR)
        assert qm.is_operator is True

    def test_elected_roles_seeded_from_cfg(self):
        qm, *_ = _make_qm(node_role=NodeRole.NODE_OPERATOR)
        assert "node_operator" in qm.elected_roles

    def test_get_promotions_empty(self):
        qm, *_ = _make_qm()
        assert qm.get_promotions() == []


# ===========================================================================
# QuorumManager — _has_live_role
# ===========================================================================


class TestHasLiveRole:
    def test_no_peers_returns_false(self):
        qm, *_ = _make_qm()
        assert qm._has_live_role(NodeRole.NODE_OPERATOR) is False

    def test_peer_with_role_returns_true(self):
        qm, nit, nal, *_ = _make_qm()
        _, peer_pub = Ed25519Pair.generate()
        nit.register("10.0.0.2", peer_pub, ttl=86400)
        nal.grant(peer_pub, NodeRole.NODE_OPERATOR, permanent=False)
        assert qm._has_live_role(NodeRole.NODE_OPERATOR) is True

    def test_expired_peer_ignored(self):
        import time

        qm, nit, nal, *_ = _make_qm()
        _, peer_pub = Ed25519Pair.generate()
        nit.register("10.0.0.2", peer_pub, ttl=1)
        # Expire the entry
        for e in nit._entries.values():
            if e.address == "10.0.0.2":
                e.registered_at = time.time() - 9999
        nal.grant(peer_pub, NodeRole.NODE_OPERATOR, permanent=False)
        assert qm._has_live_role(NodeRole.NODE_OPERATOR) is False

    def test_self_excluded_from_liveness(self):
        """The local node's own NIT entry must not count as a live holder."""
        qm, nit, nal, _, ed_pub, _ = _make_qm()
        nal.grant(ed_pub, NodeRole.NODE_OPERATOR, permanent=True)
        # Only self is in NIT with the role
        assert qm._has_live_role(NodeRole.NODE_OPERATOR) is False


# ===========================================================================
# QuorumManager — _live_peer_addresses
# ===========================================================================


class TestLivePeerAddresses:
    def test_empty_when_no_peers(self):
        qm, *_ = _make_qm()
        assert qm._live_peer_addresses() == []

    def test_returns_active_peer(self):
        qm, nit, *_ = _make_qm()
        _, pub = Ed25519Pair.generate()
        nit.register("10.0.0.2", pub, ttl=86400)
        addrs = qm._live_peer_addresses()
        assert "10.0.0.2" in addrs

    def test_excludes_expired_peer(self):
        import time

        qm, nit, *_ = _make_qm()
        _, pub = Ed25519Pair.generate()
        nit.register("10.0.0.2", pub, ttl=1)
        for e in nit._entries.values():
            if e.address == "10.0.0.2":
                e.registered_at = time.time() - 9999
        assert "10.0.0.2" not in qm._live_peer_addresses()

    def test_excludes_inactive_usd_node(self):
        from usmd.domain.usd import UnifiedSystemDomain, USDConfig
        from usmd.node.node import Node

        qm, nit, *_ = _make_qm()
        _, pub = Ed25519Pair.generate()
        nit.register("10.0.0.2", pub, ttl=86400)

        # Build a minimal USD and attach it to qm via options
        ed_priv, ed_pub = Ed25519Pair.generate()
        usd_cfg = USDConfig(
            name="t",
            cluster_name="",
            max_reference_nodes=5,
            load_threshold=0.8,
            ping_tolerance_ms=200,
            load_check_interval=30,
        )
        usd = UnifiedSystemDomain(config=usd_cfg, private_key=ed_priv)
        inactive = Node(address="10.0.0.2", name=2, state=NodeState.INACTIVE_TIMEOUT)
        usd.add_node(inactive)
        qm._usd = usd

        assert "10.0.0.2" not in qm._live_peer_addresses()


# ===========================================================================
# QuorumManager — should_grant_vote
# ===========================================================================


class TestShouldGrantVote:
    def test_grants_vote_for_valid_role(self):
        qm, *_ = _make_qm()
        assert qm.should_grant_vote(1, "10.0.0.2", "node_operator") is True

    def test_refuses_second_vote_same_epoch(self):
        qm, *_ = _make_qm()
        qm.should_grant_vote(1, "10.0.0.2", "node_operator")
        assert qm.should_grant_vote(1, "10.0.0.2", "node_operator") is False

    def test_grants_vote_different_epoch(self):
        qm, *_ = _make_qm()
        qm.should_grant_vote(1, "10.0.0.2", "node_operator")
        assert qm.should_grant_vote(2, "10.0.0.2", "node_operator") is True

    def test_refuses_unknown_role(self):
        qm, *_ = _make_qm()
        assert qm.should_grant_vote(1, "10.0.0.2", "bad_role") is False

    def test_refuses_when_live_holder_exists(self):
        qm, nit, nal, *_ = _make_qm()
        _, peer_pub = Ed25519Pair.generate()
        nit.register("10.0.0.2", peer_pub, ttl=86400)
        nal.grant(peer_pub, NodeRole.NODE_OPERATOR, permanent=False)
        assert qm.should_grant_vote(1, "10.0.0.3", "node_operator") is False

    def test_grants_all_three_operator_roles(self):
        qm, *_ = _make_qm()
        assert qm.should_grant_vote(1, "10.0.0.2", "node_operator") is True
        assert qm.should_grant_vote(1, "10.0.0.2", "usd_operator") is True
        assert qm.should_grant_vote(1, "10.0.0.2", "ucd_operator") is True


# ===========================================================================
# QuorumManager — on_promotion_announced
# ===========================================================================


class TestOnPromotionAnnounced:
    def test_grants_role_in_nal(self):
        qm, nit, nal, *_ = _make_qm()
        _, pub = Ed25519Pair.generate()
        qm.on_promotion_announced(1, pub, "10.0.0.2", "node_operator")
        assert nal.has_role(pub, NodeRole.NODE_OPERATOR)

    def test_registers_in_nit(self):
        qm, nit, *_ = _make_qm()
        _, pub = Ed25519Pair.generate()
        qm.on_promotion_announced(1, pub, "10.0.0.2", "node_operator")
        keys = {e.address for e in nit.iter_all_entries()}
        assert "10.0.0.2" in keys

    def test_records_in_nqt(self):
        qm, _, _, nqt, *_ = _make_qm()
        _, pub = Ed25519Pair.generate()
        qm.on_promotion_announced(1, pub, "10.0.0.2", "usd_operator")
        assert len(nqt) == 1

    def test_unknown_role_falls_back_to_node_operator(self):
        qm, _, nal, nqt, *_ = _make_qm()
        _, pub = Ed25519Pair.generate()
        qm.on_promotion_announced(1, pub, "10.0.0.2", "nonexistent_role")
        # Should not raise; falls back to NODE_OPERATOR
        assert nal.has_role(pub, NodeRole.NODE_OPERATOR)


# ===========================================================================
# QuorumManager — run loop
# ===========================================================================


class TestQuorumManagerRun:
    @pytest.mark.asyncio
    async def test_run_cancels_cleanly(self):
        qm, *_ = _make_qm()
        task = asyncio.create_task(qm.run())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass  # expected

    @pytest.mark.asyncio
    async def test_election_triggered_when_no_live_role(self):
        """If no live role holder exists, _start_election should be called."""
        qm, *_ = _make_qm(node_role=NodeRole.NODE_EXECUTOR)  # not an operator

        with patch.object(qm, "_start_election", new_callable=AsyncMock) as mock_elect:
            task = asyncio.create_task(qm.run())
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            assert mock_elect.call_count >= 1


# ===========================================================================
# _quorum_rpc — promote_self
# ===========================================================================


class TestPromoteSelf:
    def test_updates_elected_roles(self):
        _, ed_pub = Ed25519Pair.generate()
        cfg = NodeConfig(bootstrap=True)
        nal = NodeAccessList()
        nqt = NodeQuorumTable()
        elected_roles: set = set()
        promote_self(
            cfg,
            nal,
            nqt,
            elected_roles,
            ed_pub,
            "10.0.0.1",
            NodeRole.NODE_OPERATOR,
            1,
            "test reason",
        )
        assert NodeRole.NODE_OPERATOR in elected_roles

    def test_grants_nal_role(self):
        _, ed_pub = Ed25519Pair.generate()
        cfg = NodeConfig(bootstrap=True)
        nal = NodeAccessList()
        nqt = NodeQuorumTable()
        promote_self(
            cfg, nal, nqt, set(), ed_pub, "10.0.0.1", NodeRole.USD_OPERATOR, 1, "reason"
        )
        assert nal.has_role(ed_pub, NodeRole.USD_OPERATOR)

    def test_adds_nqt_entry(self):
        _, ed_pub = Ed25519Pair.generate()
        cfg = NodeConfig(bootstrap=True)
        nal = NodeAccessList()
        nqt = NodeQuorumTable()
        promote_self(
            cfg, nal, nqt, set(), ed_pub, "10.0.0.1", NodeRole.UCD_OPERATOR, 2, "reason"
        )
        assert len(nqt) == 1
        assert nqt.get_latest().role_name == "ucd_operator"

    def test_updates_cfg_role(self):
        _, ed_pub = Ed25519Pair.generate()
        cfg = NodeConfig(bootstrap=True)
        nal = NodeAccessList()
        nqt = NodeQuorumTable()
        promote_self(
            cfg,
            nal,
            nqt,
            set(),
            ed_pub,
            "10.0.0.1",
            NodeRole.NODE_OPERATOR,
            1,
            "reason",
        )
        assert cfg.role == "operator"


# ===========================================================================
# _quorum_rpc — should_grant_vote (direct function)
# ===========================================================================


class TestShouldGrantVoteFn:
    def _make_args(self):
        from usmd.quorum.manager import _OPERATOR_ROLES

        voted = {r: set() for r in _OPERATOR_ROLES}
        return voted, _OPERATOR_ROLES

    def test_grants_valid_vote(self):
        voted, roles = self._make_args()
        result = should_grant_vote(
            voted, lambda r: False, roles, 1, "10.0.0.2", "node_operator"
        )
        assert result is True

    def test_already_voted_returns_false(self):
        voted, roles = self._make_args()
        should_grant_vote(voted, lambda r: False, roles, 1, "10.0.0.2", "node_operator")
        assert (
            should_grant_vote(
                voted, lambda r: False, roles, 1, "10.0.0.2", "node_operator"
            )
            is False
        )

    def test_unknown_role_returns_false(self):
        voted, roles = self._make_args()
        assert (
            should_grant_vote(
                voted, lambda r: False, roles, 1, "10.0.0.2", "unknown_role"
            )
            is False
        )

    def test_live_holder_returns_false(self):
        voted, roles = self._make_args()
        assert (
            should_grant_vote(
                voted, lambda r: True, roles, 1, "10.0.0.2", "node_operator"
            )
            is False
        )


# ===========================================================================
# _quorum_rpc — request_vote (async, NCP mocked)
# ===========================================================================


class TestRequestVoteFn:
    @pytest.mark.asyncio
    async def test_returns_true_when_granted(self):
        from usmd.ncp.protocol.commands.request_vote import RequestVoteResponse

        resp = RequestVoteResponse(granted=True)
        mock_frame = MagicMock()
        mock_frame.payload = resp.to_payload()

        with patch("usmd.quorum._quorum_rpc.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=_ok(mock_frame))
            MockClient.return_value = mock_client
            result = await request_vote(
                "10.0.0.1", 5626, 2.0, None, 1, NodeRole.NODE_OPERATOR, "10.0.0.2"
            )
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_refused(self):
        from usmd.ncp.protocol.commands.request_vote import RequestVoteResponse

        resp = RequestVoteResponse(granted=False)
        mock_frame = MagicMock()
        mock_frame.payload = resp.to_payload()

        with patch("usmd.quorum._quorum_rpc.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=_ok(mock_frame))
            MockClient.return_value = mock_client
            result = await request_vote(
                "10.0.0.1", 5626, 2.0, None, 1, NodeRole.NODE_OPERATOR, "10.0.0.2"
            )
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_ncp_error(self):
        with patch("usmd.quorum._quorum_rpc.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=_err())
            MockClient.return_value = mock_client
            failure_cb = MagicMock()
            result = await request_vote(
                "10.0.0.1", 5626, 2.0, failure_cb, 1, NodeRole.NODE_OPERATOR, "10.0.0.2"
            )
        assert result is False
        failure_cb.assert_called_once_with("10.0.0.2")


# ===========================================================================
# _quorum_rpc — announce_promotion (async, NCP mocked)
# ===========================================================================


class TestAnnouncePromotionFn:
    @pytest.mark.asyncio
    async def test_sends_to_all_peers(self):
        with patch("usmd.quorum._quorum_rpc.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_frame = MagicMock()
            mock_client.send = AsyncMock(return_value=_ok(mock_frame))
            MockClient.return_value = mock_client
            _, ed_pub = Ed25519Pair.generate()
            await announce_promotion(
                "10.0.0.1",
                ed_pub,
                5626,
                2.0,
                None,
                NodeRole.NODE_OPERATOR,
                1,
                ["10.0.0.2", "10.0.0.3"],
            )
            assert mock_client.send.call_count == 2

    @pytest.mark.asyncio
    async def test_calls_failure_cb_on_ncp_error(self):
        with patch("usmd.quorum._quorum_rpc.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=_err())
            MockClient.return_value = mock_client
            _, ed_pub = Ed25519Pair.generate()
            failure_cb = MagicMock()
            await announce_promotion(
                "10.0.0.1",
                ed_pub,
                5626,
                2.0,
                failure_cb,
                NodeRole.NODE_OPERATOR,
                1,
                ["10.0.0.2"],
            )
            failure_cb.assert_called_once_with("10.0.0.2")


# ===========================================================================
# _quorum_rpc — on_promotion_announced (direct function)
# ===========================================================================


class TestOnPromotionAnnouncedFn:
    def test_grants_role_and_registers_nit(self):
        from usmd.quorum.manager import _OPERATOR_ROLES

        nal = NodeAccessList()
        nit = NodeIdentityTable()
        voted = {r: set() for r in _OPERATOR_ROLES}
        nqt = NodeQuorumTable()
        _, pub = Ed25519Pair.generate()
        on_promotion_announced(nal, nit, voted, nqt, 1, pub, "10.0.0.2", "usd_operator")
        assert nal.has_role(pub, NodeRole.USD_OPERATOR)
        keys = {e.address for e in nit.iter_all_entries()}
        assert "10.0.0.2" in keys

    def test_clears_voted_epoch(self):
        from usmd.quorum.manager import _OPERATOR_ROLES

        nal = NodeAccessList()
        nit = NodeIdentityTable()
        voted = {r: {1} for r in _OPERATOR_ROLES}  # pre-filled with epoch 1
        nqt = NodeQuorumTable()
        _, pub = Ed25519Pair.generate()
        on_promotion_announced(
            nal, nit, voted, nqt, 1, pub, "10.0.0.2", "node_operator"
        )
        assert 1 not in voted[NodeRole.NODE_OPERATOR]
