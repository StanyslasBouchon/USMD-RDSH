"""Roles: every node an executor, operators elected by the USD master [ARCH-02 12.4, NCP-02 7.3]."""
# pylint: disable=protected-access

import asyncio

import pytest
from nan_runtime.state import StateDirectory

from usmd_rdsh.node.crypto import SigningKey
from usmd_rdsh.node.ncp.codec import NodeRecord, Role, role_allows
from usmd_rdsh.node.node import Node
from usmd_rdsh.node.raft import Raft, operator_record
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import Reader, WireError

from tests.test_ncp02_transport import IDS, Cluster, until

USDN = "01JAB7R9F2W5H1N3S8D0Q4K6ME"
WEEK_MS = 7 * 24 * 3600 * 1000


def test_roles_add_up_and_every_node_is_an_executor():
    assert role_allows({Role.USD_OPERATOR}, Role.NODE_EXECUTOR)
    assert not role_allows({Role.USC_OPERATOR}, Role.USD_OPERATOR)  # no hierarchy
    assert role_allows({Role.USC_OPERATOR, Role.USD_OPERATOR}, Role.USD_OPERATOR)
    assert not role_allows({Role.NODE_EXECUTOR}, Role.NODE_OPERATOR)
    assert not role_allows(set(), Role.NODE_EXECUTOR)


def test_record_carries_the_elected_roles():
    key = SigningKey.generate()
    record = NodeRecord(IDS[0], "10.0.0.1", bytes(32), 0x2000, 1, voter=True,
                        operators=[Role.USC_OPERATOR, Role.NODE_OPERATOR]).sign(key)
    read = NodeRecord.read(Reader(record.encode()))
    read.verify(key.public)
    assert read.voter and sorted(read.operators) == [Role.USC_OPERATOR, Role.NODE_OPERATOR]
    raw = bytearray(record.encode())
    raw[26 + 4 + 32 + 2] |= 0x01  # a reserved flag
    with pytest.raises(WireError):
        NodeRecord.read(Reader(bytes(raw)))


def test_operators_are_replicated_snapshotted_and_persisted(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path, snapshot_page_bytes=400)
        try:
            leader = await cluster.form()
            lagging = cluster.nodes[IDS[2]]
            cluster.down.add(lagging.node_id)
            assert await leader.propose([
                operator_record(leader.term, Role.USC_OPERATOR, IDS[0], elected=True),
                operator_record(leader.term, Role.USD_OPERATOR, IDS[1], elected=True),
                operator_record(leader.term, Role.USD_OPERATOR, IDS[2], elected=True),
                operator_record(leader.term, Role.USD_OPERATOR, IDS[2], elected=False),
            ], timeout=3.0)
            leader.compact()
            cluster.down.clear()
            await until(lambda: lagging.snapshot_index == leader.snapshot_index)
            expected = {Role.USC_OPERATOR: {IDS[0]}, Role.USD_OPERATOR: {IDS[1]}}
            assert lagging.state.operators == expected
            reloaded = Raft(IDS[2], b"\x03" * 32, tmp_path / f"{IDS[2]}.json", None)
            assert reloaded.state.operators == expected
        finally:
            await cluster.stop()
    asyncio.run(scenario())


def _founder(tmp_path, roles) -> Node:
    node = Node(StateDirectory(tmp_path))
    node.authority.generate("usd")
    node.token = node.authority.mint_token(USDN, node.key, roles, validity_ms=WEEK_MS,
                                           founder=True)
    node.state = State.ACTIVE
    node.raft = Raft(node.node_id, node.key, tmp_path / "raft.json", None)
    node.raft.found()
    return node


def test_master_elects_then_deposes_the_operators(tmp_path):
    async def scenario():
        node = _founder(tmp_path, [Role.USC_OPERATOR, Role.USD_OPERATOR, Role.NODE_EXECUTOR])
        since: dict = {}
        while await node.elect_operators(since):
            node._sync_operators()
        assert node.roles == {Role.USC_OPERATOR, Role.USD_OPERATOR, Role.NODE_EXECUTOR}
        assert Role.NODE_OPERATOR not in node.operators  # nobody authorised for it
        node.token.roles = [Role.USD_OPERATOR]  # authorisation narrowed
        assert await node.elect_operators(since)
        node._sync_operators()
        assert node.roles == {Role.USD_OPERATOR, Role.NODE_EXECUTOR}
    asyncio.run(scenario())


def test_missing_usc_operator_is_reported(tmp_path):
    async def scenario():
        node = _founder(tmp_path, [Role.NODE_EXECUTOR])
        assert not await node.elect_operators({})
        assert node.roles == {Role.NODE_EXECUTOR}
        assert any("usc_operator" in e and "has none" in e for e in node.events)
    asyncio.run(scenario())
