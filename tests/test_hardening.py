"""Behaviours added while closing the acceptance checklist, each on its own."""

import ipaddress

import pytest
from nan_runtime.state import StateDirectory

from usmd_rdsh.node import addresses
from usmd_rdsh.node.crypto import SigningKey
from usmd_rdsh.node.ncp.codec import Area, CatalogEntry, UsdProperties
from usmd_rdsh.node.nndp import MAX_PER_SENDER, NearestServices, VectorEntry
from usmd_rdsh.node.node import Node, parse_edb
from usmd_rdsh.node.states import State, transition_allowed
from usmd_rdsh.node.wire import WireError

USDN = "01JAB7R9F2W5H1N3S8D0Q4K6ME"


def _usd(catalog):
    return UsdProperties(USDN, 1, bytes(32), [Area(1, "front", "10.80.0.0", 16)], catalog, {})


def test_catalogue_refuses_duplicate_vip_or_group():
    _usd([CatalogEntry(1, "a", 1, "10.80.0.1", "239.1.1.1")]).validate()
    with pytest.raises(WireError):
        _usd([CatalogEntry(1, "a", 1, "10.80.0.1", "0.0.0.0"),
              CatalogEntry(2, "b", 1, "10.80.0.1", "0.0.0.0")]).validate()
    with pytest.raises(WireError):
        _usd([CatalogEntry(1, "a", 1, "10.80.0.1", "239.1.1.1"),
              CatalogEntry(2, "b", 1, "10.80.0.2", "239.1.1.1")]).validate()


def test_state_transitions():
    assert transition_allowed(State.APPROVAL_REQUIRED, State.SYNCHRONISING)
    assert not transition_allowed(State.APPROVAL_REQUIRED, State.ACTIVE)
    assert transition_allowed(State.ACTIVE, State.INACTIVE_EMERGENCY_RESOURCES)
    assert not transition_allowed(State.ACTIVE, State.INACTIVE_TIMEOUT)  # origin O
    assert not transition_allowed(State.ACTIVE, State.EXCLUDED_NIT_ASSOCIATION)
    assert transition_allowed(State.INACTIVE, State.APPROVAL_REQUIRED)


def test_set_state_refuses_illegal_transition(tmp_path):
    node = Node(StateDirectory(tmp_path))
    with pytest.raises(ValueError):
        node.set_state(State.ACTIVE)
    node.set_state(State.SYNCHRONISING)
    assert node.state == State.SYNCHRONISING


def test_prefix_conflict_with_node_addresses(tmp_path):
    node = Node(StateDirectory(tmp_path))
    node.settings.address = "10.80.3.4"
    assert "node address" in node.prefix_conflict(ipaddress.IPv4Network("10.80.0.0/16"))


def test_edb_lines_are_validated():
    text = ("# EDB\n01JAB7R3KX0Y2P8M4T6VQ9C1DZ: 172.23.45.96\nnot a line\n"
            "01JAB7R9F2W5H1N3S8D0Q4K6ME: 999.1.1.1\n")
    assert parse_edb(text) == ["172.23.45.96"]


def test_one_sender_cannot_fill_the_table():
    table = NearestServices(k=MAX_PER_SENDER * 2)
    sender = SigningKey.generate().public
    vector = [VectorEntry(addresses.pack(s, 1), 10, 0) for s in range(1, MAX_PER_SENDER + 50)]
    table.receive(vector, sender=sender, sender_interval_ms=15000, rtt_ms=0,
                  ping_tolerance_ms=1000, my_services=set(range(1, 4096)), my_addresses=set(),
                  now=0)
    assert table._count_from(sender) == MAX_PER_SENDER  # pylint: disable=protected-access


def test_unique_session_indexes_and_broadcast_limit():
    from usmd_rdsh.node.sp.engine import SpEngine  # pylint: disable=import-outside-toplevel
    from usmd_rdsh.node.crypto import AgreementKey  # pylint: disable=import-outside-toplevel

    engine = SpEngine(None, SigningKey.generate(), AgreementKey.generate(),  # type: ignore[arg-type]
                      send_udp=lambda *a: None, write_tun=lambda p: None, port=9993,
                      broadcast_rate=2)
    indexes = {engine._free_index() for _ in range(200)}  # pylint: disable=protected-access
    assert len(indexes) == 200
    assert engine.broadcast_rate == 2


def test_rekey_returns_to_admission(tmp_path):
    import asyncio  # pylint: disable=import-outside-toplevel

    node = Node(StateDirectory(tmp_path))
    old = node.key
    asyncio.run(node.rekey())
    assert node.key != old and node.state == State.APPROVAL_REQUIRED
    assert Node(StateDirectory(tmp_path)).key == node.key  # persisted
