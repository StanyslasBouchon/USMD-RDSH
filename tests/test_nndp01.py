"""NNDP-01: datagram format, reception checks, inactivity, nearest services."""

import pytest
import ulid

from usmd_rdsh.node import addresses
from usmd_rdsh.node.crypto import AgreementKey, SigningKey
from usmd_rdsh.node.nndp import (
    UNREACHABLE,
    HereIAm,
    NearestServices,
    NndpHooks,
    NndpService,
    VectorEntry,
    check_datagram,
)
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import WireError

NOW = 1_800_000_000_000


def _hia(key, **overrides):
    values = dict(
        node_id=ulid.new().str, next_emission=NOW + 15_000, state=State.ACTIVE,
        timestamp=NOW, x25519=AgreementKey.generate().public,
    )
    values.update(overrides)
    return HereIAm(**values).sign(key)


def test_empty_hia_is_187_bytes_and_full_is_1155():
    key = SigningKey.generate()
    assert len(_hia(key)) == 187
    full = _hia(key, hosted=[addresses.pack(1, i) for i in range(32)],
                vector=[VectorEntry(addresses.pack(2, i), 10, 1) for i in range(120)])
    assert len(full) == 1155


@pytest.mark.parametrize("mutate, reason", [
    (lambda d: (d, 1234), "source port"),
    (lambda d: (d[:-1] + bytes([d[-1] ^ 1]), 5221), "signature"),
    (lambda d: (d[:50], 5221), "size"),
])
def test_reception_checks(mutate, reason):
    data, port = mutate(_hia(SigningKey.generate()))
    with pytest.raises(WireError, match=reason):
        check_datagram(data, port, now=NOW)


def test_freshness_interval_and_excluded_state():
    key = SigningKey.generate()
    with pytest.raises(WireError, match="freshness"):
        check_datagram(_hia(key, timestamp=NOW - 31_000, next_emission=NOW), 5221, now=NOW)
    with pytest.raises(WireError, match="interval"):
        check_datagram(_hia(key, next_emission=NOW + 500), 5221, now=NOW)
    with pytest.raises(WireError):
        HereIAm(ulid.new().str, NOW + 15000, 0x4000, NOW, bytes(32)).sign(key)


def _service(hooks_overrides=None):
    calls = {"neighbor": [], "inactive": []}
    hooks = dict(
        state=lambda: State.ACTIVE, reference_addresses=lambda: [], hosted=lambda: [],
        is_admitted=lambda key: True, nit_accepts=lambda key, ip: True,
        my_services=lambda: {0x0A1}, rtt_ms=lambda key: None, ping_tolerance_ms=lambda: 1000,
        on_neighbor=lambda n, new: calls["neighbor"].append(n),
        on_inactive=lambda n: calls["inactive"].append(n), on_vector_change=lambda: None,
    )
    hooks.update(hooks_overrides or {})
    me = SigningKey.generate()
    return NndpService(lambda: ulid.new().str, me, bytes(32), NndpHooks(**hooks)), calls


def test_replay_ordering_nit_and_inactivity():
    service, calls = _service()
    peer = SigningKey.generate()
    first = _hia(peer)
    neighbor = service.accept(first, "10.0.0.2", 5221, now=NOW)
    assert neighbor.node_id and calls["neighbor"]
    with pytest.raises(WireError, match="replayed"):
        service.accept(first, "10.0.0.2", 5221, now=NOW)
    with pytest.raises(WireError, match="older"):
        service.accept(_hia(peer, timestamp=NOW - 1, next_emission=NOW + 14_999),
                       "10.0.0.2", 5221, now=NOW)
    assert service.check_inactivity(NOW + 29_000) == []
    lost = service.check_inactivity(NOW + 30_001)  # 2 x I
    assert lost and calls["inactive"]

    refusing, _ = _service({"nit_accepts": lambda key, ip: False})
    with pytest.raises(WireError, match="NIT"):
        refusing.accept(_hia(peer), "10.0.0.9", 5221, now=NOW)


def test_vector_distance_hops_poisoning_and_expiry():
    table = NearestServices(k=2)
    x, y = SigningKey.generate().public, SigningKey.generate().public
    a = addresses.pack(0x0A1, 0x5D68)
    other_area = addresses.pack(0x0B2, 1)
    common = dict(sender_interval_ms=15_000, ping_tolerance_ms=1000,
                  my_services={0x0A1}, my_addresses=set(), now=NOW)
    table.receive([VectorEntry(a, 300, 2), VectorEntry(other_area, 1, 0)],
                  sender=x, rtt_ms=500, **common)
    best = table.best(0x0A1)
    assert (best.distance, best.hops) == (800, 3)  # 300 + 1000 * 500 / 1000
    assert table.best(0x0B2) is None  # not in our areas
    # Poisoned reverse towards the node it was learnt from.
    assert table.vector(towards=x)[0].distance == UNREACHABLE
    assert table.vector()[0].distance == 800
    # Same sender: updated even when worse; unreachable removes it.
    table.receive([VectorEntry(a, 900, 2)], sender=x, rtt_ms=0, **common)
    assert table.best(0x0A1).distance == 900
    # A strictly better route from another node replaces it [6.5].
    table.receive([VectorEntry(a, 10, 14)], sender=y, rtt_ms=0, **common)  # 15 hops: ok
    assert table.best(0x0A1).learned_from == y
    table.receive([VectorEntry(a, 10, 15)], sender=y, rtt_ms=0, **common)  # 16 hops
    assert table.best(0x0A1) is None
    table.receive([VectorEntry(a, 300, 2)], sender=x, rtt_ms=0, **common)
    assert not table.expire(NOW + 44_999)  # 3 x I
    assert table.expire(NOW + 45_000) and table.best(0x0A1) is None


def test_local_instance_and_withdrawal():
    table = NearestServices()
    a = addresses.pack(0x0A1, 7)
    table.set_local(a, 420)
    assert table.vector() == [VectorEntry(a, 420, 0)]
    table.withdraw_local(a)
    for _ in range(3):
        assert table.vector() == [VectorEntry(a, UNREACHABLE, 0)]
        table.tick_withdrawals()
    assert table.vector() == []


def test_unadmitted_node_announces_empty_lists():
    service, _ = _service({"state": lambda: State.APPROVAL_REQUIRED,
                           "hosted": lambda: [addresses.pack(1, 1)]})
    service.services.set_local(addresses.pack(1, 1), 10)
    datagram = service.build(timestamp=NOW)[0]
    assert len(datagram) == 187


def test_annex_a_example_bytes():
    """[NNDP-01 annex A]: the signed frame, byte for byte."""
    from usmd_rdsh.node.wire import frame  # pylint: disable=import-outside-toplevel

    expected = (
        "d5c101000100000064001a"
        "303141525a334e44454b54535634525246465136394735464156"
        "000001a15de77f982000000001a15de74500"
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "000100a15d68000200a15d6801380000b20007021c01"
    )
    hia = HereIAm("01ARZ3NDEKTSV4RRFFQ69G5FAV", 0x1A15DE77F98, 0x2000, 0x1A15DE74500,
                  bytes(range(32)), [0x00A15D68],
                  [VectorEntry(0x00A15D68, 312, 0), VectorEntry(0x00B20007, 540, 1)])
    assert frame(1, hia.encode_payload()).hex() == expected
    datagram = hia.sign(SigningKey.generate())
    assert len(datagram) == 205
    assert check_datagram(datagram, 5221, now=0x1A15DE74500).hia == hia


@pytest.mark.parametrize("offset, value, reason", [
    (96, 0x00, "magic"), (98, 0x02, "version"), (99, 0x07, "event|signature"), (104, 0x01, "length"),
])
def test_bad_header_fields_are_refused(offset, value, reason):
    data = bytearray(_hia(SigningKey.generate()))
    data[offset] = value
    with pytest.raises(WireError, match=reason):
        check_datagram(bytes(data), 5221, now=NOW)


def test_more_than_120_entries_are_split_and_lists_bounded():
    service, _ = _service({"my_services": lambda: set(range(1, 301))})
    for s in range(1, 301):
        service.services.set_local(addresses.pack(s, 1), 10)
    datagrams = service.build(timestamp=NOW)
    assert len(datagrams) == 3 and all(len(d) <= 1200 for d in datagrams)
    with pytest.raises(WireError):
        HereIAm(ulid.new().str, NOW + 15000, State.ACTIVE, NOW, bytes(32),
                hosted=[1] * 33).sign(SigningKey.generate())


def test_withdrawal_keeps_one_entry_per_service_and_local_is_never_evicted():
    table = NearestServices()
    mine, other = addresses.pack(0x0A1, 1), addresses.pack(0x0A1, 2)
    table.set_local(mine, 100)
    table.set_local(other, 200)
    table.withdraw_local(mine)
    assert [e.address for e in table.vector()] == [other]

    small = NearestServices(k=1)
    small.set_local(mine, 500)
    small.receive([VectorEntry(other, 10, 0)], sender=b"x" * 32, sender_interval_ms=15000,
                  rtt_ms=0, ping_tolerance_ms=1000, my_services={0x0A1}, my_addresses=set(),
                  now=NOW)
    assert mine in small.local_addresses()


def test_inactivity_is_per_key_across_addresses():
    service, calls = _service()
    peer = SigningKey.generate()
    service.accept(_hia(peer), "10.0.0.2", 5221, now=NOW)
    service.accept(_hia(peer, timestamp=NOW + 20_000, next_emission=NOW + 35_000),
                   "10.0.0.3", 5221, now=NOW + 20_000)
    assert service.check_inactivity(NOW + 31_000) == []  # the key is alive elsewhere
    assert len(service.check_inactivity(NOW + 50_001)) == 1 and len(calls["inactive"]) == 1


def test_two_services_exchange_hia_end_to_end():
    a, _ = _service()
    b, calls = _service()
    datagram = a.build(timestamp=NOW)[0]
    b.handle_datagram(datagram, "10.0.0.1", 5221)
    assert b.received == 0 and b.rejected == 1  # stale against the real clock
    neighbor = b.accept(a.build(timestamp=NOW + 1)[0], "10.0.0.1", 5221, now=NOW + 1)
    assert neighbor is not None and calls["neighbor"]


def test_sp_address_text_form():
    assert addresses.to_text(0x00A15D68) == "0a1.5d68"
    assert addresses.from_text("0a1.5d68") == 0x00A15D68
    with pytest.raises(ValueError):
        addresses.unpack(0x10000000)
