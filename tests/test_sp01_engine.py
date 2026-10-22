"""SP-01 engine: two nodes wired in memory, SAT, sessions, broadcast, ICMP."""

import ipaddress

import pytest

from usmd_rdsh.node import addresses
from usmd_rdsh.node.crypto import AgreementKey, SigningKey
from usmd_rdsh.node.sp import packets
from usmd_rdsh.node.sp.engine import CatalogService, Peer, SpEngine

PORT = 9993
CATALOG = {
    0x0A1: CatalogService(0x0A1, "front", "192.168.1.10", "239.1.1.1"),
    0x0B2: CatalogService(0x0B2, "front", "192.168.1.20", None),
    0x0C3: CatalogService(0x0C3, "back", "192.168.2.30", None),
}


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class Ctx:  # pylint: disable=too-many-instance-attributes
    def __init__(self, ed, x, ip, hosted, mgmt):
        self.ed, self.x, self.ip = ed, x, ip
        self.hosted, self.mgmt = hosted, mgmt
        self.others = []

    def catalog(self):
        return CATALOG

    def area_networks(self):
        return {"front": ipaddress.IPv4Network("192.168.1.0/24")}

    def management_id(self, service_id):
        return self.mgmt.get(service_id)

    def hosted_services(self):
        return self.hosted

    def all(self):
        return [self, *self.others]

    def owner(self, address):
        for ctx in self.all():
            service, management = addresses.unpack(address)
            if ctx.mgmt.get(service) == management:
                return ctx.ed.public
        return None

    def peer(self, key):
        for ctx in self.all():
            if ctx.ed.public == key:
                return Peer(key, ctx.x.public, ctx.ip, True, None, frozenset(ctx.hosted))
        return None

    def peers(self):
        return [self.peer(c.ed.public) for c in self.others]

    def nearest(self, service_id):
        return [(addresses.pack(service_id, c.mgmt[service_id]), 100)
                for c in self.others if service_id in c.hosted]

    def initiator_allowed(self, key, address):
        return any(c.ed.public == key and c.ip == address for c in self.all())

    def address_known(self, address):
        return any(c.ip == address for c in self.all())


def _pair():
    clock, wire, tun = Clock(), [], {"a": [], "b": []}
    a_keys, b_keys = (SigningKey.generate(), AgreementKey.generate()), \
        (SigningKey.generate(), AgreementKey.generate())
    a_ctx = Ctx(*a_keys, "10.0.0.1", {0x0A1}, {0x0A1: 1})
    b_ctx = Ctx(*b_keys, "10.0.0.2", {0x0B2, 0x0A1}, {0x0B2: 2, 0x0A1: 2})
    a_ctx.others, b_ctx.others = [b_ctx], [a_ctx]
    engines = {}

    def sender(src_ip):
        return lambda data, ip, tos: wire.append((src_ip, ip, data))

    engines["a"] = SpEngine(a_ctx, *a_keys, send_udp=sender("10.0.0.1"),
                            write_tun=tun["a"].append, port=PORT, clock=clock)
    engines["b"] = SpEngine(b_ctx, *b_keys, send_udp=sender("10.0.0.2"),
                            write_tun=tun["b"].append, port=PORT, clock=clock)
    by_ip = {"10.0.0.1": engines["a"], "10.0.0.2": engines["b"]}

    def pump():
        while wire:
            src, dst, data = wire.pop(0)
            by_ip[dst].from_udp(data, src, PORT)

    return engines, tun, pump, clock


def _udp(src, dst, payload=b"hello"):
    return packets.build(src, dst, packets.PROTO_UDP,
                         bytes.fromhex("13881389") + (8 + len(payload)).to_bytes(2, "big")
                         + b"\x00\x00" + payload)


def test_unicast_through_a_handshake_and_reply_affinity():
    engines, tun, pump, _ = _pair()
    engines["a"].from_tun(_udp("192.168.1.10", "192.168.1.20"))
    pump()
    assert len(tun["b"]) == 1 and packets.parse(tun["b"][0]).destination == "192.168.1.20"
    # Reply goes back to the exact instance that sent the request.
    reply = _udp("192.168.1.20", "192.168.1.10", b"world")
    reply = packets.build("192.168.1.20", "192.168.1.10", packets.PROTO_UDP,
                          bytes.fromhex("13891388") + (13).to_bytes(2, "big") + b"\x00\x00world")
    engines["b"].from_tun(reply)
    pump()
    assert packets.parse(tun["a"][0]).payload.endswith(b"world")


def test_area_isolation_and_unknown_destination_are_dropped():
    engines, tun, pump, _ = _pair()
    engines["a"].from_tun(_udp("192.168.1.10", "192.168.2.30"))  # other area
    engines["a"].from_tun(_udp("192.168.1.99", "192.168.1.20"))  # not a local VIP
    pump()
    assert tun["b"] == [] and engines["a"].stats["dropped"] == 2


def test_no_instance_answers_icmp_host_unreachable():
    engines, tun, pump, _ = _pair()
    engines["b"].context.hosted = set()  # nobody hosts 0x0B2 any more
    engines["a"].from_tun(_udp("192.168.1.10", "192.168.1.20"))
    pump()
    icmp = packets.parse(tun["a"][0])
    assert icmp.protocol == packets.PROTO_ICMP and icmp.payload[:2] == bytes([3, 1])


def test_df_packet_above_mtu_gets_frag_needed():
    engines, tun, _, _ = _pair()
    big = packets.build("192.168.1.10", "192.168.1.20", packets.PROTO_UDP, bytes(1500),
                        flags_fragment=0x4000)
    engines["a"].from_tun(big)
    icmp = packets.parse(tun["a"][0])
    assert icmp.payload[:2] == bytes([3, 4])
    assert int.from_bytes(icmp.payload[6:8], "big") == 1412


def test_broadcast_reaches_mutation_members_once():
    engines, tun, pump, _ = _pair()
    datagram = _udp("192.168.1.10", "239.1.1.1")
    engines["a"].from_tun(datagram)
    pump()
    assert len(tun["b"]) == 1


def test_keepalives_do_not_answer_keepalives():
    engines, _, pump, clock = _pair()
    engines["a"].from_tun(_udp("192.168.1.10", "192.168.1.20"))
    pump()
    sent = engines["a"].stats["tx_frames"] + engines["b"].stats["tx_frames"]
    for t in range(1, 60):
        clock.t = float(t)
        engines["a"].tick()
        engines["b"].tick()
        pump()
    after = engines["a"].stats["tx_frames"] + engines["b"].stats["tx_frames"]
    assert after == sent  # an idle session stays quiet


def test_duplicate_broadcast_is_written_once():
    engines, tun, pump, _ = _pair()
    datagram = _udp("192.168.1.10", "239.1.1.1")
    engines["a"].from_tun(datagram)
    wire_copy = []
    original = engines["a"]._send_udp  # pylint: disable=protected-access
    engines["a"]._send_udp = lambda d, ip, tos: (wire_copy.append((d, ip)), original(d, ip, tos))  # pylint: disable=protected-access
    pump()
    engines["a"].from_tun(datagram)
    pump()
    assert len(tun["b"]) == 2  # two broadcasts, two ids
    for data, _ip in wire_copy:  # a replayed frame is refused by the window/cache
        engines["b"].from_udp(data, "10.0.0.1", PORT)
    assert len(tun["b"]) == 2


def test_abandoned_handshake_makes_peer_ineligible():
    engines, _, _, clock = _pair()
    engines["a"].from_tun(_udp("192.168.1.10", "192.168.1.20"))  # never pumped
    for t in (2.1, 6.2, 10.3):
        clock.t = t
        engines["a"].tick()
    assert engines["a"].stats["handshakes"] == 3
    assert engines["a"].select(0x0B2) is None


@pytest.mark.parametrize("inner_ecn, outer, expected", [
    (packets.ECT0, packets.CE, packets.CE), (packets.NOT_ECT, packets.CE, None),
    (packets.ECT1, packets.NOT_ECT, packets.ECT1),
])
def test_ecn_decapsulation(inner_ecn, outer, expected):
    raw = packets.build("1.1.1.1", "2.2.2.2", 17, bytes(8), tos=inner_ecn)
    out = packets.decapsulate_ecn(raw, outer)
    assert (out is None) if expected is None else packets.parse(out).ecn == expected


def test_fragmentation_respects_mtu_and_offsets():
    packet = packets.parse(packets.build("1.1.1.1", "2.2.2.2", 17, bytes(3000)))
    pieces = [packets.parse(p) for p in packets.fragment(packet, 1412)]
    assert all(p.total_length <= 1412 for p in pieces)
    assert sum(len(p.payload) for p in pieces) == 3000
    assert not pieces[-1].more_fragments and pieces[0].more_fragments
