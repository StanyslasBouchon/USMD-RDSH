"""Balance VIPs: one address for a whole service, owner elected by the master (extension)."""
# pylint: disable=protected-access

import asyncio

import pytest
from nan_runtime.state import StateDirectory

from usmd_rdsh.node import balance
from usmd_rdsh.node.balance import BalanceHost, Plan, System, ruleset
from usmd_rdsh.node.ncp.codec import (
    Area,
    CatalogEntry,
    LogRecord,
    MutationProperties,
    RecordType,
    Role,
    UsdProperties,
)
from usmd_rdsh.node.node import Node
from usmd_rdsh.node.raft import Raft, StateMachine, balance_record
from usmd_rdsh.node.services import Balance, ServiceFileError, parse_service_file
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import Reader

from tests.test_ncp02_transport import IDS, Cluster, until

USDN = "01JAB7R9F2W5H1N3S8D0Q4K6ME"
WEEK_MS = 7 * 24 * 3600 * 1000
PG_FILE = (b"name: pg\nexpose: {port: 5432}\n"
           b"balance: {vip: 192.168.1.50/24, port: 5432, vlan: 30}\n")
PLAN = Plan("pg", "192.168.1.50/24", "eth0", 0, 5432, "tcp",
            (("10.80.0.20", 5432), ("192.168.1.12", 60209)))


# -- the definition, in the service file -----------------------------------------------


def test_balance_is_read_from_the_service_file():
    (spec,) = parse_service_file(PG_FILE)
    assert spec.balance == Balance("192.168.1.50/24", 5432, 30, "snat")
    assert spec.balance.address == "192.168.1.50"
    (plain,) = parse_service_file("name: pg\nexpose: {port: 5432}\n"
                                  "balance: {vip: 192.168.1.50, port: 5432}\n")
    assert plain.balance == Balance("192.168.1.50/32", 5432, 0, "snat")
    for wrong, reason in (("{vip: 192.168.1.50, port: 0}", "1 to 65535"),
                          ("{vip: nowhere, port: 80}", "IPv4 address/prefix"),
                          ("{vip: 224.0.0.5, port: 80}", "cannot be held"),
                          ("{vip: 192.168.1.255/24, port: 80}", "cannot be held"),
                          ("{vip: 192.168.1.50, port: 80, vlan: 4095}", "VLAN id"),
                          ("{vip: 192.168.1.50, port: 80, mode: dr}", "not available yet"),
                          ("{vip: 192.168.1.50, port: 80, mode: nat}", "is snat"),
                          ("{address: 192.168.1.50}", "has vip")):
        with pytest.raises(ServiceFileError, match=reason):
            parse_service_file(f"name: x\nexpose: {{port: 80}}\nbalance: {wrong}\n")
    with pytest.raises(ServiceFileError, match="needs 'expose'"):
        parse_service_file("name: x\nbalance: {vip: 192.168.1.50, port: 80}\n")
    with pytest.raises(ServiceFileError, match="same VIP"):
        parse_service_file("name: a\nexpose: {port: 80}\nbalance: {vip: 10.1.1.1, port: 80}\n"
                           "---\nname: b\nexpose: {port: 81}\nbalance: {vip: 10.1.1.1/24, "
                           "port: 81}\n")


# -- the kernel side: nftables, the VIP, ARP ---------------------------------------------


def test_connections_are_spread_in_turn_with_address_substitution():
    text = ruleset([PLAN])
    assert text.startswith("table ip usmd_balance\ndelete table ip usmd_balance\n")
    rule = ("ip daddr 192.168.1.50 tcp dport 5432 dnat ip to numgen inc mod 2 map "
            "{ 0 : 10.80.0.20 . 5432, 1 : 192.168.1.12 . 60209 }")
    assert text.count(rule) == 2  # prerouting, and output for the owner itself
    assert "priority -101" in text  # before the exposure table
    assert "ct original ip daddr 192.168.1.50 masquerade" in text
    # No instance takes clients: no rule, the VIP refuses connections.
    empty = Plan("pg", "192.168.1.50/24", "eth0", 0, 5432, "tcp")
    assert ruleset([empty]) == ruleset([]) == \
        "table ip usmd_balance\ndelete table ip usmd_balance\n"


class FakeSystem:
    """What a BalanceHost does on the host, recorded."""

    def __init__(self):
        self.calls: list[str] = []
        self.knobs: dict[str, str] = {}
        self.fail: dict[str, str] = {}

    def run(self, argv, text):
        line = " ".join(argv)
        self.calls.append(line if text is None else f"{line} <{text}>")
        return next((error for prefix, error in self.fail.items() if line.startswith(prefix)), "")

    def arp(self, device, address):
        self.calls.append(f"arp {device} {address}")
        return ""

    def read(self, path):
        return self.knobs.get(path, "0")

    def write(self, path, value):
        self.knobs[path] = value

    def system(self) -> System:
        return System(self.run, self.arp, self.read, self.write)


def test_owner_takes_and_releases_the_vip_on_its_vlan():
    fake = FakeSystem()
    saved = []
    host = BalanceHost(system=fake.system(), on_change=saved.append)
    plan = Plan("pg", "192.168.1.50/24", "eth0", 30, 5432, "tcp", (("192.168.1.12", 60209),))
    host.update([plan])
    assert fake.calls[:4] == [
        "ip link add link eth0 name eth0.30 type vlan id 30", "ip link set eth0.30 up",
        "ip addr add 192.168.1.50/24 dev eth0.30", "arp eth0.30 192.168.1.50"]
    assert fake.calls[4].startswith("nft -f - <") and "60209" in fake.calls[4]
    assert fake.knobs["/proc/sys/net/ipv4/conf/eth0.30/forwarding"] == "1"
    assert host.error == "" and saved[-1] == [{"vip": "192.168.1.50/24", "interface": "eth0",
                                               "vlan": 30, "created_link": True}]
    fake.calls.clear()
    host.update([plan])
    assert not fake.calls  # nothing changed, nothing done
    host.update([])
    assert fake.calls[:2] == ["ip addr del 192.168.1.50/24 dev eth0.30", "ip link del eth0.30"]
    assert fake.calls[2] == f"nft -f - <{ruleset([])}>"
    assert saved[-1] == []


def test_an_existing_vlan_is_used_and_kept():
    fake = FakeSystem()
    fake.fail["ip link add"] = "RTNETLINK answers: File exists"
    host = BalanceHost(system=fake.system())
    plan = Plan("pg", "192.168.1.50/24", "eth0", 30, 5432, "tcp")
    host.update([plan])
    assert host.error == ""
    host.update([])
    assert "ip link del eth0.30" not in fake.calls  # the administrator's, not ours


def test_a_refused_vip_is_reported_and_retried():
    fake = FakeSystem()
    fake.fail["ip addr add"] = "RTNETLINK answers: Operation not permitted"
    host = BalanceHost(system=fake.system())
    host.update([PLAN])
    assert "not permitted" in host.error and not host.held()
    del fake.fail["ip addr add"]
    host.update([PLAN])
    assert host.error == "" and host.held()


def test_vips_left_by_a_previous_run_are_released_or_kept():
    fake = FakeSystem()
    host = BalanceHost(system=fake.system())
    host.adopt([{"vip": "192.168.1.50/24", "interface": "eth0", "vlan": 0},
                {"vip": "192.168.1.60/24", "interface": "eth0", "vlan": 0}, {"bad": 1}])
    host.update([PLAN])
    assert "ip addr del 192.168.1.60/24 dev eth0" in fake.calls
    assert not any(c.startswith("ip addr add") for c in fake.calls)  # .50 still held
    assert [h["vip"] for h in host.held()] == ["192.168.1.50/24"]


def test_forwarding_gets_its_value_back():
    fake = FakeSystem()
    host = BalanceHost(system=fake.system())
    knob = "/proc/sys/net/ipv4/conf/eth0/forwarding"
    local = Plan("pg", "192.168.1.50/24", "eth0", 0, 5432, "tcp", (("10.80.0.20", 5432),),
                 "10.80.0.20")
    host.update([local])  # its own instance only: nothing forwarded
    assert knob not in fake.knobs
    host.update([PLAN])
    assert fake.knobs[knob] == "1"
    host.update([])
    assert fake.knobs[knob] == "0"


def test_nothing_is_touched_when_nothing_is_held():
    fake = FakeSystem()
    BalanceHost(system=fake.system()).update([])
    assert not fake.calls


# -- Raft: the owner is replicated, snapshotted, persisted ------------------------------


def test_balance_records():
    state = StateMachine()
    for record in (balance_record(1, 0x0D1, IDS[0]), balance_record(1, 0x0D2, IDS[1]),
                   balance_record(2, 0x0D1, IDS[2]), balance_record(2, 0x0D2, None)):
        read = LogRecord.read(Reader(record.encode()))
        state.apply(read)
    assert state.balance == {0x0D1: IDS[2]}
    assert state.copy().balance == state.balance and state.copy().balance is not state.balance
    assert balance_record(1, 0x0D1, None).type == RecordType.BALANCE_RELEASE


def test_balance_owners_are_snapshotted_and_persisted(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path, snapshot_page_bytes=400)
        try:
            leader = await cluster.form()
            lagging = cluster.nodes[IDS[2]]
            cluster.down.add(lagging.node_id)
            assert await leader.propose([balance_record(leader.term, 0x0D1, IDS[1]),
                                         balance_record(leader.term, 0x0D2, IDS[0])], timeout=3.0)
            leader.compact()
            cluster.down.clear()
            await until(lambda: lagging.snapshot_index == leader.snapshot_index)
            assert lagging.state.balance == {0x0D1: IDS[1], 0x0D2: IDS[0]}
            reloaded = Raft(IDS[2], b"\x03" * 32, tmp_path / f"{IDS[2]}.json", None)
            assert reloaded.state.balance == {0x0D1: IDS[1], 0x0D2: IDS[0]}
        finally:
            await cluster.stop()
    asyncio.run(scenario())


def test_a_snapshot_without_owners_is_still_read(tmp_path):
    """Page 0 of an earlier version ends with the assignments."""
    leader = Raft(IDS[0], b"\x01" * 32, tmp_path / "a.json", None)
    leader.found()
    leader.applied = leader.commit_index
    leader.compact()
    (page,) = leader.snapshot_pages()
    follower = Raft(IDS[1], b"\x02" * 32, tmp_path / "b.json", None)
    follower.handle_snapshot(page, 0.0)
    assert follower.snapshot_index == leader.snapshot_index and follower.state.balance == {}


# -- the master elects, the owner holds -----------------------------------------------


def _master(tmp_path) -> tuple[Node, FakeSystem]:
    node = Node(StateDirectory(tmp_path))
    node.authority.generate("usc")
    node.authority.generate("usd")
    node.token = node.authority.mint_token(USDN, node.key, [Role.NODE_EXECUTOR],
                                           validity_ms=WEEK_MS, founder=True)
    node.state = State.ACTIVE
    node.raft = Raft(node.node_id, node.key, tmp_path / "raft.json", None)
    node.raft.found()
    node.signed.usd = UsdProperties(USDN, 1, bytes(32), [Area(1, "front", "10.80.0.0", 16)],
                                    [CatalogEntry(0x0D1, "pg", 1, "10.80.0.20", "0.0.0.0")], {})
    node.signed.mutations["db"] = MutationProperties("db", 1, 1000, 1, 3, PG_FILE).sign(
        node.authority.usc)
    node.mutation = "db"
    node.hosted = {0x0D1}
    node.settings.balance_interface = "eth0"
    fake = FakeSystem()
    node.balancer = BalanceHost(system=fake.system())
    return node, fake


def test_master_elects_the_owner_which_holds_the_vip(tmp_path):
    async def scenario():
        node, fake = _master(tmp_path)
        assert await node.elect_balance()
        node._sync_balance()
        assert node.balance_owners == {0x0D1: node.node_id}
        assert not await node.elect_balance()  # the owner stays while it serves
        assert node.balance_answer(0x0D1) == balance.TAKES_CLIENTS
        node.refresh_balance()
        (plan,) = node.balancer.plans
        assert (plan.device, plan.address, plan.backends) == \
            ("eth0.30", "192.168.1.50", (("10.80.0.20", 5432),))  # its own instance, directly
        assert "ip addr add 192.168.1.50/24 dev eth0.30" in fake.calls
        node.probes["pg"] = False  # a replica: healthy, takes no clients
        assert node.balance_answer(0x0D1) == balance.NO_CLIENTS
        node.refresh_balance()
        assert node.balancer.plans[0].backends == ()
        body = node.balance_body()
        reader = Reader(body)
        assert reader.u64() >= 1 and reader.ident() == node.node_id and reader.u16() == 1
        node.state = State.INACTIVE_EMERGENCY_HEALTH_CHECK  # no longer serves
        assert node.balance_answer(0x0D1) == balance.NOT_HOSTED
        assert await node.elect_balance()
        node._sync_balance()
        assert node.balance_owners == {}
        assert "ip addr del 192.168.1.50/24 dev eth0.30" in fake.calls
        assert any("released: no Active node runs it" in e for e in node.events)
    asyncio.run(scenario())


def test_show_service_balance(tmp_path):
    from usmd_rdsh.cli.actions.catalog import _balance_text, balance_rows  # pylint: disable=import-outside-toplevel
    from usmd_rdsh.cli.runtime import RUNTIME  # pylint: disable=import-outside-toplevel

    async def scenario():
        node, _ = _master(tmp_path)
        RUNTIME.node = node
        try:
            (row,) = balance_rows()
            assert row["owner"] == "none" and row["vip"] == "192.168.1.50/24 vlan 30"
            assert await node.elect_balance()
            node._sync_balance()
            node.refresh_balance()
            (row,) = balance_rows()
            assert row["owner"] == f"{node.node_id} (self)" and row["interface"] == "eth0.30"
            assert row["instances"] == "10.80.0.20:5432" and row["port"] == "5432/tcp"
            assert "SNAT" in _balance_text([row])
        finally:
            RUNTIME.node = None
    asyncio.run(scenario())


def test_an_owner_that_no_longer_runs_the_service_is_replaced(tmp_path):
    async def scenario():
        node, _ = _master(tmp_path)
        assert await node.raft.propose([balance_record(node.raft.term, 0x0D1, IDS[1])], 5)
        assert await node.elect_balance()  # IDS[1] is not Active here: this node instead
        node._sync_balance()
        assert node.balance_owners == {0x0D1: node.node_id}
        assert any(f"instead of {IDS[1]}" in e for e in node.events)
        assert node.balance_answer(0x0FF) == balance.NOT_HOSTED  # not catalogued
        node.signed.mutations["db"] = MutationProperties(  # balance withdrawn
            "db", 2, 1000, 1, 3, b"name: pg\nexpose: {port: 5432}\n").sign(node.authority.usc)
        assert await node.elect_balance()
        node._sync_balance()
        assert node.balance_owners == {}
        assert any("no longer declared" in e for e in node.events)
    asyncio.run(scenario())
