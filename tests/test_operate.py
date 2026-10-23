"""Elected operators managing the other nodes: Operate, NCP 0x0016 [ARCH-02 12.5]."""
# pylint: disable=protected-access

import asyncio
import json

import pytest
from nan_actions.ports import get_confirm_prompt, set_confirm_prompt
from nan_actions.views import ConfigDocument
from nan_runtime.log import reset_log_sink, set_log_sink
from nan_runtime.state import StateDirectory

from usmd_rdsh.cli import operate
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.shell import ShellFactory
from usmd_rdsh.cli.store import ConfigStore, TokenStore
from usmd_rdsh.node.authority import Authority
from usmd_rdsh.node.crypto import SigningKey, b64u
from usmd_rdsh.node.ncp.codec import (
    Area,
    Command,
    CreationToken,
    OperateRequest,
    Role,
    UscProperties,
    UsdProperties,
)
from usmd_rdsh.node.ncp.transport import NcpRemoteError, NcpTimeout
from usmd_rdsh.node.node import Node
from usmd_rdsh.node.wire import WireError, now_ms

DAY = 24 * 3600 * 1000
USCN = "01JAB7R3KX0Y2P8M4T6VQ9C1DZ"
USD1 = "01JAB7R9F2W5H1N3S8D0Q4K6ME"
USD2 = "01JAB7R9F2W5H1N3S8D0Q4K6MF"
PORT = 19994


# -- codec ----------------------------------------------------------------------


def test_operate_request_round_trip_and_reserved_flags():
    plain = OperateRequest(42, b'{"line": "show node"}')
    assert OperateRequest.decode(plain.encode()) == plain
    key = SigningKey.generate()
    usd = UsdProperties(USD2, 1, key.public, [Area(1, "a", "10.9.0.0", 16)], [], {}).sign(key)
    token = CreationToken(USD2, bytes(32), [Role.USC_OPERATOR], 1, 2, b"").sign(key)
    foreign = OperateRequest(7, b"{}", USD1, usd, token, bytes(range(32)))
    read = OperateRequest.decode(foreign.encode())
    assert (read.target, read.usd.usdn, read.token.roles, read.x25519) == \
        (USD1, USD2, [Role.USC_OPERATOR], bytes(range(32)))
    raw = bytearray(plain.encode())
    raw[0] |= 0x01
    with pytest.raises(WireError):
        OperateRequest.decode(bytes(raw))


# -- selectors and the console session, without a network ---------------------------


def test_targets_parse_and_match():
    selectors, line = operate.parse_targets('all state active show "a b"')
    assert selectors == [("all", ""), ("state", "active")] and line == 'show "a b"'
    with pytest.raises(operate.OperateError):
        operate.parse_targets("mutation")
    t = operate.Target("01JAB7R9F2W5H1N3S8D0Q4K6M0", "10.0.0.7", "inactive-emergency-update",
                       "web", ["front"], ["usd-operator"], USD1)
    assert operate._matches(t, "node", "10.0.0.7") and operate._matches(t, "node", "01jab7r9")
    assert operate._matches(t, "state", "inactive") and not operate._matches(t, "state", "active")
    assert operate._matches(t, "area", "front") and operate._matches(t, "role", "usd_operator")
    assert operate._matches(t, "usd", USD1.lower()) and not operate._matches(t, "mutation", "db")


class _FakeFleet:
    """Two nodes; the second asks for a confirmation before 'write erase'."""

    def __init__(self):
        self.sent = []

    async def send(self, target, session, request):
        self.sent.append((target.node_id, request))
        if target.node_id == "B" and request.get("line") == "write erase" \
                and not request.get("confirm"):
            return {"output": ["Erase?", "Not confirmed: nothing was done."],
                    "prompt": "b#", "needs_confirm": True}
        if target.node_id == "C":
            return {"error": "no answer"}
        return {"output": [f"{target.node_id} did {request.get('line')}"],
                "prompt": f"{target.node_id.lower()}(config-x)#", "exit": False}


class _Yes:
    def __init__(self):
        self.asked = []

    async def ask(self, message):
        self.asked.append(message)
        return True


def test_group_line_asks_once_and_reports_each_node():
    fleet = _FakeFleet()
    remote = operate.Remote([operate.Target("A"), operate.Target("B"), operate.Target("C")],
                            fleet)
    yes, previous = _Yes(), get_confirm_prompt()
    lines = []
    set_confirm_prompt(yes)
    sink = set_log_sink(lines.append)
    try:
        left = asyncio.run(remote.run("write erase"))
    finally:
        reset_log_sink(sink)
        set_confirm_prompt(previous)
    assert not left
    assert yes.asked == ["Erase? [1 node(s): B]"]
    assert ("B", {"line": "write erase", "confirm": True}) in fleet.sent
    assert ("A", {"line": "write erase", "confirm": True}) not in fleet.sent
    text = "\n".join(lines)
    assert "A did write erase" in text and "B did write erase" in text
    assert "C: no answer" in text and "2/3 node(s) answered" in text
    assert remote.prompt("op") == "op>[3 nodes](config-x)#"


class _RemoteConsole:
    """A remote node completing its own commands."""

    async def send(self, target, session, request):
        typed = request.get("complete", "")
        return {"candidates": [{"value": w, "display": w, "description": "", "start": "0"}
                               for w in ("show", "exit") if w.startswith(typed)]}


def test_disconnect_is_offered_inside_a_remote_console():
    remote = operate.Remote([operate.Target("A")], _RemoteConsole())
    shell = type("Shell", (), {"remote": remote})()
    values = lambda text: [c["value"] for c in asyncio.run(remote.completions(text))]  # noqa: E731
    assert values("") == ["show", "exit", "disconnect"]
    assert values("dis") == ["disconnect"] and values("show ") == []
    lines = []
    sink = set_log_sink(lines.append)
    try:
        asyncio.run(operate.remote_line(shell, "?"))
        asyncio.run(operate.remote_line(shell, "dis?"))
    finally:
        reset_log_sink(sink)
    assert sum("disconnect" in line for line in lines) == 2
    assert any(line.strip().startswith("show") for line in lines)
    assert shell.remote is remote  # '?' leaves nobody


@pytest.fixture(name="factory")
def _factory(tmp_path, monkeypatch):
    monkeypatch.setenv("USMD_STATE_DIR", str(tmp_path))
    RUNTIME.config_store = ConfigStore()
    RUNTIME.tokens = TokenStore()
    RUNTIME.document = ConfigDocument()
    RUNTIME.node = None
    RUNTIME.web = None
    return ShellFactory()


def test_lent_console_writes_but_never_manages(factory):
    server = operate.OperateServer(factory)

    async def go():
        ask = lambda line, confirm=False: server.handle(  # noqa: E731
            "01JAB7R9F2W5H1N3S8D0Q4K6M0", b"k", 9,
            json.dumps({"line": line, "confirm": confirm}).encode())
        await ask("config system global")
        await ask("set hostname far")
        done = json.loads(await ask("end"))
        mint = json.loads(await ask("execute api-token create name=x profile=admin"))
        nested = json.loads(await ask("on all show node"))
        closed = json.loads(await server.handle("x", b"k", 9, b'{"close": true}'))
        return done, mint, nested, closed

    done, mint, nested, closed = asyncio.run(go())
    assert done["prompt"] == "far#" and RUNTIME.hostname() == "far"
    assert mint["output"] == ["Permission denied.  Missing: api:manage"]
    assert any("does not reach further" in line for line in nested["output"])
    assert closed == {"closed": True} and server.sessions == 0


def test_node_and_on_are_completed_for_an_elected_operator(factory, tmp_path):
    shell = factory.console()
    values = lambda text: [c["value"] for c in shell.completions(text)]  # noqa: E731
    assert "node" not in values("")  # no node running: nothing to manage
    node = Node(StateDirectory(tmp_path / "op"))
    node.settings.address = "10.0.0.1"
    RUNTIME.node = node
    assert "node" not in values("")  # running, not elected
    node.operators = {int(Role.USD_OPERATOR): {node.node_id}}
    assert {"node", "on"} <= set(values("")) and values("no") == ["node"]
    assert values("node 10") == ["10.0.0.1"] and node.node_id in values("node ")
    assert values("node x ") == []
    assert values("on ") == list(operate.SELECTOR_HELP)
    assert "show" in values("on all ") and values("on all sh") == ["show"]
    assert "usd" in values("on all show us")  # the line itself: the console's completion
    assert values("on role usd") == ["usd-operator"] and "active" in values("on state ")
    lines = []
    sink = set_log_sink(lines.append)
    try:
        asyncio.run(shell.execute_line("on all ?"))
        asyncio.run(shell.execute_line("node ?"))
    finally:
        reset_log_sink(sink)
        RUNTIME.node = None
    assert any(line.strip().startswith("state") for line in lines)  # answered here
    assert "  <cr>" in lines and any("10.0.0.1" in line for line in lines)
    assert operate._reason(NcpRemoteError(0x0003, "unknown command")).startswith(
        "this node does not know Operate")


# -- two USDs of one USC, on loopback addresses ---------------------------------------


def _node(tmp_path, name, address, usc_key, usd_key):
    node = Node(StateDirectory(tmp_path / name))
    s = node.settings
    s.address = s.bind_address = address
    s.ncp_port = PORT
    s.nndp_enabled = False
    s.usc_anchor, s.usd_anchor = b64u(usc_key), b64u(usd_key)
    s.ncp_retransmit = 0.5
    s.relay_delay = 0.05
    s.raft_election = (0.5, 1.0)
    s.raft_heartbeat = 0.1
    return node


async def _until(predicate, timeout=10.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return False


def _echo(name):
    async def handler(origin, sender, session, payload):
        return json.dumps({"node": name, "origin": origin, "session": session,
                           "request": json.loads(payload)}).encode()
    return handler


async def _elect(node):
    while await node.elect_operators({}):
        node._sync_operators()


async def _admit(node, endorser):
    assert await node.request_approval(endorser.key, endorser.settings.address,
                                       endorser.identity.x25519_public)
    assert await _until(lambda: node.signed.usd is not None
                        and len(node.tables.nodes.entries) >= 2)
    await node.finish_synchronisation()


def test_operators_manage_their_usd_and_the_other_usds(tmp_path):
    asyncio.run(_two_usds(tmp_path))


async def _two_usds(tmp_path):  # pylint: disable=too-many-locals,too-many-statements
    auth1 = Authority(StateDirectory(tmp_path / "auth1"))
    auth1.generate("usc")
    auth1.generate("usd")
    auth2 = Authority(StateDirectory(tmp_path / "auth2"))
    auth2.generate("usd")
    version = now_ms()
    usc = UscProperties(USCN, version, auth1.usc.public, [USD1, USD2]).sign(auth1.usc)
    usd1 = UsdProperties(USD1, version, auth1.usd.public, [Area(1, "front", "10.9.0.0", 16)],
                         [], {}).sign(auth1.usc)
    usd2 = UsdProperties(USD2, version, auth2.usd.public, [Area(1, "back", "10.8.0.0", 16)],
                         [], {}).sign(auth1.usc)
    operators = [Role.USC_OPERATOR, Role.USD_OPERATOR, Role.NODE_EXECUTOR]

    # USD 1: A founds it (usc + usd operator), B is an executor.
    a = _node(tmp_path, "a", "127.0.0.12", auth1.usc.public, auth1.usd.public)
    a.token = auth1.mint_token(USD1, a.key, operators, validity_ms=DAY, founder=True)
    b = _node(tmp_path, "b", "127.0.0.13", auth1.usc.public, auth1.usd.public)
    b.token = auth1.mint_token(USD1, b.key, [Role.NODE_EXECUTOR], validity_ms=DAY)
    # USD 2: C founds it (usc operator), D is an executor.
    c = _node(tmp_path, "c", "127.0.0.14", auth1.usc.public, auth2.usd.public)
    c.token = auth2.mint_token(USD2, c.key, operators, validity_ms=DAY, founder=True)
    d = _node(tmp_path, "d", "127.0.0.15", auth1.usc.public, auth2.usd.public)
    d.token = auth2.mint_token(USD2, d.key, [Role.NODE_EXECUTOR], validity_ms=DAY)
    nodes = (a, b, c, d)
    for node, name in zip(nodes, "abcd"):
        node.operate_handler = _echo(name)
        await node.start()
    try:
        await a.found()
        await c.found()
        assert a.inject(usc=usc, usd=usd1) and c.inject(usc=usc, usd=usd2)
        await _admit(b, a)
        await _admit(d, c)
        await _elect(a)
        await _elect(c)
        assert a.operator_scope() == "usc" and c.operator_scope() == "usc"
        b.set_operators(a.operators, a.operators_term)
        d.set_operators(c.operators, c.operators_term)
        assert b.operator_scope() == ""

        # Within the USD: an elected operator gets the node's console...
        answer = json.loads(await a.operate(b.node_id, 5, b'{"line": "show node"}'))
        assert answer == {"node": "b", "origin": a.node_id, "session": 5,
                          "request": {"line": "show node"}}
        # ... an executor does not, neither by the method nor by the wire.
        with pytest.raises(ValueError):
            await b.operate(a.node_id, 5, b"{}")
        with pytest.raises(NcpRemoteError) as refused:
            await b.call(a.node_id, Command.OPERATE, OperateRequest(5, b"{}").encode())
        assert refused.value.code == 0x0001

        # Another USD: through its contact node D, redirected to its elected
        # usc-operator C, which relays to D.
        a.usc_peers[USD2] = ("127.0.0.15", d.key, d.identity.x25519_public)
        answer = json.loads(await a.operate_foreign(USD2, 6, b'{"line": "show node"}',
                                                   target=d.node_id))
        assert answer["node"] == "d" and answer["origin"] == c.node_id
        assert USD1 in answer["request"]["via"]
        assert a._usc_relays[USD2][1] == c.key
        served = json.loads(await a.operate_foreign(USD2, 6, b'{"line": ""}'))
        assert served["node"] == "c" and USD1 in served["origin"]

        # A node that is not a usc-operator of its USD presents no valid credentials:
        # it is not answered at all.
        forged = OperateRequest(1, b"{}", "", usd1, b.token, b.identity.x25519_public)
        with pytest.raises(NcpTimeout):
            await b.call(c.key, Command.OPERATE, forged.encode(), address="127.0.0.14",
                         x25519=c.identity.x25519_public, attempts=1)
        # A usd-operator stays in its USD.
        b.set_operators({**a.operators, int(Role.USD_OPERATOR): {b.node_id}},
                        a.operators_term + 1)
        assert b.operator_scope() == "usd"
        with pytest.raises(ValueError, match="usc-operator"):
            await b.operate_foreign(USD2, 1, b"{}")
    finally:
        for node in nodes:
            await node.stop()
