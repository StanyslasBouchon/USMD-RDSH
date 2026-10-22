"""Several nodes on loopback addresses: founding, admission, sync, master."""

import asyncio
import sys

import pytest
from nan_runtime.state import StateDirectory

from usmd_rdsh.node.authority import Authority
from usmd_rdsh.node.crypto import b64u
from usmd_rdsh.node.ncp.codec import (
    Area,
    CatalogEntry,
    Command,
    MutationProperties,
    Role,
    UscProperties,
    UsdProperties,
)
from usmd_rdsh.node.node import Node
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import now_ms

DAY = 24 * 3600 * 1000
OK = "'\"" + sys.executable + "\" -c pass'"
SERVICE_FILE = f"""
name: web
type: static
build:
  - command: {OK}
unbuild:
  - command: {OK}
emergency:
  - action: unbuild
check_health:
  - command: {OK}
    timeout: 5
""".encode()


def _node(tmp_path, name, address, authority):
    state = StateDirectory(tmp_path / name)
    node = Node(state)
    s = node.settings
    s.address = s.bind_address = address
    s.ncp_port = 19992
    s.nndp_enabled = False
    s.usc_anchor = b64u(authority.usc.public)
    s.usd_anchor = b64u(authority.usd.public)
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


def _properties(authority, usd_key):
    version = now_ms()
    usc = UscProperties("01JAB7R3KX0Y2P8M4T6VQ9C1DZ", version, authority.usc.public,
                        ["01JAB7R9F2W5H1N3S8D0Q4K6ME"]).sign(authority.usc)
    usd = UsdProperties("01JAB7R9F2W5H1N3S8D0Q4K6ME", version, usd_key,
                        [Area(1, "front", "192.168.1.0", 24)],
                        [CatalogEntry(0x0A1, "web", 1, "192.168.1.10", "0.0.0.0")],
                        {0x0001: 5, 0x0002: 1000}).sign(authority.usc)
    mutation = MutationProperties("frontal", version, 1000, 1, 3, SERVICE_FILE).sign(authority.usc)
    return usc, usd, mutation


def test_founder_admission_sync_and_master(tmp_path):
    asyncio.run(_scenario(tmp_path))


async def _scenario(tmp_path):
    authority = Authority(StateDirectory(tmp_path / "operator"))
    authority.generate("usc")
    authority.generate("usd")
    usdn = "01JAB7R9F2W5H1N3S8D0Q4K6ME"

    a = _node(tmp_path, "a", "127.0.0.2", authority)
    a.token = authority.mint_token(usdn, a.key, [Role.NODE_EXECUTOR], validity_ms=DAY,
                                   founder=True)
    await a.start()
    await a.found()
    assert a.state == State.ACTIVE and a.raft.is_leader
    usc, usd, mutation = _properties(authority, authority.usd.public)
    assert a.inject(usc=usc, usd=usd, mutations=[mutation])

    b = _node(tmp_path, "b", "127.0.0.3", authority)
    b.token = authority.mint_token(usdn, b.key, [Role.NODE_EXECUTOR], validity_ms=DAY)
    b.settings.contact_node = "127.0.0.2"
    b.settings.contact_ed25519 = b64u(a.key)
    b.settings.contact_x25519 = b64u(a.identity.x25519_public)
    await b.start()
    try:
        assert await b.request_approval(a.key, "127.0.0.2", a.identity.x25519_public)
        assert b.state == State.SYNCHRONISING
        # The endorser pushes the table and the signed properties [NCP 7.2].
        assert await _until(lambda: b.signed.usd is not None and len(b.tables.nodes.entries) >= 2)
        assert b.signed.mutations["frontal"].version == mutation.version
        await b.finish_synchronisation()
        assert b.state == State.ACTIVE and a.node_id in b.references
        # B's Active record reaches A through B's relay.
        assert await _until(lambda: a.tables.nodes.get(b.key) is not None
                            and a.tables.nodes.get(b.key).record.state == State.ACTIVE)
        assert any(p.node_key == b.key for p in a.tables.nel)

        status = await b.call(a.node_id, Command.GET_STATUS)
        assert status[-2:] == int(State.ACTIVE).to_bytes(2, "big")

        # Transmutation: management id from the master, build, health, Active.
        assert await b.transmute("frontal", reason="test")
        assert b.management.get(0x0A1) == 1 and 0x0A1 in b.hosted
        assert a.raft.state.management_of(b.node_id, 0x0A1) == 1

        # A stale or unsigned USD properties object is refused.
        stale = UsdProperties(usd.usdn, usd.version, usd.public_key, usd.areas, usd.catalog,
                              usd.parameters).sign(authority.usd)
        from usmd_rdsh.node.ncp.transport import NcpRemoteError  # pylint: disable=import-outside-toplevel
        with pytest.raises(NcpRemoteError) as refused:
            await b.call(a.node_id, Command.SEND_USD_PROPERTIES, stale.encode())
        assert refused.value.code in (0x0001, 0x0006)
    finally:
        await b.stop()
        await a.stop()
