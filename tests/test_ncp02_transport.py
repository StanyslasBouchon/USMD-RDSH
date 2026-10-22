"""NCP-02 transport over loopback UDP [5.2-5.7, 8, 10] and Raft in memory [6.15-6.18]."""
# pylint: disable=protected-access

import asyncio

import pytest

from usmd_rdsh.node.crypto import AgreementKey, SigningKey
from usmd_rdsh.node.ncp import transport as transport_module
from usmd_rdsh.node.ncp.codec import Message, MessageType, RecordType
from usmd_rdsh.node.ncp.transport import NcpTimeout, NcpTransport, RateLimiter, seal_message
from usmd_rdsh.node.raft import Assignment, Raft, assign_record, voter_record
from usmd_rdsh.node.wire import Reader, WireError, Writer, now_ms


# ---------------------------------------------------------------------------
# Wire
# ---------------------------------------------------------------------------


def test_permille_bounds():
    assert Reader(Writer().u16(1000).bytes()).permille() == 1000
    assert Reader(Writer().u16(0).bytes()).permille() == 0
    with pytest.raises(WireError):
        Reader(Writer().u16(1001).bytes()).permille()


def test_rate_limiter_window_and_bound():
    limiter = RateLimiter(2, max_sources=2)
    assert limiter.allow("a", 0.0) and limiter.allow("a", 0.1)
    assert not limiter.allow("a", 0.2)
    assert limiter.allow("a", 1.2)  # new window
    limiter.allow("b", 1.3)
    limiter.allow("c", 1.4)  # evicts the oldest source
    assert len(limiter._windows) == 2


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class Peer:
    """One NcpTransport bound to 127.0.0.1 on an ephemeral port."""

    def __init__(self, **kwargs):
        self.ed = SigningKey.generate()
        self.x = AgreementKey.generate()
        self.calls = 0
        self.bodies: list[bytes] = []
        self.keys: dict[bytes, bytes] = {}  # Ed25519 -> X25519 of known peers
        kwargs.setdefault("retransmit_s", 0.2)
        kwargs.setdefault("attempts", 3)
        self.ncp = NcpTransport(self.ed, self.x, x25519_of=lambda ed, _ip: self.keys.get(ed),
                                handler=self.echo, **kwargs)
        self.address: tuple[str, int] = ("127.0.0.1", 0)

    async def echo(self, message, _address):
        self.calls += 1
        self.bodies.append(message.body)
        return MessageType.RESPONSE, b"echo:" + message.body

    async def start(self):
        udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: self.ncp, local_addr=("127.0.0.1", 0))
        self.address = udp.get_extra_info("sockname")[:2]

    def know(self, other: "Peer"):
        self.keys[other.ed.public] = other.x.public


async def _pair(**server_kwargs):
    client, server = Peer(), Peer(**server_kwargs)
    await client.start()
    await server.start()
    client.know(server)
    server.know(client)
    assert client.address[1] != server.address[1]
    return client, server


def _close(*peers):
    for peer in peers:
        peer.ncp.close()


def test_single_fragment_request_response():
    async def scenario():
        client, server = await _pair()
        try:
            body = await client.ncp.request(server.address, 0x0001, b"ping",
                                            server.ed.public, server.x.public)
            assert body == b"echo:ping"
            assert server.calls == 1
            assert client.ncp.stats["retransmitted"] == 0
        finally:
            _close(client, server)
    asyncio.run(scenario())


def test_multi_fragment_request_is_acknowledged(monkeypatch):
    acks = []
    original = transport_module.parse_fragment_ack

    def counting(body):
        result = original(body)
        acks.append(result)
        return result

    monkeypatch.setattr(transport_module, "parse_fragment_ack", counting)

    async def scenario():
        client, server = await _pair()
        try:
            payload = bytes(range(256)) * 20  # 5120 bytes: 5 fragments
            body = await client.ncp.request(server.address, 0x0001, payload,
                                            server.ed.public, server.x.public)
            assert body == b"echo:" + payload
            assert server.bodies == [payload]
            await asyncio.sleep(0.05)
            # The server acknowledged the request, the client the response.
            assert acks
            assert any(received == set(range(count)) for _salt, count, received in acks)
        finally:
            _close(client, server)
    asyncio.run(scenario())


def test_duplicate_request_answered_from_cache():
    async def scenario():
        client, server = await _pair()
        original = client.ncp.datagram_received
        lost = []

        def lossy(data, addr):
            if not lost:  # the first response datagram is lost
                lost.append(data)
                return
            original(data, addr)

        client.ncp.datagram_received = lossy
        try:
            body = await client.ncp.request(server.address, 0x0001, b"once",
                                            server.ed.public, server.x.public)
            assert body == b"echo:once"
            assert lost
            assert client.ncp.stats["retransmitted"] == 1
            assert server.calls == 1  # never re-executed [5.7]
        finally:
            _close(client, server)
    asyncio.run(scenario())


def test_stale_response_is_dropped():
    async def scenario():
        client, server = await _pair()

        def stale_build(event, kind, request_id, body, recipient_ed, recipient_x):
            message = Message(event, kind, request_id, now_ms() - 60_000, server.ed.public, body)
            return seal_message(event, message.encode(server.ed, recipient_ed), recipient_x)

        server.ncp._build = stale_build
        client.ncp.retransmit_s, client.ncp.attempts = 0.1, 2
        try:
            with pytest.raises(NcpTimeout):
                await client.ncp.request(server.address, 0x0001, b"x",
                                         server.ed.public, server.x.public)
            assert server.calls == 1
            assert client.ncp.stats["dropped"] >= 1
        finally:
            _close(client, server)
    asyncio.run(scenario())


def test_unknown_address_refused_except_request_approval():
    async def scenario():
        client, server = await _pair(address_known=lambda _ip: False)
        client.ncp.retransmit_s, client.ncp.attempts = 0.1, 1
        try:
            with pytest.raises(NcpTimeout):
                await client.ncp.request(server.address, 0x0001, b"x",
                                         server.ed.public, server.x.public)
            assert server.calls == 0
            body = await client.ncp.request(server.address, 0x0005, b"join",
                                            server.ed.public, server.x.public)
            assert body == b"echo:join"
        finally:
            _close(client, server)
    asyncio.run(scenario())


def test_reply_x25519_hook_answers_unknown_requester():
    async def scenario():
        client = Peer()
        server = Peer(reply_x25519=lambda message: client.x.public
                      if message.sender == client.ed.public else None)
        await client.start()
        await server.start()
        client.know(server)  # the server does not know the client
        try:
            body = await client.ncp.request(server.address, 0x0005, b"hi",
                                            server.ed.public, server.x.public)
            assert body == b"echo:hi"
        finally:
            _close(client, server)
    asyncio.run(scenario())


def test_timeout_schedule_without_extra_doubled_wait():
    async def scenario():
        client, server = await _pair()
        server.ncp.close()  # nobody answers
        client.ncp.retransmit_s, client.ncp.attempts = 0.1, 3
        loop = asyncio.get_running_loop()
        start = loop.time()
        try:
            with pytest.raises(NcpTimeout):
                await client.ncp.request(server.address, 0x0001, b"x",
                                         server.ed.public, server.x.public)
            elapsed = loop.time() - start
            assert 0.65 <= elapsed < 1.2  # 0.1 + 0.2 + 0.4, not + 0.8
            assert client.ncp.stats["retransmitted"] == 2
        finally:
            _close(client)
    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Raft
# ---------------------------------------------------------------------------

IDS = [f"01J{'0' * 22}{c}" for c in "ABCD"]


class Cluster:
    """Raft objects calling each other's handlers directly."""

    def __init__(self, tmp_path, n=3, **kwargs):
        self.down: set[str] = set()
        self.sent: list[tuple[str, int]] = []
        self.changes: dict[str, int] = {}
        self.nodes: dict[str, Raft] = {}
        for i, node_id in enumerate(IDS[:n]):
            self.changes[node_id] = 0
            self.nodes[node_id] = Raft(
                node_id, bytes([i + 1]) * 32, tmp_path / f"{node_id}.json",
                self._sender(node_id), heartbeat_s=0.05, election_s=(0.3, 0.6),
                on_voter_change=self._counter(node_id), **kwargs)

    def _counter(self, node_id):
        def count():
            self.changes[node_id] += 1
        return count

    def _sender(self, source):
        async def send(dest, command, body):
            if source in self.down or dest in self.down:
                raise ConnectionError("unreachable")
            self.sent.append((dest, command))
            node = self.nodes[dest]
            handler = {0x0012: node.handle_vote, 0x0013: node.handle_append,
                       0x0014: node.handle_snapshot}[command]
            return handler(body, asyncio.get_running_loop().time())
        return send

    def leaders(self):
        return [r for i, r in self.nodes.items() if r.is_leader and i not in self.down]

    async def form(self):
        """The first node founds the USD and adds the others one at a time."""
        founder = self.nodes[IDS[0]]
        founder.found()
        for raft in self.nodes.values():
            raft.start()
        for raft in list(self.nodes.values())[1:]:
            assert await founder.propose([voter_record(founder.term, raft.node_id, raft.key)],
                                         timeout=3.0)
        await until(lambda: all(len(r.voters) == len(self.nodes) for r in self.nodes.values()))
        return founder

    async def stop(self):
        for raft in self.nodes.values():
            await raft.stop()


async def until(condition, timeout=5.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition():
        if loop.time() > deadline:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.02)


def _assignment(i: int, node: int = 1) -> Assignment:
    return Assignment(0x0A1, i, IDS[node], bytes([0x40 + node]) * 32)


def test_raft_election_after_leader_loss(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path)
        try:
            founder = await cluster.form()
            assert cluster.leaders() == [founder]
            cluster.down.add(founder.node_id)
            await until(lambda: len(cluster.leaders()) == 1, timeout=8.0)
            leader = cluster.leaders()[0]
            assert leader is not founder and leader.term > 1
        finally:
            await cluster.stop()
    asyncio.run(scenario())


def test_raft_propose_commits_everywhere(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path)
        try:
            leader = await cluster.form()
            records = [assign_record(leader.term, _assignment(i)) for i in (1, 2)]
            assert await leader.propose(records, timeout=3.0)
            await until(lambda: all(r.state.management_of(IDS[1], 0x0A1) is not None
                                    and len(r.state.assignments) == 2
                                    for r in cluster.nodes.values()))
            assert all(r.commit_index == leader.commit_index for r in cluster.nodes.values())
        finally:
            await cluster.stop()
    asyncio.run(scenario())


def test_raft_snapshot_installed_in_several_pages(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path, snapshot_page_bytes=400)
        try:
            leader = await cluster.form()
            lagging = cluster.nodes[IDS[2]]
            cluster.down.add(lagging.node_id)
            records = [assign_record(leader.term, _assignment(i)) for i in range(1, 13)]
            assert await leader.propose(records, timeout=3.0)
            leader.compact()
            pages = leader.snapshot_pages()
            assert len(pages) > 2
            assert all(len(p) <= 400 for p in pages)
            cluster.sent.clear()
            cluster.down.clear()
            await until(lambda: len(lagging.state.assignments) == 12)
            assert lagging.snapshot_index == leader.snapshot_index
            assert set(lagging.voters) == set(IDS[:3])
            snapshots = [c for d, c in cluster.sent if d == lagging.node_id and c == 0x0014]
            assert len(snapshots) >= len(pages)
        finally:
            await cluster.stop()
    asyncio.run(scenario())


def test_raft_snapshot_pages_wait_for_all(tmp_path):
    leader = Raft(IDS[0], b"\x01" * 32, tmp_path / "a.json", None, snapshot_page_bytes=400)
    leader.found()
    leader.state.assignments = {(0x0A1, i): _assignment(i) for i in range(1, 9)}
    leader.applied = leader.commit_index
    leader.compact()
    pages = leader.snapshot_pages()
    assert len(pages) >= 2
    follower = Raft(IDS[1], b"\x02" * 32, tmp_path / "b.json", None)
    for body in reversed(pages[1:]):
        follower.handle_snapshot(body, 0.0)
        assert follower.snapshot_index == 0  # not before every page is in
    follower.handle_snapshot(pages[0], 0.0)
    assert follower.snapshot_index == leader.snapshot_index
    assert len(follower.state.assignments) == 8
    assert follower.is_voter is False and IDS[0] in follower.voters


def test_raft_automatic_compaction(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path, compact_after=5)
        try:
            leader = await cluster.form()
            records = [assign_record(leader.term, _assignment(i)) for i in range(1, 9)]
            assert await leader.propose(records, timeout=3.0)
            await until(lambda: all(len(r.state.assignments) == 8
                                    for r in cluster.nodes.values()))
            assert leader.snapshot_index > 0
            assert len(leader.log) < leader.last_index
            assert set(leader.snapshot_state.voters) == set(IDS[:3])
        finally:
            await cluster.stop()
    asyncio.run(scenario())


def test_raft_on_voter_change(tmp_path):
    async def scenario():
        cluster = Cluster(tmp_path)
        try:
            leader = await cluster.form()
            assert cluster.changes[IDS[0]] == 1  # found()
            assert cluster.changes[IDS[1]] == 1 and cluster.changes[IDS[2]] == 1
            assert await leader.propose([voter_record(leader.term, IDS[2], None)], timeout=3.0)
            # The leader no longer replicates to a removed voter; push the
            # entry once so that it learns of its removal.
            await leader._replicate_to(IDS[2])
            await until(lambda: cluster.changes[IDS[2]] == 2)
            assert not cluster.nodes[IDS[2]].is_voter
            assert cluster.changes[IDS[1]] == 1
        finally:
            await cluster.stop()
    asyncio.run(scenario())


def test_reserved_ids_include_uncommitted_assignments(tmp_path):
    raft = Raft(IDS[0], b"\x01" * 32, tmp_path / "r.json", None)
    raft.found()
    raft.state.assignments[(0x0A1, 1)] = _assignment(1)
    raft.log.append(assign_record(raft.term, _assignment(2)))  # not committed
    raft.log.append(assign_record(raft.term, Assignment(0x0B2, 3, IDS[1], b"\x09" * 32)))
    assert raft.reserved_ids(0x0A1) == {1, 2}
    assert raft.free_id_for(0x0A1) == 3
    assert raft.free_id_for(0x0A1, {3, 4}) == 5
    assert raft.state.management_of(IDS[1], 0x0A1) == 1  # state untouched
    assert all(r.type != RecordType.RELEASE for r in raft.log)
