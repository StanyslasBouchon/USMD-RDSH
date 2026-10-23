"""The USD master: Raft among at most Nv voters [ARCH-02 12, NCP-02 6.15-6.18].

The replicated state is the table of SP addresses: for each (service,
management id) the node and Ed25519 key it is assigned to, the set of voters,
and the nodes elected to each operator role [ARCH 12.4]. A configuration change takes effect as soon as it is in the log and
only one may be pending [6.17]. Pre-vote (Ongaro's thesis 9.6) keeps an
isolated voter from disturbing the leader when it comes back. Term, vote and
log are persisted [ARCH 12.2].
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

from usmd_rdsh.node.ncp.codec import LogRecord, RecordType
from usmd_rdsh.node.wire import Reader, Writer

log = logging.getLogger("usmd_rdsh.raft")

COMPACT_AFTER = 1000  # applied records beyond the snapshot before compaction
SNAPSHOT_PAGE_BYTES = 1000 * 1111  # body bound of one Raft_install_snapshot page [6.18]
_SNAPSHOT_HEAD = 8 + 26 + 8 + 8 + 2 + 2  # term, leader, index, term, page, pages
_VOTER_SIZE = 26 + 32
_OPERATOR_SIZE = 1 + 26
_ASSIGNMENT_SIZE = 2 + 2 + 26 + 32


@dataclass(frozen=True, slots=True)
class Assignment:
    service: int
    management: int
    node_id: str
    key: bytes


def assign_record(term: int, a: Assignment) -> LogRecord:
    data = Writer().u16(a.service).u16(a.management).ident(a.node_id).raw(a.key).bytes()
    return LogRecord(term, RecordType.ASSIGN, data)


def release_record(term: int, service: int, management: int) -> LogRecord:
    return LogRecord(term, RecordType.RELEASE, Writer().u16(service).u16(management).bytes())


def voter_record(term: int, node_id: str, key: bytes | None) -> LogRecord:
    if key is None:
        return LogRecord(term, RecordType.REMOVE_VOTER, Writer().ident(node_id).bytes())
    return LogRecord(term, RecordType.ADD_VOTER, Writer().ident(node_id).raw(key).bytes())


def operator_record(term: int, role: int, node_id: str, *, elected: bool) -> LogRecord:
    """*node_id* elected to, or deposed from, an operator role [ARCH 12.4]."""
    kind = RecordType.ELECT_OPERATOR if elected else RecordType.DEPOSE_OPERATOR
    return LogRecord(term, kind, Writer().u8(role).ident(node_id).bytes())


@dataclass
class StateMachine:
    assignments: dict[tuple[int, int], Assignment] = field(default_factory=dict)
    voters: dict[str, bytes] = field(default_factory=dict)
    operators: dict[int, set[str]] = field(default_factory=dict)  # role -> elected node ids

    def copy(self) -> "StateMachine":
        return StateMachine(dict(self.assignments), dict(self.voters),
                            {r: set(ids) for r, ids in self.operators.items()})

    def apply(self, record: LogRecord) -> None:
        reader = Reader(record.data)
        if record.type == RecordType.ASSIGN:
            a = Assignment(reader.u16(), reader.u16(), reader.ident(), reader.raw(32))
            self.assignments[(a.service, a.management)] = a
        elif record.type == RecordType.RELEASE:
            self.assignments.pop((reader.u16(), reader.u16()), None)
        elif record.type == RecordType.ELECT_OPERATOR:
            role = reader.u8()
            self.operators.setdefault(role, set()).add(reader.ident())
        elif record.type == RecordType.DEPOSE_OPERATOR:
            role = reader.u8()
            self.operators.get(role, set()).discard(reader.ident())

    def operator_pairs(self) -> list[tuple[int, str]]:
        return sorted((r, n) for r, ids in self.operators.items() for n in ids)

    def management_of(self, node_id: str, service: int) -> int | None:
        for (svc, mgmt), a in self.assignments.items():
            if svc == service and a.node_id == node_id:
                return mgmt
        return None

    def free_id(self, service: int) -> int | None:
        used = {m for (s, m) in self.assignments if s == service}
        return next((m for m in range(1, 0xFFFF) if m not in used), None)


Send = Callable[[str, int, bytes], Awaitable[bytes]]  # (voter id, command, body) -> response


@dataclass
class _PendingSnapshot:
    """Pages of a snapshot received so far [6.18]."""

    last_term: int
    pages: int
    voters: dict[str, bytes] | None = None  # from page 0
    operators: list[tuple[int, str]] = field(default_factory=list)  # from page 0
    parts: dict[int, list[Assignment]] = field(default_factory=dict)


class Raft:  # pylint: disable=too-many-instance-attributes
    """One voter (or observer, when not in the configuration)."""

    def __init__(self, node_id: str, key: bytes, storage: Path, send: Send, *,  # pylint: disable=too-many-arguments
                 heartbeat_s: float = 1.0, election_s: tuple[float, float] = (5.0, 10.0),
                 on_voter_change: Callable[[], None] | None = None,
                 compact_after: int = COMPACT_AFTER,
                 snapshot_page_bytes: int = SNAPSHOT_PAGE_BYTES) -> None:
        """``on_voter_change`` is called whenever ``is_voter`` flips."""
        self.node_id = node_id
        self.key = key
        self.storage = storage
        self._send = send
        self.heartbeat_s = heartbeat_s
        self.election_s = election_s
        self.on_voter_change = on_voter_change
        self.compact_after = compact_after
        self.snapshot_page_bytes = snapshot_page_bytes
        # Pages of an incoming snapshot, by (leader, last included index) [6.18].
        self._snapshot_pages: dict[tuple[str, int], _PendingSnapshot] = {}
        self.term = 0
        self.voted_for: str | None = None
        self.log: list[LogRecord] = []  # log[i] has index i + 1 (after the snapshot)
        self.snapshot_index = 0
        self.snapshot_term = 0
        self.snapshot_state = StateMachine()
        self.commit_index = 0
        self.applied = 0
        self.state = StateMachine()
        self.role = "follower"
        self.leader: str | None = None
        self.last_leader_contact = -1e9
        self._next: dict[str, int] = {}
        self._match: dict[str, int] = {}
        self._commit_waiters: list[tuple[int, asyncio.Future]] = []
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._load()
        self._was_voter = self.is_voter

    def _check_voter(self) -> None:
        """Report a flip of ``is_voter`` [6.17: a configuration applies when logged]."""
        now_voter = self.is_voter
        if now_voter != self._was_voter:
            self._was_voter = now_voter
            if self.on_voter_change is not None:
                try:
                    self.on_voter_change()
                except Exception:  # pylint: disable=broad-except
                    log.exception("[RAFT] on_voter_change failed")

    # -- configuration --------------------------------------------------------

    @property
    def voters(self) -> dict[str, bytes]:
        """Latest configuration in the log, committed or not [6.17]."""
        return self._voters_upto(self.last_index)

    def _voters_upto(self, index: int) -> dict[str, bytes]:
        """Configuration given by the snapshot and the log up to *index*."""
        voters = dict(self.snapshot_state.voters)
        for record in self.log[:max(0, index - self.snapshot_index)]:
            reader = Reader(record.data)
            if record.type == RecordType.ADD_VOTER:
                node_id = reader.ident()
                voters[node_id] = reader.raw(32)
            elif record.type == RecordType.REMOVE_VOTER:
                voters.pop(reader.ident(), None)
        return voters

    @property
    def is_voter(self) -> bool:
        return self.node_id in self.voters

    @property
    def is_leader(self) -> bool:
        return self.role == "leader"

    @property
    def last_index(self) -> int:
        return self.snapshot_index + len(self.log)

    def term_at(self, index: int) -> int:
        if index == self.snapshot_index:
            return self.snapshot_term
        if index < self.snapshot_index or index > self.last_index:
            return -1
        return self.log[index - self.snapshot_index - 1].term

    def quorum(self) -> int:
        return len(self.voters) // 2 + 1

    # -- persistence ----------------------------------------------------------

    def _load(self) -> None:
        if not self.storage.exists():
            return
        data = json.loads(self.storage.read_text(encoding="utf-8"))
        self.term, self.voted_for = data["term"], data["voted_for"]
        self.snapshot_index, self.snapshot_term = data["snapshot_index"], data["snapshot_term"]
        snap = StateMachine()
        for a in data["snapshot_assignments"]:
            snap.assignments[(a[0], a[1])] = Assignment(a[0], a[1], a[2], bytes.fromhex(a[3]))
        snap.voters = {k: bytes.fromhex(v) for k, v in data["snapshot_voters"].items()}
        for role, node_id in data.get("snapshot_operators", []):
            snap.operators.setdefault(role, set()).add(node_id)
        self.snapshot_state = snap
        self.log = [LogRecord(r[0], r[1], bytes.fromhex(r[2])) for r in data["log"]]
        self.commit_index = self.applied = self.snapshot_index
        self.state = snap.copy()

    def _save(self) -> None:
        snap = self.snapshot_state
        data = {
            "term": self.term, "voted_for": self.voted_for,
            "snapshot_index": self.snapshot_index, "snapshot_term": self.snapshot_term,
            "snapshot_assignments": [[a.service, a.management, a.node_id, a.key.hex()]
                                     for a in snap.assignments.values()],
            "snapshot_voters": {k: v.hex() for k, v in snap.voters.items()},
            "snapshot_operators": [list(p) for p in snap.operator_pairs()],
            "log": [[r.term, r.type, r.data.hex()] for r in self.log],
        }
        self.storage.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.storage.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(self.storage)

    # -- founding [ARCH 12.2] ---------------------------------------------------

    def found(self) -> None:
        """The founder initialises the log with itself as only voter."""
        if self.last_index:
            return
        self.term = 1
        self.log.append(voter_record(1, self.node_id, self.key))
        self.commit_index = 1
        self._apply_committed()
        self.role, self.leader = "leader", self.node_id
        self._save()
        self._check_voter()

    # -- lifecycle -------------------------------------------------------------

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.get_running_loop().create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        timeout = random.uniform(*self.election_s)
        last_attempt = -1e9
        while True:
            await asyncio.sleep(self.heartbeat_s if self.is_leader else
                                min(0.25, self.election_s[0] / 4))
            try:
                if self.is_leader:
                    await self.replicate()
                elif self.is_voter and \
                        loop.time() - max(self.last_leader_contact, last_attempt) > timeout:
                    # A failed election restarts the randomised timer, so
                    # that two candidates do not keep splitting the vote.
                    timeout = random.uniform(*self.election_s)
                    last_attempt = loop.time()
                    await self.elect()
            except Exception:  # pylint: disable=broad-except
                log.exception("[RAFT] Round failed")

    # -- election [6.16] ---------------------------------------------------------

    async def elect(self) -> bool:
        if len(self.voters) == 1 and self.is_voter:
            self.term += 1
            self.voted_for = self.node_id
            self._become_leader()
            self._save()
            return True
        if not await self._ballot(pre_vote=True, term=self.term + 1):
            return False
        self.term += 1
        self.voted_for = self.node_id
        self.role = "candidate"
        self._save()
        if await self._ballot(pre_vote=False, term=self.term):
            self._become_leader()
            return True
        self.role = "follower"
        return False

    async def _ballot(self, *, pre_vote: bool, term: int) -> bool:
        body = (Writer().boolean(pre_vote).u64(term).ident(self.node_id).u64(self.last_index)
                .u64(self.term_at(self.last_index)).bytes())
        others = [v for v in self.voters if v != self.node_id]
        results = await asyncio.gather(*(self._send(v, 0x0012, body) for v in others),
                                       return_exceptions=True)
        granted = 1
        for result in results:
            if isinstance(result, BaseException):
                continue
            reader = Reader(result)
            their_term, ok = reader.u64(), reader.boolean()
            if their_term > self.term and not pre_vote:
                self._step_down(their_term)
                return False
            granted += ok
        return granted >= self.quorum()

    def handle_vote(self, body: bytes, now: float) -> bytes:
        reader = Reader(body)
        pre_vote, term, candidate = reader.boolean(), reader.u64(), reader.ident()
        last_index, last_term = reader.u64(), reader.u64()
        recent_leader = now - self.last_leader_contact < self.election_s[0]
        up_to_date = (last_term, last_index) >= (self.term_at(self.last_index), self.last_index)
        if pre_vote:
            # Would vote for this term, without changing any state.
            ok = term > self.term and up_to_date and not recent_leader
            return Writer().u64(self.term).boolean(ok).bytes()
        if term > self.term and not recent_leader:
            self._step_down(term)
        ok = (term == self.term and not recent_leader and up_to_date
              and self.voted_for in (None, candidate))
        if ok:
            self.voted_for = candidate
            self._save()
        return Writer().u64(self.term).boolean(ok).bytes()

    def _become_leader(self) -> None:
        self.role, self.leader = "leader", self.node_id
        self._next = {v: self.last_index + 1 for v in self.voters}
        self._match = {v: 0 for v in self.voters}
        self._match[self.node_id] = self.last_index
        self.log.append(LogRecord(self.term, RecordType.NOOP, b""))
        self._match[self.node_id] = self.last_index
        self._save()
        log.warning("[RAFT] %s is the USD master (term %d)", self.node_id, self.term)

    def _step_down(self, term: int) -> None:
        if term > self.term:
            self.term, self.voted_for = term, None
        self.role = "follower"
        self._save()

    # -- replication [6.17, 6.18] ------------------------------------------------

    async def replicate(self) -> None:
        others = [v for v in self.voters if v != self.node_id]
        await asyncio.gather(*(self._replicate_to(v) for v in others), return_exceptions=True)
        self._match[self.node_id] = self.last_index
        self._advance_commit()

    async def _replicate_to(self, voter: str) -> None:
        next_index = self._next.get(voter, self.last_index + 1)
        if next_index <= self.snapshot_index:
            await self._send_snapshot(voter)
            return
        prev = next_index - 1
        records = self.log[next_index - self.snapshot_index - 1:]
        out = (Writer().u64(self.term).ident(self.node_id).u64(prev).u64(self.term_at(prev))
               .u64(self.commit_index).u16(len(records)))
        for record in records:
            out.raw(record.encode())
        reader = Reader(await self._send(voter, 0x0013, out.bytes()))
        term, ok, last = reader.u64(), reader.boolean(), reader.u64()
        if term > self.term:
            self._step_down(term)
            return
        if ok:
            self._match[voter] = last
            self._next[voter] = last + 1
        else:
            self._next[voter] = max(1, min(next_index - 1, last + 1))

    def handle_append(self, body: bytes, now: float) -> bytes:
        reader = Reader(body)
        term, leader, prev, prev_term, commit = (reader.u64(), reader.ident(), reader.u64(),
                                                 reader.u64(), reader.u64())
        records = [LogRecord.read(reader) for _ in range(reader.u16())]
        if term < self.term:
            return Writer().u64(self.term).boolean(False).u64(self.last_index).bytes()
        if term > self.term or self.role != "follower":
            self._step_down(term)
        self.leader, self.last_leader_contact = leader, now
        if self.term_at(prev) != prev_term:
            return Writer().u64(self.term).boolean(False).u64(
                min(self.last_index, max(prev - 1, self.snapshot_index))).bytes()
        index = prev
        for record in records:
            index += 1
            if index <= self.snapshot_index:
                continue
            if self.term_at(index) != record.term:
                del self.log[index - self.snapshot_index - 1:]
                self.log.append(record)
        if records:
            self._save()
        if commit > self.commit_index:
            self.commit_index = min(commit, index)
            self._apply_committed()
        self._check_voter()
        return Writer().u64(self.term).boolean(True).u64(index).bytes()

    def snapshot_pages(self) -> list[bytes]:
        """The current snapshot as Raft_install_snapshot bodies [6.18].

        Each body stays within ``snapshot_page_bytes``; the voters and the
        elected operators travel in page 0 only.
        """
        index, term, state = self.snapshot_index, self.snapshot_term, self.snapshot_state
        assignments = list(state.assignments.values())
        operators = state.operator_pairs()
        voters_size = 2 + _VOTER_SIZE * len(state.voters) + 2 + _OPERATOR_SIZE * len(operators)
        first = (self.snapshot_page_bytes - _SNAPSHOT_HEAD - voters_size - 2) // _ASSIGNMENT_SIZE
        other = (self.snapshot_page_bytes - _SNAPSHOT_HEAD - 2) // _ASSIGNMENT_SIZE
        if first < 0 or other < 1:
            raise ValueError("snapshot page too small for its fixed fields")
        slices = [assignments[:first]]
        for start in range(first, len(assignments), other):
            slices.append(assignments[start:start + other])
        if len(slices) > 0xFFFF:
            raise ValueError("snapshot needs more than 65535 pages")
        bodies = []
        for page, chunk in enumerate(slices):
            out = (Writer().u64(self.term).ident(self.node_id).u64(index).u64(term)
                   .u16(page).u16(len(slices)))
            if page == 0:
                out.u16(len(state.voters))
                for node_id, key in state.voters.items():
                    out.ident(node_id).raw(key)
                out.u16(len(operators))
                for role, node_id in operators:
                    out.u8(role).ident(node_id)
            out.u16(len(chunk))
            for a in chunk:
                out.u16(a.service).u16(a.management).ident(a.node_id).raw(a.key)
            bodies.append(out.bytes())
        return bodies

    async def _send_snapshot(self, voter: str) -> None:
        """One request per page, in order; stop at the first refusal [6.18]."""
        index = self.snapshot_index
        for body in self.snapshot_pages():
            reader = Reader(await self._send(voter, 0x0014, body))
            term = reader.u64()
            if term > self.term:
                self._step_down(term)
                return
        self._next[voter] = index + 1

    def handle_snapshot(self, body: bytes, now: float) -> bytes:  # pylint: disable=too-many-locals
        """Collect the pages; install once pages 0..pages-1 are all in [6.18]."""
        reader = Reader(body)
        term, leader = reader.u64(), reader.ident()
        last_index, last_term, page, pages = reader.u64(), reader.u64(), reader.u16(), reader.u16()
        voters: dict[str, bytes] | None = None
        operators: list[tuple[int, str]] = []
        if page == 0:
            voters = {}
            for _ in range(reader.u16()):
                node_id = reader.ident()
                voters[node_id] = reader.raw(32)
            for _ in range(reader.u16()):
                role = reader.u8()
                operators.append((role, reader.ident()))
        chunk = []
        for _ in range(reader.u16()):
            chunk.append(Assignment(reader.u16(), reader.u16(), reader.ident(), reader.raw(32)))
        if term < self.term:
            return Writer().u64(self.term).bytes()
        if term > self.term or self.role != "follower":
            self._step_down(term)
        self.leader, self.last_leader_contact = leader, now
        if pages == 0 or page >= pages or last_index <= self.snapshot_index:
            return Writer().u64(self.term).bytes()  # malformed, or already covered
        key = (leader, last_index)
        pending = self._snapshot_pages.get(key)
        if pending is None or pending.pages != pages or pending.last_term != last_term:
            # Only the latest snapshot is kept, which bounds the memory used.
            self._snapshot_pages = {key: _PendingSnapshot(last_term, pages)}
            pending = self._snapshot_pages[key]
        if voters is not None:
            pending.voters, pending.operators = voters, operators
        pending.parts[page] = chunk
        if pending.voters is None or len(pending.parts) < pages:
            return Writer().u64(self.term).bytes()
        del self._snapshot_pages[key]
        snap = StateMachine(voters=dict(pending.voters))
        for role, node_id in pending.operators:
            snap.operators.setdefault(role, set()).add(node_id)
        for part in range(pages):
            for a in pending.parts[part]:
                snap.assignments[(a.service, a.management)] = a
        # Keep the log beyond the snapshot when it agrees with it [RAFT 7].
        keep = (self.log[last_index - self.snapshot_index:]
                if self.term_at(last_index) == last_term else [])
        self.snapshot_index, self.snapshot_term, self.snapshot_state = \
            last_index, last_term, snap
        self.log = keep
        self.commit_index = max(self.commit_index, last_index)
        self.applied = last_index
        self.state = snap.copy()
        self._apply_committed()
        self._save()
        self._check_voter()
        return Writer().u64(self.term).bytes()

    def compact(self) -> None:
        """Fold the applied prefix into the snapshot."""
        if self.applied <= self.snapshot_index:
            return
        voters = self._voters_upto(self.applied)  # not the uncommitted configuration
        self.snapshot_term = self.term_at(self.applied)
        self.log = self.log[self.applied - self.snapshot_index:]
        self.snapshot_index = self.applied
        self.snapshot_state = self.state.copy()
        self.snapshot_state.voters = voters
        self._save()

    # -- management identifiers [6.15] ---------------------------------------------

    def reserved_ids(self, service: int) -> set[int]:
        """Management ids of *service* taken in the state machine or by an
        ASSIGN record not yet applied, so an allocation never touches the
        state before commit."""
        taken = {m for (s, m) in self.state.assignments if s == service}
        for record in self.log[max(0, self.applied - self.snapshot_index):]:
            if record.type == RecordType.ASSIGN:
                reader = Reader(record.data)
                if reader.u16() == service:
                    taken.add(reader.u16())
        return taken

    def free_id_for(self, service: int, extra_taken: set[int] | None = None) -> int | None:
        """Lowest free management id of *service*, or None when exhausted."""
        used = self.reserved_ids(service) | (extra_taken or set())
        return next((m for m in range(1, 0xFFFF) if m not in used), None)

    # -- commit ------------------------------------------------------------------

    def _advance_commit(self) -> None:
        for index in range(self.last_index, self.commit_index, -1):
            if self.term_at(index) != self.term:
                continue
            replicated = sum(1 for v in self.voters if self._match.get(v, 0) >= index)
            if replicated >= self.quorum():
                self.commit_index = index
                break
        self._apply_committed()

    def _apply_committed(self) -> None:
        while self.applied < self.commit_index:
            self.applied += 1
            if self.applied > self.snapshot_index:
                self.state.apply(self.log[self.applied - self.snapshot_index - 1])
        self.state.voters = self.voters
        if self.compact_after > 0 and self.applied - self.snapshot_index >= self.compact_after:
            self.compact()  # bounds the log and the persisted file
        self._check_voter()
        for index, future in list(self._commit_waiters):
            if index <= self.commit_index and not future.done():
                future.set_result(True)
        self._commit_waiters = [(i, f) for i, f in self._commit_waiters if not f.done()]

    async def propose(self, records: list[LogRecord], timeout: float) -> bool:
        """Append on the leader and wait for a majority [6.15]."""
        if not self.is_leader:
            return False
        async with self._lock:
            if any(r.type in (RecordType.ADD_VOTER, RecordType.REMOVE_VOTER) for r in records) \
                    and self._config_pending():
                return False  # one configuration change at a time
            self.log.extend(records)
            self._save()
            self._check_voter()
            target = self.last_index
        future = asyncio.get_running_loop().create_future()
        self._commit_waiters.append((target, future))
        await self.replicate()
        try:
            await asyncio.wait_for(future, timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def _config_pending(self) -> bool:
        return any(r.type in (RecordType.ADD_VOTER, RecordType.REMOVE_VOTER)
                   for r in self.log[max(0, self.commit_index - self.snapshot_index):])
