"""Server side of NCP [NCP-02 6, 7]: the common checks of 6.1 and the commands.

Mixed into :class:`usmd_rdsh.node.node.Node`; everything here reads and writes
the node's tables.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING

from usmd_rdsh.node.crypto import CryptoError, b64u
from usmd_rdsh.node.ncp.codec import (
    Command,
    CreationToken,
    EndorsementPacket,
    ErrorCode,
    Message,
    MessageType,
    NodeRecord,
    OperateRequest,
    Role,
    TableEntry,
    UscProperties,
    UsdProperties,
    ack_body,
    decode_mutations,
    error_body,
    ids,
    read_ids,
)
from usmd_rdsh.node.ncp.transport import NcpRemoteError, NcpTimeout
from usmd_rdsh.node.ncp.codec import _read_roles
from usmd_rdsh.node.signed import parameter
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import Reader, WireError, Writer, now_ms

if TYPE_CHECKING:  # pragma: no cover
    from usmd_rdsh.node.node import Node

log = logging.getLogger("usmd_rdsh.ncp")

#: Commands addressed only to reference nodes of the sender [6.1].
REFERENCE_ONLY = {Command.REQUEST_EMERGENCY, Command.REQUEST_HELP,
                  Command.SEND_USC_PROPERTIES, Command.SEND_USD_PROPERTIES,
                  Command.SEND_MUTATION_PROPERTIES, Command.INFORM_REFERENCE_NODE,
                  Command.SEND_NODE_TABLE}
#: ... except from the endorser to a node it endorsed while 0x0000 / 0x1000.
ENDORSER_EXCEPTION = {Command.SEND_USC_PROPERTIES, Command.SEND_USD_PROPERTIES,
                      Command.SEND_MUTATION_PROPERTIES, Command.SEND_NODE_TABLE}
RAFT = {Command.RAFT_REQUEST_VOTE, Command.RAFT_APPEND_ENTRIES, Command.RAFT_INSTALL_SNAPSHOT}

Answer = tuple[int, bytes] | None


def _ok(body: bytes) -> Answer:
    return MessageType.RESPONSE, body


def _error(code: ErrorCode, text: str = "") -> Answer:
    return MessageType.ERROR, error_body(int(code), text)


class NcpHandlers:  # pylint: disable=too-many-public-methods
    """Mixin: the node answering NCP requests."""

    # -- common rules [6.1, 7.6] -----------------------------------------------

    async def handle_request(self: "Node", message: Message, address: tuple[str, int]) -> Answer:
        try:
            command = Command(message.event)
        except ValueError:
            return _error(ErrorCode.MALFORMED, "unknown command")
        if abs(message.timestamp - now_ms()) > self.settings.freshness_s * 1000:
            return _error(ErrorCode.STALE_TIMESTAMP)
        key, ip = message.sender, address[0]
        if self.tables.exclusions.is_excluded(key):
            return None
        if command == Command.REQUEST_APPROVAL:
            self._remember_requester(message)
        # An operator of another USD is outside our tables: its credentials
        # are checked by the handler instead [ARCH 12.5].
        foreign = command == Command.OPERATE and message.body[:1] != b"" and \
            bool(message.body[0] & 0x80)
        if command != Command.REQUEST_APPROVAL and not foreign:
            refusal = self._check_sender(command, key, ip)
            if refusal is not False:
                return refusal
        try:
            handler = getattr(self, f"_on_{command.name.lower()}")
            return await handler(message, ip)
        except (WireError, ValueError) as exc:
            return _error(ErrorCode.MALFORMED, str(exc))
        except NcpRemoteError as exc:
            return MessageType.ERROR, error_body(exc.code, exc.text)

    def _check_sender(self: "Node", command: Command, key: bytes, ip: str) -> Answer | bool:
        """False when the sender may run *command*, else the answer (None = ignore)."""
        nit = self.tables.nit
        if not nit.knows(key):
            entry = self.tables.nodes.get(key)
            if entry is not None and entry.record.address == ip:
                self._learn_entry(entry.token, entry.record)  # TTL expired, table knows it
            else:
                return _error(ErrorCode.UNKNOWN_KEY)
        if not nit.accepts(key, ip):
            entry = self.tables.nodes.get(key)
            if entry is not None and entry.record.address == ip:
                nit.associate(key, entry.record.node_id, ip, entry.record.x25519)
            else:
                # Authenticated, not a replay (the transport's cache): exclude [7.6].
                self.tables.exclusions.exclude(key, State.EXCLUDED_NIT_ASSOCIATION)
                self.event(f"Excluded {key.hex()[:12]}: (address, key) not in the NIT")
                return None
        syncing_from_endorser = key == self.endorser and self.state in (
            State.APPROVAL_REQUIRED, State.SYNCHRONISING)
        self.renew_nit(key, ip)
        if not self.tables.nal.allows(key, Role.NODE_EXECUTOR) and not (
                syncing_from_endorser and command in ENDORSER_EXCEPTION):
            # The endorser's own role arrives with the table it is sending [7.2].
            return _error(ErrorCode.NOT_AUTHORISED, "role")
        if command in RAFT:
            voters = self.raft.voters if self.raft else {}
            entry = self.tables.nodes.get(key)
            # A node just added as voter has no configuration yet: it learns
            # it from the master's first Raft_append_entries / snapshot.
            if entry is None or (voters and entry.record.node_id not in voters):
                return _error(ErrorCode.VOTERS_ONLY)
        if command in REFERENCE_ONLY and not self._am_reference_of(key, command):
            return _error(ErrorCode.NOT_AUTHORISED, "not a reference node of the sender")
        if key not in self.tables.endorsements and key != self.endorser and \
                key != self.key and not any(p.node_key == key for p in self.tables.nel):
            asyncio.get_running_loop().create_task(self.verify_endorsement_of(key, ip))
        return False

    def _am_reference_of(self: "Node", key: bytes, command: Command) -> bool:
        entry = self.tables.nodes.get(key)
        sender_id = entry.record.node_id if entry else None
        refs = set(self.referenced_by.get(sender_id or "", []))
        if entry is not None:
            refs |= set(entry.record.reference_nodes)
        if self.node_id in refs:
            return True
        if command == Command.INFORM_REFERENCE_NODE:
            return True  # the body must name us: checked by the handler (0x0001)
        if command in ENDORSER_EXCEPTION and key == self.endorser and \
                self.state in (State.APPROVAL_REQUIRED, State.SYNCHRONISING):
            return True
        return False

    def _remember_requester(self: "Node", message: Message) -> None:
        """Keep the requester's X25519 key so even a refusal reaches it [6.7]."""
        try:
            reader = Reader(message.body)
            CreationToken.read(reader)
            record = NodeRecord.read(reader)
        except WireError:
            return
        self._approval_x25519 = {**getattr(self, "_approval_x25519", {}),
                                 message.sender: record.x25519}

    # -- 6.2 - 6.4 ------------------------------------------------------------------

    async def _on_get_status(self: "Node", message: Message, ip: str) -> Answer:
        sample = self.load.smoothed()
        body = (Writer().u16(min(sample.memory, 1000)).u16(min(sample.cpu, 1000))
                .u16(min(sample.disk, 1000)).u16(min(sample.network, 1000))
                .string(self.mutation).u16(int(self.state if self.state.declarable
                                               else State.INACTIVE)).bytes())
        return _ok(body)

    async def _on_check_distance_to_node(self: "Node", message: Message, ip: str) -> Answer:
        sent = Reader(message.body).u64()
        entry = self.tables.nodes.get(message.sender)
        is_ref = entry is not None and entry.record.node_id in self.references
        return _ok(Writer().u64(sent).u16(min(self.load.reference, 1000))
                   .string(self.mutation).boolean(is_ref).bytes())

    def _can_take(self: "Node", requester_load: int, mutation: str) -> bool:
        """[ARCH 7.2]: below the threshold with the service, bound, dependencies."""
        usd = self.signed.usd
        weak = parameter(usd, 0x0004) or 800
        if self.mutation and self.mutation != mutation:
            return False  # one mutation per node [ARCH 3.2]
        estimate = requester_load // 2
        if self.load.reference + estimate >= weak:
            return False
        props = self.signed.mutations.get(mutation)
        if props is None:
            return False
        if props.max_instances and self.instance_count(mutation) >= props.max_instances:
            return False
        for spec in self.mutation_specs(mutation):
            for dependency in spec.dependencies:
                entry = self.signed.service_by_name(dependency)
                if entry is None:
                    return False
                reachable = entry.service_id in self.hosted or (
                    self.nndp is not None and self.nndp.services.best(entry.service_id))
                if not reachable:
                    return False  # dependencies must be accessible [ARCH 7.2]
        return self.state == State.ACTIVE

    async def _on_request_help(self: "Node", message: Message, ip: str) -> Answer:
        return await self._help_or_emergency(message, emergency=False)

    async def _on_request_emergency(self: "Node", message: Message, ip: str) -> Answer:
        return await self._help_or_emergency(message, emergency=True)

    async def _help_or_emergency(self: "Node", message: Message, *, emergency: bool) -> Answer:
        if not self._request_rate_ok(message.sender):
            return _error(ErrorCode.BUSY, "too many requests from this node")
        reader = Reader(message.body)
        reason = reader.u16()
        solicited = read_ids(reader)
        load = _permille(reader)
        reader.end()
        if emergency and not 0x3301 <= reason <= 0x3304:
            raise WireError("emergency reason is 0x3301..0x3304")
        if not emergency and reason != 0:
            raise WireError("help reason is 0x0000")
        entry = self.tables.nodes.get(message.sender)
        mutation = entry.record.mutation if entry else ""
        favourable = self._can_take(load, mutation)
        extra: list[str] = []
        if emergency:
            # [6.4] relay as Request_help to our references outside the list, within 2 s.
            relay = [n for n in self.references if n not in solicited]
            body = Writer().u16(0).raw(ids(solicited + relay)).u16(load).bytes()

            async def ask(node_id: str) -> str | None:
                try:
                    answer = await asyncio.wait_for(
                        self.call(node_id, Command.REQUEST_HELP, body), 1.5)
                    return node_id if Reader(answer).boolean() else None
                except (NcpTimeout, NcpRemoteError, asyncio.TimeoutError):
                    return None

            extra = [n for n in await asyncio.gather(*(ask(n) for n in relay)) if n]
        if entry is not None and emergency:
            self.observed[message.sender] = State(reason)
            if favourable:
                # [ARCH 7.5]: no Confirm_delegation within 0x0008 -> 0x3200, and
                # the favourable nodes take the services over.
                self._soon(self._delegation_deadline(message.sender, mutation))
        return _ok(Writer().boolean(favourable).raw(ids(extra)).bytes())

    def _request_rate_ok(self: "Node", sender: bytes) -> bool:
        """At most 3 help/emergency requests per peer per 10 s [ARCH 14]."""
        now = time.monotonic()
        history = getattr(self, "_help_history", {})
        self._help_history = history
        recent = [t for t in history.get(sender, []) if now - t < 10.0]
        recent.append(now)
        history[sender] = recent
        return len(recent) <= 3

    async def _delegation_deadline(self: "Node", sender: bytes, mutation: str) -> None:
        delay = parameter(self.signed.usd, 0x0008) or 30
        confirmed = getattr(self, "_confirmed_by", {})
        self._confirmed_by = confirmed
        confirmed.pop(sender, None)
        declared = getattr(self, "_declared_inactive", set())
        self._declared_inactive = declared
        declared.discard(sender)
        await asyncio.sleep(delay)
        # Confirmed with us, or with another node (it then declared itself
        # inactive to its references [ARCH 7.4]): no expiry.
        if confirmed.pop(sender, None) or sender in declared:
            return
        self.observed[sender] = State.INACTIVE_TIMEOUT
        self.event("No delegation confirmed in time: 0x3200, taking over")
        if not self.mutation and self._can_take(0, mutation):
            await self.transmute(mutation, reason="delegation timeout")

    async def _on_confirm_delegation(self: "Node", message: Message, ip: str) -> Answer:
        reader = Reader(message.body)
        mutation, reason = reader.string(), reader.u16()
        reader.end()
        del reason
        confirmed = getattr(self, "_confirmed_by", {})
        self._confirmed_by = confirmed
        confirmed[message.sender] = True
        if not self._can_take(0, mutation) and self.mutation != mutation:
            return _ok(Writer().boolean(False).bytes())
        if self.mutation != mutation:
            asyncio.get_running_loop().create_task(self.transmute(mutation, reason="delegation"))
        return _ok(Writer().boolean(True).bytes())

    async def _on_declare_state(self: "Node", message: Message, ip: str) -> Answer:
        reader = Reader(message.body)
        state = State(reader.u16())
        validity = reader.u64() if reader.remaining == 8 else None
        reader.end()
        if not state.declarable:
            raise WireError("a node declares only origin-D states")
        if validity is not None:
            self.state_validity_of = {**getattr(self, "state_validity_of", {}),
                                      message.sender: validity}
        entry = self.tables.nodes.get(message.sender)
        if entry is not None and entry.record.node_id in self.references and \
                state != State.ACTIVE:
            self._soon(self.measure_distances())  # replace a reference at once [ARCH 6.4]
        if state.inactive:
            self._declared_inactive = {*getattr(self, "_declared_inactive", set()),
                                       message.sender}
            self.observed[message.sender] = state
            if self.sp:
                self.sp.drop_peer(message.sender)
        else:
            self.observed.pop(message.sender, None)
        return _ok(ack_body(True))

    # -- 6.7, 7.2: admission ----------------------------------------------------

    async def _on_request_approval(self: "Node", message: Message, ip: str) -> Answer:
        if self.state != State.ACTIVE:
            return _error(ErrorCode.BUSY, "not an admitted active node")
        reader = Reader(message.body)
        token = CreationToken.read(reader)
        record = NodeRecord.read(reader)
        reader.raw(16)  # nonce
        try:
            requested = _read_roles(reader)
            reader.end()
        except WireError as exc:
            return _error(ErrorCode.MALFORMED, str(exc))
        try:
            self.check_token(token, for_admission=True, requester=message.sender)
        except (ValueError, CryptoError) as exc:
            return _error(ErrorCode.BAD_CREATION_TOKEN, str(exc))
        if any(r not in token.roles for r in requested):
            return _error(ErrorCode.BAD_CREATION_TOKEN, "role not authorised by the token")
        try:
            record.verify(token.node_key)
        except CryptoError:
            return _error(ErrorCode.BAD_NODE_RECORD, "signature")
        if record.state != State.APPROVAL_REQUIRED or record.address != ip \
                or record.mutation or record.reference_nodes:
            return _error(ErrorCode.BAD_NODE_RECORD)
        clash = self.tables.nodes.by_id(record.node_id)
        if clash is not None and clash.key != token.node_key:
            return _error(ErrorCode.ID_IN_USE)
        validity = (parameter(self.signed.usd, 0x000D) or 2_592_000) * 1000
        packet = EndorsementPacket(self.key, record.node_id, token.node_key, record.x25519,
                                   requested or token.roles, now_ms() + validity)
        packet.sign(self.identity.signing)
        self.tables.nel.append(packet)
        self.tables.nodes.merge(token, record)
        self._learn_entry(token, record)
        self.schedule_relay(None, [token.node_key])
        self.event(f"Endorsed {record.node_id} ({ip})")
        asyncio.get_running_loop().create_task(self._synchronise(token.node_key))
        return _ok(Writer().boolean(True).raw(packet.encode()).bytes())

    async def _synchronise(self: "Node", key: bytes) -> None:
        """[7.2]: full table, then USC, USD and mutation properties."""
        await asyncio.sleep(0.2)
        await self._quiet(self.send_table(key, self.tables.nodes.sorted(), mode=0x00))
        from usmd_rdsh.node.ncp.codec import encode_mutations  # pylint: disable=import-outside-toplevel
        if self.signed.usc:
            await self._quiet(self.call(key, Command.SEND_USC_PROPERTIES, self.signed.usc.encode()))
        if self.signed.usd:
            await self._quiet(self.call(key, Command.SEND_USD_PROPERTIES, self.signed.usd.encode()))
        if self.signed.mutations:
            await self._quiet(self.call(key, Command.SEND_MUTATION_PROPERTIES,
                                        encode_mutations(list(self.signed.mutations.values()))))

    # -- 6.8 - 6.10: configuration ------------------------------------------------

    def _authority(self: "Node") -> bytes:
        authority = self.usc_key
        if authority is None:
            raise NcpRemoteError(int(ErrorCode.OBSOLETE_OR_UNSIGNED), "no authority key known")
        return authority

    def _held(self: "Node", version: int | None) -> int:
        return version or 0

    async def _on_send_usc_properties(self: "Node", message: Message, ip: str) -> Answer:
        obj = UscProperties.decode(message.body)
        try:
            applied = self.signed.offer_usc(obj, self._authority())
        except CryptoError:
            return _error(ErrorCode.OBSOLETE_OR_UNSIGNED, "authority signature")
        except WireError as exc:
            self.event(f"USC properties refused: {exc}", logging.WARNING)
            return _error(ErrorCode.MALFORMED, str(exc))
        if applied:
            self.save_signed()
            self._relay_properties(message.sender)
        return _ok(ack_body(applied, self._held(self.signed.usc.version if self.signed.usc
                                                else None)))

    async def _on_send_usd_properties(self: "Node", message: Message, ip: str) -> Answer:
        obj = UsdProperties.decode(message.body)
        try:
            applied = self.signed.offer_usd(obj, self._authority())
        except CryptoError:
            return _error(ErrorCode.OBSOLETE_OR_UNSIGNED, "authority signature")
        except WireError as exc:
            self.event(f"USD properties refused: {exc}", logging.WARNING)
            return _error(ErrorCode.MALFORMED, str(exc))
        if applied:
            self.save_signed()
            self.apply_anchors()
            self.on_config_changed()
            self._relay_properties(message.sender)
        return _ok(ack_body(applied, self._held(self.signed.usd.version if self.signed.usd
                                                else None)))

    async def _on_send_mutation_properties(self: "Node", message: Message, ip: str) -> Answer:
        applied_any = False
        held = 0
        self._authority()
        for mutation in decode_mutations(message.body):
            try:
                # [ARCH 8.5] a host runs update and keeps the version only on success.
                applied = await self.offer_mutation(mutation)
            except CryptoError:
                return _error(ErrorCode.OBSOLETE_OR_UNSIGNED, "authority signature")
            applied_any |= applied
            if mutation.name in self.signed.mutations:
                held = max(held, self.signed.mutations[mutation.name].version)
        if applied_any:
            self.save_signed()
            self.on_config_changed()
            self._relay_properties(message.sender)
        return _ok(ack_body(applied_any, held))

    def _relay_properties(self: "Node", sender: bytes) -> None:
        sender_entry = self.tables.nodes.get(sender)
        targets = [n for n in self.references
                   if sender_entry is None or n != sender_entry.record.node_id]
        asyncio.get_running_loop().create_task(self.push_properties(targets))

    async def _on_inform_reference_node(self: "Node", message: Message, ip: str) -> Answer:
        reader = Reader(message.body)
        refs = read_ids(reader)
        reader.end()
        if self.node_id not in refs:
            return _error(ErrorCode.NOT_AUTHORISED, "not a reference node of the sender")
        entry = self.tables.nodes.get(message.sender)
        if entry is not None:
            self.referenced_by[entry.record.node_id] = refs
        return _ok(ack_body(self.node_id in refs))

    # -- 7.4, 7.5: endorsement ------------------------------------------------------

    async def _on_endorsement_check_required(self: "Node", message: Message, ip: str) -> Answer:
        packet = self.endorsement
        if packet is None and self.token is not None and self.token.founder:
            # The founder endorses itself (no peer existed); see recette, open point.
            packet = EndorsementPacket(self.key, self.node_id, self.key,
                                       self.identity.x25519_public, self.token.roles,
                                       self.token.expires).sign(self.identity.signing)
        if packet is None:
            return _error(ErrorCode.NOT_AUTHORISED, "not endorsed")
        return _ok(packet.encode())

    async def _on_verify_endorsement(self: "Node", message: Message, ip: str) -> Answer:
        packet = EndorsementPacket.decode(message.body)
        mine = any(p.encode() == packet.encode() for p in self.tables.nel)
        founder = packet.endorser == self.key == packet.node_key and \
            self.token is not None and self.token.founder
        return _ok(Writer().boolean(mine or founder).bytes())

    async def _on_notify_end_of_service(self: "Node", message: Message, ip: str) -> Answer:
        reader = Reader(message.body)
        endorser_id = reader.ident()
        reader.end()
        if self.endorser != message.sender:
            self.tables.exclusions.exclude(message.sender, State.EXCLUDED_INVALID_END_OF_SERVICE)
            return None
        del endorser_id
        self.endorsement, self.endorser = None, None
        self.set_state(State.APPROVAL_REQUIRED, reason="endorser left")
        self.publish_record()
        self._save_admission()
        self.event("Endorser left the USD: admission restarts")
        return _ok(ack_body(True))

    async def _on_request_revocation(self: "Node", message: Message, ip: str) -> Answer:
        Reader(message.body).ident()
        before = len(self.tables.nel)
        self.tables.nel = [p for p in self.tables.nel if p.node_key != message.sender]
        if len(self.tables.nel) == before:
            self.tables.exclusions.exclude(message.sender, State.EXCLUDED_INVALID_REVOCATION)
            return None
        self._save_admission()
        return _ok(ack_body(True))

    # -- 6.14, 7.9: node table ------------------------------------------------------

    async def _on_send_node_table(self: "Node", message: Message, ip: str) -> Answer:
        reader = Reader(message.body)
        mode, page, pages = reader.u8(), reader.u16(), reader.u16()
        if mode not in (0x00, 0x01) or page >= pages or (mode == 0x01 and pages != 1):
            raise WireError("bad mode or page")
        received = [TableEntry.read(reader) for _ in range(reader.u16())]
        reader.end()
        seen = getattr(self, "_table_pages", {})
        self._table_pages = seen
        session = seen.setdefault(message.sender, set())
        accepted = []
        for entry in received:
            session.add(entry.token.node_key)
            if self.accept_entry(entry):
                accepted.append(entry.token.node_key)
        if accepted:
            self.schedule_relay(message.sender, accepted)
        newer = []
        for entry in received:
            held = self.tables.nodes.get(entry.token.node_key)
            if held is not None and held.record.date > entry.record.date:
                newer.append(TableEntry(held.token, held.record))
        if mode == 0x00 and page == pages - 1:
            newer += [TableEntry(e.token, e.record) for e in self.tables.nodes.sorted()
                      if e.key not in session]
            seen.pop(message.sender, None)
        if self.state == State.SYNCHRONISING:
            self.apply_anchors()
        out = Writer().u16(len(newer)).raw(b"".join(e.encode() for e in newer))
        return _ok(out.bytes())

    # -- 6.15 - 6.18: master --------------------------------------------------------

    async def _on_request_management_id(self: "Node", message: Message, ip: str) -> Answer:
        reader = Reader(message.body)
        services = [reader.u16() for _ in range(reader.u16())]
        entry = self.tables.nodes.get(message.sender)
        if entry is None:
            return _error(ErrorCode.UNKNOWN_KEY)
        return _ok(await self.allocate_management_ids(entry.record.node_id, message.sender,
                                                      services))

    async def _on_raft_request_vote(self: "Node", message: Message, ip: str) -> Answer:
        return _ok(self.raft.handle_vote(message.body, _loop_time()))

    async def _on_raft_append_entries(self: "Node", message: Message, ip: str) -> Answer:
        return _ok(self.raft.handle_append(message.body, _loop_time()))

    async def _on_raft_install_snapshot(self: "Node", message: Message, ip: str) -> Answer:
        return _ok(self.raft.handle_snapshot(message.body, _loop_time()))

    async def _on_send_operators(self: "Node", message: Message, ip: str) -> Answer:
        """[6.19] the master's table of elected operators, for a node without the log."""
        reader = Reader(message.body)
        term, master = reader.u64(), reader.ident()
        pairs = []
        for _ in range(reader.u16()):
            role = reader.u8()
            if role not in (1, 2, 3):
                raise WireError("not an elected role")
            pairs.append((role, reader.ident()))
        reader.end()
        entry = self.tables.nodes.get(message.sender)
        voters = set(self.raft.voters if self.raft else {}) | set(self.known_voters)
        if entry is None or entry.record.node_id != master or not (
                entry.record.voter or master in voters):
            return _error(ErrorCode.VOTERS_ONLY)
        if self.raft is not None and self.raft.is_voter:
            return _ok(ack_body(True))  # a voter reads its own log
        if term < self.operators_term:
            return _ok(ack_body(False))  # from a deposed master
        operators: dict[int, set[str]] = {}
        for role, node_id in pairs:
            operators.setdefault(role, set()).add(node_id)
        self.set_operators(operators, term)
        return _ok(ack_body(True))

    # -- Operate [ARCH 12.5] ---------------------------------------------------------

    async def _on_operate(self: "Node", message: Message, ip: str) -> Answer:
        """A console exchange from an elected operator.

        From this USD: the sender is an elected usc-operator or usd-operator,
        and the exchange is for this node. From another USD of the USC: the
        sender's credentials prove a usc-operator of that USD; only an elected
        usc-operator of this USD serves it, relaying to *target* if needed,
        and any other node answers with the operators to ask.
        """
        request = OperateRequest.decode(message.body)
        if request.token is not None:
            usdn = self._check_foreign_operator(request, message.sender)
            self._approval_x25519 = {**getattr(self, "_approval_x25519", {}),
                                     message.sender: request.x25519}
            if Role.USC_OPERATOR not in self.elected_roles:
                return _ok(json.dumps({"redirect": self.operators_to_redirect()}).encode())
            origin = f"{b64u(message.sender)[:12]} (USD {usdn})"
            if request.target and request.target != self.node_id:
                return await self._relay_operate(request, origin)
        else:
            entry = self.tables.nodes.get(message.sender)
            if entry is None:
                return _error(ErrorCode.UNKNOWN_KEY)
            origin = entry.record.node_id
            if origin not in self.operator_ids(Role.USC_OPERATOR, Role.USD_OPERATOR):
                return _error(ErrorCode.NOT_AUTHORISED, "not an elected usc/usd operator")
            if request.target and request.target != self.node_id:
                return _error(ErrorCode.NOT_AUTHORISED, "relayed only for another USD")
        if self.operate_handler is None:
            return _error(ErrorCode.BUSY, "no console on this node")
        answer = await self.operate_handler(origin, message.sender, request.session,
                                            request.payload)
        return _ok(answer)

    def _check_foreign_operator(self: "Node", request: OperateRequest, sender: bytes) -> str:
        """USC -> USD properties -> creation token -> sender, usc-operator; the USDN."""
        usc, usc_key, usd, token = self.signed.usc, self.usc_key, request.usd, request.token
        if usc is None or usc_key is None or usd is None or token is None:
            raise NcpRemoteError(ErrorCode.NOT_AUTHORISED, "no USC in force here")
        try:
            usd.verify(usc_key)
            token.verify()
        except CryptoError as exc:
            raise NcpRemoteError(ErrorCode.NOT_AUTHORISED, "credentials") from exc
        own = self.signed.usd.usdn if self.signed.usd else ""
        if usd.usdn == own or usd.usdn not in usc.usd:
            raise NcpRemoteError(ErrorCode.NOT_AUTHORISED, "USD not in the USC")
        if token.issuer != usd.public_key or token.usdn != usd.usdn or \
                token.node_key != sender or Role.USC_OPERATOR not in token.roles:
            raise NcpRemoteError(ErrorCode.NOT_AUTHORISED, "not a usc-operator of that USD")
        if len(request.x25519) != 32:
            raise WireError("X25519 key")
        return usd.usdn

    async def _relay_operate(self: "Node", request: OperateRequest, origin: str) -> Answer:
        """To a node of this USD, as its elected usc-operator; the origin travels along."""
        if self.tables.nodes.by_id(request.target) is None:
            return _error(ErrorCode.UNKNOWN_KEY, "no such node in this USD")
        try:
            payload = json.loads(request.payload)
            if not isinstance(payload, dict):
                raise ValueError
        except ValueError:
            return _error(ErrorCode.MALFORMED, "one JSON object")
        payload["via"] = origin
        try:
            return _ok(await self.operate(request.target, request.session,
                                          json.dumps(payload).encode()))
        except NcpTimeout:
            return _error(ErrorCode.BUSY, f"{request.target} does not answer")


def _permille(reader: Reader) -> int:
    """A per-mille field: 0..1000 [NCP 6.1]."""
    value = reader.u16()
    if value > 1000:
        raise WireError("per mille above 1000")
    return value


def _loop_time() -> float:
    try:
        return asyncio.get_running_loop().time()
    except RuntimeError:
        return time.monotonic()
