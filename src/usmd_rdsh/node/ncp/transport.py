"""NCP transport [NCP-02 4, 5.2-5.7].

Fragment (<= 1200 bytes of UDP payload)::

    header (9) | ephemeral X25519 (32) | salt (16) | nonce (12) | index (2)
    | count (2) | ChaCha20-Poly1305(ciphertext <= 1111 | tag 16)

    key = HKDF(salt, X25519(eph, X25519_dest), "USMD-NCP-v1"||eph||X25519_dest)
    AAD = header || eph || salt || index || count     (nonce excluded)

A new ephemeral key per message; fragments of one message share it and the
salt. Reassembly by (source address, eph, salt) within 10 s, at most 16
messages per source. Multi-fragment messages are acknowledged (type 0x03) at
the first fragment, after each 100 ms without a new one, and at the end; the
sender retransmits unacknowledged fragments after 2 s, doubling, 3 tries. A
single-fragment request is acknowledged by its response, and retransmitted
with the same request identifier.

Denial of service [10]: datagrams are rate limited per source address before
any work, a new reassembly from an address unknown to the NIT is refused
before the X25519 agreement (except Request_approval, itself rate limited),
and reassembly state is bounded per source and globally [5.7].
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from usmd_rdsh.node.crypto import AgreementKey, CryptoError, SigningKey, hkdf, open_sealed, seal
from usmd_rdsh.node.ncp.codec import (
    Message,
    MessageType,
    fragment_ack_body,
    parse_fragment_ack,
)
from usmd_rdsh.node.wire import HEADER_SIZE, FrameHeader, WireError, now_ms

log = logging.getLogger("usmd_rdsh.ncp")

PORT = 9992
MAX_UDP = 1200
MAX_PLAIN = 1111
MAX_FRAGMENTS = 1024
ENVELOPE = 64
REASSEMBLY_S = 10.0
RETRANSMIT_S = 2.0
ATTEMPTS = 3
ACK_DELAY_S = 0.1
RESPONSE_CACHE_S = 60.0
PER_SOURCE = 16
MAX_ASSEMBLIES = 256  # messages in reassembly, every source together [5.7]
MAX_BUFFERED = 16 * 1024 * 1024  # plaintext bytes held by those messages [5.7]
MAX_COMPLETED = 4096  # reassembled groups remembered to ignore late duplicates
DATAGRAMS_PER_S = 200  # per source address, before any work [10]
APPROVALS_PER_S = 5  # new Request_approval messages per source address [10]
REQUEST_APPROVAL = 0x0005


class NcpTimeout(Exception):
    """No response after every retransmission."""


class NcpRemoteError(Exception):
    """The peer answered with an error message."""

    def __init__(self, code: int, text: str = "") -> None:
        super().__init__(f"NCP error 0x{code:04X}{': ' + text if text else ''}")
        self.code = code
        self.text = text


def _key(ephemeral_public: bytes, shared: bytes, salt: bytes, dest_x25519: bytes) -> bytes:
    return hkdf(shared, salt=salt, info=b"USMD-NCP-v1" + ephemeral_public + dest_x25519,
                length=32)


def seal_message(event: int, plaintext: bytes, dest_x25519: bytes) -> tuple[list[bytes], bytes]:
    """Fragment and encrypt; returns the datagrams and the salt."""
    if len(plaintext) > MAX_PLAIN * MAX_FRAGMENTS:
        raise WireError("message larger than 1024 fragments")
    ephemeral = AgreementKey.generate()
    salt = secrets.token_bytes(16)
    key = _key(ephemeral.public, ephemeral.agree(dest_x25519), salt, dest_x25519)
    slices = [plaintext[i:i + MAX_PLAIN] for i in range(0, len(plaintext), MAX_PLAIN)] or [b""]
    count = len(slices)
    out = []
    for index, chunk in enumerate(slices):
        nonce = secrets.token_bytes(12)
        header = FrameHeader(event, ENVELOPE + len(chunk) + 16).encode()
        aad = header + ephemeral.public + salt + struct.pack("!HH", index, count)
        sealed = seal(key, nonce, chunk, aad)
        out.append(header + ephemeral.public + salt + nonce + struct.pack("!HH", index, count)
                   + sealed)
    return out, salt


@dataclass(frozen=True, slots=True)
class Fragment:
    event: int
    ephemeral: bytes
    salt: bytes
    nonce: bytes
    index: int
    count: int
    sealed: bytes
    aad: bytes


def parse_fragment(data: bytes) -> Fragment:
    if len(data) > MAX_UDP or len(data) < HEADER_SIZE + ENVELOPE + 16:
        raise WireError("fragment size")
    header = FrameHeader.decode(data)
    eph, salt, nonce = data[9:41], data[41:57], data[57:69]
    index, count = struct.unpack_from("!HH", data, 69)
    if not 1 <= count <= MAX_FRAGMENTS or index >= count:
        raise WireError("bad fragment index or count")
    if len(data) - 73 - 16 > MAX_PLAIN:
        raise WireError("fragment plaintext above 1111 bytes")
    return Fragment(header.event, eph, salt, nonce, index, count, data[73:],
                    data[:9] + eph + salt + data[69:73])


@dataclass
class _Assembly:  # pylint: disable=too-many-instance-attributes
    event: int
    count: int
    key: bytes
    started: float
    pieces: dict[int, bytes] = field(default_factory=dict)
    last_fragment: float = 0.0
    sender: bytes | None = None  # Ed25519 read from fragment 0
    ack_task: asyncio.Task | None = None
    done: bool = False
    size: int = 0  # plaintext bytes buffered


@dataclass
class _Completed:
    """A reassembled message, remembered to answer its retransmissions."""

    expiry: float
    key: bytes
    request: tuple[bytes, int] | None = None  # (sender, request id) once known


class RateLimiter:
    """At most *rate* events per one-second window and per source [NCP-02 10].

    The table of sources is bounded: when full, the oldest window is evicted,
    so spoofed addresses cannot grow it without limit.
    """

    def __init__(self, rate: int, max_sources: int = 4096) -> None:
        self.rate = rate
        self.max_sources = max_sources
        self._windows: dict[str, list[float]] = {}  # source -> [start, count]

    def allow(self, source: str, now: float) -> bool:
        """Count one event from *source*; False when over the rate."""
        window = self._windows.get(source)
        if window is None or now - window[0] >= 1.0:
            self._windows.pop(source, None)
            while len(self._windows) >= self.max_sources:
                del self._windows[next(iter(self._windows))]
            self._windows[source] = [now, 1]
            return self.rate > 0
        window[1] += 1
        return window[1] <= self.rate


@dataclass
class _Outgoing:
    datagrams: list[bytes]
    address: tuple[str, int]
    acked: set[int] = field(default_factory=set)


Handler = Callable[[Message, tuple[str, int]], Awaitable[tuple[int, bytes] | None]]


class NcpTransport(asyncio.DatagramProtocol):  # pylint: disable=too-many-instance-attributes
    """Sends requests, answers them, and keeps every reliability promise of 5.7."""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        signing: SigningKey,
        static: AgreementKey,
        *,
        x25519_of: Callable[[bytes, str], bytes | None],
        handler: Handler,
        freshness_ms: int = 30_000,
        retransmit_s: float = RETRANSMIT_S,
        attempts: int = ATTEMPTS,
        address_known: Callable[[str], bool] | None = None,
        reply_x25519: Callable[[Message], bytes | None] | None = None,
    ) -> None:
        """``attempts`` counts transmissions of a request (first send
        included), waited 2 s, 4 s, 8 s... before giving up [5.7].

        ``address_known(ip)`` tells whether the NIT holds the address; None
        accepts every address [10]. ``reply_x25519(request)`` supplies the
        requester's X25519 when ``x25519_of`` does not know it (e.g. a
        refused Request_approval from a node not yet in the table).
        """
        self._signing = signing
        self._static = static
        self._x25519_of = x25519_of  # (ed25519, address) -> X25519 of a peer
        self._handler = handler
        self._address_known = address_known
        self._reply_x25519 = reply_x25519
        self.freshness_ms = freshness_ms
        self.retransmit_s = retransmit_s
        self.attempts = attempts
        self._transport: asyncio.DatagramTransport | None = None
        self._assemblies: dict[tuple[str, bytes, bytes], _Assembly] = {}
        self._completed: dict[tuple[str, bytes, bytes], _Completed] = {}
        self._buffered = 0
        self.datagram_limit = RateLimiter(DATAGRAMS_PER_S)
        self.approval_limit = RateLimiter(APPROVALS_PER_S)
        self._outgoing: dict[bytes, _Outgoing] = {}  # by salt
        self._waiting: dict[tuple[bytes, int], asyncio.Future] = {}
        self._responses: dict[tuple[bytes, int], tuple[float, list[bytes]]] = {}
        self._executing: set[tuple[bytes, int]] = set()
        self.stats = {"sent": 0, "received": 0, "dropped": 0, "retransmitted": 0}

    # -- asyncio plumbing ----------------------------------------------------

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self._transport = transport

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        if not self.datagram_limit.allow(addr[0], time.monotonic()):
            self.stats["dropped"] += 1  # over the per-source rate, before any work [10]
            return
        try:
            self._on_fragment(data, (addr[0], addr[1]))
        except (WireError, CryptoError) as exc:
            self.stats["dropped"] += 1
            log.debug("[NCP] Dropped fragment from %s: %s", addr[0], exc)

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        for future in self._waiting.values():
            if not future.done():
                future.cancel()
        for group in list(self._assemblies):
            self._drop_assembly(group)

    def _send(self, datagrams: list[bytes], address: tuple[str, int]) -> None:
        if self._transport is None:
            return
        for datagram in datagrams:
            self._transport.sendto(datagram, address)
            self.stats["sent"] += 1

    # -- sending -------------------------------------------------------------

    def _build(self, event: int, kind: int, request_id: int, body: bytes,
               recipient_ed: bytes, recipient_x: bytes) -> tuple[list[bytes], bytes]:
        message = Message(event, kind, request_id, now_ms(), self._signing.public, body)
        plaintext = message.encode(self._signing, recipient_ed)
        return seal_message(event, plaintext, recipient_x)

    async def request(  # pylint: disable=too-many-arguments
        self,
        address: tuple[str, int],
        event: int,
        body: bytes,
        recipient_ed: bytes,
        recipient_x: bytes,
    ) -> bytes:
        """Send a request and await its response body; NcpRemoteError or NcpTimeout."""
        request_id = secrets.randbits(64) or 1
        datagrams, salt = self._build(event, MessageType.REQUEST, request_id, body,
                                      recipient_ed, recipient_x)
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        key = (recipient_ed, request_id)
        self._waiting[key] = future
        outgoing = _Outgoing(datagrams, address)
        self._outgoing[salt] = outgoing
        try:
            delay = self.retransmit_s
            self._send(datagrams, address)
            # 2 s, 4 s, 8 s then failure: no extra doubled wait after the
            # last transmission [5.7].
            tries = max(1, self.attempts)
            for attempt in range(tries):
                try:
                    return await asyncio.wait_for(asyncio.shield(future), delay)
                except asyncio.TimeoutError:
                    if attempt == tries - 1:
                        break
                    # Multi-fragment: only what was not acknowledged; a single
                    # fragment is resent whole, same request id [5.7].
                    pending = (
                        [d for i, d in enumerate(datagrams) if i not in outgoing.acked]
                        if len(datagrams) > 1 else datagrams
                    )
                    self._send(pending, address)
                    self.stats["retransmitted"] += 1
                    delay *= 2
            raise NcpTimeout(f"no response from {address[0]} to 0x{event:04X}")
        finally:
            self._waiting.pop(key, None)
            self._outgoing.pop(salt, None)

    def _reply(self, request: Message, kind: int, body: bytes, address: tuple[str, int],
               recipient_x: bytes) -> list[bytes]:
        datagrams, salt = self._build(request.event, kind, request.request_id, body,
                                      request.sender, recipient_x)
        self._outgoing[salt] = _Outgoing(datagrams, address)
        self._send(datagrams, address)
        if len(datagrams) > 1:
            asyncio.get_running_loop().create_task(self._retransmit_reply(salt))
        return datagrams

    async def _retransmit_reply(self, salt: bytes) -> None:
        delay = self.retransmit_s
        try:
            for _ in range(max(1, self.attempts) - 1):  # same schedule as request()
                await asyncio.sleep(delay)
                outgoing = self._outgoing.get(salt)
                if outgoing is None or len(outgoing.acked) == len(outgoing.datagrams):
                    return
                self._send([d for i, d in enumerate(outgoing.datagrams)
                            if i not in outgoing.acked], outgoing.address)
                delay *= 2
        finally:
            self._outgoing.pop(salt, None)

    # -- receiving -----------------------------------------------------------

    def _on_fragment(self, data: bytes, address: tuple[str, int]) -> None:
        fragment = parse_fragment(data)
        group = (address[0], fragment.ephemeral, fragment.salt)
        loop = asyncio.get_running_loop()
        now = loop.time()
        self._expire(now)
        completed = self._completed.get(group)
        if completed is not None:
            # A retransmission of a reassembled message: authenticated by the
            # AEAD (no X25519), then answered from the response cache [5.7].
            open_sealed(completed.key, fragment.nonce, fragment.sealed, fragment.aad)
            cached = self._responses.get(completed.request) if completed.request else None
            if cached is not None:
                self._send(cached[1], address)
            return
        assembly = self._assemblies.get(group)
        if assembly is None:
            assembly = self._new_assembly(fragment, address[0], now)
        if assembly.done or fragment.count != assembly.count or \
                fragment.event != assembly.event:
            return
        if fragment.index in assembly.pieces:
            return  # duplicate, not worth a decryption
        piece = open_sealed(assembly.key, fragment.nonce, fragment.sealed, fragment.aad)
        if self._buffered + len(piece) > MAX_BUFFERED:
            raise WireError("reassembly memory exhausted")
        self._assemblies[group] = assembly
        assembly.pieces[fragment.index] = piece
        assembly.size += len(piece)
        self._buffered += len(piece)
        assembly.last_fragment = now
        self.stats["received"] += 1
        if fragment.index == 0 and len(piece) >= 49:
            assembly.sender = piece[17:49]
        if assembly.count > 1:
            self._schedule_ack(group, assembly, fragment.salt, address)
        if len(assembly.pieces) == assembly.count:
            assembly.done = True
            plaintext = b"".join(assembly.pieces[i] for i in range(assembly.count))
            self._drop_assembly(group)
            completed = _Completed(now + RESPONSE_CACHE_S, assembly.key)
            self._completed[group] = completed
            while len(self._completed) > MAX_COMPLETED:
                del self._completed[next(iter(self._completed))]
            loop.create_task(self._on_message(fragment.event, plaintext, address, completed))

    def _new_assembly(self, fragment: Fragment, source: str, now: float) -> _Assembly:
        """Every cheap check comes before the X25519 agreement [10, 5.7]."""
        if fragment.event == REQUEST_APPROVAL:
            if not self.approval_limit.allow(source, now):
                raise WireError("Request_approval rate exceeded for this source")
        elif self._address_known is not None and not self._address_known(source):
            raise WireError("address absent from the NIT")
        if len(self._assemblies) >= MAX_ASSEMBLIES:
            raise WireError("too many messages in reassembly")
        if sum(1 for g in self._assemblies if g[0] == source) >= PER_SOURCE:
            raise WireError("too many messages in reassembly from this source")
        shared = self._static.agree(fragment.ephemeral)
        return _Assembly(fragment.event, fragment.count,
                         _key(fragment.ephemeral, shared, fragment.salt, self._static.public),
                         now)

    def _drop_assembly(self, group: tuple[str, bytes, bytes]) -> None:
        assembly = self._assemblies.pop(group, None)
        if assembly is None:
            return
        self._buffered -= assembly.size
        assembly.size = 0
        assembly.pieces = {i: b"" for i in assembly.pieces}  # indices kept for the acks
        if assembly.ack_task is not None and not assembly.done:
            assembly.ack_task.cancel()

    def _schedule_ack(self, group, assembly: _Assembly, salt: bytes, address) -> None:
        """First fragment, every 100 ms of silence, and completion [5.7]."""
        first = len(assembly.pieces) == 1
        complete = len(assembly.pieces) == assembly.count
        if first or complete:
            self._send_ack(assembly, salt, address)
        if assembly.ack_task is None and not complete:
            async def ticker() -> None:
                while not assembly.done:
                    await asyncio.sleep(ACK_DELAY_S)
                    loop_now = asyncio.get_running_loop().time()
                    if loop_now - assembly.last_fragment >= ACK_DELAY_S and not assembly.done:
                        self._send_ack(assembly, salt, address)
                    if loop_now - assembly.started > REASSEMBLY_S:
                        assembly.ack_task = None
                        self._drop_assembly(group)
                        return
            assembly.ack_task = asyncio.get_running_loop().create_task(ticker())

    def _send_ack(self, assembly: _Assembly, salt: bytes, address) -> None:
        if assembly.sender is None:
            return  # sender unknown until fragment 0: the retransmission covers it
        recipient_x = self._x25519_of(assembly.sender, address[0])
        if recipient_x is None:
            return
        body = fragment_ack_body(salt, assembly.count, set(assembly.pieces))
        datagrams, _ = self._build(assembly.event, MessageType.FRAGMENT_ACK, 0, body,
                                   assembly.sender, recipient_x)
        self._send(datagrams, address)

    def _expire(self, now: float) -> None:
        for group, assembly in list(self._assemblies.items()):
            if now - assembly.started > REASSEMBLY_S:
                self._drop_assembly(group)
        self._completed = {g: c for g, c in self._completed.items() if c.expiry > now}
        self._responses = {k: v for k, v in self._responses.items() if v[0] > now}

    async def _on_message(self, event: int, plaintext: bytes, address: tuple[str, int],
                          completed: _Completed | None = None) -> None:
        try:
            message = Message.decode(event, plaintext)
        except WireError:
            self.stats["dropped"] += 1
            return
        try:
            message.verify(self._signing.public)
        except CryptoError:
            self.stats["dropped"] += 1
            return  # an unauthenticated message is never answered [10]
        if message.type != MessageType.REQUEST and \
                abs(message.timestamp - now_ms()) > self.freshness_ms:
            # Requests are answered with error 0x0002 by the handler; a stale
            # response, error or acknowledgement is only dropped [8].
            self.stats["dropped"] += 1
            log.debug("[NCP] Dropped stale message type 0x%02X from %s", message.type,
                      address[0])
            return
        if message.type == MessageType.FRAGMENT_ACK:
            salt, _count, received = parse_fragment_ack(message.body)
            outgoing = self._outgoing.get(salt)
            if outgoing is not None:
                outgoing.acked |= received
            return
        if message.type in (MessageType.RESPONSE, MessageType.ERROR):
            future = self._waiting.get((message.sender, message.request_id))
            if future is not None and not future.done():
                if message.type == MessageType.ERROR:
                    from usmd_rdsh.node.ncp.codec import parse_error  # pylint: disable=import-outside-toplevel
                    code, text = parse_error(message.body)
                    future.set_exception(NcpRemoteError(code, text))
                else:
                    future.set_result(message.body)
            return
        if completed is not None:
            completed.request = (message.sender, message.request_id)
        await self._on_request(message, address)

    async def _on_request(self, message: Message, address: tuple[str, int]) -> None:
        key = (message.sender, message.request_id)
        loop_now = asyncio.get_running_loop().time()
        cached = self._responses.get(key)
        if cached is not None:
            self._send(cached[1], address)  # duplicate: resend, never re-execute
            return
        if key in self._executing:
            return
        recipient_x = self._x25519_of(message.sender, address[0])
        self._executing.add(key)
        try:
            result = await self._handler(message, address)
        except Exception:  # pylint: disable=broad-except
            log.exception("[NCP] Handler for 0x%04X failed", message.event)
            result = (MessageType.ERROR, (0x0004).to_bytes(2, "big"))
        finally:
            self._executing.discard(key)
        if result is None:
            return  # ignored without a response
        kind, body = result
        recipient_x = recipient_x or self._x25519_of(message.sender, address[0])
        if recipient_x is None and self._reply_x25519 is not None:
            recipient_x = self._reply_x25519(message)
        if recipient_x is None:
            return
        datagrams = self._reply(message, kind, body, address, recipient_x)
        self._responses[key] = (loop_now + RESPONSE_CACHE_S, datagrams)
