"""The one-round-trip handshake and the key schedule [SP-01 7.3, 7.4].

    Initiation (0x0001), 165 bytes: header | index_I (4) | e_I (32) | ts (8)
        | AEAD_k_init(Ed_I || sig_I)  (96 + 16), nonce 0, AAD = bytes 0..52
    Response (0x0002), 161 bytes: header | index_R (4) | index_I (4) | e_R (32)
        | AEAD_k_resp(Ed_R || sig_R)  (96 + 16), nonce 0, AAD = bytes 0..48

    k_init = HKDF(salt="USMD-SP-v1", ikm=DH(e_I, S_R), info="init"||e_I||S_R)
    sig_I  = Ed25519(I, "USMD-SP-v1-init"||index_I||e_I||ts||Ed_R||S_R)
    h      = SHA-256(initiation)
    k_resp = HKDF(salt=h, ikm=DH(e_R, e_I)||DH(s_R, e_I), info="resp"||e_R)
    sig_R  = Ed25519(R, "USMD-SP-v1-resp"||h||index_R||index_I||e_R||Ed_I)
    okm    = HKDF(salt=SHA-256(initiation||response),
                  ikm=DH(e_I, e_R)||DH(e_I, S_R), info="USMD-SP-v1-session", L=64)
    k_IR = okm[0:32], k_RI = okm[32:64]

The handshake AEADs use a zero nonce: k_init and k_resp are single-use, the
ephemeral keys being new for every attempt, retransmissions included.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
from dataclasses import dataclass

from usmd_rdsh.node.crypto import (
    AgreementKey,
    CryptoError,
    SigningKey,
    hkdf,
    open_sealed,
    seal,
    verify,
)
from usmd_rdsh.node.wire import HEADER_SIZE, FrameHeader, WireError, frame

EVENT_INITIATION = 0x0001
EVENT_RESPONSE = 0x0002
EVENT_DATA = 0x0003
INITIATION_SIZE = 165
RESPONSE_SIZE = 161
_ZERO_NONCE = bytes(12)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def new_index() -> int:
    """A random local session index."""
    return secrets.randbits(32)


@dataclass
class InitiatorState:
    """What I keeps between its initiation and R's response."""

    index: int
    ephemeral: AgreementKey
    initiation: bytes
    responder_ed25519: bytes
    responder_x25519: bytes
    dh1: bytes

    def forget(self) -> None:
        """Erase the ephemeral secrets [7.4]: as far as Python lets us, drop them."""
        self.dh1 = bytes(len(self.dh1))
        self.ephemeral = None  # type: ignore[assignment]


@dataclass(frozen=True)
class SessionKeys:
    """Result of a handshake, for either side."""

    local_index: int
    remote_index: int
    send_key: bytes
    receive_key: bytes
    peer_ed25519: bytes
    initiator: bool


def build_initiation(  # pylint: disable=too-many-arguments
    signing: SigningKey,
    responder_ed25519: bytes,
    responder_x25519: bytes,
    timestamp: int,
    *,
    index: int | None = None,
    ephemeral: AgreementKey | None = None,
) -> tuple[bytes, InitiatorState]:
    """I's initiation and the state it keeps."""
    index = new_index() if index is None else index
    ephemeral = ephemeral or AgreementKey.generate()
    e_i = ephemeral.public
    dh1 = ephemeral.agree(responder_x25519)
    k_init = hkdf(dh1, salt=b"USMD-SP-v1", info=b"init" + e_i + responder_x25519, length=32)
    message = (b"USMD-SP-v1-init" + struct.pack("!I", index) + e_i
               + struct.pack("!Q", timestamp) + responder_ed25519 + responder_x25519)
    sig = signing.sign(message)
    clear_part = struct.pack("!I", index) + e_i + struct.pack("!Q", timestamp)
    header = FrameHeader(EVENT_INITIATION, 4 + 32 + 8 + 112).encode()
    aad = header + clear_part
    sealed = seal(k_init, _ZERO_NONCE, signing.public + sig, aad)
    data = aad + sealed
    assert len(data) == INITIATION_SIZE
    return data, InitiatorState(index, ephemeral, data, responder_ed25519, responder_x25519, dh1)


@dataclass(frozen=True)
class Initiation:
    """A decoded and authenticated initiation."""

    index: int
    ephemeral: bytes
    timestamp: int
    initiator_ed25519: bytes
    raw: bytes


def parse_initiation_header(data: bytes) -> tuple[int, bytes, int]:
    """Cheap checks first [7.7]: format; returns (index_I, e_I, timestamp)."""
    if len(data) != INITIATION_SIZE:
        raise WireError("initiation is 165 bytes")
    header = FrameHeader.decode(data)
    if header.event != EVENT_INITIATION:
        raise WireError("not an initiation")
    index = struct.unpack_from("!I", data, HEADER_SIZE)[0]
    e_i = data[13:45]
    timestamp = struct.unpack_from("!Q", data, 45)[0]
    return index, e_i, timestamp


@dataclass(frozen=True)
class OpenedInitiation:
    """Decrypted under k_init, signature not yet checked [7.7]."""

    initiation: Initiation
    signature: bytes
    message: bytes


def open_initiation(data: bytes, static: AgreementKey, my_ed25519: bytes) -> OpenedInitiation:
    """Decrypt and verify sig_I (the remaining checks of [7.7], in order)."""
    index, e_i, timestamp = parse_initiation_header(data)
    dh1 = static.agree(e_i)
    k_init = hkdf(dh1, salt=b"USMD-SP-v1", info=b"init" + e_i + static.public, length=32)
    clear = open_sealed(k_init, _ZERO_NONCE, data[53:], data[:53])
    ed_i, sig = clear[:32], clear[32:]
    message = (b"USMD-SP-v1-init" + struct.pack("!I", index) + e_i
               + struct.pack("!Q", timestamp) + my_ed25519 + static.public)
    return OpenedInitiation(Initiation(index, e_i, timestamp, ed_i, data), sig, message)


def verify_initiation(opened: OpenedInitiation) -> Initiation:
    """Check sig_I, the last and most expensive check of [7.7]."""
    verify(opened.initiation.initiator_ed25519, opened.signature, opened.message)
    return opened.initiation


def build_response(  # pylint: disable=too-many-arguments
    signing: SigningKey,
    static: AgreementKey,
    initiation: Initiation,
    *,
    index: int | None = None,
    ephemeral: AgreementKey | None = None,
) -> tuple[bytes, SessionKeys]:
    """R's response and R's session keys."""
    index = new_index() if index is None else index
    ephemeral = ephemeral or AgreementKey.generate()
    e_r = ephemeral.public
    h = _sha256(initiation.raw)
    dh2 = ephemeral.agree(initiation.ephemeral)
    dh3 = static.agree(initiation.ephemeral)
    k_resp = hkdf(dh2 + dh3, salt=h, info=b"resp" + e_r, length=32)
    message = (b"USMD-SP-v1-resp" + h + struct.pack("!II", index, initiation.index)
               + e_r + initiation.initiator_ed25519)
    sig = signing.sign(message)
    header = FrameHeader(EVENT_RESPONSE, 4 + 4 + 32 + 112).encode()
    aad = header + struct.pack("!II", index, initiation.index) + e_r
    data = aad + seal(k_resp, _ZERO_NONCE, signing.public + sig, aad)
    assert len(data) == RESPONSE_SIZE
    okm = hkdf(dh2 + dh3, salt=_sha256(initiation.raw + data),
               info=b"USMD-SP-v1-session", length=64)
    keys = SessionKeys(index, initiation.index, okm[32:], okm[:32],
                       initiation.initiator_ed25519, initiator=False)
    del ephemeral, dh2, dh3  # e_R is not kept beyond the derivation [7.4]
    return data, keys


def response_indexes(data: bytes) -> tuple[int, int]:
    """(index_R, index_I) of a response, after the format checks."""
    if len(data) != RESPONSE_SIZE:
        raise WireError("response is 161 bytes")
    header = FrameHeader.decode(data)
    if header.event != EVENT_RESPONSE:
        raise WireError("not a response")
    return struct.unpack_from("!II", data, HEADER_SIZE)


def open_response(data: bytes, state: InitiatorState, my_ed25519: bytes) -> SessionKeys:
    """I's processing of R's response: decrypt, check Ed_R and sig_R, derive."""
    index_r, index_i = response_indexes(data)
    if index_i != state.index:
        raise WireError("response to another initiation")
    e_r = data[17:49]
    h = _sha256(state.initiation)
    dh2 = state.ephemeral.agree(e_r)
    k_resp = hkdf(dh2 + state.dh1, salt=h, info=b"resp" + e_r, length=32)
    clear = open_sealed(k_resp, _ZERO_NONCE, data[49:], data[:49])
    ed_r, sig = clear[:32], clear[32:]
    if ed_r != state.responder_ed25519:
        raise CryptoError("response signed by another key than the expected responder")
    message = (b"USMD-SP-v1-resp" + h + struct.pack("!II", index_r, index_i)
               + e_r + my_ed25519)
    verify(ed_r, sig, message)
    okm = hkdf(dh2 + state.dh1, salt=_sha256(state.initiation + data),
               info=b"USMD-SP-v1-session", length=64)
    state.forget()
    return SessionKeys(state.index, index_r, okm[:32], okm[32:], ed_r, initiator=True)


__all__ = [
    "EVENT_DATA", "EVENT_INITIATION", "EVENT_RESPONSE", "InitiatorState", "OpenedInitiation",
    "SessionKeys",
    "build_initiation", "build_response", "frame", "open_initiation", "open_response",
    "parse_initiation_header", "response_indexes", "verify_initiation",
]
