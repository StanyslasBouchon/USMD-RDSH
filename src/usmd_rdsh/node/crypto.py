"""The four primitives of version 1 [ARCH-02 4.5], and nothing else.

Ed25519 [RFC8032] signs, X25519 [RFC7748] agrees, HKDF-SHA-256 [RFC5869]
derives, ChaCha20-Poly1305 [RFC8439] seals. No negotiation: changing one is
a new major version.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_NO_ENC = serialization.NoEncryption()


class CryptoError(ValueError):
    """A signature, tag or key that does not verify."""


def b64u(data: bytes) -> str:
    """Base64url without padding, the text form of every key."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    """Inverse of :func:`b64u`."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SigningKey:
    """An Ed25519 private key."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise CryptoError("an Ed25519 seed is 32 bytes")
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.seed = seed
        self.public = self._key.public_key().public_bytes(_RAW, _RAW_PUB)

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate().private_bytes(_RAW, _RAW_PRIV, _NO_ENC))

    def sign(self, data: bytes) -> bytes:
        """64-byte signature."""
        return self._key.sign(data)


def verify(public: bytes, signature: bytes, data: bytes) -> None:
    """Raise CryptoError unless *signature* is *public*'s over *data*."""
    if len(public) != 32 or len(signature) != 64:
        raise CryptoError("malformed key or signature")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, data)
    except InvalidSignature as exc:
        raise CryptoError("bad signature") from exc


def is_valid(public: bytes, signature: bytes, data: bytes) -> bool:
    """Boolean form of :func:`verify`."""
    try:
        verify(public, signature, data)
    except CryptoError:
        return False
    return True


class AgreementKey:
    """An X25519 private key."""

    def __init__(self, private: bytes) -> None:
        if len(private) != 32:
            raise CryptoError("an X25519 key is 32 bytes")
        self._key = X25519PrivateKey.from_private_bytes(private)
        self.private = private
        self.public = self._key.public_key().public_bytes(_RAW, _RAW_PUB)

    @classmethod
    def generate(cls) -> "AgreementKey":
        return cls(X25519PrivateKey.generate().private_bytes(_RAW, _RAW_PRIV, _NO_ENC))

    def agree(self, peer_public: bytes) -> bytes:
        """The 32-byte shared secret; an all-zero result is refused [RFC7748 6.1]."""
        if len(peer_public) != 32:
            raise CryptoError("an X25519 public key is 32 bytes")
        shared = self._key.exchange(X25519PublicKey.from_public_bytes(peer_public))
        if shared == bytes(32):
            raise CryptoError("low-order X25519 point")
        return shared


def hkdf(secret: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA-256 extract-and-expand [RFC5869]."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


def seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """ChaCha20-Poly1305: ciphertext followed by the 16-byte tag."""
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def open_sealed(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Inverse of :func:`seal`; CryptoError on a bad tag."""
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError("authentication tag mismatch") from exc
