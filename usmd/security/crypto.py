"""Cryptographic primitives for USMD-RDSH.

All network communication in USMD-RDSH is secured using:

- **Ed25519**: Digital signatures for identity and packet authentication.
- **X25519**: Ephemeral Diffie-Hellman key exchange for session keys.
- **HKDF** (HMAC-based Key Derivation Function): Derives symmetric keys
  from shared secrets.
- **AEAD** ChaCha20-Poly1305: Authenticated encryption for NCP/SP payload.

This module provides a thin, consistent wrapper over the ``cryptography``
library so that the rest of USMD-RDSH never imports raw crypto primitives
directly.

Examples:
    >>> # Generate an Ed25519 identity key pair
    >>> priv, pub = Ed25519Pair.generate()
    >>> len(pub)
    32

    >>> # Sign and verify
    >>> sig = Ed25519Pair.sign(priv, b"hello world")
    >>> Ed25519Pair.verify(pub, b"hello world", sig).is_ok()
    True

    >>> # X25519 key exchange
    >>> a_priv, a_pub = X25519Pair.generate()
    >>> b_priv, b_pub = X25519Pair.generate()
    >>> shared_a = X25519Pair.exchange(a_priv, b_pub)
    >>> shared_b = X25519Pair.exchange(b_priv, a_pub)
    >>> shared_a == shared_b
    True
"""

import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.exceptions import InvalidSignature, InvalidTag

from ..utils.errors import Error, ErrorKind
from ..utils.result import Result


class Ed25519Pair:
    """Utilities for Ed25519 key generation, signing and verification.

    Ed25519 is used throughout USMD-RDSH for:
    - Node identity (every node has an Ed25519 key pair).
    - NNDP packet signatures (Here I Am).
    - Endorsement packet signatures.
    - NCP over QUIC/TLS1.3 authentication.

    All keys are represented as raw bytes:
    - Private key: 32 bytes (raw seed).
    - Public key: 32 bytes (raw).

    Examples:
        >>> priv, pub = Ed25519Pair.generate()
        >>> len(pub)
        32
        >>> sig = Ed25519Pair.sign(priv, b"data")
        >>> Ed25519Pair.verify(pub, b"data", sig).is_ok()
        True
    """

    @staticmethod
    def generate() -> tuple[bytes, bytes]:
        """Generate a new Ed25519 key pair.

        Returns:
            tuple[bytes, bytes]: (private_key_bytes, public_key_bytes)
                Private key is the 32-byte raw seed.
                Public key is the 32-byte raw public key.

        Example:
            >>> priv, pub = Ed25519Pair.generate()
            >>> len(priv), len(pub)
            (32, 32)
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_bytes = private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        pub_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv_bytes, pub_bytes

    @staticmethod
    def sign(private_key_bytes: bytes, data: bytes) -> bytes:
        """Sign data with an Ed25519 private key.

        Args:
            private_key_bytes: 32-byte raw Ed25519 private key seed.
            data: The bytes to sign.

        Returns:
            bytes: 64-byte Ed25519 signature.

        Example:
            >>> priv, pub = Ed25519Pair.generate()
            >>> sig = Ed25519Pair.sign(priv, b"hello")
            >>> len(sig)
            64
        """
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        return private_key.sign(data)

    @staticmethod
    def verify(
        public_key_bytes: bytes, data: bytes, signature: bytes
    ) -> Result[None, Error]:
        """Verify an Ed25519 signature.

        Args:
            public_key_bytes: 32-byte raw Ed25519 public key.
            data: The data that was signed.
            signature: 64-byte signature to verify.

        Returns:
            Result[None, Error]: Ok(None) if valid, Err if the signature is invalid.

        Examples:
            >>> priv, pub = Ed25519Pair.generate()
            >>> sig = Ed25519Pair.sign(priv, b"test")
            >>> Ed25519Pair.verify(pub, b"test", sig).is_ok()
            True
            >>> Ed25519Pair.verify(pub, b"tampered", sig).is_err()
            True
        """
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, data)
            return Result.Ok(None)
        except InvalidSignature:
            return Result.Err(
                Error.new(
                    ErrorKind.INVALID_SIGNATURE, "Ed25519 signature verification failed"
                )
            )
        except (ValueError, TypeError) as exc:
            return Result.Err(
                Error.new(ErrorKind.CRYPTO_ERROR, f"Ed25519 verify error: {exc}")
            )


class X25519Pair:
    """Utilities for X25519 Diffie-Hellman key exchange.

    X25519 is used to derive shared session keys between pairs of nodes.
    In USMD-RDSH, each node's session key (included in the endorsement
    packet) is an X25519 public key.

    Examples:
        >>> a_priv, a_pub = X25519Pair.generate()
        >>> b_priv, b_pub = X25519Pair.generate()
        >>> X25519Pair.exchange(a_priv, b_pub) == X25519Pair.exchange(b_priv, a_pub)
        True
    """

    @staticmethod
    def generate() -> tuple[bytes, bytes]:
        """Generate a new X25519 key pair.

        Returns:
            tuple[bytes, bytes]: (private_key_bytes, public_key_bytes)
                Both are 32 bytes in raw format.

        Example:
            >>> priv, pub = X25519Pair.generate()
            >>> len(priv), len(pub)
            (32, 32)
        """
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        priv_bytes = private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        pub_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv_bytes, pub_bytes

    @staticmethod
    def exchange(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
        """Perform X25519 Diffie-Hellman and return the shared secret.

        Args:
            private_key_bytes: 32-byte raw X25519 private key.
            peer_public_key_bytes: 32-byte raw X25519 public key of the peer.

        Returns:
            bytes: 32-byte shared secret.

        Example:
            >>> a_priv, a_pub = X25519Pair.generate()
            >>> b_priv, b_pub = X25519Pair.generate()
            >>> s1 = X25519Pair.exchange(a_priv, b_pub)
            >>> s2 = X25519Pair.exchange(b_priv, a_pub)
            >>> s1 == s2
            True
        """
        private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        return private_key.exchange(peer_public_key)


class HkdfDeriver:
    """HKDF key derivation from a shared secret.

    HKDF is used to derive symmetric encryption keys from an X25519 shared
    secret.

    Examples:
        >>> secret = b"\\x00" * 32
        >>> key = HkdfDeriver.derive(secret, length=32, info=b"ncp-session")
        >>> len(key)
        32
    """

    @staticmethod
    def derive(
        shared_secret: bytes,
        length: int = 32,
        salt: bytes = b"",
        info: bytes = b"usmd-rdsh-v1",
    ) -> bytes:
        """Derive a symmetric key from a shared secret using HKDF-SHA256.

        Args:
            shared_secret: The input key material (e.g. X25519 shared secret).
            length: Number of output bytes. Default: 32.
            salt: Optional salt bytes. Default: empty.
            info: Context/application-specific info bytes.

        Returns:
            bytes: Derived key of ``length`` bytes.

        Example:
            >>> secret = b"s" * 32
            >>> key = HkdfDeriver.derive(secret, length=32)
            >>> len(key)
            32
        """
        hkdf = HKDF(
            algorithm=SHA256(),
            length=length,
            salt=salt or None,
            info=info,
        )
        return hkdf.derive(shared_secret)


class AeadCipher:
    """ChaCha20-Poly1305 AEAD encryption/decryption.

    Used to encrypt and authenticate all NCP and SP payloads once a session
    key has been derived via HKDF.

    Examples:
        >>> key = os.urandom(32)
        >>> cipher = AeadCipher(key)
        >>> nonce = os.urandom(12)
        >>> ct = cipher.encrypt(nonce, b"hello", b"aad")
        >>> cipher.decrypt(nonce, ct, b"aad")
        b'hello'
    """

    NONCE_SIZE = 12  # ChaCha20-Poly1305 requires a 12-byte nonce.

    def __init__(self, key: bytes) -> None:
        """Initialise with a 32-byte symmetric key.

        Args:
            key: 32-byte ChaCha20-Poly1305 key.

        Raises:
            ValueError: If the key is not 32 bytes.
        """
        if len(key) != 32:
            raise ValueError(f"AeadCipher key must be 32 bytes, got {len(key)}")
        self._chacha = ChaCha20Poly1305(key)

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt and authenticate plaintext.

        Args:
            nonce: 12-byte random nonce (must be unique per message).
            plaintext: Data to encrypt.
            aad: Additional authenticated data (not encrypted, but authenticated).

        Returns:
            bytes: Ciphertext + 16-byte Poly1305 tag.

        Example:
            >>> import os
            >>> key = os.urandom(32)
            >>> cipher = AeadCipher(key)
            >>> ct = cipher.encrypt(os.urandom(12), b"secret")
            >>> len(ct) > 0
            True
        """
        return self._chacha.encrypt(nonce, plaintext, aad or None)

    def decrypt(
        self, nonce: bytes, ciphertext: bytes, aad: bytes = b""
    ) -> Result[bytes, Error]:
        """Decrypt and verify ciphertext.

        Args:
            nonce: The 12-byte nonce used during encryption.
            ciphertext: Encrypted data including the Poly1305 tag.
            aad: Additional authenticated data (must match what was used on encrypt).

        Returns:
            Result[bytes, Error]: Ok with plaintext, or Err if authentication fails.

        Example:
            >>> import os
            >>> key = os.urandom(32)
            >>> cipher = AeadCipher(key)
            >>> nonce = os.urandom(12)
            >>> ct = cipher.encrypt(nonce, b"secret")
            >>> cipher.decrypt(nonce, ct).is_ok()
            True
        """
        try:
            plaintext = self._chacha.decrypt(nonce, ciphertext, aad or None)
            return Result.Ok(plaintext)
        except (InvalidTag, ValueError, TypeError) as exc:
            return Result.Err(
                Error.new(ErrorKind.INVALID_SIGNATURE, f"AEAD decryption failed: {exc}")
            )

    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a cryptographically random 12-byte nonce.

        Returns:
            bytes: 12 random bytes suitable for ChaCha20-Poly1305.

        Example:
            >>> nonce = AeadCipher.generate_nonce()
            >>> len(nonce)
            12
        """
        return os.urandom(AeadCipher.NONCE_SIZE)
