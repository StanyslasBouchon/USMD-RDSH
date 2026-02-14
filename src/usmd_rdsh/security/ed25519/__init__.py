"""Ed25519 key pair generation module.

This module provides functionality for generating Ed25519 cryptographic key pairs
using the PyNaCl library. Ed25519 is a modern elliptic curve signature scheme
that provides high security and performance.

The module includes:
    - Base64URL encoding utility for key representation
    - Ed25519KeyPair dataclass for storing key components
    - Key generation method that creates a complete key pair

All keys are encoded using Base64URL encoding (RFC 4648 Section 5), which is
URL-safe and padding-free, making them suitable for use in URLs, JSON, and
other text-based formats.

Example usage:

    >>> from usmd_rdsh.security.ed25519.generate import Ed25519KeyPair
    >>>
    >>> # Generate a new key pair
    >>> key_pair = Ed25519KeyPair.generate()
    >>>
    >>> # Access the encoded key components
    >>> print(f"Seed (32 bytes): {key_pair.seed32_b64u}")
    >>> print(f"Private key (64 bytes): {key_pair.priv64_b64u}")
    >>> print(f"Public key (32 bytes): {key_pair.pub32_b64u}")
    >>>
    >>> # The private key is the concatenation of seed + public key
    >>> # seed32_b64u + pub32_b64u = priv64_b64u (when decoded and concatenated)
"""

import base64
from dataclasses import dataclass
from typing import Optional

from nacl.encoding import RawEncoder
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from usmd_rdsh.utils.errors import Error, ErrorKind
from usmd_rdsh.utils.result import Result


def b64u(b: bytes) -> str:
    """Encode bytes to Base64URL string without padding.

    Base64URL is a URL-safe variant of Base64 encoding that uses '-' and '_'
    instead of '+' and '/', and omits padding characters ('='). This makes it
    suitable for use in URLs and other contexts where special characters might
    cause issues.

    Args:
        b: The bytes to encode

    Returns:
        str: Base64URL-encoded string without padding

    Example:
        >>> b64u(b"Hello, World!")
        'SGVsbG8sIFdvcmxkIQ'
        >>>
        >>> b64u(b"\\x00\\x01\\x02\\x03")
        'AAECAw'
        >>>
        >>> # Empty bytes
        >>> b64u(b"")
        ''
    """
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def unb64u(s: str) -> bytes:
    """Decode Base64URL string to bytes.

    Base64URL is a URL-safe variant of Base64 encoding. This function decodes
    a Base64URL-encoded string back to its original bytes representation. It
    automatically handles padding by adding the necessary '=' characters if
    the string length is not a multiple of 4.

    Args:
        s: The Base64URL-encoded string to decode

    Returns:
        bytes: The decoded bytes

    Example:
        >>> unb64u("SGVsbG8sIFdvcmxkIQ")
        b'Hello, World!'
        >>>
        >>> unb64u("AAECAw")
        b'\\x00\\x01\\x02\\x03'
        >>>
        >>> # Empty string
        >>> unb64u("")
        b''
        >>>
        >>> # Round-trip encoding/decoding
        >>> original = b"test data"
        >>> encoded = b64u(original)
        >>> decoded = unb64u(encoded)
        >>> assert decoded == original
    """
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass
class Ed25519KeyPair:
    """Represents an Ed25519 cryptographic key pair.

    Ed25519 is a modern elliptic curve signature scheme based on Curve25519.
    This dataclass stores the three key components in Base64URL-encoded format:

        - seed32_b64u: The 32-byte seed (secret key material)
        - priv64_b64u: The 64-byte private key (seed + public key concatenated)
        - pub32_b64u: The 32-byte public key (verification key)

    Attributes:
        seed32_b64u: Base64URL-encoded 32-byte seed
        priv64_b64u: Base64URL-encoded 64-byte private key
        pub32_b64u: Base64URL-encoded 32-byte public key

    Note:
        The private key (priv64_b64u) is the concatenation of the seed and
        public key: priv64 = seed32 + pub32. This format is used by some
        cryptographic libraries for compatibility.

    Example:
        >>> # Generate a new key pair
        >>> key_pair = Ed25519KeyPair.generate()
        >>>
        >>> # Access individual components
        >>> seed = key_pair.seed32_b64u
        >>> private_key = key_pair.priv64_b64u
        >>> public_key = key_pair.pub32_b64u
        >>>
        >>> # All components are Base64URL-encoded strings
        >>> assert isinstance(seed, str)
        >>> assert isinstance(private_key, str)
        >>> assert isinstance(public_key, str)
        >>>
        >>> # The seed is 32 bytes (43 characters in Base64URL)
        >>> import base64
        >>> decoded_seed = base64.urlsafe_b64decode(seed + "==")
        >>> assert len(decoded_seed) == 32
    """

    seed32_b64u: str
    priv64_b64u: str
    pub32_b64u: str
    sk: SigningKey

    @staticmethod
    def generate() -> "Ed25519KeyPair":
        """Generate a new Ed25519 key pair.

        This method creates a cryptographically secure Ed25519 key pair using
        the PyNaCl library. The key pair consists of:
            - A 32-byte seed (secret key material)
            - A 32-byte public key (verification key)
            - A 64-byte private key (seed + public key concatenated)

        All keys are encoded using Base64URL encoding for safe text representation.

        Returns:
            Ed25519KeyPair: A new key pair with all components Base64URL-encoded

        Example:
            >>> # Generate a new key pair
            >>> key_pair = Ed25519KeyPair.generate()
            >>>
            >>> # Each generation produces a unique key pair
            >>> key_pair1 = Ed25519KeyPair.generate()
            >>> key_pair2 = Ed25519KeyPair.generate()
            >>> assert key_pair1.seed32_b64u != key_pair2.seed32_b64u
            >>> assert key_pair1.pub32_b64u != key_pair2.pub32_b64u
            >>>
            >>> # Verify the structure
            >>> assert len(key_pair.seed32_b64u) > 0
            >>> assert len(key_pair.priv64_b64u) > 0
            >>> assert len(key_pair.pub32_b64u) > 0
            >>>
            >>> # The private key should be longer than the seed and public key
            >>> assert len(key_pair.priv64_b64u) > len(key_pair.seed32_b64u)
            >>> assert len(key_pair.priv64_b64u) > len(key_pair.pub32_b64u)
        """
        sk = SigningKey.generate()
        seed32 = sk.encode(encoder=RawEncoder)
        vk = sk.verify_key
        pub32 = vk.encode(encoder=RawEncoder)

        priv64 = seed32 + pub32

        return Ed25519KeyPair(
            seed32_b64u=b64u(seed32),
            priv64_b64u=b64u(priv64),
            pub32_b64u=b64u(pub32),
            sk=sk,
        )

    @staticmethod
    def from_b64u(
        *, seed32_b64u: Optional[str] = None, priv64_b64u: Optional[str] = None
    ) -> "Ed25519KeyPair":
        """Create a SigningKey from Base64URL-encoded seed or private key.

        This method reconstructs a PyNaCl SigningKey from either a 32-byte seed
        or a 64-byte private key, both provided as Base64URL-encoded strings.
        At least one of the parameters must be provided (not None).

        When a private key is provided, only the first 32 bytes (the seed
        portion) are used to create the SigningKey, as the remaining 32 bytes
        are the public key which can be derived from the seed.

        Args:
            seed32_b64u: Optional Base64URL-encoded 32-byte seed
            priv64_b64u: Optional Base64URL-encoded 64-byte private key

        Returns:
            SigningKey: A PyNaCl SigningKey instance that can be used for
                       signing operations

        Raises:
            ValueError: If both parameters are None, or if the decoded value
                       does not have the expected length (32 bytes for seed,
                       64 bytes for private key)

        Example:
            >>> from usmd_rdsh.security.ed25519.generate import Ed25519KeyPair
            >>> from nacl.signing import SigningKey
            >>>
            >>> # Generate a key pair
            >>> key_pair = Ed25519KeyPair.generate()
            >>>
            >>> # Reconstruct SigningKey from seed
            >>> sk_from_seed = Ed25519KeyPair.from_b64u(
            ...     seed32_b64u=key_pair.seed32_b64u,
            ...     priv64_b64u=None
            ... )
            >>> assert isinstance(sk_from_seed, SigningKey)
            >>>
            >>> # Reconstruct SigningKey from private key
            >>> sk_from_priv = Ed25519KeyPair.from_b64u(
            ...     seed32_b64u=None,
            ...     priv64_b64u=key_pair.priv64_b64u
            ... )
            >>> assert isinstance(sk_from_priv, SigningKey)
            >>>
            >>> # Both methods produce equivalent signing keys
            >>> # (they sign the same data identically)
            >>> test_message = b"Hello, World!"
            >>> sig1 = sk_from_seed.sign(test_message)
            >>> sig2 = sk_from_priv.sign(test_message)
            >>> assert sig1.signature == sig2.signature
            >>>
            >>> # Error: both parameters are None
            >>> try:
            ...     Ed25519KeyPair.from_b64u(seed32_b64u=None, priv64_b64u=None)
            ... except ValueError as e:
            ...     assert "cannot be None" in str(e)
        """
        sk = None
        seed32 = None

        if seed32_b64u is None and priv64_b64u is None:
            raise ValueError("seed32_b64u or priv64_b64u cannot be None")

        if seed32_b64u is not None:
            seed32 = unb64u(seed32_b64u)
            if len(seed32) != 32:
                raise ValueError("seed32_b64u is not a valid 32-byte seed")

            sk = SigningKey(seed32, encoder=RawEncoder)

        if priv64_b64u is not None:
            priv64 = unb64u(priv64_b64u)
            if len(priv64) != 64:
                raise ValueError("priv64_b64u is not a valid 64-byte private key")

            seed32 = priv64[:32]
            sk = SigningKey(seed32, encoder=RawEncoder)

        if sk is None:
            raise ValueError("seed32_b64u or priv64_b64u cannot be None")

        return Ed25519KeyPair(
            seed32_b64u=b64u(seed32),
            priv64_b64u=b64u(priv64),
            pub32_b64u=b64u(sk.verify_key.encode(encoder=RawEncoder)),
            sk=sk,
        )

    @staticmethod
    def verify(pub32: bytes, signed_packet: bytes) -> Result[bytes, Error]:
        """Verify a signed packet using a public key.

        Args:
            pub32: The 32-byte public key
            signed_packet: The signed packet to verify

        Returns:
            Result[bytes, Error]: Ok(bytes) if the packet was verified successfully,
                                   Err(Error) if verification failed
        """
        vk = VerifyKey(pub32, encoder=RawEncoder)
        try:
            return Result.Ok(vk.verify(signed_packet))
        except BadSignatureError as e:
            return Result.Err(Error.new(ErrorKind.PROTOCOL_ERROR, str(e)))
