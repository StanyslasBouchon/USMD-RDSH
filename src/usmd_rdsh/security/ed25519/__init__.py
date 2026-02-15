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

    >>> from usmd_rdsh.security.ed25519 import Ed25519KeyPair
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
from datetime import datetime, timedelta, timezone
import os
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509.oid import NameOID
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
            Ed25519KeyPair: A key pair reconstructed from the given seed or
                            private key, with all components Base64URL-encoded.

        Raises:
            ValueError: If both parameters are None, or if the decoded value
                       does not have the expected length (32 bytes for seed,
                       64 bytes for private key).

        Example:
            >>> from usmd_rdsh.security.ed25519 import Ed25519KeyPair
            >>> from nacl.signing import SigningKey
            >>>
            >>> # Generate a key pair
            >>> key_pair = Ed25519KeyPair.generate()
            >>>
            >>> # Reconstruct key pair from seed only
            >>> kp_from_seed = Ed25519KeyPair.from_b64u(
            ...     seed32_b64u=key_pair.seed32_b64u,
            ...     priv64_b64u=None
            ... )
            >>> assert kp_from_seed.pub32_b64u == key_pair.pub32_b64u
            >>>
            >>> # Reconstruct key pair from private key only
            >>> kp_from_priv = Ed25519KeyPair.from_b64u(
            ...     seed32_b64u=None,
            ...     priv64_b64u=key_pair.priv64_b64u
            ... )
            >>> assert kp_from_priv.pub32_b64u == key_pair.pub32_b64u
            >>>
            >>> # Both produce equivalent key pairs (same signatures)
            >>> test_message = b"Hello, World!"
            >>> sig1 = kp_from_seed.sign(test_message)
            >>> sig2 = kp_from_priv.sign(test_message)
            >>> assert sig1 == sig2
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
            priv64 = sk.encode(encoder=RawEncoder) + sk.verify_key.encode(
                encoder=RawEncoder
            )

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

        The signed_packet must be in the format produced by sign(): original
        data followed by the 64-byte Ed25519 signature. On success, returns
        the original message (without the signature).

        Args:
            pub32: The 32-byte raw public key (verification key).
            signed_packet: The signed blob (message + 64-byte signature).

        Returns:
            Result[bytes, Error]: Ok(message_bytes) if verification succeeded,
                                   Err(Error) if signature is invalid.

        Example:
            >>> kp = Ed25519KeyPair.generate()
            >>> msg = b"authenticated message"
            >>> signed = kp.sign(msg)
            >>> pub = unb64u(kp.pub32_b64u)
            >>> res = Ed25519KeyPair.verify(pub, signed)
            >>> assert res.is_ok() and res.unwrap() == msg
            >>> bad_res = Ed25519KeyPair.verify(pub, b"tampered")
            >>> assert bad_res.is_err()
        """
        vk = VerifyKey(pub32, encoder=RawEncoder)
        try:
            return Result.Ok(vk.verify(signed_packet))
        except BadSignatureError as e:
            return Result.Err(Error.new(ErrorKind.PROTOCOL_ERROR, str(e)))

    def sign(self, data: bytes) -> bytes:
        """Sign data using the Ed25519 private key.

        This method creates a cryptographic signature for the given data using
        the Ed25519 private key. The signature can later be verified using the
        corresponding public key to ensure the data's authenticity and integrity.

        The signature is deterministic: signing the same data with the same key
        will always produce the same signature. The signature is 64 bytes long
        and is appended to the original data in the returned bytes.

        Args:
            data: The data to sign (bytes)

        Returns:
            bytes: The signed data, which consists of the original data followed
                  by the 64-byte Ed25519 signature. The format is: data + signature

        Example:
            >>> from usmd_rdsh.security.ed25519 import Ed25519KeyPair
            >>>
            >>> # Generate a key pair
            >>> key_pair = Ed25519KeyPair.generate()
            >>>
            >>> # Sign some data
            >>> message = b"Hello, World!"
            >>> signed_data = key_pair.sign(message)
            >>>
            >>> # The signed data is longer than the original (64 bytes added)
            >>> assert len(signed_data) == len(message) + 64
            >>>
            >>> # The signature is deterministic
            >>> signed_data2 = key_pair.sign(message)
            >>> assert signed_data == signed_data2
            >>>
            >>> # Different data produces different signatures
            >>> signed_data3 = key_pair.sign(b"Different message")
            >>> assert signed_data != signed_data3
            >>>
            >>> # Verify the signature using the public key
            >>> from usmd_rdsh.security.ed25519 import unb64u
            >>> pub_key_bytes = unb64u(key_pair.pub32_b64u)
            >>> verify_result = Ed25519KeyPair.verify(pub_key_bytes, signed_data)
            >>> assert verify_result.is_ok()
            >>> assert verify_result.unwrap() == message
        """
        return bytes(self.sk.sign(data))


@dataclass
class Ed25519Certificate:
    """Self-signed X.509 certificate for Ed25519 keys.

    Builds PEM-encoded certificate + private key and writes them to a single
    file. Uses the same Ed25519 key material as Ed25519KeyPair (seed/priv/pub).
    Certificate is valid for 365 days and uses the given node_id as CN and
    SAN (DNSName).

    Example:
        >>> from usmd_rdsh.security.ed25519 import Ed25519Certificate
        >>> kp = Ed25519Certificate.generate("myserver.local", "/tmp/mycert.pem")
        >>> # File contains: PEM certificate then PEM private key
        >>> with open("/tmp/mycert.pem", "rb") as f:
        ...     data = f.read()
        >>> assert b"-----BEGIN CERTIFICATE-----" in data
        >>> assert b"-----BEGIN PRIVATE KEY-----" in data
    """

    @staticmethod
    def generate(node_id: str, cert_dir: str) -> "Ed25519KeyPair":
        """Generate a new Ed25519 key pair and a self-signed X.509 cert; write to file.

        Creates an Ed25519 key pair, builds a self-signed certificate with
        subject/issuer CN = node_id and SAN DNS = node_id, then writes
        certificate (PEM) followed by private key (PEM, PKCS#8, unencrypted)
        to the given path. Returns the same key pair for use in code.

        Args:
            node_id: Common name and DNS SAN for the certificate (e.g. hostname).
            cert_dir: Directory to write PEM certificate + private key.

        Returns:
            Ed25519KeyPair: The generated key pair (seed/priv/pub in Base64URL).

        Example:
            >>> kp = Ed25519Certificate.generate("node1.example.com", "cert.pem")
            >>> assert kp.pub32_b64u
            >>> import os
            >>> os.path.exists("cert.pem")
            True
        """
        # New key pair (PyNaCl); same format as Ed25519KeyPair
        kp = Ed25519KeyPair.generate()
        # cryptography's Ed25519 private key expects 32-byte seed (not 64-byte priv)
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(unb64u(kp.seed32_b64u))

        # Self-signed: subject and issuer are the same
        subjet = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])

        now = datetime.now(timezone.utc)

        # Build X.509 cert: CN, validity 1 year, SAN DNS = node_id
        cert = (
            x509.CertificateBuilder()
            .subject_name(subjet)
            .issuer_name(issuer)
            .public_key(pk.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(node_id)]), critical=False
            )
            .sign(private_key=pk, algorithm=None)
        )

        cert_pem = cert.public_bytes(encoding=Encoding.PEM)
        key_pem = pk.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

        # Single file: cert first, then key (common for TLS servers)
        os.makedirs(cert_dir, exist_ok=True)
        with open(os.path.join(cert_dir, "node.crt"), "wb") as f:
            f.write(cert_pem)
        with open(os.path.join(cert_dir, "node.key"), "wb") as f:
            f.write(key_pem)

        return kp

    @staticmethod
    def load(cert_dir: str) -> "Ed25519KeyPair":
        """Load an Ed25519 key pair from a directory containing node.key (PEM).

        Reads the private key from ``{cert_dir}/node.key`` (PKCS#8 PEM, as
        written by :meth:`generate`), then reconstructs an :class:`Ed25519KeyPair`
        with the same seed/priv/pub in Base64URL. The certificate file
        (e.g. ``node.crt``) is not required for loading the key pair.

        Args:
            cert_dir: Directory containing ``node.key`` (and optionally
                      ``node.crt``).

        Returns:
            Ed25519KeyPair: Key pair loaded from the PEM file, with
                            seed32_b64u, priv64_b64u, pub32_b64u and internal
                            SigningKey populated.

        Raises:
            FileNotFoundError: If ``node.key`` is missing under ``cert_dir``.
            ValueError: If the PEM data is not a valid Ed25519 private key.

        Example:
            >>> from usmd_rdsh.security.ed25519 import Ed25519Certificate, Ed25519KeyPair
            >>> import tempfile, os
            >>> with tempfile.TemporaryDirectory() as d:
            ...     kp1 = Ed25519Certificate.generate("node1.local", d)
            ...     kp2 = Ed25519Certificate.load(d)
            ...     assert kp1.pub32_b64u == kp2.pub32_b64u
            ...     assert kp1.sign(b"test") == kp2.sign(b"test")
            >>>
            >>> # Load from a custom path
            >>> kp = Ed25519Certificate.load("/etc/myapp/certs")
            >>> msg = b"authenticated"
            >>> sig = kp.sign(msg)
        """
        key_path = os.path.join(cert_dir, "node.key")
        with open(key_path, "rb") as f:
            key_pem = f.read()

        # Parse PEM and get cryptography Ed25519 private key
        pk = load_pem_private_key(key_pem, password=None)
        if not isinstance(pk, ed25519.Ed25519PrivateKey):
            raise ValueError("node.key is not an Ed25519 private key")

        # Export 32-byte raw seed (same as PyNaCl seed) and build Ed25519KeyPair
        raw_seed_32 = pk.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        return Ed25519KeyPair.from_b64u(seed32_b64u=b64u(raw_seed_32))
