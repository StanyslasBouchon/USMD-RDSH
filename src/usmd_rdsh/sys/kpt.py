"""Key pair descriptor for recipients.

This module defines a frozen dataclass holding a recipient's public keys
(Ed25519) in Base64URL encoding, along with validity bounds.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class KeyPair:
    """Recipient key pair with Ed25519 public keys and validity window.

    Attributes:
        recipient_ed25519_pub32_b64u: Base64URL-encoded 32-byte Ed25519 public key.
        not_before: Validity start (inclusive).
        not_after: Validity end (inclusive).

    Example:
        >>> from usmd_rdsh.sys.kpt import KeyPair
        >>> from datetime import datetime, timezone
        >>> now = datetime.now(timezone.utc)
        >>> kp = KeyPair(
        ...     recipient_ed25519_pub32_b64u="AbC123...",
        ...     not_before=now,
        ...     not_after=datetime(2026, 12, 31, tzinfo=timezone.utc),
        ... )
        >>> kp.recipient_ed25519_pub32_b64u
        'AbC123...'
    """

    recipient_ed25519_pub32_b64u: str
    not_before: datetime
    not_after: datetime
