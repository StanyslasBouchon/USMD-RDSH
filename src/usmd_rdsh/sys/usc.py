"""USC (Unified Service Configuration) representation.

This module defines a dataclass for a USC: identifier, version, public key,
and a list of USD (Unified Service Descriptor) entries.
"""

from dataclasses import dataclass

from usmd_rdsh.sys.usd import USD


@dataclass
class USC:
    """Unified Service Configuration with identifier, version, pubkey, and USD list.

    Attributes:
        uscn: USC identifier (name).
        version: Configuration version.
        ed25519_pub_key_32: Base64URL-encoded 32-byte Ed25519 public key.
        usd_list: List of USD entries.

    Example:
        >>> from usmd_rdsh.sys.usc import USC
        >>> from usmd_rdsh.sys.usd import USD, USDSettings
        >>> from usmd_rdsh.sys.neighbor import NodeNeighbor
        >>> from usmd_rdsh.utils.node_state import NodeState
        >>> usd = USD(
        ...     usdn="usd-1", version=1,
        ...     settings=USDSettings(nnr=2, ptms=1000),
        ...     neighbors=[], ed25519_pub_key_32="pub...",
        ... )
        >>> usc = USC(uscn="usc-1", version=1, ed25519_pub_key_32="pub...", usd_list=[usd])
        >>> usc.uscn
        'usc-1'
        >>> len(usc.usd_list)
        1
    """

    uscn: str
    version: int
    ed25519_pub_key_32: str
    usd_list: list[USD]
