"""USD (Unified Service Descriptor) representation.

This module defines USDSettings (nnr, ptms) and USD dataclass for a service
descriptor: identifier, version, settings, neighbors, and public key.
"""

from dataclasses import dataclass

from usmd_rdsh.sys.neighbor import NodeNeighbor


@dataclass
class USDSettings:
    """Settings for a USD: node references count and ping tolerance.

    Attributes:
        nnr: Number of Node References.
        ptms: Ping Tolerance in milliseconds.

    Example:
        >>> from usmd_rdsh.sys.usd import USDSettings
        >>> s = USDSettings(nnr=3, ptms=1000)
        >>> s.nnr
        3
        >>> s.ptms
        1000
    """

    nnr: int  # Number of Node References
    ptms: int  # Ping Tolerance in milliseconds


@dataclass
class USD:
    """Unified Service Descriptor with settings, neighbors, and pubkey.

    Attributes:
        usdn: USD identifier (name).
        version: Configuration version.
        settings: USDSettings (nnr, ptms).
        neighbors: List of NodeNeighbor entries.
        ed25519_pub_key_32: Base64URL-encoded 32-byte Ed25519 public key.

    Example:
        >>> from usmd_rdsh.sys.usd import USD, USDSettings
        >>> from usmd_rdsh.sys.neighbor import NodeNeighbor
        >>> from usmd_rdsh.utils.node_state import NodeState
        >>> usd = USD(
        ...     usdn="usd-1", version=1,
        ...     settings=USDSettings(nnr=2, ptms=500),
        ...     neighbors=[],
        ...     ed25519_pub_key_32="pub...",
        ... )
        >>> usd.usdn
        'usd-1'
        >>> usd.settings.ptms
        500
    """

    usdn: str
    version: int
    settings: USDSettings
    neighbors: list[NodeNeighbor]
    ed25519_pub_key_32: str
