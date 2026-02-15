"""NNDP (Network Node Discovery Protocol) base environment and data structures.

This module defines the core data structures used by the NNDP protocol for node
announcement packets. It provides the `HereIAmData` dataclass which represents
the payload data sent by nodes to announce their presence on the network.

The module is part of the NNDP-specific implementation, building upon the base
protocol environment defined in `usmd_rdsh.proto.base.env`.

Example usage:

    >>> from usmd_rdsh.proto.nndp.base.env import HereIAmData
    >>> from usmd_rdsh.utils.node_state import NodeState
    >>> import time
    >>>
    >>> # Create a "HIA" packet data structure
    >>> hia_data = HereIAmData(
    ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ...     ed25519_pub32=b"\\x00" * 32,
    ...     ip="192.168.1.100",
    ...     next_hia_pkt_time=int((time.time() + 15.0) * 1000),
    ...     state=NodeState.ACTIVE,
    ... )
    >>>
    >>> # Access node information
    >>> print(f"Node ID: {hia_data.node_id}")
    >>> print(f"IP Address: {hia_data.ip}")
    >>> print(f"State: {hia_data.state.name}")
    >>> print(f"Next packet time: {hia_data.next_hia_pkt_time}")
    >>>
    >>> # Version defaults to NNDP_VERSION
    >>> assert hia_data.version == NNDP_VERSION
    >>>
    >>> # Create packet with different state
    >>> inactive_data = HereIAmData(
    ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ...     ed25519_pub32=b"\\x01" * 32,
    ...     ip="192.168.1.101",
    ...     next_hia_pkt_time=int((time.time() + 30.0) * 1000),
    ...     state=NodeState.INACTIVE,
    ... )
    >>> assert inactive_data.state == NodeState.INACTIVE
"""

from dataclasses import dataclass

from usmd_rdsh.proto.base.env import NNDP_VERSION
from usmd_rdsh.utils.node_state import NodeState


@dataclass
class HereIAmData:
    """Data structure for NNDP "HIA" announcement packets.

    This dataclass represents the payload data sent by nodes to announce their
    presence on the network. It contains information about the node's identity,
    current state, and when the next announcement will be sent.

    Attributes:
        node_id: Unique identifier for the node (typically a ULID string)
        next_hia_pkt_time: Timestamp (in milliseconds) when the next "HIA"
                          packet will be sent
        state: Current state of the node (e.g., ACTIVE, INACTIVE, SYNCHRONISING)
        ed25519_pub32: Ed25519 public key
        ip: IP address of the node
        version: Protocol version (defaults to NNDP_VERSION constant)

    Note:
        The `next_hia_pkt_time` is typically calculated as the current time
        plus the announcement interval (e.g., 15 seconds) in milliseconds.

    Example:
        >>> from usmd_rdsh.proto.nndp.base.env import HereIAmData, NNDP_VERSION
        >>> from usmd_rdsh.utils.node_state import NodeState
        >>> import time
        >>>
        >>> # Create a HIA data packet
        >>> hia_data = HereIAmData(
        ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ...     ed25519_pub32=b"\x00" * 32,
        ...     ip="127.0.0.1",
        ...     next_hia_pkt_time=int((time.time() + 15.0) * 1000),
        ...     state=NodeState.ACTIVE,
        ... )
        >>>
        >>> # Access the fields
        >>> assert hia_data.node_id == "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        >>> assert hia_data.state == NodeState.ACTIVE
        >>> assert hia_data.version == NNDP_VERSION
        >>> assert hia_data.next_hia_pkt_time > int(time.time() * 1000)
        >>>
        >>> # Version is optional and defaults to VERSION
        >>> hia_data2 = HereIAmData(
        ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ...     ed25519_pub32=b"\x00" * 32,
        ...     ip="127.0.0.1",
        ...     next_hia_pkt_time=int(time.time() * 1000),
        ...     state=NodeState.SYNCHRONISING,
        ... )
        >>> assert hia_data2.version == NNDP_VERSION
    """

    ed25519_pub32: bytes
    node_id: str
    ip: str
    next_hia_pkt_time: int
    state: NodeState
    version: int = NNDP_VERSION
