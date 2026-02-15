"""System tables aggregator module.

This module provides a centralized data structure for aggregating and managing
various system tables used in the USMD-RDSH network. The tables track node
identities, endorsements, access permissions, and neighbor information.

The module includes:
    - TableAggregator: A dataclass that aggregates all system tables in one place

System Tables:
    - NIT (Node Identity Table): Stores node identity information including
      public keys, IDs, IP addresses, and TTL values
    - NEL (Node Endorsement List): Stores endorsement packets that grant
      roles and permissions to nodes
    - NAL (Node Access List): Stores access control information mapping
      public keys to their assigned roles
    - UNL (Unique Node List): Stores neighbor information including hosted
      services, node references, usage metrics, and state

Example usage:

    >>> from usmd_rdsh.sys.tables import TableAggregator
    >>> from usmd_rdsh.sys.nit import NodeIdentity
    >>> from usmd_rdsh.sys.nal import NodeAccess, Role
    >>> from usmd_rdsh.utils.node_state import NodeState
    >>>
    >>> # Create a table aggregator
    >>> tables = TableAggregator()
    >>>
    >>> # Add a node identity
    >>> node_id = NodeIdentity(
    ...     ed25519_pub32=b"\\x00" * 32,
    ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ...     node_ip="192.168.1.100",
    ...     ttl=300,
    ... )
    >>> tables.nit.append(node_id)
    >>>
    >>> # Add node access information
    >>> access = NodeAccess(
    ...     ed25519_pub_key_32="base64url_encoded_key",
    ...     roles=[Role.NODE_OPERATOR],
    ... )
    >>> tables.nal.append(access)
    >>>
    >>> # Access the tables
    >>> assert len(tables.nit) == 1
    >>> assert len(tables.nal) == 1
    >>> assert tables.nit[0].node_id == "01ARZ3NDEKTSV4RRFFQ69G5FAV"
"""

from dataclasses import dataclass, field

from usmd_rdsh.sys.nal import NodeAccess
from usmd_rdsh.sys.nel import NodeEndorsementPacket
from usmd_rdsh.sys.nit import NodeIdentity
from usmd_rdsh.sys.neighbor import NodeNeighbor


@dataclass
class TableAggregator:
    """Aggregator for all system tables in the USMD-RDSH network.

    This dataclass provides a centralized container for managing all system
    tables used for node discovery, identity management, access control, and
    neighbor tracking. All tables are initialized as empty lists and can be
    populated as nodes are discovered and relationships are established.

    Attributes:
        nit: Node Identity Table - List of NodeIdentity objects containing
             node identification information (public keys, IDs, IPs, TTL)
        nel: Node Endorsement List - List of NodeEndorsementPacket objects
             containing endorsement information (roles, signatures, expiration)
        nal: Node Access List - List of NodeAccess objects mapping public keys
             to their assigned roles and permissions
        unl: Unique Node List - List of NodeNeighbor objects containing
             neighbor information (services, references, usage, state)

    Note:
        All tables use `field(default_factory=list)` to ensure each instance
        gets its own independent list, preventing shared state between instances.

    Example:
        >>> from usmd_rdsh.sys.tables import TableAggregator
        >>> from usmd_rdsh.sys.nit import NodeIdentity
        >>> from usmd_rdsh.sys.nal import NodeAccess, Role
        >>> from usmd_rdsh.sys.neighbor import NodeNeighbor
        >>> from usmd_rdsh.utils.node_state import NodeState
        >>>
        >>> # Create a new table aggregator
        >>> tables = TableAggregator()
        >>>
        >>> # Initially all tables are empty
        >>> assert len(tables.nit) == 0
        >>> assert len(tables.nel) == 0
        >>> assert len(tables.nal) == 0
        >>> assert len(tables.unl) == 0
        >>>
        >>> # Add a node identity
        >>> identity = NodeIdentity(
        ...     ed25519_pub32=b"\\x00" * 32,
        ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ...     node_ip="192.168.1.100",
        ...     ttl=300,
        ... )
        >>> tables.nit.append(identity)
        >>>
        >>> # Add access control information
        >>> access = NodeAccess(
        ...     ed25519_pub_key_32="dGVzdF9wdWJsaWNfa2V5XzMyX2J5dGVz",
        ...     roles=[Role.NODE_OPERATOR, Role.NODE_EXECUTOR],
        ... )
        >>> tables.nal.append(access)
        >>>
        >>> # Add neighbor information
        >>> neighbor = NodeNeighbor(
        ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ...     hosted_services=["service1", "service2"],
        ...     node_references=["ref1", "ref2"],
        ...     usage={"cpu": 0.5, "memory": 0.7},
        ...     usage_reference=1.0,
        ...     state=NodeState.ACTIVE,
        ... )
        >>> tables.unl.append(neighbor)
        >>>
        >>> # Verify the tables are populated
        >>> assert len(tables.nit) == 1
        >>> assert len(tables.nal) == 1
        >>> assert len(tables.unl) == 1
        >>> assert tables.nit[0].node_id == "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        >>> assert tables.nal[0].ed25519_pub_key_32 == "dGVzdF9wdWJsaWNfa2V5XzMyX2J5dGVz"
        >>> assert tables.unl[0].state == NodeState.ACTIVE
        >>>
        >>> # Each instance has its own independent tables
        >>> tables2 = TableAggregator()
        >>> assert len(tables2.nit) == 0  # Empty, not shared with tables
        >>> assert len(tables.nit) == 1   # Original still has data
    """

    nit: list[NodeIdentity] = field(default_factory=list)
    nel: list[NodeEndorsementPacket] = field(default_factory=list)
    nal: list[NodeAccess] = field(default_factory=list)
    unl: list[NodeNeighbor] = field(default_factory=list)
