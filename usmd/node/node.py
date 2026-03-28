"""Node representation for USMD-RDSH.

A Node is the fundamental unit of the system. Its name is the UNIX timestamp
(in seconds) at which it joined the USD. Each node tracks its own state,
its current mutation (service), and a list of reference nodes (nearest peers).

Examples:
    >>> import time
    >>> node = Node(name=int(time.time()), state=NodeState.PENDING_APPROVAL)
    >>> node.is_reachable()
    False
    >>> node.set_state(NodeState.ACTIVE)
    >>> node.is_reachable()
    True
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from .state import NodeState


@dataclass
class NodeInfo:
    """Lightweight description of a node as shared across the USD.

    This is the structure broadcast to all peers when a node joins or updates.

    Attributes:
        name: UNIX timestamp (seconds) when the node joined — used as unique ID.
        state: Current lifecycle state of the node.
        address: IPv4 or IPv6 address of the node.
        service_name: Name of the mutation/service currently hosted (or None).
        reference_nodes: Names (timestamps) of this node's reference peers.

    Examples:
        >>> info = NodeInfo(name=1710000000, state=NodeState.ACTIVE,
        ...                 address="192.168.1.10", service_name="backend")
        >>> info.name
        1710000000
    """

    name: int
    state: NodeState
    address: str
    service_name: Optional[str] = None
    reference_nodes: list[int] = field(default_factory=list)


class Node:
    """A node participating in an USD.

    On creation the node picks its name as the current UNIX time. If another
    node in the domain already carries that name, the node retries with a new
    timestamp.

    Attributes:
        name: UNIX timestamp (s) of when this node joined — unique per USD.
        state: Current lifecycle state.
        address: Network address (IPv4/v6).
        service_name: Active mutation service (None when inactive).
        reference_nodes: Sorted list of peer names used as proximity references.
        reference_load: Normalised load score in [0, 1] used by the distance formula.

    Examples:
        >>> node = Node(address="10.0.0.1")
        >>> node.state
        <NodeState.PENDING_APPROVAL: 'pending_approval'>
        >>> node.set_state(NodeState.ACTIVE)
        >>> node.is_reachable()
        True
    """

    def __init__(
        self,
        address: str,
        name: Optional[int] = None,
        state: NodeState = NodeState.PENDING_APPROVAL,
        service_name: Optional[str] = None,
    ) -> None:
        """Initialise a new Node.

        Args:
            address: Network address (IPv4 or IPv6) of this node.
            name: UNIX timestamp name; defaults to current time if omitted.
            state: Initial state; defaults to PENDING_APPROVAL.
            service_name: Active mutation name, or None.

        Example:
            >>> node = Node(address="10.0.0.5", name=1710000000)
            >>> node.name
            1710000000
        """
        self.name: int = name if name is not None else int(time.time())
        self.state: NodeState = state
        self.address: str = address
        self.service_name: Optional[str] = service_name
        self.reference_nodes: list[int] = []
        self.reference_load: float = 0.0

        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] Node \x1b[38;5;220m%d\x1b[0m "
            "created at %s (state=%s)",
            self.name,
            address,
            state,
        )

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------

    def set_state(self, new_state: NodeState) -> None:
        """Transition this node to a new state.

        Args:
            new_state: The target NodeState.

        Example:
            >>> node = Node(address="10.0.0.1")
            >>> node.set_state(NodeState.ACTIVE)
            >>> node.state == NodeState.ACTIVE
            True
        """
        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] Node %d state: %s → %s",
            self.name,
            self.state,
            new_state,
        )
        self.state = new_state

    def is_reachable(self) -> bool:
        """Return True if this node is active and can accept NCP requests.

        Example:
            >>> node = Node(address="10.0.0.1")
            >>> node.is_reachable()
            False
            >>> node.set_state(NodeState.ACTIVE)
            >>> node.is_reachable()
            True
        """
        return self.state.is_active()

    # ------------------------------------------------------------------
    # Reference node management
    # ------------------------------------------------------------------

    def add_reference_node(self, peer_name: int) -> None:
        """Register a peer as a reference node for this node.

        Args:
            peer_name: The UNIX-timestamp name of the reference peer.

        Example:
            >>> node = Node(address="10.0.0.1")
            >>> node.add_reference_node(1710000001)
            >>> 1710000001 in node.reference_nodes
            True
        """
        if peer_name not in self.reference_nodes:
            self.reference_nodes.append(peer_name)

    def remove_reference_node(self, peer_name: int) -> None:
        """Remove a peer from this node's reference list.

        Args:
            peer_name: The UNIX-timestamp name of the peer to remove.

        Example:
            >>> node = Node(address="10.0.0.1")
            >>> node.add_reference_node(1710000001)
            >>> node.remove_reference_node(1710000001)
            >>> 1710000001 in node.reference_nodes
            False
        """
        if peer_name in self.reference_nodes:
            self.reference_nodes.remove(peer_name)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_info(self) -> NodeInfo:
        """Serialise this node to a NodeInfo for broadcasting.

        Returns:
            NodeInfo: Lightweight snapshot of this node's current status.

        Example:
            >>> node = Node(address="10.0.0.5", name=1710000000)
            >>> info = node.to_info()
            >>> info.name
            1710000000
        """
        return NodeInfo(
            name=self.name,
            state=self.state,
            address=self.address,
            service_name=self.service_name,
            reference_nodes=list(self.reference_nodes),
        )

    def __repr__(self) -> str:
        return (
            f"Node(name={self.name}, state={self.state}, "
            f"address={self.address!r}, service={self.service_name!r})"
        )
