"""Node neighbor representation.

This module defines a dataclass for a neighbor node, including its identifier,
hosted services, references, usage metrics, and state.
"""

from dataclasses import dataclass

from usmd_rdsh.utils.node_state import NodeState


@dataclass
class NodeNeighbor:
    """A neighbor node with services, references, usage, and state.

    Attributes:
        node_id: Neighbor node identifier.
        hosted_services: List of service identifiers hosted by this node.
        node_references: List of node identifiers this node references.
        usage: Usage metrics (e.g. CPU, memory) as name -> value.
        usage_reference: Reference value for usage comparison.
        state: Current node state (e.g. ACTIVE, INACTIVE).

    Example:
        >>> from usmd_rdsh.sys.neighbor import NodeNeighbor
        >>> from usmd_rdsh.utils.node_state import NodeState
        >>> n = NodeNeighbor(
        ...     node_id="node-1",
        ...     hosted_services=["svc-a", "svc-b"],
        ...     node_references=["node-2"],
        ...     usage={"cpu": 0.5, "mem": 1024},
        ...     usage_reference=2048.0,
        ...     state=NodeState.ACTIVE,
        ... )
        >>> n.node_id
        'node-1'
        >>> n.state == NodeState.ACTIVE
        True
    """

    node_id: str
    hosted_services: list[str]
    node_references: list[str]
    usage: dict[str, float | int]
    usage_reference: float
    state: NodeState
