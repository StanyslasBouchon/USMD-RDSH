from dataclasses import dataclass

from usmd_rdsh.utils.node_state import NodeState


@dataclass
class NodeNeighbor:
    """Node neighbor class."""

    name: str
    hosted_services: list[str]
    node_references: list[str]
    usage: dict[str, float | int]
    usage_reference: float
    state: NodeState
