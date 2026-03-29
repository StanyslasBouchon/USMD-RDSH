"""Pick the best peer to satisfy a remote service dependency (lowest reference load)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..domain.usd import UnifiedSystemDomain
    from ..node.node import Node


def best_node_for_dependency(
    usd: "UnifiedSystemDomain",
    dependency_service_name: str,
    *,
    exclude_name: Optional[int] = None,
) -> Optional["Node"]:
    """Return the active USD node hosting *dependency_service_name* with lowest load.

    Args:
        usd: Local USD registry.
        dependency_service_name: Name of the mutation service required (e.g. ``"db"``).
        exclude_name: Optional node name to skip (usually the local node).

    Returns:
        The best :class:`~usmd.node.node.Node`, or ``None`` if no candidate.
    """
    best: Optional[Node] = None
    best_load = 2.0
    for node in usd.nodes.values():
        if exclude_name is not None and node.name == exclude_name:
            continue
        if not node.state.is_active():
            continue
        if not node.hosts_service(dependency_service_name):
            continue
        load = float(node.reference_load)
        if load < best_load:
            best_load = load
            best = node
    return best
