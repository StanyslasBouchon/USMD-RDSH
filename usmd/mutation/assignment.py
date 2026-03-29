"""Plan which mutation services a node should host (static vs dynamic).

* **Static** services from the catalogue must all be launched on every node.
* **Dynamic** services are sharded: a node claims every dynamic service name that
  is not already hosted by one of its **reference** peers (as seen in the local
  USD registry, optionally refreshed via ``GET_STATUS``).

Legacy field :attr:`~usmd.node.node.Node.service_name` is kept as the first
dynamic name if any, otherwise the first static name, for older NCP consumers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .catalog import MutationCatalog
from .service import ServiceType

if TYPE_CHECKING:
    from ..domain.usd import UnifiedSystemDomain


def static_service_names(catalog: MutationCatalog) -> list[str]:
    """All static mutation names in the catalogue (sorted)."""
    names = [
        s.name
        for s in catalog.all_services()
        if s.service_type == ServiceType.STATIC
    ]
    return sorted(names)


def dynamic_service_names(catalog: MutationCatalog) -> list[str]:
    """All dynamic mutation names in the catalogue (sorted)."""
    names = [
        s.name
        for s in catalog.all_services()
        if s.service_type == ServiceType.DYNAMIC
    ]
    return sorted(names)


def peer_claimed_dynamic_names(catalog: MutationCatalog, peer: "Node | None") -> set[str]:
    """Dynamic service names a reference peer is considered to host.

    Uses :attr:`~usmd.node.node.Node.hosting_dynamic` when non-empty, otherwise
    falls back to :attr:`~usmd.node.node.Node.service_name` if that name is
    dynamic in the catalogue.
    """
    if peer is None or not peer.state.is_active():
        return set()
    claimed: set[str] = set()
    for n in peer.hosting_dynamic:
        claimed.add(n)
    if not peer.hosting_dynamic and peer.service_name:
        svc = catalog.get(peer.service_name)
        if svc is not None and svc.service_type == ServiceType.DYNAMIC:
            claimed.add(peer.service_name)
    return claimed


def dynamics_claimed_by_reference_peers(
    catalog: MutationCatalog,
    usd: UnifiedSystemDomain,
    reference_names: list[int],
) -> set[str]:
    """Union of dynamic shards hosted by the given reference node names."""
    out: set[str] = set()
    for nm in reference_names:
        peer = usd.get_node(nm)
        out |= peer_claimed_dynamic_names(catalog, peer)
    return out


def compute_hosting_planes(
    catalog: MutationCatalog,
    usd: UnifiedSystemDomain,
    local: "Node",
) -> tuple[list[str], list[str]]:
    """Return ``(static_names, dynamic_names)`` this node should run.

    Static: full catalogue static set. Dynamic: catalogue dynamics not claimed
    by active reference peers.
    """
    static_names = static_service_names(catalog)
    all_dyn = dynamic_service_names(catalog)
    taken = dynamics_claimed_by_reference_peers(
        catalog, usd, local.reference_nodes
    )
    local_dynamic = [n for n in all_dyn if n not in taken]
    return static_names, local_dynamic


def apply_hosting_to_local_node(
    catalog: MutationCatalog,
    usd: UnifiedSystemDomain,
    local: "Node",
) -> None:
    """Write ``hosting_static``, ``hosting_dynamic``, and legacy ``service_name``."""
    hs, hd = compute_hosting_planes(catalog, usd, local)
    local.hosting_static = hs
    local.hosting_dynamic = hd
    if hd:
        local.service_name = hd[0]
    elif hs:
        local.service_name = hs[0]
    else:
        local.service_name = None
