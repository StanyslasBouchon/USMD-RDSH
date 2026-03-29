"""Internal module — status snapshot builder for NodeDaemon.

Provides :func:`_build_status_snapshot`, called by the CTL and Web servers
to produce a fully serialisable dict of the current node state.

This module is private to the USMD-RDSH daemon subsystem.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from ._daemon_helpers import _get_resource_usage
from ._daemon_nrt import _usd_addr_to_peer_name

if TYPE_CHECKING:
    from .node_daemon import NodeDaemon


def _nrt_rows_for_snapshot(daemon: "NodeDaemon") -> list[dict]:
    """NRT rows plus ``node_name`` so UIs can match references by name, not only IP."""
    addr_to_name = _usd_addr_to_peer_name(daemon)
    rows = daemon.nrt.get_all()
    for row in rows:
        row["node_name"] = addr_to_name.get(row["address"])
    return rows


def _build_status_snapshot(daemon: "NodeDaemon") -> dict:
    """Return a fully serialisable dict of the current node state.

    Called by the CTL server on every incoming status request.
    All bytes are hex-encoded and truncated for readability.

    Args:
        daemon: The running :class:`NodeDaemon` instance.

    Returns:
        dict: Snapshot suitable for JSON serialisation.
    """
    now = time.time()

    # First NIT address seen per public key (for linking NAL / NEL to /node/<ip>/)
    pub_hex_to_address: dict[str, str] = {}
    for entry in daemon.nit.iter_all_entries():
        hx = entry.public_key.hex()
        if hx not in pub_hex_to_address:
            pub_hex_to_address[hx] = entry.address

    # NIT
    nit_data = []
    for entry in daemon.nit.iter_all_entries():
        ttl_remaining = max(0, int(entry.ttl - (now - entry.registered_at)))
        nit_data.append({
            "address":       entry.address,
            "pub_key":       entry.public_key.hex(),
            "ttl_remaining": ttl_remaining,
            "expired":       entry.is_expired(),
        })

    # NAL
    nal_data = []
    for pub_key, roles in daemon.nal.iter_all_entries():
        hx = pub_key.hex()
        nal_data.append({
            "pub_key":   hx,
            "roles":     [r.value for r in roles],
            "permanent": daemon.nal.is_permanent(pub_key),
            "address":   pub_hex_to_address.get(hx),
        })

    # NEL — received
    nel_received = None
    recv = daemon.nel.get_received()
    if recv:
        ek = recv.endorser_key.hex()
        nel_received = {
            "endorser_key":       ek,
            "endorser_address":   pub_hex_to_address.get(ek),
            "node_name":          recv.node_name,
            "roles":              [r.value for r in recv.roles],
            "expiration":         recv.expiration,
            "expired":            recv.is_expired(),
        }

    # NEL — issued
    nel_issued = []
    for pkt in daemon.nel.all_issued():
        npk = pkt.node_pub_key.hex()
        peer = daemon.usd.get_node(pkt.node_name)
        node_addr = peer.address if peer else pub_hex_to_address.get(npk)
        nel_issued.append({
            "node_pub_key": npk,
            "node_name":    pkt.node_name,
            "node_address": node_addr,
            "roles":        [r.value for r in pkt.roles],
            "expiration":   pkt.expiration,
            "expired":      pkt.is_expired(),
        })

    # Reference nodes
    ref_nodes_data = []
    for peer_name in daemon.node.reference_nodes:
        peer = daemon.usd.get_node(peer_name)
        ref_nodes_data.append({
            "name":           peer_name,
            "address":        peer.address if peer else None,
            "state":          peer.state.value if peer else "unknown",
            "service":        peer.service_name if peer else None,
            "reference_load": round(peer.reference_load * 100, 1) if peer else None,
        })

    # Resources
    usage = _get_resource_usage()

    return {
        "node": {
            "name":              daemon.node.name,
            "address":           daemon.node.address,
            "state":             daemon.node.state.value,
            "role":              daemon.cfg.node_role.value,
            "uptime_seconds":    now - daemon.start_time,
            "service_name":      daemon.node.service_name,
            "hosting_static":    list(daemon.node.hosting_static),
            "hosting_dynamic":   list(daemon.node.hosting_dynamic),
        },
        "usd": {
            "name":           daemon.usd.config.name,
            "cluster_name":   daemon.usd.config.cluster_name,
            "edb_address":    daemon.usd.config.edb_address,
            "config_version": daemon.usd.config.version,
            "node_count":     len(daemon.usd.nodes),
            "min_services":   daemon.usd.config.min_services,
            "max_services":   daemon.usd.config.max_services,
            "dependency_check_interval": (
                daemon.usd.config.dependency_check_interval
            ),
        },
        "mutations": [
            {
                "name":    s.name,
                "type":    s.service_type.value,
                "version": s.version,
                "deps":    s.dependencies,
            }
            for s in daemon.usd.mutation_catalog.all_services()
        ],
        "nit": nit_data,
        "nal": nal_data,
        "nel": {
            "received": nel_received,
            "issued":   nel_issued,
        },
        "reference_nodes": ref_nodes_data,
        # Same address → name map as reference selection (_usd_addr_to_peer_name)
        "nrt": _nrt_rows_for_snapshot(daemon),
        "nrl": daemon.nrl.get_all_dicts(),
        "resources": {
            "cpu_percent":     usage.cpu_percent,
            "ram_percent":     usage.ram_percent,
            "disk_percent":    usage.disk_percent,
            "network_percent": usage.network_percent,
            "reference_load":  usage.reference_load(),
        },
        "quorum": {
            "enabled":       daemon.cfg.quorum.enabled,
            "is_operator":   (
                daemon.quorum_manager.is_operator
                if daemon.quorum_manager else False
            ),
            "elected_roles": (
                daemon.quorum_manager.elected_roles
                if daemon.quorum_manager else []
            ),
            "promotions": daemon.nqt.get_all_dicts(),
        },
    }
