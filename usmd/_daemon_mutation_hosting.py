"""Refresh local mutation hosting (static vs dynamic) and peer GET_STATUS hints."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from .mutation.assignment import apply_hosting_to_local_node
from .ncp.client.tcp import NcpClient
from .ncp.protocol.commands.get_status import GetStatusRequest
from .ncp.protocol.frame import NcpCommandId

if TYPE_CHECKING:
    from .node_daemon import NodeDaemon

logger = logging.getLogger(__name__)

# How often we poll reference peers for GET_STATUS (service / hosting fields).
_PEER_STATUS_MIN_INTERVAL = 15.0


async def _poll_reference_peers_service_view(daemon: "NodeDaemon") -> None:
    """Best-effort GET_STATUS to each reference peer; update local USD Node copies."""
    for name in list(daemon.node.reference_nodes):
        peer = daemon.usd.get_node(name)
        if peer is None or not peer.address:
            continue
        if peer.address == daemon.node.address:
            continue
        client = NcpClient(
            address=peer.address,
            port=daemon.cfg.ncp_port,
            timeout=daemon.cfg.ncp_timeout,
        )
        result = await client.send(
            NcpCommandId.GET_STATUS,
            GetStatusRequest().to_payload(),
        )
        if result.is_err():
            logger.debug(
                "[\x1b[38;5;51mUSMD\x1b[0m] GET_STATUS → %s failed: %s",
                peer.address,
                result.unwrap_err(),
            )
            continue
        try:
            doc = json.loads(result.unwrap().payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            logger.debug("GET_STATUS JSON from %s: %s", peer.address, exc)
            continue
        svc = doc.get("service")
        if svc is not None:
            peer.service_name = str(svc) if svc else None
        if "hosting_static" in doc:
            peer.hosting_static = [str(x) for x in (doc.get("hosting_static") or [])]
        if "hosting_dynamic" in doc:
            peer.hosting_dynamic = [str(x) for x in (doc.get("hosting_dynamic") or [])]


async def refresh_mutation_hosting(
    daemon: "NodeDaemon",
    *,
    poll_peers: bool = True,
    force_peer_poll: bool = False,
) -> None:
    """Recompute ``hosting_*`` / ``service_name``; optionally refresh peer view via NCP."""
    if poll_peers and daemon.node.reference_nodes:
        if daemon.consume_monotonic_gate(
            "peer_status_poll",
            _PEER_STATUS_MIN_INTERVAL,
            force=force_peer_poll,
        ):
            await _poll_reference_peers_service_view(daemon)

    apply_hosting_to_local_node(
        daemon.usd.mutation_catalog,
        daemon.usd,
        daemon.node,
    )
