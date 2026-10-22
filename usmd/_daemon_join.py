"""Internal module — bootstrap / join logic for NodeDaemon.

Provides the async helpers that handle node initialisation:

- :func:`_bootstrap` — first-node path: creates the USD and becomes ACTIVE.
- :func:`_join`      — wait for a peer then call :func:`_try_join_via`.
- :func:`_try_join_via` — send ``REQUEST_APPROVAL`` and process the response.
- :func:`_sync_nqt_from` — pull the NQT from a peer after joining.
- :func:`_store_endorsement` — decode and persist the endorsement from the
  approval response.

This module is private to the USMD-RDSH daemon subsystem.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import TYPE_CHECKING

from .ncp.client.tcp import NcpClient
from .ncp.protocol.commands.get_nqt import GetNqtRequest, GetNqtResponse
from .ncp.protocol.commands.request_approval import RequestApprovalRequest
from .ncp.protocol.frame import NcpCommandId
from .node.nel import EndorsementPacket
from .node.role import NodeRole
from .node.state import NodeState

if TYPE_CHECKING:
    from .node_daemon import NodeDaemon

logger = logging.getLogger(__name__)


async def _bootstrap(daemon: "NodeDaemon") -> None:
    """Bootstrap: this node IS the first node — it creates the USD.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
    """
    logger.info(
        "[\x1b[38;5;51mUSMD\x1b[0m] Bootstrapping USD '%s'…",
        daemon.usd.config.name,
    )
    result = daemon.usd.add_node(daemon.node)
    if result.is_err():
        logger.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] Could not add self to USD: %s",
            result.unwrap_err(),
        )
    daemon.node.set_state(NodeState.ACTIVE)
    daemon.mark_joined()
    logger.info(
        "[\x1b[38;5;51mUSMD\x1b[0m] Node \x1b[38;5;220m%d\x1b[0m "
        "is now ACTIVE (bootstrap) as %s",
        daemon.node.name,
        daemon.cfg.node_role.value,
    )


async def _join(daemon: "NodeDaemon") -> None:
    """Join: wait for a peer and send REQUEST_APPROVAL.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
    """
    logger.info(
        "[\x1b[38;5;51mUSMD\x1b[0m] Waiting for a peer (join_timeout=%.1fs)…",
        daemon.cfg.join_timeout,
    )
    deadline = asyncio.get_event_loop().time() + daemon.cfg.join_timeout
    while asyncio.get_event_loop().time() < deadline:
        if daemon.has_pending_peers:
            _, ip = daemon.pop_pending_peer()
            success = await _try_join_via(daemon, ip)
            if success:
                return
        await asyncio.sleep(0.5)

    logger.error(
        "[\x1b[38;5;51mUSMD\x1b[0m] Join timeout — no peer approved us. "
        "Starting anyway in INACTIVE_TIMEOUT state."
    )
    daemon.node.set_state(NodeState.INACTIVE_TIMEOUT)
    daemon.mark_joined()


async def _try_join_via(daemon: "NodeDaemon", peer_ip: str) -> bool:
    """Send REQUEST_APPROVAL to *peer_ip* and process the response.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
        peer_ip: IP address of the approving peer.

    Returns:
        bool: True if the join was accepted, False otherwise.
    """
    nonce = os.urandom(16)
    req   = RequestApprovalRequest(
        node_name=daemon.node.name,
        ed25519_pub=daemon.ed_pub,
        x25519_pub=daemon.x_pub,
        nonce=nonce,
        signature=b"",
    )
    req.signature = daemon.sign_ed25519(req.signable_bytes())

    client = NcpClient(
        address=peer_ip,
        port=daemon.cfg.ncp_port,
        timeout=daemon.cfg.ncp_timeout,
    )
    result = await client.send(NcpCommandId.REQUEST_APPROVAL, req.to_payload())
    if result.is_err():
        logger.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] REQUEST_APPROVAL to %s failed: %s",
            peer_ip,
            result.unwrap_err(),
        )
        return False

    response_frame = result.unwrap()
    payload = response_frame.payload

    if len(payload) < 1:
        logger.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] REQUEST_APPROVAL from %s: empty payload",
            peer_ip,
        )
        return False

    if payload[0] != 0x01:
        logger.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] REQUEST_APPROVAL rejected by %s",
            peer_ip,
        )
        return False

    if len(payload) > 1:
        _store_endorsement(daemon, payload[1:], peer_ip)

    result_add = daemon.usd.add_node(daemon.node)
    if result_add.is_err():
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] Self already in USD: %s",
            result_add.unwrap_err(),
        )

    daemon.node.set_state(NodeState.ACTIVE)
    daemon.mark_joined()
    logger.info(
        "[\x1b[38;5;51mUSMD\x1b[0m] Node \x1b[38;5;220m%d\x1b[0m "
        "is now ACTIVE (joined via %s) as %s",
        daemon.node.name,
        peer_ip,
        daemon.cfg.node_role.value,
    )
    await _sync_nqt_from(daemon, peer_ip)
    return True


async def _sync_nqt_from(daemon: "NodeDaemon", peer_ip: str) -> None:
    """Request the NQT from *peer_ip* and merge it into the local table.

    Called immediately after a successful join so the new node knows who the
    current operators are (even if elected before we joined).  Grants the
    appropriate NAL role for the most recent promotion of each role so that
    :meth:`~QuorumManager._has_live_role` works correctly straight away.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
        peer_ip: IP address of the peer to query.
    """
    client = NcpClient(
        address=peer_ip,
        port=daemon.cfg.ncp_port,
        timeout=daemon.cfg.ncp_timeout,
    )
    result = await client.send(NcpCommandId.GET_NQT, GetNqtRequest().to_payload())
    if result.is_err():
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] GET_NQT from %s failed: %s",
            peer_ip,
            result.unwrap_err(),
        )
        return

    parsed = GetNqtResponse.from_payload(result.unwrap().payload)
    if parsed.is_err():
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] GET_NQT parse error from %s: %s",
            peer_ip,
            parsed.unwrap_err(),
        )
        return

    added = daemon.nqt.merge_from_dicts(parsed.unwrap().entries)
    logger.info(
        "[\x1b[38;5;51mUSMD\x1b[0m] NQT sync from %s: +%d entr%s",
        peer_ip,
        added,
        "ie" if added == 1 else "ies",
    )

    # Grant NAL role for the most recent entry per role so quorum liveness
    # checks work immediately after joining.
    seen_roles: set[str] = set()
    for entry in daemon.nqt.get_all_entries():
        if entry.role_name in seen_roles:
            continue
        seen_roles.add(entry.role_name)
        try:
            node_role = NodeRole(entry.role_name)
        except ValueError:
            node_role = NodeRole.NODE_OPERATOR
        daemon.nal.grant(entry.pub_key, node_role, permanent=False)
        daemon.nit.register(entry.address, entry.pub_key, ttl=120)


def _store_endorsement(
    daemon: "NodeDaemon",
    endorsement_bytes: bytes,
    peer_ip: str,
) -> None:
    """Decode and store the endorsement packet from the approval response.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
        endorsement_bytes: Raw endorsement payload (JSON-encoded).
        peer_ip: IP address of the endorsing peer (for logging).
    """
    try:
        doc = json.loads(endorsement_bytes.decode("utf-8"))
        packet = EndorsementPacket(
            endorser_key=bytes.fromhex(doc["endorser_key"]),
            node_name=int(doc["node_name"]),
            node_pub_key=bytes.fromhex(doc["node_pub_key"]),
            node_session_key=bytes.fromhex(doc["node_session_key"]),
            roles=[NodeRole(r) for r in doc["roles"]],
            serial=bytes.fromhex(doc["serial"]),
            expiration=int(doc["expiration"]),
            signature=bytes.fromhex(doc["signature"]),
        )
        daemon.nel.set_received(packet)
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] Endorsement stored from %s", peer_ip
        )
    except (KeyError, ValueError, json.JSONDecodeError) as exc:
        logger.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] Could not parse endorsement from %s: %s",
            peer_ip,
            exc,
        )
