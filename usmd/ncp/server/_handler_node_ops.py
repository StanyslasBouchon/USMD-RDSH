"""Internal module — node-operation NCP command handlers.

Provides three handler functions extracted from :class:`NcpCommandHandler` to
keep ``handler.py`` under the 450-line limit:

- :func:`handle_check_distance`   — computes the distance metric for the sender.
- :func:`handle_request_approval` — validates and approves a joining node.
- :func:`handle_inform_reference_node` — updates the NRL from the sender's list.

Each function receives the shared :class:`HandlerContext` and the raw
:class:`NcpFrame`, and returns a response :class:`NcpFrame`.

This module is private to the NCP server subsystem.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

from ..protocol.commands.check_distance import (
    CheckDistanceRequest,
    CheckDistanceResponse,
)
from ..protocol.commands.inform_reference_node import InformReferenceNodeRequest
from ..protocol.commands.request_approval import (
    RequestApprovalRequest,
    RequestApprovalResponse,
)
from ..protocol.frame import NcpCommandId, NcpFrame
from ..protocol.versions import NcpVersion
from ...mutation.transmutation import DistanceCalculator
from ...node.role import NodeRole
from ...security.crypto import Ed25519Pair

if TYPE_CHECKING:
    from .handler import HandlerContext

logger = logging.getLogger(__name__)


def _make_response(command_id: NcpCommandId, payload: bytes) -> NcpFrame:
    """Build a response NcpFrame (re-exported helper, avoids circular import)."""
    return NcpFrame(version=NcpVersion(1, 0, 0, 0), command_id=command_id, payload=payload)


def _error_response(command_id: NcpCommandId, err: object) -> NcpFrame:
    logger.warning(
        "[\x1b[38;5;51mUSMD\x1b[0m] NCP cmd=%s error: %s",
        command_id.name,
        err,
    )
    return _make_response(command_id, b"")


# ---------------------------------------------------------------------------
# Command 1: Check_distance
# ---------------------------------------------------------------------------


def handle_check_distance(ctx: "HandlerContext", frame: NcpFrame) -> NcpFrame:
    """Compute the distance metric for the requesting node.

    Args:
        ctx: Shared handler context.
        frame: Incoming NCP frame.

    Returns:
        NcpFrame: Response containing the computed distance.
    """
    parse_result = CheckDistanceRequest.from_payload(frame.payload)
    if parse_result.is_err():
        return _error_response(NcpCommandId.CHECK_DISTANCE, parse_result.unwrap_err())

    req = parse_result.unwrap()
    now_ms = int(time.time() * 1000)
    ping_ms = float(max(0, now_ms - req.sent_at_ms))

    usage = ctx.resource_getter()
    load = usage.reference_load()

    calc = DistanceCalculator(
        ping_tolerance_ms=ctx.usd.config.ping_tolerance_ms
    )
    d = calc.compute(
        ping_ms=ping_ms,
        reference_load=load,
        same_service=False,
        is_already_reference=False,
    )
    return _make_response(
        NcpCommandId.CHECK_DISTANCE,
        CheckDistanceResponse(distance=d).to_payload(),
    )


# ---------------------------------------------------------------------------
# Command 4: Request_approval
# ---------------------------------------------------------------------------


def handle_request_approval(ctx: "HandlerContext", frame: NcpFrame) -> NcpFrame:
    """Validate and approve a joining node's REQUEST_APPROVAL.

    Verifies the request signature, checks name uniqueness, issues an
    endorsement packet, and returns it with the approval byte.

    Args:
        ctx: Shared handler context.
        frame: Incoming NCP frame.

    Returns:
        NcpFrame: Approval (0x01 + endorsement JSON) or rejection (0x00).
    """
    parse_result = RequestApprovalRequest.from_payload(frame.payload)
    if parse_result.is_err():
        return _error_response(NcpCommandId.REQUEST_APPROVAL, parse_result.unwrap_err())

    req = parse_result.unwrap()

    # Verify the request signature
    sig_result = Ed25519Pair.verify(
        req.ed25519_pub, req.signable_bytes(), req.signature
    )
    if sig_result.is_err():
        logger.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] REQUEST_APPROVAL rejected "
            "(bad signature) for node %d",
            req.node_name,
        )
        return _make_response(
            NcpCommandId.REQUEST_APPROVAL,
            RequestApprovalResponse(approved=False).to_payload(),
        )

    # Check name uniqueness
    if ctx.usd.get_node(req.node_name) is not None:
        logger.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] REQUEST_APPROVAL rejected "
            "(name conflict) for node %d",
            req.node_name,
        )
        return _make_response(
            NcpCommandId.REQUEST_APPROVAL,
            RequestApprovalResponse(approved=False).to_payload(),
        )

    # Only active nodes can endorse
    if not ctx.node.is_reachable():
        return _make_response(
            NcpCommandId.REQUEST_APPROVAL,
            RequestApprovalResponse(approved=False).to_payload(),
        )

    # Issue endorsement
    packet = ctx.endorsement_factory.issue(
        node_name=req.node_name,
        node_pub_key=req.ed25519_pub,
        node_session_key=req.x25519_pub,
        roles=[NodeRole.NODE_EXECUTOR],
        ttl_seconds=86400,
    )
    ctx.nel.add_issued(packet)

    # Register in NIT so the new node can talk to us
    ctx.nit.register(
        address="unknown",  # will be refreshed when the node sends HIA
        public_key=req.ed25519_pub,
        ttl=int(packet.expiration - time.time()),
    )

    # Encode endorsement packet inline with the approval byte
    endorsement_doc = {
        "endorser_key": packet.endorser_key.hex(),
        "node_name": packet.node_name,
        "node_pub_key": packet.node_pub_key.hex(),
        "node_session_key": packet.node_session_key.hex(),
        "roles": [r.value for r in packet.roles],
        "serial": packet.serial.hex(),
        "expiration": packet.expiration,
        "signature": packet.signature.hex(),
    }
    approval_byte = bytes([0x01])
    endorsement_bytes = json.dumps(endorsement_doc).encode("utf-8")

    logger.info(
        "[\x1b[38;5;51mUSMD\x1b[0m] REQUEST_APPROVAL approved for node %d",
        req.node_name,
    )
    return _make_response(
        NcpCommandId.REQUEST_APPROVAL,
        approval_byte + endorsement_bytes,
    )


# ---------------------------------------------------------------------------
# Command 8: Inform_reference_node
# ---------------------------------------------------------------------------


def handle_inform_reference_node(ctx: "HandlerContext", frame: NcpFrame) -> NcpFrame:
    """Process an INFORM_REFERENCE_NODE notification from a peer.

    Updates the local NRL to track which nodes have selected us as a reference.

    Args:
        ctx: Shared handler context.
        frame: Incoming NCP frame.

    Returns:
        NcpFrame: Empty acknowledgement.
    """
    parse_result = InformReferenceNodeRequest.from_payload(frame.payload)
    if parse_result.is_err():
        return _error_response(
            NcpCommandId.INFORM_REFERENCE_NODE, parse_result.unwrap_err()
        )
    req = parse_result.unwrap()

    if ctx.nrl is not None and req.sender_name != 0:
        if ctx.node.name in req.reference_names:
            ctx.nrl.add(req.sender_name, req.sender_address)
            logger.info(
                "[\x1b[38;5;51mUSMD\x1b[0m] NRL: %s (#%d) nous mandate.",
                req.sender_address,
                req.sender_name,
            )
        else:
            if ctx.nrl.get(req.sender_name) is not None:
                ctx.nrl.remove(req.sender_name)
                logger.info(
                    "[\x1b[38;5;51mUSMD\x1b[0m] NRL: %s (#%d) ne nous mandate plus.",
                    req.sender_address,
                    req.sender_name,
                )
    else:
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP INFORM_REFERENCE_NODE: refs=%s",
            req.reference_names,
        )
    return _make_response(NcpCommandId.INFORM_REFERENCE_NODE, b"")
