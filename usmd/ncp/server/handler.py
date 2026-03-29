"""NCP command handler for USMD-RDSH.

Dispatches incoming NCP frames to the appropriate command handler and
returns a response frame. The handler holds a reference to the running
node's shared state (node, USD, NIT, NAL, NEL, etc.) via a context object.

Examples:
    >>> ctx = HandlerContext.__new__(HandlerContext)
    >>> isinstance(ctx, HandlerContext)
    True
"""
# pylint: disable=too-many-lines

import logging
import time
from dataclasses import dataclass
from typing import Callable

from ..protocol.commands.check_distance import (
    CheckDistanceRequest,
    CheckDistanceResponse,
)
from ..protocol.commands.get_status import (
    GetStatusRequest,
    GetStatusResponse,
    NodeStatus,
)
from ..protocol.commands.announce_promotion import (
    AnnouncePromotionRequest,
    AnnouncePromotionResponse,
)
from ..protocol.commands.inform_reference_node import InformReferenceNodeRequest
from ..protocol.commands.request_approval import (
    RequestApprovalRequest,
    RequestApprovalResponse,
)
from ..protocol.commands.request_emergency import (
    RequestEmergencyRequest,
    RequestEmergencyResponse,
)
from ..protocol.commands.request_help import RequestHelpRequest, RequestHelpResponse
from ..protocol.commands.request_snapshot import (
    RequestSnapshotRequest,
    RequestSnapshotResponse,
)
from ..protocol.commands.request_vote import (
    RequestVoteRequest,
    RequestVoteResponse,
)
from ..protocol.commands.send_mutation_properties import SendMutationPropertiesRequest
from ..protocol.commands.send_ucd_properties import SendUcdPropertiesRequest
from ..protocol.commands.send_usd_properties import SendUsdPropertiesRequest
from ..protocol.frame import NcpCommandId, NcpFrame
from ..protocol.versions import NcpVersion
from ...domain.usd import UnifiedSystemDomain
from ...mutation.transmutation import DistanceCalculator, ResourceUsage
from ...security.crypto import Ed25519Pair
from ...node.nal import NodeAccessList
from ...node.nel import NodeEndorsementList
from ...node.nit import NodeIdentityTable
from ...node.node import Node
from ...node.role import NodeRole
from ...security.endorsement import EndorsementFactory
from ...utils.errors import Error
from ...quorum.manager import QuorumManager

_CURRENT_VERSION = NcpVersion(1, 0, 0, 0)

logger = logging.getLogger(__name__)


@dataclass
class HandlerContext:  # pylint: disable=too-many-instance-attributes
    """All mutable state the NCP handler needs to process commands.

    Attributes:
        node: The local node object.
        usd: The local USD instance.
        nit: Node Identity Table.
        nal: Node Access List.
        nel: Node Endorsement List.
        endorsement_factory: Issues endorsement packets to joining nodes.
        resource_getter: Callable returning current ResourceUsage.
        ping_tolerance_ms: Max ping tolerance T from the USD config.

    Examples:
        >>> ctx = HandlerContext.__new__(HandlerContext)
        >>> isinstance(ctx, HandlerContext)
        True
    """

    node: Node
    usd: UnifiedSystemDomain
    nit: NodeIdentityTable
    nal: NodeAccessList
    nel: NodeEndorsementList
    endorsement_factory: EndorsementFactory
    resource_getter: Callable[[], ResourceUsage]
    snapshot_fn: Callable[[], dict] = lambda: {}
    ping_tolerance_ms: int = 200
    quorum_manager: QuorumManager | None = None


def _make_response(command_id: NcpCommandId, payload: bytes) -> NcpFrame:
    """Build a response NcpFrame with the current protocol version."""
    return NcpFrame(
        version=_CURRENT_VERSION,
        command_id=command_id,
        payload=payload,
    )


def _error_response(command_id: NcpCommandId, err: Error) -> NcpFrame:
    """Build an empty-payload response when an error occurs (log + return empty)."""
    logger.warning(
        "[\x1b[38;5;51mUSMD\x1b[0m] NCP cmd=%s error: %s",
        command_id.name,
        err,
    )
    return _make_response(command_id, b"")


class NcpCommandHandler:  # pylint: disable=too-few-public-methods
    """Dispatches NCP frames to command-specific handlers.

    Instantiate once per node and pass the same instance to the TCP server
    so that all connections share the same state context.

    Attributes:
        ctx: Shared handler context (node state, tables, etc.).

    Examples:
        >>> ctx = HandlerContext.__new__(HandlerContext)
        >>> handler = NcpCommandHandler(ctx)
        >>> isinstance(handler, NcpCommandHandler)
        True
    """

    def __init__(self, ctx: HandlerContext) -> None:
        """Initialise with a shared HandlerContext.

        Args:
            ctx: Shared mutable state for all handlers.
        """
        self.ctx = ctx
        self._dispatch = {
            NcpCommandId.GET_STATUS: self._handle_get_status,
            NcpCommandId.CHECK_DISTANCE: self._handle_check_distance,
            NcpCommandId.REQUEST_EMERGENCY: self._handle_request_emergency,
            NcpCommandId.REQUEST_HELP: self._handle_request_help,
            NcpCommandId.REQUEST_APPROVAL: self._handle_request_approval,
            NcpCommandId.SEND_UCD_PROPERTIES: self._handle_send_ucd_properties,
            NcpCommandId.SEND_USD_PROPERTIES: self._handle_send_usd_properties,
            NcpCommandId.SEND_MUTATION_PROPERTIES: self._handle_send_mutation_properties,
            NcpCommandId.INFORM_REFERENCE_NODE: self._handle_inform_reference_node,
            NcpCommandId.REQUEST_SNAPSHOT: self._handle_request_snapshot,
            NcpCommandId.REQUEST_VOTE: self._handle_request_vote,
            NcpCommandId.ANNOUNCE_PROMOTION: self._handle_announce_promotion,
        }

    def handle(self, frame: NcpFrame) -> NcpFrame:
        """Dispatch a frame to the appropriate handler and return a response.

        Args:
            frame: The incoming NCP frame.

        Returns:
            NcpFrame: The response frame to send back.

        Example:
            >>> ctx = HandlerContext.__new__(HandlerContext)
            >>> handler = NcpCommandHandler(ctx)
            >>> isinstance(handler, NcpCommandHandler)
            True
        """
        handler_fn = self._dispatch.get(frame.command_id)
        if handler_fn is None:
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] NCP unknown command %d",
                frame.command_id,
            )
            return _make_response(frame.command_id, b"")
        return handler_fn(frame)

    # ------------------------------------------------------------------
    # Command 0: Get_status
    # ------------------------------------------------------------------

    def _handle_get_status(self, frame: NcpFrame) -> NcpFrame:
        usage = self.ctx.resource_getter()
        status = NodeStatus(
            ram_percent=usage.ram_percent,
            cpu_percent=usage.cpu_percent,
            disk_percent=usage.disk_percent,
            network_percent=usage.network_percent,
            service_name=self.ctx.node.service_name,
            state=self.ctx.node.state,
        )
        _ = GetStatusRequest.from_payload(frame.payload)  # validate (empty)
        return _make_response(
            NcpCommandId.GET_STATUS,
            GetStatusResponse(status).to_payload(),
        )

    # ------------------------------------------------------------------
    # Command 1: Check_distance
    # ------------------------------------------------------------------

    def _handle_check_distance(self, frame: NcpFrame) -> NcpFrame:
        parse_result = CheckDistanceRequest.from_payload(frame.payload)
        if parse_result.is_err():
            return _error_response(
                NcpCommandId.CHECK_DISTANCE, parse_result.unwrap_err()
            )

        req = parse_result.unwrap()
        now_ms = int(time.time() * 1000)
        ping_ms = float(max(0, now_ms - req.sent_at_ms))

        usage = self.ctx.resource_getter()
        load = usage.reference_load()

        calc = DistanceCalculator(
            ping_tolerance_ms=self.ctx.usd.config.ping_tolerance_ms
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

    # ------------------------------------------------------------------
    # Command 2: Request_emergency
    # ------------------------------------------------------------------

    def _handle_request_emergency(self, frame: NcpFrame) -> NcpFrame:
        parse_result = RequestEmergencyRequest.from_payload(frame.payload)
        if parse_result.is_err():
            return _error_response(
                NcpCommandId.REQUEST_EMERGENCY, parse_result.unwrap_err()
            )

        usage = self.ctx.resource_getter()
        threshold = self.ctx.usd.config.load_threshold
        can_help = not usage.is_weakened(threshold) and self.ctx.node.is_reachable()

        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP REQUEST_EMERGENCY: can_help=%s",
            can_help,
        )
        return _make_response(
            NcpCommandId.REQUEST_EMERGENCY,
            RequestEmergencyResponse(can_help=can_help).to_payload(),
        )

    # ------------------------------------------------------------------
    # Command 3: Request_help
    # ------------------------------------------------------------------

    def _handle_request_help(self, frame: NcpFrame) -> NcpFrame:
        parse_result = RequestHelpRequest.from_payload(frame.payload)
        if parse_result.is_err():
            return _error_response(NcpCommandId.REQUEST_HELP, parse_result.unwrap_err())

        usage = self.ctx.resource_getter()
        threshold = self.ctx.usd.config.load_threshold
        can_help = not usage.is_weakened(threshold) and self.ctx.node.is_reachable()

        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP REQUEST_HELP: can_help=%s", can_help
        )
        return _make_response(
            NcpCommandId.REQUEST_HELP,
            RequestHelpResponse(can_help=can_help).to_payload(),
        )

    # ------------------------------------------------------------------
    # Command 4: Request_approval
    # ------------------------------------------------------------------

    def _handle_request_approval(self, frame: NcpFrame) -> NcpFrame:
        parse_result = RequestApprovalRequest.from_payload(frame.payload)
        if parse_result.is_err():
            return _error_response(
                NcpCommandId.REQUEST_APPROVAL, parse_result.unwrap_err()
            )

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
        if self.ctx.usd.get_node(req.node_name) is not None:
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
        if not self.ctx.node.is_reachable():
            return _make_response(
                NcpCommandId.REQUEST_APPROVAL,
                RequestApprovalResponse(approved=False).to_payload(),
            )

        # Issue endorsement
        packet = self.ctx.endorsement_factory.issue(
            node_name=req.node_name,
            node_pub_key=req.ed25519_pub,
            node_session_key=req.x25519_pub,
            roles=[NodeRole.NODE_EXECUTOR],
            ttl_seconds=86400,
        )
        self.ctx.nel.add_issued(packet)

        # Register in NIT so the new node can talk to us
        self.ctx.nit.register(
            address="unknown",  # will be refreshed when the node sends HIA
            public_key=req.ed25519_pub,
            ttl=int(packet.expiration - time.time()),
        )

        # Encode endorsement packet inline with the approval byte
        import json  # pylint: disable=import-outside-toplevel

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

    # ------------------------------------------------------------------
    # Command 5: Send_ucd_properties
    # ------------------------------------------------------------------

    def _handle_send_ucd_properties(self, frame: NcpFrame) -> NcpFrame:
        parse_result = SendUcdPropertiesRequest.from_payload(frame.payload)
        if parse_result.is_err():
            return _error_response(
                NcpCommandId.SEND_UCD_PROPERTIES, parse_result.unwrap_err()
            )
        req = parse_result.unwrap()
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP SEND_UCD_PROPERTIES: v%d props=%s",
            req.version,
            list(req.properties.keys()),
        )
        # Apply if this is a reference node and the config is newer
        return _make_response(NcpCommandId.SEND_UCD_PROPERTIES, b"")

    # ------------------------------------------------------------------
    # Command 6: Send_usd_properties
    # ------------------------------------------------------------------

    def _handle_send_usd_properties(self, frame: NcpFrame) -> NcpFrame:
        parse_result = SendUsdPropertiesRequest.from_payload(frame.payload)
        if parse_result.is_err():
            return _error_response(
                NcpCommandId.SEND_USD_PROPERTIES, parse_result.unwrap_err()
            )
        req = parse_result.unwrap()
        new_cfg = req.to_usd_config()
        self.ctx.usd.update_config(new_cfg)
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP SEND_USD_PROPERTIES: domain=%s v%d",
            req.name,
            req.config_version,
        )
        return _make_response(NcpCommandId.SEND_USD_PROPERTIES, b"")

    # ------------------------------------------------------------------
    # Command 7: Send_mutation_properties
    # ------------------------------------------------------------------

    def _handle_send_mutation_properties(self, frame: NcpFrame) -> NcpFrame:
        parse_result = SendMutationPropertiesRequest.from_payload(frame.payload)
        if parse_result.is_err():
            return _error_response(
                NcpCommandId.SEND_MUTATION_PROPERTIES, parse_result.unwrap_err()
            )
        req = parse_result.unwrap()
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP SEND_MUTATION_PROPERTIES: %d service(s)",
            len(req.services),
        )
        return _make_response(NcpCommandId.SEND_MUTATION_PROPERTIES, b"")

    # ------------------------------------------------------------------
    # Command 8: Inform_reference_node
    # ------------------------------------------------------------------

    def _handle_inform_reference_node(self, frame: NcpFrame) -> NcpFrame:
        parse_result = InformReferenceNodeRequest.from_payload(frame.payload)
        if parse_result.is_err():
            return _error_response(
                NcpCommandId.INFORM_REFERENCE_NODE, parse_result.unwrap_err()
            )
        req = parse_result.unwrap()
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP INFORM_REFERENCE_NODE: refs=%s",
            req.reference_names,
        )
        return _make_response(NcpCommandId.INFORM_REFERENCE_NODE, b"")

    # ------------------------------------------------------------------
    # Command 9: Request_snapshot
    # ------------------------------------------------------------------

    def _handle_request_snapshot(self, frame: NcpFrame) -> NcpFrame:
        _ = RequestSnapshotRequest.from_payload(frame.payload)
        snapshot = self.ctx.snapshot_fn()
        return _make_response(
            NcpCommandId.REQUEST_SNAPSHOT,
            RequestSnapshotResponse(snapshot).to_payload(),
        )

    # ------------------------------------------------------------------
    # Command 10: Request_vote
    # ------------------------------------------------------------------

    def _handle_request_vote(self, frame: NcpFrame) -> NcpFrame:
        parse_result = RequestVoteRequest.from_payload(frame.payload)
        if parse_result.is_err():
            return _error_response(NcpCommandId.REQUEST_VOTE, parse_result.unwrap_err())

        req = parse_result.unwrap()
        if self.ctx.quorum_manager is not None:
            granted = self.ctx.quorum_manager.should_grant_vote(
                req.epoch, req.candidate_address
            )
        else:
            granted = False

        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP REQUEST_VOTE epoch=%d from=%s → %s",
            req.epoch,
            req.candidate_address,
            "YES" if granted else "NO",
        )
        return _make_response(
            NcpCommandId.REQUEST_VOTE,
            RequestVoteResponse(granted=granted).to_payload(),
        )

    # ------------------------------------------------------------------
    # Command 11: Announce_promotion
    # ------------------------------------------------------------------

    def _handle_announce_promotion(self, frame: NcpFrame) -> NcpFrame:
        parse_result = AnnouncePromotionRequest.from_payload(frame.payload)
        if parse_result.is_err():
            return _error_response(
                NcpCommandId.ANNOUNCE_PROMOTION, parse_result.unwrap_err()
            )

        req = parse_result.unwrap()
        if self.ctx.quorum_manager is not None:
            self.ctx.quorum_manager.on_promotion_announced(
                req.epoch, req.pub_key, req.address
            )

        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP ANNOUNCE_PROMOTION epoch=%d addr=%s",
            req.epoch,
            req.address,
        )
        return _make_response(
            NcpCommandId.ANNOUNCE_PROMOTION,
            AnnouncePromotionResponse().to_payload(),
        )
