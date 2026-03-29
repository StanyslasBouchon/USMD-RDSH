"""NCP command handler for USMD-RDSH.

Dispatches incoming NCP frames to the appropriate command handler and
returns a response frame. The handler holds a reference to the running
node's shared state (node, USD, NIT, NAL, NEL, etc.) via a context object.

Implementation note — three heavier handlers are split into a private module
to keep this file under 450 lines:

- :mod:`._handler_node_ops` — CHECK_DISTANCE, REQUEST_APPROVAL, INFORM_REFERENCE_NODE.

Examples:
    >>> ctx = HandlerContext.__new__(HandlerContext)
    >>> isinstance(ctx, HandlerContext)
    True
"""

import logging
from dataclasses import dataclass
from typing import Callable, Optional

from ._handler_node_ops import (
    handle_check_distance,
    handle_inform_reference_node,
    handle_request_approval,
    handle_revoke_endorsement,
)

from ..protocol.commands.get_nqt import GetNqtRequest, GetNqtResponse
from ..protocol.commands.get_status import (
    GetStatusRequest,
    GetStatusResponse,
    NodeStatus,
)
from ..protocol.commands.announce_promotion import (
    AnnouncePromotionRequest,
    AnnouncePromotionResponse,
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
from ..protocol.frame import NcpCommandId, NcpFrame, format_ncp_cmd_for_log
from ..protocol.versions import NcpVersion
from ...domain.usd import UnifiedSystemDomain
from ...mutation.transmutation import ResourceUsage
from ...node.nal import NodeAccessList
from ...node.nel import NodeEndorsementList
from ...node.nit import NodeIdentityTable
from ...node.node import Node
from ...node.nqt import NodeQuorumTable
from ...node.nrl import NodeReferenceList
from ...security.endorsement import EndorsementFactory
from ...utils.errors import Error
from ...quorum.manager import QuorumManager

_CURRENT_VERSION = NcpVersion(1, 0, 0, 0)

logger = logging.getLogger(__name__)


@dataclass
class HandlerContext:
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
    nqt: NodeQuorumTable | None = None
    nrl: NodeReferenceList | None = None
    rejoin_fn: Optional[Callable[[], None]] = None


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
        format_ncp_cmd_for_log(command_id),
        err,
    )
    return _make_response(command_id, b"")


class NcpCommandHandler:
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
            NcpCommandId.GET_NQT: self._handle_get_nqt,
            NcpCommandId.REVOKE_ENDORSEMENT: self._handle_revoke_endorsement,
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
                "[\x1b[38;5;51mUSMD\x1b[0m] NCP unknown command %s",
                format_ncp_cmd_for_log(frame.command_id),
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
            hosting_static=list(self.ctx.node.hosting_static),
            hosting_dynamic=list(self.ctx.node.hosting_dynamic),
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
        return handle_check_distance(self.ctx, frame)

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
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s: can_help=%s",
            format_ncp_cmd_for_log(NcpCommandId.REQUEST_EMERGENCY),
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
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s: can_help=%s",
            format_ncp_cmd_for_log(NcpCommandId.REQUEST_HELP),
            can_help,
        )
        return _make_response(
            NcpCommandId.REQUEST_HELP,
            RequestHelpResponse(can_help=can_help).to_payload(),
        )

    # ------------------------------------------------------------------
    # Command 4: Request_approval
    # ------------------------------------------------------------------

    def _handle_request_approval(self, frame: NcpFrame) -> NcpFrame:
        return handle_request_approval(self.ctx, frame)

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
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s: v%d props=%s",
            format_ncp_cmd_for_log(NcpCommandId.SEND_UCD_PROPERTIES),
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
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s: domain=%s v%d",
            format_ncp_cmd_for_log(NcpCommandId.SEND_USD_PROPERTIES),
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
        self.ctx.usd.mutation_catalog.apply_remote_summaries(req.services)
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s: %d service(s)",
            format_ncp_cmd_for_log(NcpCommandId.SEND_MUTATION_PROPERTIES),
            len(req.services),
        )
        return _make_response(NcpCommandId.SEND_MUTATION_PROPERTIES, b"")

    # ------------------------------------------------------------------
    # Command 8: Inform_reference_node
    # ------------------------------------------------------------------

    def _handle_inform_reference_node(self, frame: NcpFrame) -> NcpFrame:
        return handle_inform_reference_node(self.ctx, frame)

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
                req.epoch, req.candidate_address, req.role
            )
        else:
            granted = False

        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s epoch=%d role=%s from=%s → %s",
            format_ncp_cmd_for_log(NcpCommandId.REQUEST_VOTE),
            req.epoch,
            req.role,
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
                req.epoch, req.pub_key, req.address, req.role
            )

        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s epoch=%d role=%s addr=%s",
            format_ncp_cmd_for_log(NcpCommandId.ANNOUNCE_PROMOTION),
            req.epoch,
            req.role,
            req.address,
        )
        return _make_response(
            NcpCommandId.ANNOUNCE_PROMOTION,
            AnnouncePromotionResponse().to_payload(),
        )

    def _handle_get_nqt(self, frame: NcpFrame) -> NcpFrame:
        """Return this node's full Node Quorum Table as a JSON response.

        Used by newly-joined peers to synchronise their local NQT so they
        immediately know who the current operator is.
        """
        parse_result = GetNqtRequest.from_payload(frame.payload)
        if parse_result.is_err():
            return _error_response(NcpCommandId.GET_NQT, parse_result.unwrap_err())

        entries = self.ctx.nqt.get_all_dicts() if self.ctx.nqt is not None else []
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s → %d entries",
            format_ncp_cmd_for_log(NcpCommandId.GET_NQT),
            len(entries),
        )
        return _make_response(
            NcpCommandId.GET_NQT,
            GetNqtResponse(entries=entries).to_payload(),
        )

    # ------------------------------------------------------------------
    # Command 13: Revoke_endorsement
    # ------------------------------------------------------------------

    def _handle_revoke_endorsement(self, frame: NcpFrame) -> NcpFrame:
        """Handle a REVOKE_ENDORSEMENT from a departing peer.

        Delegates to :func:`._handler_node_ops.handle_revoke_endorsement`.

        Args:
            frame: Incoming NCP frame carrying the REVOKE_ENDORSEMENT payload.

        Returns:
            NcpFrame: Empty acknowledgement, or empty response on exclusion.
        """
        return handle_revoke_endorsement(self.ctx, frame)
