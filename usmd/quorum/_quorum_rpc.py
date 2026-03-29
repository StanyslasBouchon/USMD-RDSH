"""Internal module — NCP I/O and self-promotion helpers for QuorumManager.

Provides helper functions and the :class:`QuorumOptions` configuration class
extracted from :class:`QuorumManager` to keep ``manager.py`` under the
450-line limit:

- :class:`QuorumOptions`     — tunable parameters for a QuorumManager instance.
- :func:`request_vote`       — sends REQUEST_VOTE to one peer.
- :func:`announce_promotion` — broadcasts ANNOUNCE_PROMOTION to all peers.
- :func:`promote_self`       — updates local state after winning an election.

All mutable state is passed explicitly to avoid any ``protected-access``
Pylint warning; the class methods in :class:`QuorumManager` act as thin
wrappers that unpack ``self`` and forward to these functions.

This module is private to the ``quorum`` sub-package.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable

from ..ncp.client.tcp import NcpClient
from ..ncp.protocol.commands.announce_promotion import AnnouncePromotionRequest
from ..ncp.protocol.commands.request_vote import (
    RequestVoteRequest,
    RequestVoteResponse,
)
from ..ncp.protocol.frame import NcpCommandId
from ..node.nal import NodeAccessList
from ..node.nit import NodeIdentityTable
from ..node.nqt import NodeQuorumTable
from ..node.role import NodeRole

if TYPE_CHECKING:
    from ..config import NodeConfig
    from ..domain.usd import UnifiedSystemDomain

logger = logging.getLogger(__name__)

# Maps NodeRole → config role string used by NodeConfig.role
_ROLE_TO_CFG: dict[NodeRole, str] = {
    NodeRole.NODE_OPERATOR: "operator",
    NodeRole.USD_OPERATOR:  "usd_operator",
    NodeRole.UCD_OPERATOR:  "ucd_operator",
}


class QuorumOptions:
    """Tunable parameters for a :class:`QuorumManager` instance.

    All parameters have sensible defaults so only the fields that differ from
    the node configuration need to be supplied.

    Attributes:
        check_interval: Seconds between operator liveness checks.
        ncp_port: TCP port for outbound NCP connections.
        ncp_timeout: Timeout in seconds for outbound NCP connections.
        on_ncp_failure: Optional callback invoked with a peer's address when an
            outgoing NCP request to that peer fails.
        usd: Optional live UnifiedSystemDomain used to exclude inactive nodes
            from election polls.

    Examples:
        >>> opts = QuorumOptions(check_interval=10.0, ncp_port=5626)
        >>> opts.check_interval
        10.0
    """

    def __init__(
        self,
        check_interval: float = 30.0,
        ncp_port: int = 5626,
        ncp_timeout: float = 5.0,
        on_ncp_failure: Callable[[str], None] | None = None,
        usd: "UnifiedSystemDomain | None" = None,
    ) -> None:
        self.check_interval = check_interval
        self.ncp_port = ncp_port
        self.ncp_timeout = ncp_timeout
        self.on_ncp_failure = on_ncp_failure
        self.usd = usd


async def request_vote(
    node_address: str,
    ncp_port: int,
    ncp_timeout: float,
    on_ncp_failure: Callable[[str], None] | None,
    epoch: int,
    role: NodeRole,
    address: str,
) -> bool:
    """Send a REQUEST_VOTE frame to one peer and return the vote.

    Args:
        node_address: IP address of the local (candidate) node.
        ncp_port: TCP port for outbound NCP connections.
        ncp_timeout: Timeout in seconds for outbound NCP connections.
        on_ncp_failure: Optional callback invoked with the peer address on failure.
        epoch: Current election epoch.
        role: Operator role being contested.
        address: Peer IP address.

    Returns:
        bool: True if the peer voted YES.
    """
    req = RequestVoteRequest(
        epoch=epoch,
        role=role.value,
        candidate_address=node_address,
    )
    client = NcpClient(address=address, port=ncp_port, timeout=ncp_timeout)
    result = await client.send(NcpCommandId.REQUEST_VOTE, req.to_payload())
    if result.is_err():
        logger.debug(
            "[USMD-QUORUM] REQUEST_VOTE to %s failed: %s",
            address,
            result.unwrap_err(),
        )
        if on_ncp_failure:
            on_ncp_failure(address)
        return False

    parse_result = RequestVoteResponse.from_payload(result.unwrap().payload)
    if parse_result.is_err():
        logger.debug(
            "[USMD-QUORUM] REQUEST_VOTE response parse error from %s: %s",
            address,
            parse_result.unwrap_err(),
        )
        return False

    granted = parse_result.unwrap().granted
    logger.debug(
        "[USMD-QUORUM] [%s] Vote from %s: %s",
        role.value,
        address,
        "YES" if granted else "NO",
    )
    return granted


async def announce_promotion(
    node_address: str,
    ed_pub: bytes,
    ncp_port: int,
    ncp_timeout: float,
    on_ncp_failure: Callable[[str], None] | None,
    role: NodeRole,
    epoch: int,
    peers: list[str],
) -> None:
    """Broadcast ANNOUNCE_PROMOTION to all live peers.

    Args:
        node_address: IP address of this (promoted) node.
        ed_pub: Ed25519 public key of this node (32 bytes).
        ncp_port: TCP port for outbound NCP connections.
        ncp_timeout: Timeout in seconds for outbound NCP connections.
        on_ncp_failure: Optional callback invoked with the peer address on failure.
        role: Operator role that was just won.
        epoch: Election epoch.
        peers: List of peer IP addresses to notify.
    """
    req = AnnouncePromotionRequest(
        epoch=epoch,
        role=role.value,
        pub_key=ed_pub,
        address=node_address,
    )
    payload = req.to_payload()
    for address in peers:
        client = NcpClient(address=address, port=ncp_port, timeout=ncp_timeout)
        result = await client.send(NcpCommandId.ANNOUNCE_PROMOTION, payload)
        if result.is_err():
            logger.debug(
                "[USMD-QUORUM] ANNOUNCE_PROMOTION to %s failed: %s",
                address,
                result.unwrap_err(),
            )
            if on_ncp_failure:
                on_ncp_failure(address)
        else:
            logger.debug(
                "[USMD-QUORUM] ANNOUNCE_PROMOTION acknowledged by %s.", address
            )


def promote_self(
    cfg: "NodeConfig",
    nal: NodeAccessList,
    nqt: NodeQuorumTable,
    elected_roles: set[NodeRole],
    ed_pub: bytes,
    node_address: str,
    role: NodeRole,
    epoch: int,
    reason: str,
) -> None:
    """Update local role in cfg and NAL for the elected role.

    Mutates *cfg*, *nal*, *nqt*, and *elected_roles* in-place.

    Args:
        cfg: Node configuration (``role`` field is updated).
        nal: Node Access List (the role is granted to *ed_pub*).
        nqt: Node Quorum Table (a new entry is appended).
        elected_roles: Mutable set of currently held operator roles.
        ed_pub: Ed25519 public key of this node (32 bytes).
        node_address: IP address of this node.
        role: Operator role this node has been elected to.
        epoch: Election epoch.
        reason: Human-readable explanation stored in the NQT.
    """
    cfg.role = _ROLE_TO_CFG[role]
    nal.grant(ed_pub, role, permanent=False)
    elected_roles.add(role)
    nqt.add(epoch, ed_pub, node_address, reason, role.value)
    logger.info(
        "[USMD-QUORUM] This node (%s) is now %s.",
        node_address,
        role.value.upper(),
    )


# ---------------------------------------------------------------------------
# NCP handler callbacks
# ---------------------------------------------------------------------------


def should_grant_vote(
    voted_epochs: dict,
    has_live_role_fn: "Callable[[NodeRole], bool]",
    operator_roles: list,
    epoch: int,
    candidate_address: str,
    role_name: str = "node_operator",
) -> bool:
    """Decide whether to grant a vote for the given epoch, role, and candidate.

    A node votes YES if and only if:
    - The requested role is one of the three managed operator roles.
    - It has not yet voted for this role in this epoch.
    - It does not believe a live holder of that role already exists.

    Args:
        voted_epochs: Per-role sets of epochs already voted on.
        has_live_role_fn: Callable returning True if a live holder of a role exists.
        operator_roles: List of valid operator :class:`NodeRole` values.
        epoch: Election epoch from the candidate.
        candidate_address: IP address of the candidate node.
        role_name: Name of the operator role being contested.

    Returns:
        bool: True to grant the vote (YES), False to refuse (NO).
    """
    try:
        role = NodeRole(role_name)
    except ValueError:
        logger.debug(
            "[USMD-QUORUM] Unknown role '%s' in vote request from %s — refusing.",
            role_name,
            candidate_address,
        )
        return False

    if role not in operator_roles:
        return False

    role_epochs = voted_epochs[role]
    if epoch in role_epochs:
        logger.debug(
            "[USMD-QUORUM] [%s] Already voted in epoch %d — refusing %s.",
            role_name,
            epoch,
            candidate_address,
        )
        return False

    if has_live_role_fn(role):
        logger.debug(
            "[USMD-QUORUM] [%s] Live holder exists — refusing vote for %s.",
            role_name,
            candidate_address,
        )
        return False

    role_epochs.add(epoch)
    logger.info(
        "[USMD-QUORUM] [%s] Granting vote (epoch=%d) to candidate %s.",
        role_name,
        epoch,
        candidate_address,
    )
    return True


def on_promotion_announced(
    nal: NodeAccessList,
    nit: "NodeIdentityTable",
    voted_epochs: dict,
    nqt: NodeQuorumTable,
    epoch: int,
    pub_key: bytes,
    address: str,
    role_name: str = "node_operator",
) -> None:
    """Handle an incoming ANNOUNCE_PROMOTION notification.

    Registers the promoted node's public key in the local NAL with the
    announced role, and registers or refreshes its NIT entry.

    Args:
        nal: Node Access List to grant the role in.
        nit: Node Identity Table to register the peer in.
        voted_epochs: Per-role sets of epochs to clear after announcement.
        nqt: Node Quorum Table to record the promotion.
        epoch: Election epoch from the announcement.
        pub_key: Ed25519 public key of the promoted node (32 bytes).
        address: IP address of the promoted node.
        role_name: Name of the role the node was promoted to.
    """
    try:
        role = NodeRole(role_name)
    except ValueError:
        logger.warning(
            "[USMD-QUORUM] Unknown role '%s' in ANNOUNCE_PROMOTION from %s.",
            role_name,
            address,
        )
        role = NodeRole.NODE_OPERATOR

    logger.info(
        "[USMD-QUORUM] Epoch %d: %s promoted to %s (key=%s…).",
        epoch,
        address,
        role.value.upper(),
        pub_key.hex()[:16],
    )
    nal.grant(pub_key, role, permanent=False)
    nit.register(address, pub_key, ttl=86400)
    voted_epochs[role].discard(epoch)
    nqt.add(
        epoch, pub_key, address,
        f"Annonce reçue d'un pair (epoch {epoch})",
        role.value,
    )
