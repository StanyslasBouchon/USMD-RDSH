"""Quorum manager — distributed operator election for USMD-RDSH.

Monitors the NIT/NAL for active operators.  When none are detected,
orchestrates a Raft-inspired election to promote one executor to
NODE_OPERATOR status.

Algorithm summary (simplified Raft leader election):

1. Every ``check_interval`` seconds, scan NIT+NAL for a live operator.
2. If none found, wait a random delay (1 to 8 seconds) then enter candidacy.
3. Gather all non-expired NIT peer addresses.
4. Send ``REQUEST_VOTE`` (epoch, self_address) to every peer.
5. Count YES votes: if ``yes_votes > total_peers / 2`` → elected.
6. Promote self in cfg + NAL.
7. Broadcast ``ANNOUNCE_PROMOTION`` to all live peers.

On the receiver side (called by the NCP handler):

- :meth:`should_grant_vote` — votes YES at most once per epoch.
- :meth:`on_promotion_announced` — grants NODE_OPERATOR to the winner.
"""

from __future__ import annotations

# pylint: disable=too-many-lines

import asyncio
import datetime
import logging
import random
import time
from typing import TYPE_CHECKING

from ..ncp.client.tcp import NcpClient
from ..ncp.protocol.commands.announce_promotion import AnnouncePromotionRequest
from ..ncp.protocol.commands.request_vote import (
    RequestVoteRequest,
    RequestVoteResponse,
)
from ..ncp.protocol.frame import NcpCommandId
from ..node.nal import NodeAccessList
from ..node.nit import NodeIdentityTable
from ..node.role import NodeRole

if TYPE_CHECKING:
    from ..config import NodeConfig

logger = logging.getLogger(__name__)

_ELECTION_DELAY_MIN = 1.0  # seconds — minimum random candidacy delay
_MAX_PROMOTIONS = 50  # maximum entries kept in the promotion history


class QuorumManager:  # pylint: disable=too-many-instance-attributes
    """Monitors operator liveness and runs elections when needed.

    Attributes:
        _node_address: IP address of this node.
        _ed_pub: Ed25519 public key of this node (32 bytes).
        _nit: Shared Node Identity Table.
        _nal: Shared Node Access List.
        _cfg: Node configuration (role updated on self-promotion).
        _check_interval: Seconds between operator liveness checks.
        _ncp_port: TCP port for outbound NCP connections.
        _ncp_timeout: Timeout in seconds for outbound NCP connections.
        _epoch: Current election epoch counter.
        _voted_epochs: Set of epochs in which this node already voted.
        _is_operator: True once this node has been promoted.

    Examples:
        >>> from usmd.node.nit import NodeIdentityTable
        >>> from usmd.node.nal import NodeAccessList
        >>> from usmd.config import NodeConfig
        >>> qm = QuorumManager(
        ...     node_address="10.0.0.1",
        ...     ed_pub=b"k" * 32,
        ...     nit=NodeIdentityTable(),
        ...     nal=NodeAccessList(),
        ...     cfg=NodeConfig(bootstrap=True),
        ... )
        >>> isinstance(qm, QuorumManager)
        True
    """

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        node_address: str,
        ed_pub: bytes,
        nit: NodeIdentityTable,
        nal: NodeAccessList,
        cfg: "NodeConfig",
        check_interval: float = 30.0,
        ncp_port: int = 5626,
        ncp_timeout: float = 5.0,
    ) -> None:
        """Initialise the QuorumManager.

        Args:
            node_address: IP address of this node.
            ed_pub: Ed25519 public key of this node (32 bytes).
            nit: Shared Node Identity Table.
            nal: Shared Node Access List.
            cfg: Node configuration.
            check_interval: Seconds between operator liveness checks.
            ncp_port: TCP port for outbound NCP connections.
            ncp_timeout: Timeout in seconds for outbound NCP connections.
        """
        self._node_address = node_address
        self._ed_pub = ed_pub
        self._nit = nit
        self._nal = nal
        self._cfg = cfg
        self._check_interval = check_interval
        self._ncp_port = ncp_port
        self._ncp_timeout = ncp_timeout

        self._epoch: int = 0
        self._voted_epochs: set[int] = set()
        self._is_operator: bool = cfg.node_role == NodeRole.NODE_OPERATOR
        self._promotions: list[dict] = []

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    @property
    def is_operator(self) -> bool:
        """Return True if this node has been promoted to NODE_OPERATOR."""
        return self._is_operator

    def get_promotions(self) -> list[dict]:
        """Return a copy of the promotion history (most recent first).

        Each entry is a dict with keys:
        ``epoch``, ``address``, ``pub_key``, ``promoted_at``,
        ``promoted_at_str``, ``reason``.

        Returns:
            list[dict]: Promotion records, newest first.

        Example:
            >>> from usmd.node.nit import NodeIdentityTable
            >>> from usmd.node.nal import NodeAccessList
            >>> from usmd.config import NodeConfig
            >>> qm = QuorumManager("10.0.0.1", b"k"*32,
            ...                    NodeIdentityTable(), NodeAccessList(),
            ...                    NodeConfig())
            >>> qm.get_promotions()
            []
        """
        return list(self._promotions)

    # ------------------------------------------------------------------
    # Main monitoring loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Monitor for live operators and run an election when none found.

        Runs until the asyncio task is cancelled.
        """
        logger.debug(
            "[USMD-QUORUM] Monitor started (check_interval=%.1fs)",
            self._check_interval,
        )
        while True:
            try:
                await asyncio.sleep(self._check_interval)
                if self._is_operator:
                    continue
                if not self._has_live_operator():
                    logger.info(
                        "[USMD-QUORUM] No live operator detected — starting election."
                    )
                    await self._start_election()
            except asyncio.CancelledError:
                break
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("[USMD-QUORUM] Monitor loop error: %s", exc)

    # ------------------------------------------------------------------
    # Liveness check
    # ------------------------------------------------------------------

    def _has_live_operator(self) -> bool:
        """Return True if at least one non-expired operator peer is known.

        Checks every non-expired NIT entry to see whether the corresponding
        public key holds the NODE_OPERATOR role in the local NAL.

        Returns:
            bool: True if a live operator is found, False otherwise.

        Example:
            >>> from usmd.node.nit import NodeIdentityTable
            >>> from usmd.node.nal import NodeAccessList
            >>> from usmd.config import NodeConfig
            >>> qm = QuorumManager("10.0.0.1", b"k"*32,
            ...                    NodeIdentityTable(), NodeAccessList(),
            ...                    NodeConfig())
            >>> qm._has_live_operator()
            False
        """
        for (
            pub_key,
            entry,
        ) in self._nit._entries.items():  # pylint: disable=protected-access
            if entry.is_expired():
                continue
            if entry.address == self._node_address:
                continue
            if self._nal.has_role(pub_key, NodeRole.NODE_OPERATOR):
                return True
        return False

    # ------------------------------------------------------------------
    # Promotion recorder
    # ------------------------------------------------------------------

    def _record_promotion(
        self, epoch: int, pub_key: bytes, address: str, reason: str
    ) -> None:
        """Append a promotion event to the internal history.

        Args:
            epoch: Election epoch of the promotion.
            pub_key: Ed25519 public key of the promoted node (32 bytes).
            address: IP address of the promoted node.
            reason: Human-readable explanation (French).
        """
        ts = time.time()
        entry = {
            "epoch": epoch,
            "address": address,
            "pub_key": pub_key.hex()[:20] + "…",
            "promoted_at": ts,
            "promoted_at_str": datetime.datetime.fromtimestamp(ts).strftime(
                "%d/%m/%Y %H:%M:%S"
            ),
            "reason": reason,
        }
        self._promotions.insert(0, entry)
        if len(self._promotions) > _MAX_PROMOTIONS:
            self._promotions = self._promotions[:_MAX_PROMOTIONS]

    # ------------------------------------------------------------------
    # Election
    # ------------------------------------------------------------------

    async def _start_election(self) -> None:
        """Run a single election round.

        Random delay → send REQUEST_VOTE to all live peers → evaluate votes.
        """
        delay = random.uniform(_ELECTION_DELAY_MIN, self._cfg.quorum_election_timeout)
        logger.debug("[USMD-QUORUM] Candidacy delay %.2fs before sending votes.", delay)
        await asyncio.sleep(delay)

        if self._has_live_operator():
            logger.debug(
                "[USMD-QUORUM] Operator appeared during candidacy delay — aborting."
            )
            return

        self._epoch += 1
        epoch = self._epoch
        peers = self._live_peer_addresses()

        if not peers:
            logger.warning(
                "[USMD-QUORUM] No live peers — cannot reach quorum, staying as executor."
            )
            return

        logger.info(
            "[USMD-QUORUM] Epoch %d: requesting vote from %d peer(s).",
            epoch,
            len(peers),
        )

        yes_votes = 0
        for address in peers:
            granted = await self._request_vote(epoch, address)
            if granted:
                yes_votes += 1

        logger.info(
            "[USMD-QUORUM] Epoch %d: %d/%d YES votes.", epoch, yes_votes, len(peers)
        )

        if yes_votes > len(peers) / 2:
            logger.info("[USMD-QUORUM] Epoch %d: elected — promoting self.", epoch)
            reason = (
                f"Élection — {yes_votes}/{len(peers)} vote(s) OUI "
                f"(epoch {epoch}, aucun opérateur détecté)"
            )
            self._promote_self(epoch=epoch, reason=reason)
            await self._announce_promotion(epoch, peers)
        else:
            logger.info(
                "[USMD-QUORUM] Epoch %d: not elected (insufficient votes).", epoch
            )

    def _live_peer_addresses(self) -> list[str]:
        """Return addresses of all non-expired, non-self NIT entries.

        Returns:
            list[str]: Unique list of peer IP addresses.
        """
        seen: set[str] = set()
        addresses: list[str] = []
        for entry in self._nit._entries.values():  # pylint: disable=protected-access
            if entry.is_expired():
                continue
            if entry.address == self._node_address:
                continue
            if entry.address not in seen:
                seen.add(entry.address)
                addresses.append(entry.address)
        return addresses

    async def _request_vote(self, epoch: int, address: str) -> bool:
        """Send a REQUEST_VOTE frame to one peer and return the vote.

        Args:
            epoch: Current election epoch.
            address: Peer IP address.

        Returns:
            bool: True if the peer voted YES.
        """
        req = RequestVoteRequest(epoch=epoch, candidate_address=self._node_address)
        client = NcpClient(
            address=address,
            port=self._ncp_port,
            timeout=self._ncp_timeout,
        )
        result = await client.send(NcpCommandId.REQUEST_VOTE, req.to_payload())
        if result.is_err():
            logger.debug(
                "[USMD-QUORUM] REQUEST_VOTE to %s failed: %s",
                address,
                result.unwrap_err(),
            )
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
            "[USMD-QUORUM] Vote from %s: %s", address, "YES" if granted else "NO"
        )
        return granted

    def _promote_self(self, epoch: int, reason: str) -> None:
        """Update local role to NODE_OPERATOR in cfg and NAL."""
        self._cfg.role = "operator"
        self._nal.grant(self._ed_pub, NodeRole.NODE_OPERATOR, permanent=False)
        self._is_operator = True
        self._record_promotion(epoch, self._ed_pub, self._node_address, reason)
        logger.info(
            "[USMD-QUORUM] This node (%s) is now NODE_OPERATOR.",
            self._node_address,
        )

    async def _announce_promotion(self, epoch: int, peers: list[str]) -> None:
        """Broadcast ANNOUNCE_PROMOTION to all live peers.

        Args:
            epoch: Election epoch.
            peers: List of peer IP addresses to notify.
        """
        req = AnnouncePromotionRequest(
            epoch=epoch,
            pub_key=self._ed_pub,
            address=self._node_address,
        )
        payload = req.to_payload()
        for address in peers:
            client = NcpClient(
                address=address,
                port=self._ncp_port,
                timeout=self._ncp_timeout,
            )
            result = await client.send(NcpCommandId.ANNOUNCE_PROMOTION, payload)
            if result.is_err():
                logger.debug(
                    "[USMD-QUORUM] ANNOUNCE_PROMOTION to %s failed: %s",
                    address,
                    result.unwrap_err(),
                )
            else:
                logger.debug(
                    "[USMD-QUORUM] ANNOUNCE_PROMOTION acknowledged by %s.", address
                )

    # ------------------------------------------------------------------
    # NCP handler callbacks
    # ------------------------------------------------------------------

    def should_grant_vote(self, epoch: int, candidate_address: str) -> bool:
        """Decide whether to grant a vote for the given epoch and candidate.

        A node votes YES if and only if:
        - It has not yet voted in this epoch.
        - It does not believe a live operator already exists.

        Args:
            epoch: Election epoch from the candidate.
            candidate_address: IP address of the candidate node.

        Returns:
            bool: True to grant the vote (YES), False to refuse (NO).

        Example:
            >>> from usmd.node.nit import NodeIdentityTable
            >>> from usmd.node.nal import NodeAccessList
            >>> from usmd.config import NodeConfig
            >>> qm = QuorumManager("10.0.0.1", b"k"*32,
            ...                    NodeIdentityTable(), NodeAccessList(),
            ...                    NodeConfig())
            >>> qm.should_grant_vote(1, "10.0.0.2")
            True
        """
        if epoch in self._voted_epochs:
            logger.debug(
                "[USMD-QUORUM] Already voted in epoch %d — refusing %s.",
                epoch,
                candidate_address,
            )
            return False
        if self._has_live_operator():
            logger.debug(
                "[USMD-QUORUM] Live operator exists — refusing vote for %s.",
                candidate_address,
            )
            return False
        self._voted_epochs.add(epoch)
        logger.info(
            "[USMD-QUORUM] Granting vote (epoch=%d) to candidate %s.",
            epoch,
            candidate_address,
        )
        return True

    def on_promotion_announced(self, epoch: int, pub_key: bytes, address: str) -> None:
        """Handle an incoming ANNOUNCE_PROMOTION notification.

        Registers the promoted node's public key in the local NAL with
        NODE_OPERATOR role, and registers or refreshes its NIT entry.

        Args:
            epoch: Election epoch from the announcement.
            pub_key: Ed25519 public key of the promoted node (32 bytes).
            address: IP address of the promoted node.
        """
        logger.info(
            "[USMD-QUORUM] Epoch %d: %s promoted to NODE_OPERATOR (key=%s…).",
            epoch,
            address,
            pub_key.hex()[:16],
        )
        self._nal.grant(pub_key, NodeRole.NODE_OPERATOR, permanent=False)
        self._nit.register(address, pub_key, ttl=86400)
        self._voted_epochs.discard(epoch)
        self._record_promotion(
            epoch, pub_key, address, f"Annonce reçue d'un pair (epoch {epoch})"
        )
