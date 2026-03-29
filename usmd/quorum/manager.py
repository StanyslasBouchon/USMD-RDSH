"""Quorum manager — distributed operator election for USMD-RDSH.

Monitors the NIT/NAL for active holders of each of the three operator roles.
When no live holder is detected for a given role, orchestrates a
Raft-inspired election to promote one executor to that role.

Monitored roles (independent elections):

- ``NODE_OPERATOR``  — manages individual nodes within an USD
- ``USD_OPERATOR``   — manages a Unified System Domain
- ``UCD_OPERATOR``   — manages the Unified Configuration Database

Algorithm summary (per role, simplified Raft leader election):

1. Every ``check_interval`` seconds, scan NIT+NAL for each operator role.
2. For each role with no live holder, wait a random delay then enter candidacy.
3. Gather all non-expired, active NIT peer addresses.
4. Send ``REQUEST_VOTE`` (epoch, self_address, role) to every peer.
5. Count YES votes: if ``yes_votes > total_peers / 2`` → elected for that role.
6. Promote self in cfg + NAL for that specific role.
7. Broadcast ``ANNOUNCE_PROMOTION`` (with role) to all live peers.

On the receiver side:

- :meth:`should_grant_vote`     — votes YES at most once per (role, epoch).
- :meth:`on_promotion_announced` — grants the announced role to the winner.

Heavy helpers are split into :mod:`._quorum_rpc` to stay under 450 lines.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import TYPE_CHECKING

from ._quorum_rpc import (
    QuorumOptions,
    announce_promotion,
    on_promotion_announced as _on_promotion_announced,
    promote_self,
    request_vote,
    should_grant_vote as _should_grant_vote,
)
from ..node.nal import NodeAccessList
from ..node.nit import NodeIdentityTable
from ..node.nqt import NodeQuorumTable
from ..node.role import NodeRole

if TYPE_CHECKING:
    from ..config import NodeConfig

logger = logging.getLogger(__name__)

_ELECTION_DELAY_MIN = 1.0  # seconds — minimum random candidacy delay

# The three operator roles managed by independent elections
_OPERATOR_ROLES: list[NodeRole] = [
    NodeRole.NODE_OPERATOR,
    NodeRole.USD_OPERATOR,
    NodeRole.UCD_OPERATOR,
]


class QuorumManager:
    """Monitors operator liveness and runs elections for all three operator roles.

    Attributes:
        _node_address: IP address of this node.
        _ed_pub: Ed25519 public key of this node (32 bytes).
        _nit: Shared Node Identity Table.
        _nal: Shared Node Access List.
        _nqt: Shared Node Quorum Table (promotion history).
        _cfg: Node configuration (role updated on self-promotion).
        _options: Tunable runtime parameters (intervals, ports, callbacks).
        _epochs: Per-role election epoch counters.
        _voted_epochs: Per-role sets of epochs in which this node already voted.
        _elected_roles: Set of roles this node currently holds.

    Examples:
        >>> from usmd.node.nit import NodeIdentityTable
        >>> from usmd.node.nal import NodeAccessList
        >>> from usmd.node.nqt import NodeQuorumTable
        >>> from usmd.config import NodeConfig
        >>> qm = QuorumManager(
        ...     node_address="10.0.0.1",
        ...     ed_pub=b"k" * 32,
        ...     nit=NodeIdentityTable(),
        ...     nal=NodeAccessList(),
        ...     nqt=NodeQuorumTable(),
        ...     cfg=NodeConfig(bootstrap=True),
        ... )
        >>> isinstance(qm, QuorumManager)
        True
    """

    def __init__(
        self,
        node_address: str,
        ed_pub: bytes,
        nit: NodeIdentityTable,
        nal: NodeAccessList,
        nqt: NodeQuorumTable,
        cfg: "NodeConfig",
        options: QuorumOptions | None = None,
    ) -> None:
        """Initialise the QuorumManager.

        Args:
            node_address: IP address of this node.
            ed_pub: Ed25519 public key of this node (32 bytes).
            nit: Shared Node Identity Table.
            nal: Shared Node Access List.
            nqt: Shared Node Quorum Table.
            cfg: Node configuration.
            options: Tunable runtime parameters (intervals, ports, callbacks).
                     Defaults to :class:`QuorumOptions` with stock values.
        """
        _opts = options or QuorumOptions()
        self._node_address = node_address
        self._ed_pub = ed_pub
        self._nit = nit
        self._nal = nal
        self._nqt = nqt
        self._cfg = cfg
        self._check_interval = _opts.check_interval
        self._ncp_port = _opts.ncp_port
        self._ncp_timeout = _opts.ncp_timeout
        self._on_ncp_failure = _opts.on_ncp_failure
        self._usd = _opts.usd

        self._epochs: dict[NodeRole, int] = {r: 0 for r in _OPERATOR_ROLES}
        self._voted_epochs: dict[NodeRole, set[int]] = {r: set() for r in _OPERATOR_ROLES}

        # Seed elected roles from the configured role so a node that was
        # previously elected and restarted with its role persisted in yaml
        # does not immediately trigger a new election for its own role.
        self._elected_roles: set[NodeRole] = set()
        if cfg.node_role in _OPERATOR_ROLES:
            self._elected_roles.add(cfg.node_role)

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    @property
    def is_operator(self) -> bool:
        """Return True if this node holds any operator role.

        Kept for backward compatibility with call-sites that check
        ``is_operator`` without caring which specific role is held.
        """
        return bool(self._elected_roles)

    @property
    def elected_roles(self) -> list[str]:
        """Return the list of operator role names held by this node.

        Returns:
            list[str]: Role values (e.g. ``["node_operator", "usd_operator"]``).
        """
        return [r.value for r in self._elected_roles]

    def get_promotions(self) -> list[dict]:
        """Return the promotion history from the shared NQT (most recent first).

        Each entry is a dict with keys:
        ``epoch``, ``address``, ``pub_key``, ``promoted_at``,
        ``promoted_at_str``, ``reason``, ``role_name``.

        Returns:
            list[dict]: Promotion records, newest first.
        """
        return self._nqt.get_all_dicts()

    # ------------------------------------------------------------------
    # Main monitoring loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Monitor for live operator holders and run elections when needed.

        Checks each of the three operator roles independently every
        ``check_interval`` seconds.  Runs until the asyncio task is cancelled.
        """
        logger.debug(
            "[USMD-QUORUM] Monitor started (check_interval=%.1fs, roles=%s)",
            self._check_interval,
            [r.value for r in _OPERATOR_ROLES],
        )
        while True:
            try:
                await asyncio.sleep(self._check_interval)
                for role in _OPERATOR_ROLES:
                    if role in self._elected_roles:
                        continue
                    if not self._has_live_role(role):
                        logger.info(
                            "[USMD-QUORUM] No live %s detected — starting election.",
                            role.value,
                        )
                        await self._start_election(role)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("[USMD-QUORUM] Monitor loop error: %s", exc)

    # ------------------------------------------------------------------
    # Liveness check
    # ------------------------------------------------------------------

    def _has_live_role(self, role: NodeRole) -> bool:
        """Return True if at least one non-expired non-self peer holds *role*.

        Args:
            role: The operator role to look up.

        Returns:
            bool: True if a live holder is found, False otherwise.
        """
        for entry in self._nit.iter_all_entries():
            if entry.is_expired():
                continue
            if entry.address == self._node_address:
                continue
            if self._nal.has_role(entry.public_key, role):
                return True
        return False

    # ------------------------------------------------------------------
    # Election
    # ------------------------------------------------------------------

    async def _start_election(self, role: NodeRole) -> None:
        """Run a single election round for *role*.

        Random delay → send REQUEST_VOTE (with role) to all live peers
        → evaluate votes → promote self if elected.

        Args:
            role: The operator role being contested.
        """
        delay = random.uniform(_ELECTION_DELAY_MIN, self._cfg.quorum.election_timeout)
        logger.debug(
            "[USMD-QUORUM] [%s] Candidacy delay %.2fs before sending votes.",
            role.value,
            delay,
        )
        await asyncio.sleep(delay)

        if self._has_live_role(role):
            logger.debug(
                "[USMD-QUORUM] [%s] Role holder appeared during candidacy delay — aborting.",
                role.value,
            )
            return

        self._epochs[role] += 1
        epoch = self._epochs[role]
        peers = self._live_peer_addresses()

        if not peers:
            logger.warning(
                "[USMD-QUORUM] [%s] No live peers — cannot reach quorum, staying as executor.",
                role.value,
            )
            return

        logger.info(
            "[USMD-QUORUM] [%s] Epoch %d: requesting vote from %d peer(s).",
            role.value,
            epoch,
            len(peers),
        )

        yes_votes = 0
        for address in peers:
            granted = await self._request_vote(epoch, role, address)
            if granted:
                yes_votes += 1

        logger.info(
            "[USMD-QUORUM] [%s] Epoch %d: %d/%d YES votes.",
            role.value,
            epoch,
            yes_votes,
            len(peers),
        )

        if yes_votes > len(peers) / 2:
            logger.info(
                "[USMD-QUORUM] [%s] Epoch %d: elected — promoting self.",
                role.value,
                epoch,
            )
            reason = (
                f"Election — {yes_votes}/{len(peers)} YES vote(s) "
                f"(epoch {epoch}, no {role.value} detected)"
            )
            self._promote_self(role=role, epoch=epoch, reason=reason)
            await self._announce_promotion(role=role, epoch=epoch, peers=peers)
        else:
            logger.info(
                "[USMD-QUORUM] [%s] Epoch %d: not elected (insufficient votes).",
                role.value,
                epoch,
            )

    def _live_peer_addresses(self) -> list[str]:
        """Return addresses of non-expired, non-self, active NIT entries.

        Inactive USD nodes are excluded to avoid polling unreachable peers.
        """
        inactive_addrs: set[str] = set()
        if self._usd is not None:
            inactive_addrs = {
                n.address for n in self._usd.nodes.values()
                if not n.state.is_active() and n.address != self._node_address
            }
        seen: set[str] = set()
        addresses: list[str] = []
        for entry in self._nit.iter_all_entries():
            if entry.is_expired():
                continue
            if entry.address == self._node_address:
                continue
            if entry.address in inactive_addrs:
                continue
            if entry.address not in seen:
                seen.add(entry.address)
                addresses.append(entry.address)
        return addresses

    async def _request_vote(
        self, epoch: int, role: NodeRole, address: str
    ) -> bool:
        """Send a REQUEST_VOTE frame to one peer and return the vote."""
        return await request_vote(
            self._node_address,
            self._ncp_port,
            self._ncp_timeout,
            self._on_ncp_failure,
            epoch,
            role,
            address,
        )

    def _promote_self(self, role: NodeRole, epoch: int, reason: str) -> None:
        """Update local role in cfg and NAL for the elected role."""
        promote_self(
            self._cfg,
            self._nal,
            self._nqt,
            self._elected_roles,
            self._ed_pub,
            self._node_address,
            role,
            epoch,
            reason,
        )

    async def _announce_promotion(
        self, role: NodeRole, epoch: int, peers: list[str]
    ) -> None:
        """Broadcast ANNOUNCE_PROMOTION to all live peers."""
        await announce_promotion(
            self._node_address,
            self._ed_pub,
            self._ncp_port,
            self._ncp_timeout,
            self._on_ncp_failure,
            role,
            epoch,
            peers,
        )

    # ------------------------------------------------------------------
    # NCP handler callbacks
    # ------------------------------------------------------------------

    def should_grant_vote(
        self,
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
            epoch: Election epoch from the candidate.
            candidate_address: IP address of the candidate node.
            role_name: Name of the operator role being contested.

        Returns:
            bool: True to grant the vote (YES), False to refuse (NO).

        Example:
            >>> from usmd.node.nit import NodeIdentityTable
            >>> from usmd.node.nal import NodeAccessList
            >>> from usmd.node.nqt import NodeQuorumTable
            >>> from usmd.config import NodeConfig
            >>> qm = QuorumManager("10.0.0.1", b"k"*32,
            ...                    NodeIdentityTable(), NodeAccessList(),
            ...                    NodeQuorumTable(), NodeConfig())
            >>> qm.should_grant_vote(1, "10.0.0.2", "node_operator")
            True
        """
        return _should_grant_vote(
            self._voted_epochs,
            self._has_live_role,
            _OPERATOR_ROLES,
            epoch,
            candidate_address,
            role_name,
        )

    def on_promotion_announced(
        self,
        epoch: int,
        pub_key: bytes,
        address: str,
        role_name: str = "node_operator",
    ) -> None:
        """Handle an incoming ANNOUNCE_PROMOTION notification.

        Registers the promoted node's public key in the local NAL with the
        announced role, and registers or refreshes its NIT entry.

        Args:
            epoch: Election epoch from the announcement.
            pub_key: Ed25519 public key of the promoted node (32 bytes).
            address: IP address of the promoted node.
            role_name: Name of the role the node was promoted to.
        """
        _on_promotion_announced(
            self._nal,
            self._nit,
            self._voted_epochs,
            self._nqt,
            epoch,
            pub_key,
            address,
            role_name,
        )
