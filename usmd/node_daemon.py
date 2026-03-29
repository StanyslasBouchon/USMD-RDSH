"""NodeDaemon — the main orchestrator for a running USMD-RDSH node.

On startup the daemon:

1. Loads (or generates) the node's Ed25519 and X25519 key pairs from a JSON
   file (``keys_file``).
2. Creates the local Node, USD, NIT, NAL, NEL, NRT, NQT, NRL structures.
3. Starts the NCP TCP server, CTL socket, Web dashboard, and NNDP service.
4. Either **bootstraps** (creates the USD as the first node) or **joins**
   (sends a REQUEST_APPROVAL to the first peer discovered via NNDP).
5. Runs a heartbeat loop: periodically checks resource usage and purges
   expired NIT entries.

Large private methods are split into dedicated private modules:

- :mod:`._daemon_init`      — core structures and server setup.
- :mod:`._daemon_peer`      — peer-discovery and NCP-failure callbacks.
- :mod:`._daemon_run`       — main asyncio run loop.
- :mod:`._daemon_helpers`   — resource usage and key persistence.
- :mod:`._daemon_snapshot`  — status snapshot serialisation.
- :mod:`._daemon_nrt`       — NRT update and reference node selection.
- :mod:`._daemon_join`      — bootstrap / join / NQT sync.
- :mod:`._daemon_heartbeat` — heartbeat loop.

Examples:
    >>> from usmd.config import NodeConfig
    >>> cfg = NodeConfig(bootstrap=True, usd_name="test-domain")
    >>> daemon = NodeDaemon(cfg)
    >>> isinstance(daemon, NodeDaemon)
    True
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ._daemon_init import _init_core, _init_servers
from ._daemon_join import _bootstrap, _join, _store_endorsement, _sync_nqt_from, _try_join_via
from ._daemon_nrt import _update_nrt_for_peer, _update_reference_nodes
from ._daemon_peer import _mark_peer_inactive, _on_peer_discovered
from ._daemon_run import _run
from ._daemon_snapshot import _build_status_snapshot
from .config import NodeConfig
from .nndp.protocol.here_i_am import HereIAmPacket
from .node.state import NodeState
from .security.crypto import Ed25519Pair

if TYPE_CHECKING:
    from .quorum.manager import QuorumManager

logger = logging.getLogger(__name__)


class NodeDaemon:
    """Orchestrates all USMD-RDSH subsystems for a single running node."""

    def __init__(self, cfg: NodeConfig) -> None:
        """Initialise the daemon from a NodeConfig.

        Args:
            cfg: Loaded node configuration.
        """
        self.cfg = cfg

        core = _init_core(cfg)
        self._ed_priv  = core.ed_priv
        self._ed_pub   = core.ed_pub
        self._x_priv   = core.x_priv
        self._x_pub    = core.x_pub
        self.node      = core.node
        self.usd       = core.usd
        self.nit       = core.nit
        self.nal       = core.nal
        self.nel       = core.nel
        self.nrt       = core.nrt
        self.nqt       = core.nqt
        self.nrl       = core.nrl
        self._start_time: float = core.start_time

        srv = _init_servers(cfg, core, self.build_status_snapshot,
                            self._on_peer_discovered, self._mark_peer_inactive)
        self._quorum     = srv.quorum
        self._handler    = srv.handler
        self._ncp_server = srv.ncp_server
        self._ctl        = srv.ctl
        self._web        = srv.web
        self._nndp       = srv.nndp

        self._pending_peers: list[tuple[HereIAmPacket, str]] = []
        self._joined = asyncio.Event()
        # Monotonic timestamps: peer name → when it entered reference_nodes (local stickiness)
        self._reference_since: dict[int, float] = {}

        # Wire the rejoin callback so the NCP handler can trigger a re-join
        # when our endorser sends us a REVOKE_ENDORSEMENT on shutdown.
        self._handler.ctx.rejoin_fn = self._schedule_rejoin

    # ------------------------------------------------------------------
    # Public snapshot (served via CTL socket and Web server)
    # ------------------------------------------------------------------

    def build_status_snapshot(self) -> dict:
        """Return a fully serialisable dict of the current node state."""
        return _build_status_snapshot(self)

    # ------------------------------------------------------------------
    # Public accessors — keys and identity
    # ------------------------------------------------------------------

    @property
    def start_time(self) -> float:
        """UNIX timestamp of daemon startup."""
        return self._start_time

    @property
    def reference_since(self) -> "dict[int, float]":
        """Monotonic timestamps: peer name → when it entered the reference set."""
        return self._reference_since

    @property
    def ed_pub(self) -> bytes:
        """Ed25519 public key of this node."""
        return self._ed_pub

    @property
    def x_pub(self) -> bytes:
        """X25519 public key of this node."""
        return self._x_pub

    def sign_ed25519(self, data: bytes) -> bytes:
        """Sign *data* with this node's Ed25519 private key.

        Args:
            data: Raw bytes to sign.

        Returns:
            bytes: Ed25519 signature (64 bytes).
        """
        return Ed25519Pair.sign(self._ed_priv, data)

    # ------------------------------------------------------------------
    # Public accessors — servers / managers
    # ------------------------------------------------------------------

    @property
    def quorum_manager(self) -> "QuorumManager | None":
        """Active quorum manager, or None if quorum is disabled."""
        return self._quorum

    @property
    def ncp_server(self):
        """Running NCP TCP server."""
        return self._ncp_server

    @property
    def ctl_server(self):
        """Running CTL socket server."""
        return self._ctl

    @property
    def web_server(self):
        """Running web dashboard server, or None if disabled."""
        return self._web

    @property
    def nndp_service(self):
        """Running NNDP broadcaster / listener service."""
        return self._nndp

    # ------------------------------------------------------------------
    # Public accessors — join state and pending peers
    # ------------------------------------------------------------------

    @property
    def is_joined(self) -> bool:
        """True once the node has successfully joined (or bootstrapped)."""
        return self._joined.is_set()

    def mark_joined(self) -> None:
        """Signal that the node has successfully joined (or bootstrapped)."""
        self._joined.set()

    @property
    def has_pending_peers(self) -> bool:
        """True if NNDP-discovered peers are queued for the join process."""
        return bool(self._pending_peers)

    def pop_pending_peer(self) -> "tuple[HereIAmPacket, str] | None":
        """Remove and return the first queued (HIA packet, ip) pair, or None."""
        return self._pending_peers.pop(0) if self._pending_peers else None

    def add_pending_peer(self, packet: HereIAmPacket, ip: str) -> None:
        """Append a newly discovered peer to the pending-join queue."""
        self._pending_peers.append((packet, ip))

    # ------------------------------------------------------------------
    # Peer-discovery and NCP-failure callbacks (impl in _daemon_peer)
    # ------------------------------------------------------------------

    def _on_peer_discovered(self, packet: HereIAmPacket, ip: str) -> None:
        _on_peer_discovered(self, packet, ip)

    def _mark_peer_inactive(self, address: str) -> None:
        _mark_peer_inactive(self, address)

    # ------------------------------------------------------------------
    # Rejoin after endorsement revocation
    # ------------------------------------------------------------------

    def _schedule_rejoin(self) -> None:
        """Schedule a re-join after our endorser has revoked our endorsement.

        Called by :meth:`~usmd.ncp.server.handler.NcpCommandHandler._handle_revoke_endorsement`
        (via :attr:`~usmd.ncp.server.handler.HandlerContext.rejoin_fn`) when the
        node that originally endorsed us sends a ``REVOKE_ENDORSEMENT`` on shutdown.

        The node's state is set back to ``PENDING_APPROVAL`` and a new
        :func:`~usmd._daemon_join._join` task is scheduled on the running event loop.
        If the loop is not reachable (e.g. called outside an asyncio context during
        testing), a WARNING is emitted and no task is created.

        Examples:
            >>> from usmd.config import NodeConfig
            >>> cfg = NodeConfig(bootstrap=True, usd_name="test-domain")
            >>> daemon = NodeDaemon(cfg)
            >>> daemon._schedule_rejoin()  # sets state to PENDING_APPROVAL
            >>> daemon.node.state.value
            'pending_approval'
        """
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] Endossement révoqué par l'endosseur "
            "— relance du processus d'adhésion pour le nœud %d.",
            self.node.name,
        )
        self.node.set_state(NodeState.PENDING_APPROVAL)
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(_join(self), name="rejoin-after-revocation")
        except RuntimeError:
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] _schedule_rejoin : "
                "impossible de planifier le rejoin — aucune boucle asyncio active."
            )

    # ------------------------------------------------------------------
    # Delegated private methods (implementations in _daemon_* modules)
    # ------------------------------------------------------------------

    async def _update_nrt_for_peer(self, address: str) -> None:
        await _update_nrt_for_peer(self, address)

    async def _update_reference_nodes(self) -> None:
        await _update_reference_nodes(self)

    async def _bootstrap(self) -> None:
        await _bootstrap(self)

    async def _join(self) -> None:
        await _join(self)

    async def _try_join_via(self, peer_ip: str) -> bool:
        return await _try_join_via(self, peer_ip)

    async def _sync_nqt_from(self, peer_ip: str) -> None:
        await _sync_nqt_from(self, peer_ip)

    def _store_endorsement(self, endorsement_bytes: bytes, peer_ip: str) -> None:
        _store_endorsement(self, endorsement_bytes, peer_ip)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start all subsystems and run until the task is cancelled."""
        await _run(self)

    @classmethod
    def from_config(cls, cfg: NodeConfig) -> "NodeDaemon":
        """Convenience factory — equivalent to ``NodeDaemon(cfg)``."""
        return cls(cfg)
