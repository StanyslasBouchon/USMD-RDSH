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
- :mod:`._daemon_mutation_web` — dashboard mutation YAML + local lifecycle.

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
import time
from typing import TYPE_CHECKING, Literal

from ._daemon_init import _init_core, _init_servers
from ._daemon_mutation_hosting import refresh_mutation_hosting
from ._daemon_mutation_web import local_mutation_apply_branch, parse_mutation_web_input
from ._daemon_join import _bootstrap, _join, _store_endorsement, _sync_nqt_from, _try_join_via
from ._daemon_nrt import _update_nrt_for_peer, _update_reference_nodes
from ._daemon_peer import _mark_peer_inactive, _on_peer_discovered
from ._daemon_run import _run
from ._daemon_snapshot import _build_status_snapshot
from .config import NodeConfig
from .mutation.update_flow import ServiceUpdateOutcome
from .ncp.client.tcp import NcpClient
from .ncp.protocol.commands.send_mutation_properties import (
    SendMutationPropertiesRequest,
)
from .ncp.protocol.commands.send_usd_properties import SendUsdPropertiesRequest
from .ncp.protocol.frame import NcpCommandId
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
        self._last_dependency_check_monotonic: float = 0.0
        self._last_peer_status_monotonic: float = 0.0
        # Local mutation lifecycle runs (dashboard "apply locally" only)
        self._service_execution_log: list[dict] = []

        # Wire the rejoin callback so the NCP handler can trigger a re-join
        # when our endorser sends us a REVOKE_ENDORSEMENT on shutdown.
        self._handler.ctx.rejoin_fn = self._schedule_rejoin

        if self._web is not None:
            self._web.set_mutation_apply_fn(self.apply_mutation_from_web)

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

    def consume_monotonic_gate(
        self,
        kind: Literal["dependency_check", "peer_status_poll"],
        interval: float,
        *,
        force: bool = False,
    ) -> bool:
        """Rate-limit heartbeat work: dependency logging or peer GET_STATUS polling."""
        now = time.monotonic()
        if kind == "dependency_check":
            if interval <= 0:
                return False
            if now - self._last_dependency_check_monotonic < interval:
                return False
            self._last_dependency_check_monotonic = now
            return True
        if force or now - self._last_peer_status_monotonic >= interval:
            self._last_peer_status_monotonic = now
            return True
        return False

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
    # Mutation / transmutation (dashboard + NCP propagation)
    # ------------------------------------------------------------------

    def _record_service_execution(self, service_name: str, outcome: str) -> None:
        """Append a local lifecycle run (bounded list for the dashboard)."""
        self._service_execution_log.append(
            {
                "at": time.time(),
                "service": service_name,
                "outcome": outcome,
            }
        )
        if len(self._service_execution_log) > 200:
            self._service_execution_log[:] = self._service_execution_log[-200:]

    async def apply_mutation_from_web(
        self,
        service_name: str,
        yaml_text: str,
        apply_locally: bool = False,
    ) -> tuple[bool, str]:
        """Parse YAML, optionally run lifecycle on this node, sync USD + catalogue.

        Requires ``usd_operator`` in the local NAL (may be one of several roles).
        Updates :attr:`usd.config.version` and pushes ``SEND_USD_PROPERTIES`` +
        ``SEND_MUTATION_PROPERTIES`` to references when the update succeeds (or
        when only the catalogue is updated with ``apply_locally=False``).
        """
        prep = parse_mutation_web_input(self, service_name, yaml_text)
        if isinstance(prep, str):
            return False, prep
        name, new_svc, existing, is_new = prep
        new_ver = int(time.time())
        new_svc.version = new_ver

        local = local_mutation_apply_branch(
            self, name, new_svc, existing, apply_locally
        )
        outcome: ServiceUpdateOutcome | None = None
        if isinstance(local, tuple):
            ok, _msg = local
            self._record_service_execution(
                name, "ROLLBACK_OK" if ok else "LOCAL_FAILED"
            )
            return local
        if local is not None:
            outcome = local
            self._record_service_execution(name, local.name)

        cat = self.usd.mutation_catalog
        ms = self.usd.config.min_services
        after_count = cat.count() + (1 if is_new else 0)
        if ms > 0 and after_count < ms:
            return (
                False,
                f"min_services={ms}: not enough service definitions "
                f"in the domain (currently {after_count}).",
            )

        cat.register(new_svc, yaml_text)
        self.usd.config.version = new_ver

        await self._broadcast_usd_to_references()
        await self._broadcast_mutation_to_references()

        await refresh_mutation_hosting(self, poll_peers=True, force_peer_poll=True)

        msg = "Mutation saved and pushed to reference nodes."
        if apply_locally and outcome is not None:
            msg += f" (local: {outcome.name})"
        return True, msg

    async def _broadcast_usd_to_references(self) -> None:
        req = SendUsdPropertiesRequest.from_usd_config(self.usd.config)
        payload = req.to_payload()
        for peer_name in self.node.reference_nodes:
            peer = self.usd.get_node(peer_name)
            if peer is None or not peer.address:
                continue
            client = NcpClient(
                peer.address, self.cfg.ncp_port, timeout=self.cfg.ncp_timeout
            )
            result = await client.send(NcpCommandId.SEND_USD_PROPERTIES, payload)
            if result.is_err():
                logger.warning(
                    "[\x1b[38;5;51mUSMD\x1b[0m] SEND_USD_PROPERTIES → %s failed: %s",
                    peer.address,
                    result.unwrap_err(),
                )

    async def _broadcast_mutation_to_references(self) -> None:
        summaries = self.usd.mutation_catalog.summaries_for_broadcast()
        if not summaries:
            return
        payload = SendMutationPropertiesRequest(services=summaries).to_payload()
        for peer_name in self.node.reference_nodes:
            peer = self.usd.get_node(peer_name)
            if peer is None or not peer.address:
                continue
            client = NcpClient(
                peer.address, self.cfg.ncp_port, timeout=self.cfg.ncp_timeout
            )
            result = await client.send(
                NcpCommandId.SEND_MUTATION_PROPERTIES, payload
            )
            if result.is_err():
                logger.warning(
                    "[\x1b[38;5;51mUSMD\x1b[0m] "
                    "SEND_MUTATION_PROPERTIES → %s failed: %s",
                    peer.address,
                    result.unwrap_err(),
                )

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
            "[\x1b[38;5;51mUSMD\x1b[0m] Endorsement revoked by endorser "
            "— restarting join for node %d.",
            self.node.name,
        )
        self.node.set_state(NodeState.PENDING_APPROVAL)
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(_join(self), name="rejoin-after-revocation")
        except RuntimeError:
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] _schedule_rejoin: "
                "cannot schedule rejoin — no active asyncio loop."
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
