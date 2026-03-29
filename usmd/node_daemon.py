"""NodeDaemon — the main orchestrator for a running USMD-RDSH node.

On startup the daemon:

1. Loads (or generates) the node's Ed25519 and X25519 key pairs from a JSON
   file (``keys_file``).
2. Creates the local Node, USD, NIT, NAL, NEL, and EndorsementFactory.
3. Starts the NCP TCP server (port 5626) and the NNDP UDP broadcaster +
   listener.
4. Either **bootstraps** (creates the USD as the first node) or **joins**
   (sends a REQUEST_APPROVAL to the first peer discovered via NNDP).
5. Runs a heartbeat loop: periodically checks resource usage, updates the
   reference-load on the local Node, and purges expired NIT entries.

Resource usage is read via ``psutil`` if available, otherwise dummy values
(0.0 for all metrics) are used so the daemon still starts without the
optional dependency.

Examples:
    >>> from usmd.config import NodeConfig
    >>> cfg = NodeConfig(bootstrap=True, usd_name="test-domain")
    >>> daemon = NodeDaemon(cfg)
    >>> isinstance(daemon, NodeDaemon)
    True
"""

from __future__ import annotations
# pylint: disable=too-many-lines

import asyncio
import json
import logging
import os
import sys
import time
from .config import NodeConfig
from .domain.usd import UnifiedSystemDomain
from .mutation.transmutation import ResourceUsage
from .ncp.client.tcp import NcpClient
from .ncp.protocol.commands.request_approval import RequestApprovalRequest
from .ncp.protocol.frame import NcpCommandId
from .ncp.server.handler import HandlerContext, NcpCommandHandler
from .ncp.server.tcp import NcpServer
from .nndp.lib import NndpService
from .nndp.protocol.here_i_am import HereIAmPacket
from .node.nal import NodeAccessList
from .node.nel import EndorsementPacket, NodeEndorsementList
from .node.nit import NodeIdentityTable
from .node.node import Node
from .node.role import NodeRole
from .node.state import NodeState
from .ctl.server import CtlServer
from .web.server import WebServer
from .security.crypto import Ed25519Pair, X25519Pair
from .security.endorsement import EndorsementFactory
from .quorum.manager import QuorumManager

logger = logging.getLogger(__name__)

_KEYS_VERSION = 1
_HEARTBEAT_INTERVAL = 5.0  # seconds between resource checks


# ---------------------------------------------------------------------------
# Resource usage helper
# ---------------------------------------------------------------------------


def _get_resource_usage() -> ResourceUsage:
    """Return current resource usage via psutil if available, else dummy 0s."""
    try:
        import psutil  # pylint: disable=import-outside-toplevel

        ram = psutil.virtual_memory().percent / 100.0
        # cpu_percent(interval=None) returns 0.0 on the very first call
        # because it needs a previous baseline measurement.  Subsequent calls
        # (done every _HEARTBEAT_INTERVAL seconds) return real values.
        cpu = psutil.cpu_percent(interval=None) / 100.0
        _disk_root = "C:\\" if sys.platform == "win32" else "/"
        disk = psutil.disk_usage(_disk_root).percent / 100.0
        net_io = psutil.net_io_counters()
        # Approximate network usage as bytes_sent fraction of a 125 MB/s link
        net = min(1.0, (net_io.bytes_sent + net_io.bytes_recv) / (125_000_000 * 10))
        return ResourceUsage(
            ram_percent=ram,
            cpu_percent=cpu,
            disk_percent=disk,
            network_percent=net,
        )
    except ImportError:
        logger.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] psutil non installé — "
            "métriques ressources indisponibles. Exécutez : pip install psutil"
        )
        return ResourceUsage(
            ram_percent=0.0,
            cpu_percent=0.0,
            disk_percent=0.0,
            network_percent=0.0,
        )
    except Exception as exc:  # pylint: disable=broad-except
        logger.debug("[\x1b[38;5;51mUSMD\x1b[0m] Erreur lecture ressources : %s", exc)
        return ResourceUsage(
            ram_percent=0.0,
            cpu_percent=0.0,
            disk_percent=0.0,
            network_percent=0.0,
        )


# ---------------------------------------------------------------------------
# Key persistence
# ---------------------------------------------------------------------------


def _load_or_generate_keys(path: str) -> tuple[bytes, bytes, bytes, bytes, int]:
    """Load keys from JSON or generate fresh ones.

    Returns:
        tuple: (ed_priv, ed_pub, x_priv, x_pub, node_name)
    """
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            ed_priv = bytes.fromhex(data["ed25519_priv"])
            ed_pub = bytes.fromhex(data["ed25519_pub"])
            x_priv = bytes.fromhex(data["x25519_priv"])
            x_pub = bytes.fromhex(data["x25519_pub"])
            node_name = int(data["node_name"])
            logger.info(
                "[\x1b[38;5;51mUSMD\x1b[0m] Keys loaded from %s (node_name=%d)",
                path,
                node_name,
            )
            return ed_priv, ed_pub, x_priv, x_pub, node_name
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] Keys file %s invalid (%s); "
                "generating new keys",
                path,
                exc,
            )

    ed_priv, ed_pub = Ed25519Pair.generate()
    x_priv, x_pub = X25519Pair.generate()
    node_name = int(time.time())

    data = {
        "version": _KEYS_VERSION,
        "node_name": node_name,
        "ed25519_priv": ed_priv.hex(),
        "ed25519_pub": ed_pub.hex(),
        "x25519_priv": x_priv.hex(),
        "x25519_pub": x_pub.hex(),
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] New keys generated and saved to %s",
            path,
        )
    except OSError as exc:
        logger.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] Could not save keys to %s: %s",
            path,
            exc,
        )
    return ed_priv, ed_pub, x_priv, x_pub, node_name


# ---------------------------------------------------------------------------
# NodeDaemon
# ---------------------------------------------------------------------------


class NodeDaemon:  # pylint: disable=too-many-instance-attributes
    """Orchestrates all USMD-RDSH subsystems for a single running node.

    Attributes:
        cfg: Loaded node configuration.
        node: The local Node object.
        usd: The local USD instance.
        nit: Node Identity Table.
        nal: Node Access List.
        nel: Node Endorsement List.

    Examples:
        >>> from usmd.config import NodeConfig
        >>> daemon = NodeDaemon(NodeConfig(bootstrap=True))
        >>> isinstance(daemon, NodeDaemon)
        True
    """

    def __init__(self, cfg: NodeConfig) -> None:
        """Initialise the daemon from a NodeConfig.

        Args:
            cfg: Loaded node configuration.
        """
        self.cfg = cfg

        # Load or generate cryptographic identity
        (
            self._ed_priv,
            self._ed_pub,
            self._x_priv,
            self._x_pub,
            _node_name,
        ) = _load_or_generate_keys(cfg.keys_file)

        address = cfg.resolve_address()

        self.node = Node(
            address=address,
            name=_node_name,
            state=NodeState.PENDING_APPROVAL,
        )

        usd_cfg = cfg.to_usd_config()
        self.usd = UnifiedSystemDomain(
            config=usd_cfg,
            private_key=self._ed_priv,
        )

        self.nit = NodeIdentityTable()
        self.nal = NodeAccessList()
        self.nel = NodeEndorsementList()

        # Register ourselves in the NIT
        self.nit.register(address, self._ed_pub, ttl=86400)

        # Grant ourselves our role in the NAL
        role = cfg.node_role
        self.nal.grant(self._ed_pub, role, permanent=True)

        endorsement_factory = EndorsementFactory(
            endorser_private_key=self._ed_priv,
            endorser_public_key=self._ed_pub,
        )

        self._start_time: float = time.time()

        # Prime the cpu_percent baseline so the first real heartbeat
        # returns a non-zero value (psutil needs two measurements).
        try:
            import psutil as _psutil  # pylint: disable=import-outside-toplevel
            _psutil.cpu_percent(interval=None)
        except ImportError:
            pass

        handler_ctx = HandlerContext(
            node=self.node,
            usd=self.usd,
            nit=self.nit,
            nal=self.nal,
            nel=self.nel,
            endorsement_factory=endorsement_factory,
            resource_getter=_get_resource_usage,
            snapshot_fn=self._build_status_snapshot,
            ping_tolerance_ms=cfg.ping_tolerance_ms,
        )

        self._quorum: QuorumManager | None = None
        if cfg.quorum_enabled:
            self._quorum = QuorumManager(
                node_address=address,
                ed_pub=self._ed_pub,
                nit=self.nit,
                nal=self.nal,
                cfg=cfg,
                check_interval=cfg.quorum_check_interval,
                ncp_port=cfg.ncp_port,
                ncp_timeout=cfg.ncp_timeout,
            )
            handler_ctx.quorum_manager = self._quorum

        self._handler = NcpCommandHandler(handler_ctx)
        self._ncp_server = NcpServer(
            handler=self._handler,
            port=cfg.ncp_port,
            timeout=cfg.ncp_timeout,
        )
        self._ctl = CtlServer(
            socket_path=cfg.ctl_socket,
            snapshot_fn=self._build_status_snapshot,
            ctl_port=cfg.ctl_port,
        )
        self._web: WebServer | None = (
            WebServer(
                cfg=cfg,
                snapshot_fn=self._build_status_snapshot,
                nit=self.nit,
            )
            if cfg.web_enabled
            else None
        )
        self._nndp = NndpService(
            node_name=self.node.name,
            pub_key=self._ed_pub,
            priv_key=self._ed_priv,
            ttl=cfg.nndp_ttl,
            state_getter=lambda: self.node.state,
            on_peer_discovered=self._on_peer_discovered,
            listen_port=cfg.nndp_listen_port,
            send_port=cfg.nndp_send_port,
            broadcast_address=cfg.broadcast_address,
        )

        # Pending peers waiting for the join handshake
        self._pending_peers: list[tuple[HereIAmPacket, str]] = []
        self._joined = asyncio.Event()

    # ------------------------------------------------------------------
    # Status snapshot (served via CTL socket)
    # ------------------------------------------------------------------

    def _build_status_snapshot(self) -> dict:
        """Return a fully serialisable dict of the current node state.

        Called by the CTL server on every incoming status request.
        All bytes are hex-encoded and truncated for readability.
        """
        now = time.time()

        # NIT
        nit_data = []
        for entry in self.nit._entries.values():  # pylint: disable=protected-access
            ttl_remaining = max(0, int(entry.ttl - (now - entry.registered_at)))
            nit_data.append({
                "address":       entry.address,
                "pub_key":       entry.public_key.hex()[:20] + "…",
                "ttl_remaining": ttl_remaining,
                "expired":       entry.is_expired(),
            })

        # NAL
        nal_data = []
        # pylint: disable=protected-access
        for pub_key, roles in self.nal._entries.items():
            nal_data.append({
                "pub_key":   pub_key.hex()[:20] + "…",
                "roles":     [r.value for r in roles],
                "permanent": self.nal.is_permanent(pub_key),
            })

        # NEL — received
        nel_received = None
        recv = self.nel.get_received()
        if recv:
            nel_received = {
                "endorser_key": recv.endorser_key.hex()[:20] + "…",
                "node_name":    recv.node_name,
                "roles":        [r.value for r in recv.roles],
                "expiration":   recv.expiration,
                "expired":      recv.is_expired(),
            }

        # NEL — issued
        nel_issued = [
            {
                "node_pub_key": pkt.node_pub_key.hex()[:20] + "…",
                "node_name":    pkt.node_name,
                "roles":        [r.value for r in pkt.roles],
                "expiration":   pkt.expiration,
                "expired":      pkt.is_expired(),
            }
            for pkt in self.nel.all_issued()
        ]

        # Resources
        usage = _get_resource_usage()

        return {
            "node": {
                "name":           self.node.name,
                "address":        self.node.address,
                "state":          self.node.state.value,
                "role":           self.cfg.node_role.value,
                "uptime_seconds": now - self._start_time,
            },
            "usd": {
                "name":           self.usd.config.name,
                "cluster_name":   self.usd.config.cluster_name,
                "edb_address":    self.usd.config.edb_address,
                "config_version": self.usd.config.version,
                "node_count":     len(self.usd.nodes),
            },
            "nit": nit_data,
            "nal": nal_data,
            "nel": {
                "received": nel_received,
                "issued":   nel_issued,
            },
            "resources": {
                "cpu_percent":     usage.cpu_percent,
                "ram_percent":     usage.ram_percent,
                "disk_percent":    usage.disk_percent,
                "network_percent": usage.network_percent,
                "reference_load":  usage.reference_load(),
            },
            "quorum": {
                "enabled":    self.cfg.quorum_enabled,
                "is_operator": (
                    self._quorum.is_operator if self._quorum else False
                ),
                "promotions": (
                    self._quorum.get_promotions() if self._quorum else []
                ),
            },
        }

    # ------------------------------------------------------------------
    # Peer discovery callback (called from NNDP listener)
    # ------------------------------------------------------------------

    def _on_peer_discovered(self, packet: HereIAmPacket, ip: str) -> None:
        """Called by the NNDP listener when a valid HIA arrives."""
        # Register the peer in the NIT
        self.nit.register(ip, packet.sender_pub_key, ttl=int(packet.data.ttl) * 3)
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] Peer discovered: %s key=%s",
            ip,
            packet.sender_pub_key.hex()[:16] + "…",
        )

        # If we haven't joined yet, queue this peer for the join attempt
        if not self._joined.is_set():
            self._pending_peers.append((packet, ip))

    # ------------------------------------------------------------------
    # Startup flow
    # ------------------------------------------------------------------

    async def _bootstrap(self) -> None:
        """Bootstrap: this node IS the first node — it creates the USD."""
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] Bootstrapping USD '%s'…",
            self.usd.config.name,
        )
        # Add ourselves to the USD
        result = self.usd.add_node(self.node)
        if result.is_err():
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] Could not add self to USD: %s",
                result.unwrap_err(),
            )
        self.node.set_state(NodeState.ACTIVE)
        self._joined.set()
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] Node \x1b[38;5;220m%d\x1b[0m "
            "is now ACTIVE (bootstrap) as %s",
            self.node.name,
            self.cfg.node_role.value,
        )

    async def _join(self) -> None:
        """Join: wait for a peer and send REQUEST_APPROVAL."""
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] Waiting for a peer (join_timeout=%.1fs)…",
            self.cfg.join_timeout,
        )

        deadline = asyncio.get_event_loop().time() + self.cfg.join_timeout
        while asyncio.get_event_loop().time() < deadline:
            if self._pending_peers:
                _, ip = self._pending_peers.pop(0)
                success = await self._try_join_via(ip)
                if success:
                    return
            await asyncio.sleep(0.5)

        logger.error(
            "[\x1b[38;5;51mUSMD\x1b[0m] Join timeout — no peer approved us. "
            "Starting anyway in INACTIVE_TIMEOUT state."
        )
        self.node.set_state(NodeState.INACTIVE_TIMEOUT)
        self._joined.set()

    async def _try_join_via(self, peer_ip: str) -> bool:
        """Send REQUEST_APPROVAL to peer_ip and process the response."""
        nonce = os.urandom(16)
        req = RequestApprovalRequest(
            node_name=self.node.name,
            ed25519_pub=self._ed_pub,
            x25519_pub=self._x_pub,
            nonce=nonce,
            signature=b"",  # placeholder
        )
        # Sign the request
        req.signature = Ed25519Pair.sign(self._ed_priv, req.signable_bytes())

        client = NcpClient(
            address=peer_ip,
            port=self.cfg.ncp_port,
            timeout=self.cfg.ncp_timeout,
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

        approved = payload[0] == 0x01
        if not approved:
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] REQUEST_APPROVAL rejected by %s",
                peer_ip,
            )
            return False

        # Parse endorsement packet if present
        if len(payload) > 1:
            self._store_endorsement(payload[1:], peer_ip)

        # Add ourselves to the local USD view
        result_add = self.usd.add_node(self.node)
        if result_add.is_err():
            logger.debug(
                "[\x1b[38;5;51mUSMD\x1b[0m] Self already in USD: %s",
                result_add.unwrap_err(),
            )

        self.node.set_state(NodeState.ACTIVE)
        self._joined.set()
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] Node \x1b[38;5;220m%d\x1b[0m "
            "is now ACTIVE (joined via %s) as %s",
            self.node.name,
            peer_ip,
            self.cfg.node_role.value,
        )
        return True

    def _store_endorsement(self, endorsement_bytes: bytes, peer_ip: str) -> None:
        """Decode and store the endorsement packet from the approval response."""
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
            self.nel.set_received(packet)
            logger.debug(
                "[\x1b[38;5;51mUSMD\x1b[0m] Endorsement stored from %s", peer_ip
            )
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] Could not parse endorsement from %s: %s",
                peer_ip,
                exc,
            )

    # ------------------------------------------------------------------
    # Heartbeat loop
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Periodically update resource load and purge stale NIT entries."""
        while True:
            try:
                usage = _get_resource_usage()
                self.node.reference_load = usage.reference_load()

                purged = self.nit.purge_expired()
                if purged:
                    logger.debug(
                        "[\x1b[38;5;51mUSMD\x1b[0m] NIT purged %d expired entries",
                        purged,
                    )

                load_str = f"{self.node.reference_load:.1%}"
                logger.debug(
                    "[\x1b[38;5;51mUSMD\x1b[0m] Heartbeat: state=%s load=%s nit=%d",
                    self.node.state.value,
                    load_str,
                    len(self.nit),
                )
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("[\x1b[38;5;51mUSMD\x1b[0m] Heartbeat error: %s", exc)
            await asyncio.sleep(_HEARTBEAT_INTERVAL)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start all subsystems and run until the task is cancelled.

        Sequence:
        1. Start the NCP server (TCP 5626).
        2. Start the NNDP listener (UDP 5221).
        3. Bootstrap or join.
        4. Start NNDP broadcaster + heartbeat as background tasks.
        5. Wait forever (until CancelledError).
        """
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] "
            "\x1b[1mUSMD-RDSH node starting\x1b[0m "
            "(name=%d role=%s address=%s)",
            self.node.name,
            self.cfg.node_role.value,
            self.node.address,
        )

        # 1. NCP TCP server
        await self._ncp_server.start()

        # 2. CTL Unix socket
        await self._ctl.start()

        # 3. Web dashboard (optional)
        web_task: asyncio.Task[None] | None = None
        if self._web is not None:
            web_task = asyncio.create_task(self._web.start(), name="web-dashboard")

            def _on_web_done(task: asyncio.Task) -> None:  # type: ignore[type-arg]
                if not task.cancelled() and task.exception():
                    logger.error(
                        "[\x1b[38;5;51mUSMD\x1b[0m] Tableau de bord web arrêté : %s",
                        task.exception(),
                    )

            web_task.add_done_callback(_on_web_done)

        # 3. NNDP listener
        listener_transport = await self._nndp.start_listener()

        # 4. Bootstrap or join
        # For join: start the broadcaster *before* waiting for peers, so
        # other nodes can also discover us.
        if not self.cfg.bootstrap:
            broadcast_task: asyncio.Task[None] = asyncio.create_task(
                self._nndp.broadcast_loop(), name="nndp-broadcast"
            )
            await self._join()
        else:
            await self._bootstrap()
            broadcast_task = asyncio.create_task(
                self._nndp.broadcast_loop(), name="nndp-broadcast"
            )

        # 6. Heartbeat
        heartbeat_task = asyncio.create_task(self._heartbeat_loop(), name="heartbeat")

        # 7. Quorum monitor (optional)
        quorum_task: asyncio.Task[None] | None = None
        if self._quorum is not None:
            quorum_task = asyncio.create_task(self._quorum.run(), name="quorum-monitor")
            logger.info("[\x1b[38;5;51mUSMD\x1b[0m] Quorum monitor started.")

        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] "
            "\x1b[32mNode %d is running\x1b[0m (state=%s)",
            self.node.name,
            self.node.state.value,
        )

        try:
            # Run the NCP server (blocks until cancelled)
            await self._ncp_server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            broadcast_task.cancel()
            heartbeat_task.cancel()
            if quorum_task is not None:
                quorum_task.cancel()
            if web_task is not None:
                if self._web is not None:
                    self._web.close()
                web_task.cancel()
            self._ncp_server.close()
            self._ctl.close()
            if listener_transport:
                listener_transport.close()
            logger.info("[\x1b[38;5;51mUSMD\x1b[0m] Node %d shut down.", self.node.name)

    @classmethod
    def from_config(cls, cfg: NodeConfig) -> "NodeDaemon":
        """Convenience factory matching the __main__ call pattern.

        Args:
            cfg: Loaded NodeConfig.

        Returns:
            NodeDaemon: Ready-to-run instance.

        Example:
            >>> from usmd.config import NodeConfig
            >>> daemon = NodeDaemon.from_config(NodeConfig(bootstrap=True))
            >>> isinstance(daemon, NodeDaemon)
            True
        """
        return cls(cfg)
