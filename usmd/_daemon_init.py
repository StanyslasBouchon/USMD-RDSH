"""Daemon initialisation helpers — core structures and server setup.

Two functions are provided:

- :func:`_init_core`    — keys, node, USD, NIT/NAL/NEL/NRT/NQT/NRL.
  Returns a :class:`_CoreComponents` dataclass.
- :func:`_init_servers` — HandlerContext, QuorumManager, NcpServer, CtlServer,
  WebServer, NndpService.
  Returns a :class:`_ServerComponents` dataclass.

Both are called from :meth:`NodeDaemon.__init__`, which unpacks the
returned dataclasses into instance attributes.  Neither function touches
protected members of the daemon directly.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from ._daemon_helpers import _get_resource_usage, _load_or_generate_keys
from .ctl.server import CtlServer
from .domain.usd import UnifiedSystemDomain
from .ncp.server.handler import HandlerContext, NcpCommandHandler
from .ncp.server.tcp import NcpServer
from .nndp.lib import NndpOptions, NndpService
from .nndp.protocol.here_i_am import HereIAmPacket
from .node.nal import NodeAccessList
from .node.nel import NodeEndorsementList
from .node.nit import NodeIdentityTable
from .node.node import Node
from .node.nqt import NodeQuorumTable
from .node.nrl import NodeReferenceList
from .node.nrt import NodeReferenceTable
from .node.state import NodeState
from .quorum.manager import QuorumManager, QuorumOptions
from .security.endorsement import EndorsementFactory
from .web.server import WebServer

if TYPE_CHECKING:
    from .config import NodeConfig


@dataclass
class _CoreComponents:
    """All objects produced during the core-initialisation phase."""

    ed_priv: bytes
    ed_pub: bytes
    x_priv: bytes
    x_pub: bytes
    node: Node
    usd: UnifiedSystemDomain
    nit: NodeIdentityTable
    nal: NodeAccessList
    nel: NodeEndorsementList
    nrt: NodeReferenceTable
    nqt: NodeQuorumTable
    nrl: NodeReferenceList
    start_time: float
    endorsement_factory: EndorsementFactory


@dataclass
class _ServerComponents:
    """All server/manager objects produced during the server-initialisation phase."""

    quorum: QuorumManager | None
    handler: NcpCommandHandler
    ncp_server: NcpServer
    ctl: CtlServer
    web: WebServer | None
    nndp: NndpService


def _init_core(cfg: "NodeConfig") -> _CoreComponents:
    """Initialise keys, node identity, USD, and all lookup tables.

    Args:
        cfg: Loaded node configuration.

    Returns:
        _CoreComponents: All initialised core objects.
    """
    ed_priv, ed_pub, x_priv, x_pub, node_name = _load_or_generate_keys(cfg.keys_file)

    address = cfg.resolve_address()
    node = Node(address=address, name=node_name, state=NodeState.PENDING_APPROVAL)

    usd = UnifiedSystemDomain(config=cfg.to_usd_config(), private_key=ed_priv)

    nit = NodeIdentityTable()
    nal = NodeAccessList()
    nel = NodeEndorsementList()
    nrt = NodeReferenceTable()
    nqt = NodeQuorumTable()
    nrl = NodeReferenceList()

    nit.register(address, ed_pub, ttl=86400)
    nal.grant(ed_pub, cfg.node_role, permanent=True)

    # Prime psutil cpu_percent baseline (needs two calls for a real reading).
    try:
        import psutil as _psutil  # pylint: disable=import-outside-toplevel

        _psutil.cpu_percent(interval=None)
    except ImportError:
        pass

    return _CoreComponents(
        ed_priv=ed_priv,
        ed_pub=ed_pub,
        x_priv=x_priv,
        x_pub=x_pub,
        node=node,
        usd=usd,
        nit=nit,
        nal=nal,
        nel=nel,
        nrt=nrt,
        nqt=nqt,
        nrl=nrl,
        start_time=time.time(),
        endorsement_factory=EndorsementFactory(
            endorser_private_key=ed_priv,
            endorser_public_key=ed_pub,
        ),
    )


def _init_servers(
    cfg: "NodeConfig",
    core: _CoreComponents,
    build_snapshot_fn: Callable[[], dict],
    on_peer_discovered: Callable[[HereIAmPacket, str], None],
    on_ncp_failure: Callable[[str], None],
) -> _ServerComponents:
    """Initialise HandlerContext, QuorumManager, and all server objects.

    Args:
        cfg: Loaded node configuration.
        core: Core components returned by :func:`_init_core`.
        build_snapshot_fn: Callable that returns the current status snapshot.
        on_peer_discovered: NNDP HIA callback (bound method on NodeDaemon).
        on_ncp_failure: NCP failure callback (bound method on NodeDaemon).

    Returns:
        _ServerComponents: All initialised server and manager objects.
    """
    address = core.node.address

    handler_ctx = HandlerContext(
        node=core.node,
        usd=core.usd,
        nit=core.nit,
        nal=core.nal,
        nel=core.nel,
        endorsement_factory=core.endorsement_factory,
        resource_getter=_get_resource_usage,
        snapshot_fn=build_snapshot_fn,
        ping_tolerance_ms=cfg.ping_tolerance_ms,
        nqt=core.nqt,
        nrl=core.nrl,
    )

    quorum: QuorumManager | None = None
    if cfg.quorum_enabled:
        quorum = QuorumManager(
            node_address=address,
            ed_pub=core.ed_pub,
            nit=core.nit,
            nal=core.nal,
            nqt=core.nqt,
            cfg=cfg,
            options=QuorumOptions(
                check_interval=cfg.quorum_check_interval,
                ncp_port=cfg.ncp_port,
                ncp_timeout=cfg.ncp_timeout,
                on_ncp_failure=on_ncp_failure,
                usd=core.usd,
            ),
        )
        handler_ctx.quorum_manager = quorum

    handler = NcpCommandHandler(handler_ctx)

    return _ServerComponents(
        quorum=quorum,
        handler=handler,
        ncp_server=NcpServer(
            handler=handler,
            port=cfg.ncp_port,
            timeout=cfg.ncp_timeout,
        ),
        ctl=CtlServer(
            socket_path=cfg.ctl_socket,
            snapshot_fn=build_snapshot_fn,
            ctl_port=cfg.ctl_port,
        ),
        web=(
            WebServer(
                cfg=cfg,
                snapshot_fn=build_snapshot_fn,
                nit=core.nit,
                usd=core.usd,
                on_ncp_failure=on_ncp_failure,
            )
            if cfg.web_enabled
            else None
        ),
        nndp=NndpService(
            node_name=core.node.name,
            pub_key=core.ed_pub,
            priv_key=core.ed_priv,
            ttl=cfg.nndp_ttl,
            state_getter=lambda: core.node.state,
            on_peer_discovered=on_peer_discovered,
            options=NndpOptions(
                listen_port=cfg.nndp_listen_port,
                send_port=cfg.nndp_send_port,
                broadcast_address=cfg.broadcast_address,
            ),
        ),
    )
