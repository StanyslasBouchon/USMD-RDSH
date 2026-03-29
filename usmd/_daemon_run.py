"""Daemon main run loop — start all subsystems and serve forever.

:func:`_run` is the implementation of :meth:`NodeDaemon.run`.  It is
extracted here to keep ``node_daemon.py`` under 250 lines.

This module only accesses *public* attributes, properties, and methods
of :class:`NodeDaemon`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ._daemon_heartbeat import _heartbeat_loop
from ._daemon_join import _bootstrap, _join
from .ncp.client.tcp import NcpClient
from .ncp.protocol.commands.revoke_endorsement import RevokeEndorsementRequest
from .ncp.protocol.frame import NcpCommandId

if TYPE_CHECKING:
    from .node_daemon import NodeDaemon

logger = logging.getLogger(__name__)


async def _revoke_endorsements_on_shutdown(daemon: "NodeDaemon") -> None:
    """Notify all endorsement peers before this node shuts down.

    Two complementary flows are handled:

    1. **As endorser**: for every node recorded in ``NEL._issued``, look up
       its address in the NIT and send a :data:`REVOKE_ENDORSEMENT` so it
       can clear its received packet and restart the join process.

    2. **As endorsed node**: if a received endorsement is stored in
       ``NEL._received``, look up the endorser's address in the NIT and
       send a :data:`REVOKE_ENDORSEMENT` so the endorser can remove this
       node from its ``NEL._issued`` list.

    Both operations are best-effort: failures are logged at WARNING level
    but never raise, so the shutdown sequence always completes.

    Args:
        daemon: The running :class:`~usmd.node_daemon.NodeDaemon` instance.

    Examples:
        >>> # Called automatically by _run() in the finally block.
        >>> # No direct usage needed.
    """
    payload = RevokeEndorsementRequest(daemon.ed_pub).to_payload()

    # ------------------------------------------------------------------ #
    # Case 1 — notify every node this node has endorsed                   #
    # ------------------------------------------------------------------ #
    for packet in daemon.nel.all_issued():
        addr = daemon.nit.get_address(packet.node_pub_key)
        if addr is None:
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] REVOKE: adresse NIT introuvable "
                "pour le nœud endossé %s — impossible de notifier.",
                packet.node_pub_key.hex()[:16] + "…",
            )
            continue
        client = NcpClient(
            address=addr,
            port=daemon.cfg.ncp_port,
            timeout=daemon.cfg.ncp_timeout,
        )
        result = await client.send(NcpCommandId.REVOKE_ENDORSEMENT, payload)
        if result.is_err():
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] REVOKE → nœud endossé %s : échec : %s",
                addr,
                result.unwrap_err(),
            )
        else:
            logger.info(
                "[\x1b[38;5;51mUSMD\x1b[0m] REVOKE → nœud endossé %s notifié.",
                addr,
            )

    # ------------------------------------------------------------------ #
    # Case 2 — notify our own endorser                                    #
    # ------------------------------------------------------------------ #
    received = daemon.nel.get_received()
    if received is not None:
        addr = daemon.nit.get_address(received.endorser_key)
        if addr is None:
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] REVOKE: adresse NIT introuvable "
                "pour l'endosseur %s — impossible de notifier.",
                received.endorser_key.hex()[:16] + "…",
            )
        else:
            client = NcpClient(
                address=addr,
                port=daemon.cfg.ncp_port,
                timeout=daemon.cfg.ncp_timeout,
            )
            result = await client.send(NcpCommandId.REVOKE_ENDORSEMENT, payload)
            if result.is_err():
                logger.warning(
                    "[\x1b[38;5;51mUSMD\x1b[0m] REVOKE → endosseur %s : échec : %s",
                    addr,
                    result.unwrap_err(),
                )
            else:
                logger.info(
                    "[\x1b[38;5;51mUSMD\x1b[0m] REVOKE → endosseur %s notifié.",
                    addr,
                )


async def _run(daemon: "NodeDaemon") -> None:
    """Start all subsystems and run until the task is cancelled.

    Sequence:
    1. Start the NCP server (TCP 5626).
    2. Start the CTL socket.
    3. Start the Web dashboard (optional).
    4. Start the NNDP listener.
    5. Bootstrap or join.
    6. Start NNDP broadcaster + heartbeat as background tasks.
    7. Start the quorum monitor (optional).
    8. Serve forever.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
    """
    logger.info(
        "[\x1b[38;5;51mUSMD\x1b[0m] "
        "\x1b[1mUSMD-RDSH node starting\x1b[0m "
        "(name=%d role=%s address=%s)",
        daemon.node.name,
        daemon.cfg.node_role.value,
        daemon.node.address,
    )

    await daemon.ncp_server.start()
    await daemon.ctl_server.start()

    web_task: asyncio.Task[None] | None = None
    if daemon.web_server is not None:
        web_task = asyncio.create_task(daemon.web_server.start(), name="web-dashboard")

        def _on_web_done(task: asyncio.Task) -> None:  # type: ignore[type-arg]
            if not task.cancelled() and task.exception():
                logger.error(
                    "[\x1b[38;5;51mUSMD\x1b[0m] Tableau de bord web arrêté : %s",
                    task.exception(),
                )

        web_task.add_done_callback(_on_web_done)

    listener_transport = await daemon.nndp_service.start_listener()

    if not daemon.cfg.bootstrap:
        broadcast_task: asyncio.Task[None] = asyncio.create_task(
            daemon.nndp_service.broadcast_loop(), name="nndp-broadcast"
        )
        await _join(daemon)
    else:
        await _bootstrap(daemon)
        broadcast_task = asyncio.create_task(
            daemon.nndp_service.broadcast_loop(), name="nndp-broadcast"
        )

    heartbeat_task = asyncio.create_task(_heartbeat_loop(daemon), name="heartbeat")

    quorum_task: asyncio.Task[None] | None = None
    if daemon.quorum_manager is not None:
        quorum_task = asyncio.create_task(
            daemon.quorum_manager.run(), name="quorum-monitor"
        )
        logger.info("[\x1b[38;5;51mUSMD\x1b[0m] Quorum monitor started.")

    logger.info(
        "[\x1b[38;5;51mUSMD\x1b[0m] "
        "\x1b[32mNode %d is running\x1b[0m (state=%s)",
        daemon.node.name,
        daemon.node.state.value,
    )

    try:
        await daemon.ncp_server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        # Notify endorsement peers before closing (outgoing TCP still works).
        await _revoke_endorsements_on_shutdown(daemon)

        broadcast_task.cancel()
        heartbeat_task.cancel()
        if quorum_task is not None:
            quorum_task.cancel()
        if web_task is not None:
            if daemon.web_server is not None:
                daemon.web_server.close()
            web_task.cancel()
        daemon.ncp_server.close()
        daemon.ctl_server.close()
        if listener_transport:
            listener_transport.close()
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] Node %d shut down.", daemon.node.name
        )
