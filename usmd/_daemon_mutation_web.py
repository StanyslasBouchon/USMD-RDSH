"""Parse dashboard mutation YAML and run optional local lifecycle (NodeDaemon)."""

from __future__ import annotations

import copy
import logging
from typing import TYPE_CHECKING

from .mutation.lifecycle import ServiceLifecycleRunner
from .mutation.service import Service
from .mutation.update_flow import ServiceUpdateFlow, ServiceUpdateOutcome
from .mutation.yaml_parser import ServiceYamlParser
from .node.role import NodeRole

if TYPE_CHECKING:
    from .node_daemon import NodeDaemon

logger = logging.getLogger(__name__)


def parse_mutation_web_input(
    daemon: "NodeDaemon", service_name: str, yaml_text: str
) -> tuple[str, Service, Service | None, bool] | str:
    """Return ``(name, new_svc, existing, is_new)`` or an error message."""
    if daemon.cfg.node_role != NodeRole.USD_OPERATOR:
        return "Reserved for the usd_operator role."
    name = service_name.strip()
    if not name:
        return "Service name is required."
    parsed = ServiceYamlParser.parse(name, yaml_text)
    if parsed.is_err():
        return str(parsed.unwrap_err())
    new_svc = parsed.unwrap()
    cat = daemon.usd.mutation_catalog
    existing = cat.get(name)
    is_new = existing is None
    mx = daemon.usd.config.max_services
    if is_new and mx is not None and cat.count() >= mx:
        return f"max_services limit ({mx}) reached."
    return (name, new_svc, existing, is_new)


def local_mutation_apply_branch(
    daemon: "NodeDaemon",
    name: str,
    new_svc: Service,
    existing: Service | None,
    apply_locally: bool,
) -> tuple[bool, str] | ServiceUpdateOutcome | None:
    """Run local lifecycle when requested; early ``(ok, msg)`` or ``OK_PROPAGATE``."""
    if not apply_locally:
        return None
    old = copy.deepcopy(existing) if existing is not None else None
    runner = ServiceLifecycleRunner()
    active = daemon.node.service_name == name and daemon.node.state.is_active()
    outcome = ServiceUpdateFlow.apply(
        old, new_svc, runner, service_active=active
    )
    if outcome == ServiceUpdateOutcome.ROLLBACK_OK:
        return (
            True,
            "Update failed — previous version restored. "
            "Not propagated to reference nodes.",
        )
    if outcome != ServiceUpdateOutcome.OK_PROPAGATE:
        if outcome == ServiceUpdateOutcome.EMERGENCY_REQUESTED:
            logger.error(
                "[\x1b[38;5;51mUSMD\x1b[0m] Mutation %s: critical state "
                "after failed update — not propagating.",
                name,
            )
        return (
            False,
            f"Local update rejected ({outcome.name}). "
            f"Details: {'; '.join(runner.last_failures[-3:])}",
        )
    return ServiceUpdateOutcome.OK_PROPAGATE
