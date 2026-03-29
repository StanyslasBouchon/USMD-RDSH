"""Service update orchestration: apply, health, rollback, propagate decision flags."""

from __future__ import annotations

from enum import Enum, auto
from typing import Optional

from .lifecycle import LifecyclePhase, ServiceLifecycleRunner
from .service import Service


class ServiceUpdateOutcome(Enum):
    """Result of applying a new :class:`Service` definition on this node."""

    OK_PROPAGATE = auto()
    """Update and health OK — caller may forward to reference nodes."""

    FAILED_NO_PROPAGATE = auto()
    """Update or health failed before any successful state — do not propagate."""

    EMERGENCY_REQUESTED = auto()
    """Service unavailable after update — caller should broadcast emergency."""

    ROLLBACK_OK = auto()
    """Previous version restored and healthy."""

    ROLLBACK_STILL_BAD = auto()
    """Rollback attempted but node should stay inactive."""


class ServiceUpdateFlow:
    """Applies in-place updates, optional rollback to *old* service, and health checks."""

    @staticmethod
    def apply(
        old: Optional[Service],
        new: Service,
        runner: ServiceLifecycleRunner,
        *,
        service_active: bool,
    ) -> ServiceUpdateOutcome:
        """Run update commands or rebuild path, then health; rollback *old* if needed.

        Args:
            old: Previously registered service (for rollback), if any.
            new: Parsed service from the new YAML (``version`` already set).
            runner: Lifecycle runner (inject a no-op runner in tests).
            service_active: True if this node currently hosts *new.name*.

        Returns:
            ServiceUpdateOutcome: What the daemon should do next (propagate / emergency / …).
        """
        runner.last_failures.clear()

        if service_active and old is not None:
            if new.update_commands:
                res = runner.run_phase(new, LifecyclePhase.UPDATE)
                if res.is_err():
                    return ServiceUpdateFlow._try_rollback(old, new, runner)
            else:
                u1 = runner.execute_unbuild(old)
                if u1.is_err():
                    return ServiceUpdateOutcome.FAILED_NO_PROPAGATE
                b1 = runner.execute_build(new)
                if b1.is_err():
                    return ServiceUpdateFlow._try_rollback(old, new, runner)
        else:
            b0 = runner.execute_build(new)
            if b0.is_err():
                return ServiceUpdateOutcome.FAILED_NO_PROPAGATE

        final: ServiceUpdateOutcome
        if runner.check_health(new):
            final = ServiceUpdateOutcome.OK_PROPAGATE
        elif old is not None:
            rb = ServiceUpdateFlow._try_rollback(old, new, runner)
            final = (
                rb
                if rb == ServiceUpdateOutcome.ROLLBACK_OK
                else ServiceUpdateOutcome.EMERGENCY_REQUESTED
            )
        else:
            final = ServiceUpdateOutcome.EMERGENCY_REQUESTED
        return final

    @staticmethod
    def _try_rollback(
        old: Service,
        new: Service,
        runner: ServiceLifecycleRunner,
    ) -> ServiceUpdateOutcome:
        runner.last_failures.clear()
        _ = runner.execute_unbuild(new)
        _ = runner.execute_build(old)
        if runner.check_health(old):
            return ServiceUpdateOutcome.ROLLBACK_OK
        return ServiceUpdateOutcome.ROLLBACK_STILL_BAD
