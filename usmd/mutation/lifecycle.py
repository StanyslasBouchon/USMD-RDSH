"""Execute transmutation phases (build, unbuild, emergency, health) in order."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable

from ..utils.errors import Error, ErrorKind
from ..utils.result import Result
from .service import Service

logger = logging.getLogger(__name__)

CommandRunner = Callable[[str], Result[None, Error]]


def default_subprocess_runner(cmd: str) -> Result[None, Error]:
    """Run *cmd* through the shell (same semantics as operator-written YAML)."""
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            check=False,
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if proc.returncode != 0:
            return Result.Err(
                Error.new(
                    ErrorKind.MUTATION_FAILED,
                    f"command failed ({proc.returncode}): {cmd!r} stderr={proc.stderr!r}",
                )
            )
        return Result.Ok(None)
    except subprocess.TimeoutExpired:
        return Result.Err(
            Error.new(ErrorKind.MUTATION_FAILED, f"command timeout: {cmd!r}")
        )
    except OSError as exc:
        return Result.Err(
            Error.new(ErrorKind.MUTATION_FAILED, f"command os error: {cmd!r}: {exc}")
        )


class LifecyclePhase(Enum):
    """Lifecycle step executed by :class:`ServiceLifecycleRunner`."""

    BUILD = auto()
    UNBUILD = auto()
    EMERGENCY = auto()
    HEALTH = auto()
    UPDATE = auto()


@dataclass
class ServiceLifecycleRunner:
    """Runs lifecycle command lists, including ``action:unbuild`` indirections."""

    runner: CommandRunner = default_subprocess_runner
    _unbuild_depth: int = 0
    _max_unbuild_depth: int = 8
    last_failures: list[str] = field(default_factory=list)

    def run_line(self, line: str, service: Service, phase: LifecyclePhase) -> Result[None, Error]:
        """Execute one YAML-derived line (shell command or ``action:name``)."""
        line = line.strip()
        if not line:
            return Result.Ok(None)
        if line.startswith("action:"):
            act = line.split(":", 1)[1].strip()
            if act == "unbuild":
                if self._unbuild_depth >= self._max_unbuild_depth:
                    return Result.Err(
                        Error.new(
                            ErrorKind.MUTATION_FAILED,
                            "action:unbuild nested too deeply",
                        )
                    )
                self._unbuild_depth += 1
                try:
                    return self.run_phase(service, LifecyclePhase.UNBUILD)
                finally:
                    self._unbuild_depth -= 1
            return Result.Err(
                Error.new(ErrorKind.MUTATION_FAILED, f"unknown action:{act!r}")
            )
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] transmutation %s %s: %s",
            phase.name,
            service.name,
            line[:120] + ("…" if len(line) > 120 else ""),
        )
        return self.runner(line)

    def run_phase(self, service: Service, phase: LifecyclePhase) -> Result[None, Error]:
        """Run all commands for *phase* in order; stop on first failure."""
        if phase is LifecyclePhase.BUILD:
            cmds = service.build_commands
        elif phase is LifecyclePhase.UNBUILD:
            cmds = service.unbuild_commands
        elif phase is LifecyclePhase.EMERGENCY:
            cmds = service.emergency_commands
        elif phase is LifecyclePhase.UPDATE:
            cmds = service.update_commands
        else:
            cmds = service.health_check_commands
        for cmd in cmds:
            res = self.run_line(cmd, service, phase)
            if res.is_err():
                self.last_failures.append(str(res.unwrap_err()))
                return res
        return Result.Ok(None)

    def check_health(self, service: Service) -> bool:
        """Return True if every health command succeeds (empty list → True)."""
        if not service.health_check_commands:
            return True
        for cmd in service.health_check_commands:
            res = self.run_line(cmd, service, LifecyclePhase.HEALTH)
            if res.is_err():
                self.last_failures.append(str(res.unwrap_err()))
                return False
        return True

    def execute_build(self, service: Service) -> Result[None, Error]:
        """Run the build phase (transmutation: bring service up)."""
        return self.run_phase(service, LifecyclePhase.BUILD)

    def execute_unbuild(self, service: Service) -> Result[None, Error]:
        """Run the unbuild phase (transmutation: tear service down)."""
        return self.run_phase(service, LifecyclePhase.UNBUILD)

    def execute_emergency(self, service: Service) -> Result[None, Error]:
        """Run emergency steps (e.g. copy data then action:unbuild)."""
        return self.run_phase(service, LifecyclePhase.EMERGENCY)
