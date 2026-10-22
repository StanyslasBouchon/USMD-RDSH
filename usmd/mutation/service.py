"""Service definitions for USMD-RDSH mutations.

A service is the role a node plays when it is active. Services are described
in YAML files and categorised as either static or dynamic.

- **Static services**: All nodes hosting this service share the same
  parameters, data AND commands. Every node is expected to run **all** static
  services from the domain catalogue.
- **Dynamic services**: All nodes hosting this service share parameters and
  commands, but each holds its own distinct data (e.g. a database shard).
  Assignment is **exclusive across reference peers**: a node claims dynamic
  names not already hosted by its reference nodes (see
  :mod:`usmd.mutation.assignment`).

Examples:
    >>> svc = Service(
    ...     name="backend",
    ...     service_type=ServiceType.STATIC,
    ...     dependencies=["db"],
    ...     build_commands=["apt install curl -y"],
    ...     unbuild_commands=["apt purge curl -y"],
    ...     emergency_commands=["cp /var/app/* /mnt/rdisk/"],
    ...     health_check_commands=["curl -f http://localhost/health"],
    ... )
    >>> svc.name
    'backend'
    >>> svc.service_type == ServiceType.STATIC
    True
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ServiceType(Enum):
    """The data-sharing model of a service.

    Values:
        STATIC: Nodes share parameters, data and commands.
        DYNAMIC: Nodes share parameters and commands; data differs per node.

    Examples:
        >>> ServiceType.STATIC.value
        'static'
        >>> ServiceType.DYNAMIC.is_dynamic()
        True
    """

    STATIC = "static"
    DYNAMIC = "dynamic"

    def is_static(self) -> bool:
        """Return True for static services.

        Example:
            >>> ServiceType.STATIC.is_static()
            True
        """
        return self == ServiceType.STATIC

    def is_dynamic(self) -> bool:
        """Return True for dynamic services.

        Example:
            >>> ServiceType.DYNAMIC.is_dynamic()
            True
        """
        return self == ServiceType.DYNAMIC

    def __str__(self) -> str:
        return self.value


@dataclass
class ServiceCommand:
    """A single shell command to execute during a lifecycle phase.

    Attributes:
        command: Shell command string to execute on the node.
        action: Optional named action keyword (e.g. ``'unbuild'``).

    Examples:
        >>> cmd = ServiceCommand(command="apt install curl -y")
        >>> cmd.command
        'apt install curl -y'
        >>> action = ServiceCommand(action="unbuild")
        >>> action.is_action()
        True
    """

    command: Optional[str] = None
    action: Optional[str] = None

    def is_action(self) -> bool:
        """Return True if this entry is a named action rather than a shell command.

        Example:
            >>> ServiceCommand(action="unbuild").is_action()
            True
            >>> ServiceCommand(command="echo hi").is_action()
            False
        """
        return self.action is not None and self.command is None

    def __str__(self) -> str:
        if self.is_action():
            return f"action:{self.action}"
        return self.command or ""


@dataclass
class Service:
    """A fully-parsed service definition for USMD-RDSH.

    Attributes:
        name: Unique name of this service (used as the mutation identifier).
        service_type: STATIC or DYNAMIC data model.
        dependencies: Names of other services that must be reachable.
        build_commands: Commands executed to start the service.
        unbuild_commands: Commands executed to stop/remove the service.
        emergency_commands: Commands executed when the node is failing fast.
        health_check_commands: Commands used to verify the service is healthy.
        update_commands: Commands run when an in-place service upgrade is applied.
        version: Timestamp of the last update pushed by the administrator.

    Examples:
        >>> svc = Service(
        ...     name="web",
        ...     service_type=ServiceType.STATIC,
        ...     dependencies=["backend"],
        ...     build_commands=["nginx -t && nginx"],
        ...     unbuild_commands=["nginx -s stop"],
        ... )
        >>> svc.name
        'web'
        >>> svc.service_type.is_static()
        True
    """

    name: str
    service_type: ServiceType = ServiceType.STATIC
    dependencies: list[str] = field(default_factory=list)
    build_commands: list[str] = field(default_factory=list)
    unbuild_commands: list[str] = field(default_factory=list)
    emergency_commands: list[str] = field(default_factory=list)
    health_check_commands: list[str] = field(default_factory=list)
    update_commands: list[str] = field(default_factory=list)
    version: int = 0

    def has_dependency(self, service_name: str) -> bool:
        """Return True if this service lists the given name as a dependency.

        Args:
            service_name: The dependency to check.

        Example:
            >>> svc = Service(name="web", dependencies=["backend"])
            >>> svc.has_dependency("backend")
            True
            >>> svc.has_dependency("db")
            False
        """
        return service_name in self.dependencies

    def __repr__(self) -> str:
        return (
            f"Service(name={self.name!r}, type={self.service_type}, "
            f"deps={self.dependencies})"
        )
