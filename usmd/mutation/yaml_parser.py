"""YAML service file parser for USMD-RDSH mutations.

Each service is described in a YAML file with the following structure::

    type: static          # optional: static | dynamic (default static)
    dependencies:         # optional; may be empty or omitted
      - backend
      - db
    build:
      - command: apt install curl -y
    unbuild:
      - command: apt purge curl -y
      - command: apt autoremove
    emergency:
      - command: cp /var/prog/app/* /mnt/rdisk/
      - action: unbuild
    check_health:
      - command: curl -f http://localhost/health
    update:
      - command: apt upgrade myapp -y

The parser converts this YAML into a :class:`~usmd.mutation.service.Service`
instance. By convention, the file name (without extension) becomes the
service name.

Examples:
    >>> yaml_content = '''
    ... dependencies:
    ...   - db
    ... build:
    ...   - command: echo start
    ... unbuild:
    ...   - command: echo stop
    ... '''
    >>> result = ServiceYamlParser.parse("myservice", yaml_content)
    >>> result.is_ok()
    True
    >>> result.unwrap().name
    'myservice'
    >>> result.unwrap().build_commands
    ['echo start']
"""

import logging
import os
from typing import Any

import yaml

from ..utils.errors import Error, ErrorKind
from ..utils.result import Result
from .service import Service, ServiceCommand, ServiceType


class ServiceYamlParser:
    """Parses YAML service definition files into Service objects.

    Examples:
        >>> yaml_str = "build:\\n  - command: echo hi\\n"
        >>> result = ServiceYamlParser.parse("svc", yaml_str)
        >>> result.is_ok()
        True
    """

    @staticmethod
    def _parse_commands(raw: list[dict[str, Any]]) -> list[str]:
        """Convert a YAML list of command/action entries to strings.

        Args:
            raw: List of dicts, each with either a ``command`` or ``action`` key.

        Returns:
            list[str]: Formatted command strings.
        """
        result: list[str] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            cmd = ServiceCommand(
                command=entry.get("command"),
                action=entry.get("action"),
            )
            result.append(str(cmd))
        return result

    @staticmethod
    def parse(service_name: str, yaml_content: str) -> Result[Service, Error]:
        """Parse a YAML string into a Service object.

        Args:
            service_name: Name assigned to this service (typically the filename
                          without extension).
            yaml_content: Raw YAML text of the service definition.

        Returns:
            Result[Service, Error]: Ok with the parsed Service, or Err on failure.

        Examples:
            >>> yaml_str = '''
            ... dependencies:
            ...   - db
            ... build:
            ...   - command: apt install myapp
            ... unbuild:
            ...   - command: apt remove myapp
            ... '''
            >>> result = ServiceYamlParser.parse("myapp", yaml_str)
            >>> result.is_ok()
            True
            >>> result.unwrap().dependencies
            ['db']
        """
        try:
            data: dict[str, Any] = yaml.safe_load(yaml_content) or {}
        except yaml.YAMLError as exc:
            return Result.Err(
                Error.new(ErrorKind.BAD_REQUEST, f"YAML parse error: {exc}")
            )

        dependencies: list[str] = data.get("dependencies", []) or []
        type_raw = (data.get("type") or "static")
        if isinstance(type_raw, str) and type_raw.lower() == "dynamic":
            stype = ServiceType.DYNAMIC
        else:
            stype = ServiceType.STATIC

        build_raw: list[dict] = data.get("build", []) or []
        unbuild_raw: list[dict] = data.get("unbuild", []) or []
        emergency_raw: list[dict] = data.get("emergency", []) or []
        health_raw: list[dict] = data.get("check_health", []) or []
        update_raw: list[dict] = data.get("update", []) or []

        service = Service(
            name=service_name,
            service_type=stype,
            dependencies=dependencies,
            build_commands=ServiceYamlParser._parse_commands(build_raw),
            unbuild_commands=ServiceYamlParser._parse_commands(unbuild_raw),
            emergency_commands=ServiceYamlParser._parse_commands(emergency_raw),
            health_check_commands=ServiceYamlParser._parse_commands(health_raw),
            update_commands=ServiceYamlParser._parse_commands(update_raw),
        )

        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] Service %r parsed "
            "(deps=%d, build=%d, unbuild=%d)",
            service_name,
            len(dependencies),
            len(service.build_commands),
            len(service.unbuild_commands),
        )
        return Result.Ok(service)

    @staticmethod
    def parse_file(path: str) -> Result[Service, Error]:
        """Read and parse a YAML service file from disk.

        The service name is derived from the file name without its extension.

        Args:
            path: Absolute or relative path to the YAML file.

        Returns:
            Result[Service, Error]: Ok with the parsed Service, or Err on failure.

        Example:
            >>> # Assuming /tmp/backend.yaml exists:
            >>> result = ServiceYamlParser.parse_file("/tmp/backend.yaml")
            >>> result.is_ok()
            True
        """
        service_name = os.path.splitext(os.path.basename(path))[0]
        try:
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.NOT_FOUND, f"Cannot read service file {path!r}: {exc}"
                )
            )
        return ServiceYamlParser.parse(service_name, content)
