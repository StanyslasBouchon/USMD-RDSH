"""NCP Command 7 — Send_mutation_properties.

Propagates available mutation (service) definitions to reference nodes.
Each service definition includes its version (last modification timestamp).

Only reference nodes may receive this command.

Request payload: JSON list of service summary objects.
Response payload: empty.

Examples:
    >>> services = [
    ...     MutationSummary(name="backend", version=1710000000),
    ...     MutationSummary(name="db", version=1700000000),
    ... ]
    >>> req = SendMutationPropertiesRequest(services=services)
    >>> parsed = SendMutationPropertiesRequest.from_payload(req.to_payload()).unwrap()
    >>> parsed.services[0].name
    'backend'
"""

import json
from dataclasses import dataclass, field

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


@dataclass
class MutationSummary:
    """Lightweight summary of a mutation/service definition.

    Attributes:
        name: Service name.
        version: Last modification UNIX timestamp (set by USD master).

    Examples:
        >>> m = MutationSummary(name="web", version=1710000000)
        >>> m.name
        'web'
    """

    name: str
    version: int


@dataclass
class SendMutationPropertiesRequest:
    """NCP command 7 request — mutation definitions propagation.

    Attributes:
        services: List of MutationSummary objects for all known services.

    Examples:
        >>> services = [MutationSummary("web", 1000)]
        >>> req = SendMutationPropertiesRequest(services=services)
        >>> SendMutationPropertiesRequest.from_payload(req.to_payload()).is_ok()
        True
    """

    services: list[MutationSummary] = field(default_factory=list)

    def to_payload(self) -> bytes:
        """Serialise to JSON bytes."""
        doc = [{"name": s.name, "version": s.version} for s in self.services]
        return json.dumps(doc).encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> Result["SendMutationPropertiesRequest", Error]:
        """Deserialise from JSON bytes.

        Args:
            payload: UTF-8 JSON bytes.

        Returns:
            Result[SendMutationPropertiesRequest, Error]: Ok or Err.

        Example:
            >>> req = SendMutationPropertiesRequest([MutationSummary("db", 999)])
            >>> SendMutationPropertiesRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        try:
            data = json.loads(payload.decode("utf-8"))
            services = [
                MutationSummary(name=str(s["name"]), version=int(s["version"]))
                for s in data
            ]
            return Result.Ok(SendMutationPropertiesRequest(services=services))
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR, f"SendMutationProperties parse error: {exc}"
                )
            )
