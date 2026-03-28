"""NCP Command 5 — Send_ucd_properties.

Propagates UCD (Unified Configuration Database) properties to reference nodes.
Also carries the UCD version (last modification timestamp from the USD master).

Only reference nodes may receive this command.

Request payload: JSON object with UCD properties and version.
Response payload: empty (fire-and-forget propagation).

Examples:
    >>> props = {"max_nodes": 20, "log_level": "info"}
    >>> req = SendUcdPropertiesRequest(version=1710000000, properties=props)
    >>> parsed = SendUcdPropertiesRequest.from_payload(req.to_payload()).unwrap()
    >>> parsed.version
    1710000000
"""

import json
from dataclasses import dataclass, field
from typing import Any

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


@dataclass
class SendUcdPropertiesRequest:
    """NCP command 5 request — UCD configuration propagation.

    Attributes:
        version: UCD version (last modification UNIX timestamp).
        properties: Arbitrary key-value properties dict.

    Examples:
        >>> req = SendUcdPropertiesRequest(version=100, properties={"k": "v"})
        >>> SendUcdPropertiesRequest.from_payload(req.to_payload()).unwrap().version
        100
    """

    version: int
    properties: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> bytes:
        """Serialise to JSON bytes."""
        doc = {"version": self.version, "properties": self.properties}
        return json.dumps(doc).encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> Result["SendUcdPropertiesRequest", Error]:
        """Deserialise from JSON bytes.

        Args:
            payload: UTF-8 JSON bytes.

        Returns:
            Result[SendUcdPropertiesRequest, Error]: Ok or Err.

        Example:
            >>> req = SendUcdPropertiesRequest(1, {"a": 1})
            >>> SendUcdPropertiesRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        try:
            doc = json.loads(payload.decode("utf-8"))
            return Result.Ok(
                SendUcdPropertiesRequest(
                    version=int(doc["version"]),
                    properties=dict(doc.get("properties", {})),
                )
            )
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR, f"SendUcdProperties parse error: {exc}"
                )
            )
