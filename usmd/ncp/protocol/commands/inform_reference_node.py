"""NCP Command 8 — Inform_reference_node.

A node informs each of its reference nodes about the full list of nodes it
itself uses as references. This allows the network to maintain an accurate
picture of proximity relationships.

Request payload: JSON list of node names (UNIX timestamps).
Response payload: empty.

Examples:
    >>> req = InformReferenceNodeRequest(reference_names=[1710000001, 1710000002])
    >>> parsed = InformReferenceNodeRequest.from_payload(req.to_payload()).unwrap()
    >>> parsed.reference_names
    [1710000001, 1710000002]
"""

import json
from dataclasses import dataclass, field

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


@dataclass
class InformReferenceNodeRequest:
    """NCP command 8 request — reference node list announcement.

    Attributes:
        reference_names: UNIX-timestamp names of the sender's reference nodes.

    Examples:
        >>> req = InformReferenceNodeRequest(reference_names=[100, 200, 300])
        >>> InformReferenceNodeRequest.from_payload(req.to_payload()).unwrap().reference_names
        [100, 200, 300]
    """

    reference_names: list[int] = field(default_factory=list)

    def to_payload(self) -> bytes:
        """Serialise to JSON bytes."""
        return json.dumps(self.reference_names).encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> Result["InformReferenceNodeRequest", Error]:
        """Deserialise from JSON bytes.

        Args:
            payload: UTF-8 JSON array of node names (integers).

        Returns:
            Result[InformReferenceNodeRequest, Error]: Ok or Err.

        Example:
            >>> req = InformReferenceNodeRequest([1, 2])
            >>> InformReferenceNodeRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        try:
            data = json.loads(payload.decode("utf-8"))
            return Result.Ok(InformReferenceNodeRequest(reference_names=list(map(int, data))))
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR, f"InformReferenceNode parse error: {exc}"
                )
            )
