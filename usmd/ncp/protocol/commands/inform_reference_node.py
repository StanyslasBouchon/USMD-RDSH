"""NCP Command 8 — Inform_reference_node.

A node informs each of its reference nodes about the full list of nodes it
itself uses as references.  This allows the network to maintain an accurate
picture of proximity relationships and lets each reference node maintain its
own *Node Reference List* (NRL) — the set of nodes that have chosen it.

Request payload: UTF-8 JSON object with three keys:

    ``sender_name``      - UNIX-timestamp name (int) of the sending node.
    ``sender_address``   - IP address (str) of the sending node.
    ``reference_names``  - JSON array of node names (ints) that the sender
                           currently uses as its reference nodes.

Response payload: empty.

Examples:
    >>> req = InformReferenceNodeRequest(
    ...     sender_name=1710000001,
    ...     sender_address="10.0.0.2",
    ...     reference_names=[1710000003, 1710000004],
    ... )
    >>> parsed = InformReferenceNodeRequest.from_payload(req.to_payload()).unwrap()
    >>> parsed.sender_name
    1710000001
    >>> parsed.sender_address
    '10.0.0.2'
    >>> parsed.reference_names
    [1710000003, 1710000004]
"""

import json
from typing import Optional

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


class InformReferenceNodeRequest:
    """NCP command 8 request — reference node list announcement.

    Attributes:
        sender_name: UNIX-timestamp name of the sending node.
        sender_address: IP address of the sending node.
        reference_names: UNIX-timestamp names of the sender's chosen
            reference nodes.

    Examples:
        >>> req = InformReferenceNodeRequest(1, "10.0.0.1", [2, 3])
        >>> InformReferenceNodeRequest.from_payload(req.to_payload()).unwrap().sender_name
        1
    """

    def __init__(
        self,
        sender_name: int,
        sender_address: str,
        reference_names: Optional[list[int]] = None,
    ) -> None:
        self.sender_name = sender_name
        self.sender_address = sender_address
        self.reference_names: list[int] = (
            reference_names if reference_names is not None else []
        )

    def to_payload(self) -> bytes:
        """Serialise to UTF-8 JSON bytes.

        Returns:
            bytes: UTF-8 JSON payload.
        """
        return json.dumps(
            {
                "sender_name": self.sender_name,
                "sender_address": self.sender_address,
                "reference_names": self.reference_names,
            },
            ensure_ascii=False,
        ).encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> "Result[InformReferenceNodeRequest, Error]":
        """Deserialise an Inform_reference_node request.

        Args:
            payload: Raw bytes from the network.

        Returns:
            Result[InformReferenceNodeRequest, Error]: Ok or Err.

        Examples:
            >>> req = InformReferenceNodeRequest("1.2.3.4", [1, 2])
            >>> InformReferenceNodeRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        try:
            data = json.loads(payload.decode("utf-8"))
            return Result.Ok(
                InformReferenceNodeRequest(
                    sender_name=int(data.get("sender_name", 0)),
                    sender_address=str(data.get("sender_address", "")),
                    reference_names=[
                        int(n) for n in data.get("reference_names", [])
                    ],
                )
            )
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, KeyError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"InformReferenceNodeRequest parse error: {exc}",
                )
            )
