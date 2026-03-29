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
            bytes: JSON object with sender_name, sender_address, reference_names.

        Example:
            >>> req = InformReferenceNodeRequest(1, "10.0.0.1", [2])
            >>> import json; json.loads(req.to_payload())["sender_name"]
            1
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
    def from_payload(
        payload: bytes,
    ) -> "Result[InformReferenceNodeRequest, Error]":
        """Deserialise from JSON bytes.

        Accepts both the new object format and the legacy array-only format
        (array → sender_name=0, sender_address='', reference_names=array).

        Args:
            payload: UTF-8 JSON bytes.

        Returns:
            Result[InformReferenceNodeRequest, Error]: Ok or Err.

        Example:
            >>> req = InformReferenceNodeRequest(99, "1.2.3.4", [5, 6])
            >>> InformReferenceNodeRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        try:
            data = json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"InformReferenceNode parse error: {exc}",
                )
            )

        # Legacy format: plain JSON array of names
        if isinstance(data, list):
            try:
                return Result.Ok(
                    InformReferenceNodeRequest(
                        sender_name=0,
                        sender_address="",
                        reference_names=list(map(int, data)),
                    )
                )
            except (TypeError, ValueError) as exc:
                return Result.Err(
                    Error.new(
                        ErrorKind.PROTOCOL_ERROR,
                        f"InformReferenceNode legacy parse: {exc}",
                    )
                )

        # Current format: JSON object
        if not isinstance(data, dict):
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    "InformReferenceNode: expected JSON object or array",
                )
            )
        try:
            return Result.Ok(
                InformReferenceNodeRequest(
                    sender_name=int(data.get("sender_name", 0)),
                    sender_address=str(data.get("sender_address", "")),
                    reference_names=list(map(int, data.get("reference_names", []))),
                )
            )
        except (TypeError, ValueError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"InformReferenceNode object parse: {exc}",
                )
            )
