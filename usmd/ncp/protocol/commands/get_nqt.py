"""NCP Command 12 — Get_nqt (Node Quorum Table synchronisation).

Used by a newly-joined node to obtain the full quorum promotion history
from a peer so that it immediately knows who the current operator is.

Request payload : empty.
Response payload: UTF-8 encoded JSON array of NQT entry dicts, as produced
                  by :meth:`~usmd.node.nqt.NodeQuorumTable.get_all_dicts`.

Examples:
    >>> req = GetNqtRequest()
    >>> req.to_payload()
    b''
    >>> resp = GetNqtResponse(entries=[{"epoch": 1, "address": "10.0.0.1"}])
    >>> import json
    >>> json.loads(resp.to_payload())[0]["epoch"]
    1
    >>> parsed = GetNqtResponse.from_payload(resp.to_payload()).unwrap()
    >>> parsed.entries[0]["address"]
    '10.0.0.1'
"""

import json

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


class GetNqtRequest:
    """NCP command 12 request — no payload needed.

    Examples:
        >>> GetNqtRequest().to_payload()
        b''
    """

    def to_payload(self) -> bytes:
        """Serialise the request (always empty).

        Returns:
            bytes: Empty bytes.
        """
        return b""

    @staticmethod
    def from_payload(_payload: bytes) -> "Result[GetNqtRequest, Error]":
        """Deserialise a Get_nqt request (ignores payload content).

        Args:
            _payload: Ignored.

        Returns:
            Result[GetNqtRequest, Error]: Always Ok.
        """
        return Result.Ok(GetNqtRequest())


class GetNqtResponse:
    """NCP command 12 response — carries the peer's full NQT as JSON.

    Attributes:
        entries: List of NQT entry dicts (newest first).

    Examples:
        >>> resp = GetNqtResponse(entries=[])
        >>> resp.to_payload()
        b'[]'
        >>> GetNqtResponse.from_payload(b'[]').unwrap().entries
        []
    """

    def __init__(self, entries: list[dict]) -> None:
        self.entries = entries

    def to_payload(self) -> bytes:
        """Serialise the NQT entries as UTF-8 JSON.

        Returns:
            bytes: UTF-8 encoded JSON array.

        Example:
            >>> GetNqtResponse([{"epoch": 2}]).to_payload()
            b'[{"epoch": 2}]'
        """
        return json.dumps(self.entries, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> "Result[GetNqtResponse, Error]":
        """Deserialise a Get_nqt response.

        Args:
            payload: UTF-8 encoded JSON array of NQT entry dicts.

        Returns:
            Result[GetNqtResponse, Error]: Ok with the entries, or Err on parse failure.

        Examples:
            >>> GetNqtResponse.from_payload(b'[]').is_ok()
            True
            >>> GetNqtResponse.from_payload(b'not-json').is_err()
            True
        """
        if not payload:
            return Result.Ok(GetNqtResponse(entries=[]))
        try:
            entries = json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"GetNqt response decode error: {exc}",
                )
            )
        if not isinstance(entries, list):
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    "GetNqt response: expected JSON array",
                )
            )
        return Result.Ok(GetNqtResponse(entries=entries))
