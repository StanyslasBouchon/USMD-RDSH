"""NCP Command 9 — Request_snapshot.

Returns the full status snapshot of a node (same payload as the CTL
Unix socket): NIT, NAL, NEL, USD, node identity, and resource metrics,
all serialised as UTF-8 JSON.

This command is used by the USMD-RDSH web dashboard to aggregate the
state of all known nodes without relying on a shared database.

Request payload: empty.
Response payload: UTF-8 JSON dict (see _build_status_snapshot in NodeDaemon).

Examples:
    >>> req = RequestSnapshotRequest()
    >>> req.to_payload()
    b''
"""

import json
from typing import Any

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


class RequestSnapshotRequest:
    """NCP command 9 request — carries no payload.

    Examples:
        >>> req = RequestSnapshotRequest()
        >>> req.to_payload()
        b''
    """

    def to_payload(self) -> bytes:
        """Serialise the request (empty payload).

        Returns:
            bytes: Always empty.
        """
        return b""

    @staticmethod
    def from_payload(_payload: bytes) -> "Result[RequestSnapshotRequest, Error]":
        """Deserialise a Request_snapshot request from payload bytes.

        Args:
            _payload: Expected to be empty.

        Returns:
            Result[RequestSnapshotRequest, Error]: Always Ok.
        """
        return Result.Ok(RequestSnapshotRequest())


class RequestSnapshotResponse:
    """NCP command 9 response — carries the full status snapshot.

    Attributes:
        snapshot: Full status dict (nit, nal, nel, usd, node, resources).

    Examples:
        >>> snap = {"node": {"address": "1.2.3.4"}, "nit": [], "nal": [], "nel": {}}
        >>> resp = RequestSnapshotResponse(snap)
        >>> payload = resp.to_payload()
        >>> RequestSnapshotResponse.from_payload(payload).is_ok()
        True
    """

    def __init__(self, snapshot: dict[str, Any]) -> None:
        self.snapshot = snapshot

    def to_payload(self) -> bytes:
        """Serialise the snapshot to UTF-8 JSON bytes.

        Returns:
            bytes: JSON-encoded snapshot.

        Example:
            >>> snap = {"node": {}, "nit": [], "nal": [], "nel": {}}
            >>> len(RequestSnapshotResponse(snap).to_payload()) > 0
            True
        """
        return json.dumps(self.snapshot).encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> "Result[RequestSnapshotResponse, Error]":
        """Deserialise a Request_snapshot response from payload bytes.

        Args:
            payload: UTF-8 JSON bytes.

        Returns:
            Result[RequestSnapshotResponse, Error]: Ok with snapshot or Err.

        Example:
            >>> snap = {"node": {}, "nit": [], "nal": [], "nel": {}}
            >>> raw = RequestSnapshotResponse(snap).to_payload()
            >>> RequestSnapshotResponse.from_payload(raw).is_ok()
            True
        """
        try:
            snapshot = json.loads(payload.decode("utf-8"))
            return Result.Ok(RequestSnapshotResponse(snapshot))
        except (ValueError, UnicodeDecodeError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"RequestSnapshotResponse parse error: {exc}",
                )
            )
