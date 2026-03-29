"""NCP Command 10 — Request_vote (quorum election).

Sent by a candidate node to solicit a vote from its peers during a quorum
election for a specific operator role.  Used when no active holder of that
role is detected in the USD.

Request payload: UTF-8 JSON object with three keys:

    ``epoch``             – uint election epoch counter (int).
    ``role``              – target role name (str): ``"node_operator"``,
                            ``"usd_operator"`` or ``"ucd_operator"``.
    ``candidate_address`` – IP address of the candidate node (str).

Response payload:
    [vote: uint8] — 0x01 = YES, 0x00 = NO.

Backward compatibility: the legacy binary format
(4-byte epoch + UTF-8 address) is still accepted on ``from_payload``
and treated as a ``node_operator`` election.

Examples:
    >>> req = RequestVoteRequest(epoch=1, role="node_operator",
    ...                          candidate_address="192.168.1.1")
    >>> import json; json.loads(req.to_payload())["role"]
    'node_operator'
    >>> parsed = RequestVoteRequest.from_payload(req.to_payload()).unwrap()
    >>> parsed.epoch
    1
    >>> parsed.candidate_address
    '192.168.1.1'
"""

import json
import struct

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result

_LEGACY_EPOCH_SIZE = 4  # uint32 big-endian — used for backward-compat detection


class RequestVoteRequest:
    """NCP command 10 request — candidate proposes itself for a specific role.

    Attributes:
        epoch: Election epoch counter (prevents stale votes from older rounds).
        role: Target operator role name (e.g. ``"node_operator"``).
        candidate_address: IP address of the candidate node.

    Examples:
        >>> req = RequestVoteRequest(epoch=3, role="usd_operator",
        ...                          candidate_address="10.0.0.1")
        >>> import json
        >>> json.loads(req.to_payload())["epoch"]
        3
    """

    def __init__(self, epoch: int, candidate_address: str,
                 role: str = "node_operator") -> None:
        self.epoch = epoch
        self.role = role
        self.candidate_address = candidate_address

    def to_payload(self) -> bytes:
        """Serialise the request as a UTF-8 JSON object.

        Returns:
            bytes: UTF-8 encoded JSON.
        """
        return json.dumps(
            {
                "epoch":             self.epoch,
                "role":              self.role,
                "candidate_address": self.candidate_address,
            },
            ensure_ascii=False,
        ).encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> "Result[RequestVoteRequest, Error]":
        """Deserialise a Request_vote request.

        Accepts the current JSON format and the legacy binary format
        (4-byte uint32 epoch + UTF-8 address → assumes ``node_operator``).

        Args:
            payload: Raw bytes from the network.

        Returns:
            Result[RequestVoteRequest, Error]: Ok with parsed request, or Err.

        Examples:
            >>> req = RequestVoteRequest(1, "1.2.3.4", "ucd_operator")
            >>> RequestVoteRequest.from_payload(req.to_payload()).unwrap().role
            'ucd_operator'
        """
        # Try JSON first (current format)
        try:
            data = json.loads(payload.decode("utf-8"))
            if isinstance(data, dict):
                return Result.Ok(
                    RequestVoteRequest(
                        epoch=int(data.get("epoch", 0)),
                        role=str(data.get("role", "node_operator")),
                        candidate_address=str(data.get("candidate_address", "")),
                    )
                )
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            pass

        # Legacy binary format: [epoch uint32] [address UTF-8]
        if len(payload) < _LEGACY_EPOCH_SIZE:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"RequestVoteRequest too short: {len(payload)} bytes",
                  )
            )
        epoch = struct.unpack("!I", payload[:_LEGACY_EPOCH_SIZE])[0]
        address = payload[_LEGACY_EPOCH_SIZE:].decode("utf-8", errors="replace")
        return Result.Ok(
            RequestVoteRequest(
                epoch=epoch,
                role="node_operator",
                candidate_address=address,
            )
        )


class RequestVoteResponse:
    """NCP command 10 response.

    Attributes:
        granted: True if the peer grants the vote (YES), False otherwise (NO).

    Examples:
        >>> resp = RequestVoteResponse(granted=True)
        >>> resp.to_payload()
        b'\x01'
        >>> RequestVoteResponse.from_payload(b"\x01").unwrap().granted
        True
    """

    def __init__(self, granted: bool) -> None:
        self.granted = granted

    def to_payload(self) -> bytes:
        """Serialise the vote.

        Returns:
            bytes: ``b"\x01"`` for YES, ``b"\x00"`` for NO.
        """
        return b"\x01" if self.granted else b"\x00"

    @staticmethod
    def from_payload(payload: bytes) -> "Result[RequestVoteResponse, Error]":
        """Deserialise a Request_vote response.

        Args:
            payload: Raw bytes (at least 1 byte).

        Returns:
            Result[RequestVoteResponse, Error]: Ok or Err.

        Examples:
            >>> RequestVoteResponse.from_payload(b"\x01").unwrap().granted
            True
            >>> RequestVoteResponse.from_payload(b"\x00").unwrap().granted
            False
            >>> RequestVoteResponse.from_payload(b"").is_err()
            True
        """
        if len(payload) < 1:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    "RequestVoteResponse payload is empty",
                )
            )
        return Result.Ok(RequestVoteResponse(granted=payload[0] == 0x01))
