"""NCP Command 0 — Get_status.

Queries the current state and resource usage of a remote node.
The receiver responds with its own status information.

Request payload: empty (no data sent — the receiver answers from its own state).
Response payload: JSON-serialised NodeStatus.

Examples:
    >>> req = GetStatusRequest()
    >>> req.to_payload()
    b''

    >>> status = NodeStatus(
    ...     ram_percent=0.45,
    ...     cpu_percent=0.30,
    ...     disk_percent=0.10,
    ...     network_percent=0.05,
    ...     service_name="backend",
    ...     state=NodeState.ACTIVE,
    ... )
    >>> resp = GetStatusResponse(status)
    >>> payload = resp.to_payload()
    >>> parsed = GetStatusResponse.from_payload(payload).unwrap()
    >>> parsed.status.service_name
    'backend'
"""

import json
from dataclasses import dataclass, field
from typing import Optional

from ....node.state import NodeState
from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


@dataclass
class NodeStatus:
    """Current status snapshot of a node, as reported in response to Get_status.

    Attributes:
        ram_percent: RAM utilisation ∈ [0, 1].
        cpu_percent: CPU utilisation ∈ [0, 1].
        disk_percent: Disk utilisation ∈ [0, 1].
        network_percent: Network card utilisation ∈ [0, 1].
        service_name: Name of the active mutation service (or None).
        hosting_static: Static services this node runs (may be empty).
        hosting_dynamic: Dynamic shards on this node (may be empty).
        state: Current NodeState.

    Examples:
        >>> s = NodeStatus(0.5, 0.3, 0.1, 0.05, "web", NodeState.ACTIVE)
        >>> s.reference_load()
        0.5
    """

    ram_percent: float
    cpu_percent: float
    disk_percent: float
    network_percent: float
    service_name: Optional[str]
    state: NodeState
    hosting_static: list[str] = field(default_factory=list)
    hosting_dynamic: list[str] = field(default_factory=list)

    def reference_load(self) -> float:
        """Return the reference load (maximum of all metrics).

        Example:
            >>> NodeStatus(0.5, 0.8, 0.3, 0.1, None, NodeState.ACTIVE).reference_load()
            0.8
        """
        return max(
            self.ram_percent, self.cpu_percent, self.disk_percent, self.network_percent
        )


class GetStatusRequest:
    """NCP command 0 request — carries no payload.

    Examples:
        >>> req = GetStatusRequest()
        >>> req.to_payload()
        b''
    """

    def to_payload(self) -> bytes:
        """Serialise the request payload (empty for Get_status).

        Returns:
            bytes: Always empty bytes.
        """
        return b""

    @staticmethod
    def from_payload(_payload: bytes) -> Result["GetStatusRequest", Error]:
        """Deserialise a Get_status request from payload bytes.

        Args:
            _payload: Expected to be empty.

        Returns:
            Result[GetStatusRequest, Error]: Always Ok.
        """
        return Result.Ok(GetStatusRequest())


class GetStatusResponse:
    """NCP command 0 response — carries the node's current status.

    Attributes:
        status: The NodeStatus to transmit.

    Examples:
        >>> status = NodeStatus(0.4, 0.3, 0.2, 0.1, None, NodeState.ACTIVE)
        >>> resp = GetStatusResponse(status)
        >>> payload = resp.to_payload()
        >>> GetStatusResponse.from_payload(payload).is_ok()
        True
    """

    def __init__(self, status: NodeStatus) -> None:
        self.status = status

    def to_payload(self) -> bytes:
        """Serialise the response to JSON bytes.

        Returns:
            bytes: UTF-8 JSON encoding of the status.

        Example:
            >>> s = NodeStatus(0.1, 0.2, 0.3, 0.4, "svc", NodeState.ACTIVE)
            >>> len(GetStatusResponse(s).to_payload()) > 0
            True
        """
        doc = {
            "ram": self.status.ram_percent,
            "cpu": self.status.cpu_percent,
            "disk": self.status.disk_percent,
            "net": self.status.network_percent,
            "service": self.status.service_name,
            "state": self.status.state.value,
            "hosting_static": self.status.hosting_static,
            "hosting_dynamic": self.status.hosting_dynamic,
        }
        return json.dumps(doc).encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> Result["GetStatusResponse", Error]:
        """Deserialise a Get_status response from payload bytes.

        Args:
            payload: UTF-8 JSON bytes.

        Returns:
            Result[GetStatusResponse, Error]: Ok with parsed response, or Err.

        Example:
            >>> s = NodeStatus(0.1, 0.2, 0.3, 0.4, "svc", NodeState.ACTIVE)
            >>> raw = GetStatusResponse(s).to_payload()
            >>> GetStatusResponse.from_payload(raw).is_ok()
            True
        """
        try:
            doc = json.loads(payload.decode("utf-8"))
            state = NodeState(doc["state"])
            hs = (
                [str(x) for x in doc["hosting_static"]]
                if "hosting_static" in doc
                else []
            )
            hd = (
                [str(x) for x in doc["hosting_dynamic"]]
                if "hosting_dynamic" in doc
                else []
            )
            status = NodeStatus(
                ram_percent=float(doc["ram"]),
                cpu_percent=float(doc["cpu"]),
                disk_percent=float(doc["disk"]),
                network_percent=float(doc["net"]),
                service_name=doc.get("service"),
                state=state,
                hosting_static=hs,
                hosting_dynamic=hd,
            )
            return Result.Ok(GetStatusResponse(status))
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR, f"GetStatusResponse parse error: {exc}"
                )
            )
