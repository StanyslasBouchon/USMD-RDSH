"""NCP Command 6 — Send_usd_properties.

Propagates USD (Unified System Domain) properties to reference nodes.
Carries the USD version (last modification timestamp from the USD master).

Only reference nodes may receive this command.

Request payload: JSON object with USD config fields and version.
Response payload: empty.

Examples:
    >>> from usmd.domain.usd import USDConfig
    >>> cfg = USDConfig(name="prod", cluster_name="eu", version=1710000000)
    >>> req = SendUsdPropertiesRequest.from_usd_config(cfg)
    >>> parsed = SendUsdPropertiesRequest.from_payload(req.to_payload()).unwrap()
    >>> parsed.config_version
    1710000000
"""

import json
from dataclasses import dataclass

from ....domain.usd import USDConfig
from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


@dataclass
class SendUsdPropertiesRequest:
    """NCP command 6 request — USD configuration propagation.

    Attributes:
        config_version: Version of the USD config (last modification timestamp).
        name: USD name (USDN).
        cluster_name: Cluster name (USCN) — may be empty.
        edb_address: Optional EDB server address.
        max_reference_nodes: Max reference peers per node.
        load_threshold: Weakened-node load threshold.
        ping_tolerance_ms: Max ping tolerance T (ms).
        load_check_interval: Load check interval (seconds).
        emergency_threshold: Emergency trigger load threshold.

    Examples:
        >>> req = SendUsdPropertiesRequest(
        ...     config_version=1, name="prod", cluster_name="eu",
        ...     edb_address=None, max_reference_nodes=5, load_threshold=0.8,
        ...     ping_tolerance_ms=200, load_check_interval=30,
        ...     emergency_threshold=0.9)
        >>> SendUsdPropertiesRequest.from_payload(req.to_payload()).is_ok()
        True
    """

    config_version: int
    name: str
    cluster_name: str
    edb_address: str | None
    max_reference_nodes: int
    load_threshold: float
    ping_tolerance_ms: int
    load_check_interval: int
    emergency_threshold: float

    @staticmethod
    def from_usd_config(cfg: USDConfig) -> "SendUsdPropertiesRequest":
        """Build from a USDConfig object.

        Args:
            cfg: The domain configuration to propagate.

        Returns:
            SendUsdPropertiesRequest: Ready-to-send request.

        Example:
            >>> from usmd.domain.usd import USDConfig
            >>> cfg = USDConfig(name="t", version=1)
            >>> req = SendUsdPropertiesRequest.from_usd_config(cfg)
            >>> req.config_version
            1
        """
        return SendUsdPropertiesRequest(
            config_version=cfg.version,
            name=cfg.name,
            cluster_name=cfg.cluster_name,
            edb_address=cfg.edb_address,
            max_reference_nodes=cfg.max_reference_nodes,
            load_threshold=cfg.load_threshold,
            ping_tolerance_ms=cfg.ping_tolerance_ms,
            load_check_interval=cfg.load_check_interval,
            emergency_threshold=cfg.emergency_threshold,
        )

    def to_usd_config(self) -> USDConfig:
        """Convert back to a USDConfig.

        Returns:
            USDConfig: Reconstructed domain configuration.
        """
        return USDConfig(
            name=self.name,
            cluster_name=self.cluster_name,
            edb_address=self.edb_address,
            max_reference_nodes=self.max_reference_nodes,
            load_threshold=self.load_threshold,
            ping_tolerance_ms=self.ping_tolerance_ms,
            load_check_interval=self.load_check_interval,
            emergency_threshold=self.emergency_threshold,
            version=self.config_version,
        )

    def to_payload(self) -> bytes:
        """Serialise to JSON bytes."""
        doc = {
            "version": self.config_version,
            "name": self.name,
            "cluster": self.cluster_name,
            "edb": self.edb_address,
            "max_refs": self.max_reference_nodes,
            "load_thresh": self.load_threshold,
            "ping_tol_ms": self.ping_tolerance_ms,
            "load_interval": self.load_check_interval,
            "emerg_thresh": self.emergency_threshold,
        }
        return json.dumps(doc).encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> Result["SendUsdPropertiesRequest", Error]:
        """Deserialise from JSON bytes.

        Args:
            payload: UTF-8 JSON bytes.

        Returns:
            Result[SendUsdPropertiesRequest, Error]: Ok or Err.

        Example:
            >>> from usmd.domain.usd import USDConfig
            >>> cfg = USDConfig(name="t", version=2)
            >>> req = SendUsdPropertiesRequest.from_usd_config(cfg)
            >>> SendUsdPropertiesRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        try:
            doc = json.loads(payload.decode("utf-8"))
            return Result.Ok(
                SendUsdPropertiesRequest(
                    config_version=int(doc["version"]),
                    name=str(doc["name"]),
                    cluster_name=str(doc.get("cluster", "")),
                    edb_address=doc.get("edb"),
                    max_reference_nodes=int(doc.get("max_refs", 5)),
                    load_threshold=float(doc.get("load_thresh", 0.8)),
                    ping_tolerance_ms=int(doc.get("ping_tol_ms", 200)),
                    load_check_interval=int(doc.get("load_interval", 30)),
                    emergency_threshold=float(doc.get("emerg_thresh", 0.9)),
                )
            )
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR, f"SendUsdProperties parse error: {exc}"
                )
            )
