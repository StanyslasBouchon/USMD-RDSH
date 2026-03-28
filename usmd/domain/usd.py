"""Unified System Domain (USD) for USMD-RDSH.

A USD is the fundamental administrative boundary: it groups a set of nodes
that share the same configuration, mutations and cluster membership. Every
node belongs to exactly one USD.

Configuration (USDConfig) is managed exclusively by UCD operators and is
propagated via NCP Send_usd_properties commands.

Examples:
    >>> cfg = USDConfig(name="prod-domain", cluster_name="eu-cluster",
    ...                 max_reference_nodes=5, load_threshold=0.8,
    ...                 ping_tolerance_ms=200, load_check_interval=30,
    ...                 emergency_threshold=0.9)
    >>> usd = UnifiedSystemDomain(config=cfg, private_key=b"\\x00"*32)
    >>> usd.config.name
    'prod-domain'
"""

import logging
from dataclasses import dataclass
from typing import Optional

from ..node.node import Node, NodeInfo
from ..utils.errors import Error, ErrorKind
from ..utils.result import Result


@dataclass
class USDConfig:  # pylint: disable=too-many-instance-attributes
    """Configuration parameters for a Unified System Domain.

    These parameters are set by the administrator and propagated to all nodes
    via NCP. All nodes obey these parameters for distance calculation, load
    monitoring and emergency triggers.

    Attributes:
        name: Human-readable USDN (Unified System Domain Name).
        cluster_name: USCN this USD belongs to (may be empty).
        edb_address: Optional DNS/IP of the Easy Deployment Base server.
        max_reference_nodes: How many reference nodes each node maintains.
            Default: 5.
        load_threshold: Normalised load (0–1) above which a node is considered
            weakened and triggers emergency. Default: 0.8.
        ping_tolerance_ms: Maximum ping (ms) used as T in the distance formula.
            Default: 200.
        load_check_interval: Seconds between resource usage checks. Default: 30.
        emergency_threshold: Normalised load at which an emergency request is
            sent. Default: 0.9.
        version: Last modification timestamp (set by the USD master).

    Examples:
        >>> cfg = USDConfig(name="staging", cluster_name="us-east",
        ...                 max_reference_nodes=3, load_threshold=0.75,
        ...                 ping_tolerance_ms=100, load_check_interval=15,
        ...                 emergency_threshold=0.85)
        >>> cfg.name
        'staging'
    """

    name: str
    cluster_name: str = ""
    edb_address: Optional[str] = None
    max_reference_nodes: int = 5
    load_threshold: float = 0.8
    ping_tolerance_ms: int = 200
    load_check_interval: int = 30
    emergency_threshold: float = 0.9
    version: int = 0


class UnifiedSystemDomain:
    """Represents a Unified System Domain (USD) from the perspective of one node.

    Each node holds a local copy of its USD's configuration and the list of
    all known nodes inside the domain.

    Attributes:
        config: Domain configuration propagated from the master.
        private_key: Cluster private key used to authenticate NCP packets.
        nodes: Mapping of node name (UNIX timestamp) → Node.

    Examples:
        >>> cfg = USDConfig(name="demo", cluster_name="")
        >>> usd = UnifiedSystemDomain(config=cfg, private_key=b"\\x00"*32)
        >>> usd.add_node(Node(address="10.0.0.1", name=1710000000))
        >>> usd.get_node(1710000000) is not None
        True
    """

    def __init__(
        self,
        config: USDConfig,
        private_key: bytes,
    ) -> None:
        """Initialise a new USD instance.

        Args:
            config: Domain configuration parameters.
            private_key: 32-byte cluster private key for NCP authentication.

        Example:
            >>> cfg = USDConfig(name="test")
            >>> usd = UnifiedSystemDomain(config=cfg, private_key=b"\\x00"*32)
        """
        self.config = config
        self.private_key = private_key
        self.nodes: dict[int, Node] = {}

        logging.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] USD \x1b[38;5;220m%s\x1b[0m "
            "initialised (cluster=%s)",
            config.name,
            config.cluster_name or "(none)",
        )

    # ------------------------------------------------------------------
    # Node registry
    # ------------------------------------------------------------------

    def add_node(self, node: Node) -> Result[None, Error]:
        """Register a new node in this domain.

        A node name must be unique within the domain. If a conflict is detected
        the node must pick a new name (new UNIX timestamp) and retry.

        Args:
            node: The Node to register.

        Returns:
            Result[None, Error]: Ok(None) if added, Err if name conflict.

        Examples:
            >>> cfg = USDConfig(name="t")
            >>> usd = UnifiedSystemDomain(cfg, b"\\x00"*32)
            >>> n = Node(address="10.0.0.1", name=1234567890)
            >>> usd.add_node(n).is_ok()
            True
            >>> usd.add_node(n).is_err()
            True
        """
        if node.name in self.nodes:
            return Result.Err(
                Error.new(
                    ErrorKind.NODE_NAME_CONFLICT,
                    f"Node name {node.name} already exists in USD {self.config.name}",
                )
            )
        self.nodes[node.name] = node
        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] USD %s: node %d added (%s)",
            self.config.name,
            node.name,
            node.address,
        )
        return Result.Ok(None)

    def remove_node(self, name: int) -> Result[Node, Error]:
        """Remove a node from the domain by its name.

        Args:
            name: UNIX-timestamp name of the node to remove.

        Returns:
            Result[Node, Error]: The removed Node, or Err if not found.

        Example:
            >>> cfg = USDConfig(name="t")
            >>> usd = UnifiedSystemDomain(cfg, b"\\x00"*32)
            >>> usd.remove_node(9999).is_err()
            True
        """
        node = self.nodes.pop(name, None)
        if node is None:
            return Result.Err(
                Error.new(
                    ErrorKind.NODE_NOT_FOUND,
                    f"Node {name} not in USD {self.config.name}",
                )
            )
        return Result.Ok(node)

    def get_node(self, name: int) -> Optional[Node]:
        """Return a node by its UNIX-timestamp name, or None.

        Args:
            name: UNIX-timestamp name.

        Example:
            >>> cfg = USDConfig(name="t")
            >>> usd = UnifiedSystemDomain(cfg, b"\\x00"*32)
            >>> usd.get_node(99999) is None
            True
        """
        return self.nodes.get(name)

    def active_nodes(self) -> list[Node]:
        """Return all currently active nodes.

        Example:
            >>> cfg = USDConfig(name="t")
            >>> usd = UnifiedSystemDomain(cfg, b"\\x00"*32)
            >>> usd.active_nodes()
            []
        """
        return [n for n in self.nodes.values() if n.state.is_active()]

    def all_node_infos(self) -> list[NodeInfo]:
        """Return lightweight NodeInfo snapshots for all nodes.

        Used when bootstrapping a newly joined node.

        Returns:
            list[NodeInfo]: Snapshots for all registered nodes.
        """
        return [n.to_info() for n in self.nodes.values()]

    def update_config(self, new_config: USDConfig) -> None:
        """Replace the domain configuration with a newer version.

        Only applied if new_config.version > self.config.version.

        Args:
            new_config: Incoming configuration from a reference node.

        Example:
            >>> cfg = USDConfig(name="t", version=1)
            >>> usd = UnifiedSystemDomain(cfg, b"\\x00"*32)
            >>> usd.update_config(USDConfig(name="t", version=2))
            >>> usd.config.version
            2
        """
        if new_config.version > self.config.version:
            logging.info(
                "[\x1b[38;5;51mUSMD\x1b[0m] USD %s config updated v%d→v%d",
                self.config.name,
                self.config.version,
                new_config.version,
            )
            self.config = new_config

    def __repr__(self) -> str:
        return (
            f"UnifiedSystemDomain(name={self.config.name!r}, "
            f"nodes={len(self.nodes)})"
        )
