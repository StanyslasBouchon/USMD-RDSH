"""USMD-RDSH node configuration.

Loaded from a YAML file (default: usmd.yaml) or constructed from CLI arguments.

Example usmd.yaml::

    node:
      address: auto          # or "192.168.1.100"
      role: executor         # executor | operator | usd_operator | ucd_operator

    usd:
      name: my-domain
      cluster_name: ""
      edb_address: null
      max_reference_nodes: 5
      reference_hold_seconds: 300  # stabilité des nœuds de référence (s), sauf préemption
      load_threshold: 0.8
      ping_tolerance_ms: 200
      load_check_interval: 30
      emergency_threshold: 0.9

    bootstrap: false         # true = créer un nouvel USD, false = rejoindre
    keys_file: usmd_keys.json
    nndp_ttl: 30

    ports:
      ncp: 5626
      nndp_listen: 5221
      nndp_send: 5222
"""

import socket
from dataclasses import dataclass
from typing import Optional

import yaml

from .domain.usd import USDConfig
from .node.role import NodeRole


@dataclass
class NodeConfig:
    """All tunable parameters for a running USMD-RDSH node.

    Attributes:
        address: IP address of this node ("auto" = detect).
        role: Role string ("executor", "operator", "usd_operator", "ucd_operator").
        keys_file: Path to JSON file where keys are persisted.
        bootstrap: If True, this node creates the USD instead of joining.
        nndp_ttl: Seconds between NNDP Here-I-Am broadcasts.
        usd_name: Human-readable Unified System Domain Name (USDN).
        cluster_name: USCN of the cluster this USD belongs to (may be empty).
        edb_address: Optional DNS/IP of the Easy Deployment Base.
        max_reference_nodes: Max reference peers per node.
        reference_hold_seconds: Minimum time (s) a chosen reference peer stays in the
            set unless a strictly closer peer forces preemption. Default 300 (5 min).
        load_threshold: Normalised load above which node is considered weakened.
        ping_tolerance_ms: Max tolerated ping T (ms) for distance formula.
        load_check_interval: Seconds between resource usage checks.
        emergency_threshold: Load level that triggers an emergency request.
        ncp_port: TCP port for the NCP server (spec: 5626).
        nndp_listen_port: UDP port that receives HIA packets (spec: 5221).
        nndp_send_port: UDP source port for HIA broadcasts (spec: 5222).
        broadcast_address: UDP broadcast destination.
        ncp_timeout: Per-connection NCP timeout in seconds.
        join_timeout: Seconds to wait for peer discovery + approval on startup.
        ctl_socket: Path to the Unix-domain control socket (Linux/macOS).
        ctl_port: TCP loopback port for the control server (Windows).
        quorum_enabled: Enable the distributed operator election system.
        quorum_check_interval: Seconds between operator liveness checks.
        quorum_election_timeout: Max random candidacy delay in seconds.

    Examples:
        >>> cfg = NodeConfig()
        >>> cfg.ncp_port
        5626
        >>> cfg.node_role
        <NodeRole.NODE_EXECUTOR: 'node_executor'>
    """

    # Network identity
    address: str = "auto"
    role: str = "executor"
    keys_file: str = "usmd_keys.json"

    # Startup behaviour
    bootstrap: bool = False
    nndp_ttl: int = 30

    # USD parameters
    usd_name: str = "default-domain"
    cluster_name: str = ""
    edb_address: Optional[str] = None
    max_reference_nodes: int = 5
    reference_hold_seconds: float = 300.0
    load_threshold: float = 0.8
    ping_tolerance_ms: int = 200
    load_check_interval: int = 30
    emergency_threshold: float = 0.9

    # Port numbers
    ncp_port: int = 5626
    nndp_listen_port: int = 5221
    nndp_send_port: int = 5222
    broadcast_address: str = "auto"

    # Timeouts
    ncp_timeout: float = 5.0
    join_timeout: float = 30.0

    # Control socket / TCP (Linux: Unix-domain socket; Windows: TCP loopback)
    ctl_socket: str = "usmd.sock"  # Unix-domain socket path (Linux/macOS)
    ctl_port: int = 5627  # TCP loopback port (Windows)

    # Web dashboard
    web_enabled: bool = False
    web_host: str = "0.0.0.0"
    web_port: int = 8443
    web_username: str = "admin"
    web_password: str = "changeme"
    web_ssl_cert: str = ""  # path to TLS cert (PEM), "" → auto self-signed
    web_ssl_key: str = ""  # path to TLS key (PEM)

    # Quorum election
    quorum_enabled: bool = True
    quorum_check_interval: float = 30.0  # seconds between operator liveness checks
    quorum_election_timeout: float = 8.0  # max candidacy delay (random 1 to N seconds)

    # ------------------------------------------------------------------ #
    # Derived properties                                                   #
    # ------------------------------------------------------------------ #

    @property
    def node_role(self) -> NodeRole:
        """Translate the role string to a NodeRole enum value.

        Example:
            >>> NodeConfig(role="usd_operator").node_role
            <NodeRole.USD_OPERATOR: 'usd_operator'>
        """
        mapping: dict[str, NodeRole] = {
            "executor": NodeRole.NODE_EXECUTOR,
            "operator": NodeRole.NODE_OPERATOR,
            "usd_operator": NodeRole.USD_OPERATOR,
            "ucd_operator": NodeRole.UCD_OPERATOR,
        }
        return mapping.get(self.role, NodeRole.NODE_EXECUTOR)

    def resolve_address(self) -> str:
        """Return the node's IP address, auto-detecting if configured as 'auto'.

        Uses a dummy UDP connect to determine the outbound interface address.

        Returns:
            str: IPv4 address string.

        Example:
            >>> addr = NodeConfig().resolve_address()
            >>> isinstance(addr, str)
            True
        """
        if self.address != "auto":
            return self.address
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            addr = sock.getsockname()[0]
            sock.close()
            return addr
        except OSError:
            return "127.0.0.1"

    def to_usd_config(self) -> USDConfig:
        """Build a USDConfig from this node's settings.

        Returns:
            USDConfig: Ready-to-use domain configuration.

        Example:
            >>> cfg = NodeConfig(usd_name="prod", cluster_name="eu")
            >>> usd_cfg = cfg.to_usd_config()
            >>> usd_cfg.name
            'prod'
        """
        return USDConfig(
            name=self.usd_name,
            cluster_name=self.cluster_name,
            edb_address=self.edb_address,
            max_reference_nodes=self.max_reference_nodes,
            load_threshold=self.load_threshold,
            ping_tolerance_ms=self.ping_tolerance_ms,
            load_check_interval=self.load_check_interval,
            emergency_threshold=self.emergency_threshold,
            version=0,
        )

    # ------------------------------------------------------------------ #
    # Loading                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def from_file(path: str) -> "NodeConfig":
        """Load configuration from a YAML file.

        Missing keys fall back to class defaults. If the file does not exist
        a default NodeConfig is returned without error.

        Args:
            path: Path to the YAML configuration file.

        Returns:
            NodeConfig: Loaded (or default) configuration.

        Example:
            >>> cfg = NodeConfig.from_file("/nonexistent/usmd.yaml")
            >>> cfg.usd_name
            'default-domain'
        """
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except FileNotFoundError:
            return NodeConfig()

        cfg = NodeConfig()

        node_sec = data.get("node", {}) or {}
        cfg.address = node_sec.get("address", cfg.address)
        cfg.role = node_sec.get("role", cfg.role)

        cfg.keys_file = data.get("keys_file", cfg.keys_file)
        cfg.bootstrap = bool(data.get("bootstrap", cfg.bootstrap))
        cfg.nndp_ttl = int(data.get("nndp_ttl", cfg.nndp_ttl))

        usd_sec = data.get("usd", {}) or {}
        cfg.usd_name = usd_sec.get("name", cfg.usd_name)
        cfg.cluster_name = usd_sec.get("cluster_name", cfg.cluster_name)
        cfg.edb_address = usd_sec.get("edb_address", cfg.edb_address)
        cfg.max_reference_nodes = int(
            usd_sec.get("max_reference_nodes", cfg.max_reference_nodes)
        )
        cfg.reference_hold_seconds = float(
            usd_sec.get("reference_hold_seconds", cfg.reference_hold_seconds)
        )
        cfg.load_threshold = float(usd_sec.get("load_threshold", cfg.load_threshold))
        cfg.ping_tolerance_ms = int(
            usd_sec.get("ping_tolerance_ms", cfg.ping_tolerance_ms)
        )
        cfg.load_check_interval = int(
            usd_sec.get("load_check_interval", cfg.load_check_interval)
        )
        cfg.emergency_threshold = float(
            usd_sec.get("emergency_threshold", cfg.emergency_threshold)
        )

        ports_sec = data.get("ports", {}) or {}
        cfg.ncp_port = int(ports_sec.get("ncp", cfg.ncp_port))
        cfg.nndp_listen_port = int(ports_sec.get("nndp_listen", cfg.nndp_listen_port))
        cfg.nndp_send_port = int(ports_sec.get("nndp_send", cfg.nndp_send_port))
        cfg.broadcast_address = str(ports_sec.get("broadcast", cfg.broadcast_address))

        cfg.ctl_socket = str(data.get("ctl_socket", cfg.ctl_socket))
        cfg.ctl_port = int(data.get("ctl_port", cfg.ctl_port))

        web_sec = data.get("web", {}) or {}
        cfg.web_enabled = bool(web_sec.get("enabled", cfg.web_enabled))
        cfg.web_host = str(web_sec.get("host", cfg.web_host))
        cfg.web_port = int(web_sec.get("port", cfg.web_port))
        cfg.web_username = str(web_sec.get("username", cfg.web_username))
        cfg.web_password = str(web_sec.get("password", cfg.web_password))
        cfg.web_ssl_cert = str(web_sec.get("ssl_cert", cfg.web_ssl_cert))
        cfg.web_ssl_key = str(web_sec.get("ssl_key", cfg.web_ssl_key))

        quorum_sec = data.get("quorum", {}) or {}
        cfg.quorum_enabled = bool(quorum_sec.get("enabled", cfg.quorum_enabled))
        cfg.quorum_check_interval = float(
            quorum_sec.get("check_interval", cfg.quorum_check_interval)
        )
        cfg.quorum_election_timeout = float(
            quorum_sec.get("election_timeout", cfg.quorum_election_timeout)
        )

        return cfg
