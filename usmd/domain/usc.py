"""Unified System Cluster (USC) for USMD-RDSH.

A USC groups multiple USDs into a cluster. It provides a shared private key
used by all nodes across all member domains to authenticate NCP packets.

The cluster configuration is managed by UCD operators and propagated via
NCP Send_ucd_properties commands.

Examples:
    >>> cfg = USCConfig(name="eu-cluster", private_key=b"\\x00"*32)
    >>> usc = UnifiedSystemCluster(config=cfg)
    >>> usc.add_domain("prod-domain")
    >>> "prod-domain" in usc.domain_names
    True
"""

import logging
from dataclasses import dataclass

from ..utils.errors import Error, ErrorKind
from ..utils.result import Result
from ._versioned import log_config_update


@dataclass
class USCConfig:
    """Configuration for a Unified System Cluster.

    Attributes:
        name: Human-readable USCN (Unified System Cluster Name).
        private_key: 32-byte shared private key for NCP authentication across the cluster.
        version: Last modification timestamp (set by the UCD master).

    Examples:
        >>> cfg = USCConfig(name="global", private_key=b"\\x00"*32)
        >>> cfg.name
        'global'
    """

    name: str
    private_key: bytes
    version: int = 0


class UnifiedSystemCluster:
    """Represents a Unified System Cluster (USC).

    A cluster groups named USDs and provides the shared cryptographic key
    that allows nodes across all member domains to authenticate each other.

    Attributes:
        config: Cluster configuration.
        domain_names: Set of USDN names belonging to this cluster.

    Examples:
        >>> cfg = USCConfig(name="eu-cluster", private_key=b"k"*32)
        >>> usc = UnifiedSystemCluster(config=cfg)
        >>> usc.add_domain("backend-domain")
        >>> "backend-domain" in usc.domain_names
        True
    """

    def __init__(self, config: USCConfig) -> None:
        """Initialise a new USC.

        Args:
            config: Cluster configuration.

        Example:
            >>> cfg = USCConfig(name="test-cluster", private_key=b"\\x00"*32)
            >>> usc = UnifiedSystemCluster(config=cfg)
        """
        self.config = config
        self.domain_names: set[str] = set()

        logging.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] USC \x1b[38;5;220m%s\x1b[0m initialised",
            config.name,
        )

    # ------------------------------------------------------------------
    # Domain management
    # ------------------------------------------------------------------

    def add_domain(self, domain_name: str) -> Result[None, Error]:
        """Register a USD name as a member of this cluster.

        Args:
            domain_name: The USDN to add.

        Returns:
            Result[None, Error]: Ok(None) if added, Err if already present.

        Example:
            >>> cfg = USCConfig(name="c", private_key=b"\\x00"*32)
            >>> usc = UnifiedSystemCluster(config=cfg)
            >>> usc.add_domain("d1").is_ok()
            True
            >>> usc.add_domain("d1").is_err()
            True
        """
        if domain_name in self.domain_names:
            return Result.Err(
                Error.new(
                    ErrorKind.CONFLICT,
                    f"Domain {domain_name!r} already in cluster {self.config.name!r}",
                )
            )
        self.domain_names.add(domain_name)
        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] USC %s: domain %r added",
            self.config.name,
            domain_name,
        )
        return Result.Ok(None)

    def remove_domain(self, domain_name: str) -> Result[None, Error]:
        """Remove a USD name from this cluster.

        Args:
            domain_name: The USDN to remove.

        Returns:
            Result[None, Error]: Ok(None) if removed, Err if not found.

        Example:
            >>> cfg = USCConfig(name="c", private_key=b"\\x00"*32)
            >>> usc = UnifiedSystemCluster(config=cfg)
            >>> usc.remove_domain("nonexistent").is_err()
            True
        """
        if domain_name not in self.domain_names:
            return Result.Err(
                Error.new(
                    ErrorKind.DOMAIN_NOT_FOUND,
                    f"Domain {domain_name!r} not in cluster {self.config.name!r}",
                )
            )
        self.domain_names.discard(domain_name)
        return Result.Ok(None)

    def has_domain(self, domain_name: str) -> bool:
        """Return True if the given USDN is a member of this cluster.

        Args:
            domain_name: The USDN to look up.

        Example:
            >>> cfg = USCConfig(name="c", private_key=b"\\x00"*32)
            >>> usc = UnifiedSystemCluster(config=cfg)
            >>> usc.has_domain("x")
            False
        """
        return domain_name in self.domain_names

    def update_config(self, new_config: USCConfig) -> None:
        """Replace the cluster configuration if the version is newer.

        Args:
            new_config: Incoming configuration from a reference node.

        Example:
            >>> cfg = USCConfig(name="c", private_key=b"\\x00"*32, version=1)
            >>> usc = UnifiedSystemCluster(config=cfg)
            >>> usc.update_config(USCConfig(name="c", private_key=b"\\x00"*32, version=2))
            >>> usc.config.version
            2
        """
        if new_config.version > self.config.version:
            log_config_update("USC", self.config.name, self.config.version, new_config.version)
            self.config = new_config

    def __repr__(self) -> str:
        return (
            f"UnifiedSystemCluster(name={self.config.name!r}, "
            f"domains={len(self.domain_names)})"
        )
