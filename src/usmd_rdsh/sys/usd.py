from dataclasses import dataclass

from usmd_rdsh.sys.neighbor import NodeNeighbor


@dataclass
class USDSettings:
    """USD settings class."""

    nnr: int  # Number of Node References
    ptms: int  # Ping Tolerance in milliseconds


@dataclass
class USD:
    """USD class."""

    usdn: str
    version: int
    settings: USDSettings
    neighbors: list[NodeNeighbor]
    pubkey: str
