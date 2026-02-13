from dataclasses import dataclass

from usmd_rdsh.utils.node_state import NodeState


MAGIC = 0xD5C1
VERSION = 0x0001


@dataclass
class HereIAmData:
    """Here I Am data class."""

    node_name: str
    next_hia_pkt_time: int
    state: NodeState
    version: int = VERSION
