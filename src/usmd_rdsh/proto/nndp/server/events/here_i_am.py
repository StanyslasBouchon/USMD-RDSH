from dataclasses import dataclass

from usmd_rdsh.proto.nndp.base.env import HereIAmData


@dataclass(frozen=True)
class HereIAmReceivedEvent:
    """Event for when a Here I Am packet is received."""

    data: HereIAmData
