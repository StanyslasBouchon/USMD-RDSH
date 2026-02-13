from dataclasses import dataclass

from usmd_rdsh.sys.usd import USD


@dataclass
class USC:
    """USC class."""

    uscn: str
    version: int
    pubkey: str
    usd_list: list[USD]
