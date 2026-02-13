from dataclasses import dataclass
from enum import Enum


class Role(Enum):
    """Role enumeration."""

    UCD_OPERATOR = "UCD_OPERATOR"
    USD_OPERATOR = "USD_OPERATOR"
    NODE_OPERATOR = "NODE_OPERATOR"
    NODE_EXECUTOR = "NODE_EXECUTOR"


@dataclass
class NodeAccess:
    """Node access class."""

    pubkey: str
    roles: list[Role]
