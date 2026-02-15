"""Node access and role definitions.

This module defines roles (UCD/USD/NODE operator/executor) and a NodeAccess
dataclass that associates a public key with a list of roles.
"""

from dataclasses import dataclass
from enum import Enum


class Role(Enum):
    """Role enumeration for node access control.

    Example:
        >>> from usmd_rdsh.sys.nal import Role
        >>> Role.NODE_OPERATOR.value
        'NODE_OPERATOR'
        >>> list(Role)
        [<Role.UCD_OPERATOR>, <Role.USD_OPERATOR>, <Role.NODE_OPERATOR>, <Role.NODE_EXECUTOR>]
    """

    UCD_OPERATOR = "UCD_OPERATOR"
    USD_OPERATOR = "USD_OPERATOR"
    NODE_OPERATOR = "NODE_OPERATOR"
    NODE_EXECUTOR = "NODE_EXECUTOR"


@dataclass
class NodeAccess:
    """Access entry for a node: public key and assigned roles.

    Attributes:
        ed25519_pub_key_32: Base64URL-encoded 32-byte Ed25519 public key.
        roles: List of roles granted to this key.

    Example:
        >>> from usmd_rdsh.sys.nal import NodeAccess, Role
        >>> na = NodeAccess(
        ...     ed25519_pub_key_32="AbC123...",
        ...     roles=[Role.NODE_OPERATOR, Role.NODE_EXECUTOR],
        ... )
        >>> na.ed25519_pub_key_32
        'AbC123...'
        >>> Role.NODE_OPERATOR in na.roles
        True
    """

    ed25519_pub_key_32: str
    roles: list[Role]
