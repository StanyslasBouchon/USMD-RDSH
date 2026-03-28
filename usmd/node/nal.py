"""Node Access List (NAL) for USMD-RDSH.

The NAL maps each Ed25519 public key to one or more NodeRoles. It is used
to authorise NCP commands: before executing any privileged operation, the
receiving node checks the sender's public key against its local NAL.

Entries in the NAL that originate from UCD or USD public keys are stored
permanently (they may never be removed except by the administrator).

Examples:
    >>> nal = NodeAccessList()
    >>> key = b"k" * 32
    >>> nal.grant(key, NodeRole.NODE_EXECUTOR)
    >>> nal.has_role(key, NodeRole.NODE_EXECUTOR)
    True
    >>> nal.has_role(key, NodeRole.UCD_OPERATOR)
    False
"""

import logging
from typing import Optional

from ..utils.errors import Error, ErrorKind
from ..utils.result import Result
from .role import NodeRole


class NodeAccessList:
    """Manages the role-based access control list for a node.

    Each public key may hold multiple roles. Permanent entries (UCD/USD keys)
    cannot be removed through normal operation.

    Attributes:
        _entries: Mapping of public_key → set of NodeRoles.
        _permanent: Set of public keys that are stored permanently.

    Examples:
        >>> nal = NodeAccessList()
        >>> key = b"x" * 32
        >>> nal.grant(key, NodeRole.NODE_OPERATOR)
        >>> nal.get_roles(key)
        {<NodeRole.NODE_OPERATOR: 'node_operator'>}
    """

    def __init__(self) -> None:
        self._entries: dict[bytes, set[NodeRole]] = {}
        self._permanent: set[bytes] = set()

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def grant(
        self,
        public_key: bytes,
        role: NodeRole,
        permanent: bool = False,
    ) -> None:
        """Grant a role to a public key.

        Args:
            public_key: Ed25519 public key receiving the role.
            role: The NodeRole to grant.
            permanent: If True, this entry can never be revoked programmatically.

        Example:
            >>> nal = NodeAccessList()
            >>> nal.grant(b"k" * 32, NodeRole.USD_OPERATOR, permanent=True)
        """
        self._entries.setdefault(public_key, set()).add(role)
        if permanent:
            self._permanent.add(public_key)
        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NAL grant: %s ← %s%s",
            public_key.hex()[:16] + "…",
            role,
            " (permanent)" if permanent else "",
        )

    def revoke(
        self, public_key: bytes, role: Optional[NodeRole] = None
    ) -> Result[None, Error]:
        """Revoke a role (or all roles) from a public key.

        Permanent entries cannot be revoked.

        Args:
            public_key: Ed25519 public key to modify.
            role: Specific role to revoke, or None to revoke all roles.

        Returns:
            Result[None, Error]: Ok(None) if revoked, Err if the key is permanent
                                 or not found.

        Examples:
            >>> nal = NodeAccessList()
            >>> key = b"k" * 32
            >>> nal.grant(key, NodeRole.NODE_EXECUTOR)
            >>> nal.revoke(key, NodeRole.NODE_EXECUTOR).is_ok()
            True
            >>> nal.has_role(key, NodeRole.NODE_EXECUTOR)
            False
        """
        if public_key in self._permanent:
            return Result.Err(
                Error.new(
                    ErrorKind.FORBIDDEN,
                    f"Cannot revoke permanent NAL entry {public_key.hex()[:16]}…",
                )
            )
        if public_key not in self._entries:
            return Result.Err(
                Error.new(
                    ErrorKind.NOT_FOUND,
                    f"No NAL entry for key {public_key.hex()[:16]}…",
                )
            )
        if role is None:
            del self._entries[public_key]
        else:
            self._entries[public_key].discard(role)
            if not self._entries[public_key]:
                del self._entries[public_key]
        return Result.Ok(None)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def has_role(self, public_key: bytes, role: NodeRole) -> bool:
        """Return True if the public key holds the specified role.

        Args:
            public_key: Ed25519 public key to check.
            role: The NodeRole to verify.

        Example:
            >>> nal = NodeAccessList()
            >>> nal.grant(b"k" * 32, NodeRole.NODE_EXECUTOR)
            >>> nal.has_role(b"k" * 32, NodeRole.NODE_EXECUTOR)
            True
        """
        roles = self._entries.get(public_key)
        return role in roles if roles else False

    def get_roles(self, public_key: bytes) -> set[NodeRole]:
        """Return all roles held by a public key.

        Args:
            public_key: Ed25519 public key.

        Returns:
            set[NodeRole]: Set of roles (may be empty).

        Example:
            >>> nal = NodeAccessList()
            >>> nal.grant(b"k" * 32, NodeRole.USD_OPERATOR)
            >>> NodeRole.USD_OPERATOR in nal.get_roles(b"k" * 32)
            True
        """
        return set(self._entries.get(public_key, set()))

    def authorize(self, public_key: bytes, role: NodeRole) -> Result[None, Error]:
        """Assert that a public key holds a required role.

        Args:
            public_key: Ed25519 public key of the requestor.
            role: Required NodeRole.

        Returns:
            Result[None, Error]: Ok(None) if authorised, Err if not.

        Examples:
            >>> nal = NodeAccessList()
            >>> key = b"k" * 32
            >>> nal.grant(key, NodeRole.NODE_OPERATOR)
            >>> nal.authorize(key, NodeRole.NODE_OPERATOR).is_ok()
            True
            >>> nal.authorize(key, NodeRole.UCD_OPERATOR).is_err()
            True
        """
        if self.has_role(public_key, role):
            return Result.Ok(None)
        return Result.Err(
            Error.new(
                ErrorKind.FORBIDDEN,
                f"Key {public_key.hex()[:16]}… lacks role {role}",
            )
        )

    def is_permanent(self, public_key: bytes) -> bool:
        """Return True if this key has a permanent NAL entry.

        Example:
            >>> nal = NodeAccessList()
            >>> nal.grant(b"k" * 32, NodeRole.UCD_OPERATOR, permanent=True)
            >>> nal.is_permanent(b"k" * 32)
            True
        """
        return public_key in self._permanent

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"NodeAccessList(entries={len(self._entries)}, permanent={len(self._permanent)})"
