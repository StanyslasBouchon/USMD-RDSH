"""Node role definitions for USMD-RDSH (Node Access List roles).

Each node in the system is assigned one role at creation time.
The role determines which operations the node is authorised to perform
via NCP commands.

Examples:
    >>> role = NodeRole.NODE_EXECUTOR
    >>> role.can_manage_nodes()
    False
    >>> role.can_execute()
    True

    >>> role = NodeRole.UCD_OPERATOR
    >>> role.can_manage_ucd()
    True
"""

from enum import Enum


class NodeRole(Enum):
    """Roles available in the Node Access List (NAL).

    Roles are assigned at node creation and stored permanently in the NAL
    of every node that has accepted the new node.

    Values:
        UCD_OPERATOR: Can manage the Unified Configuration Database (UCD).
        USD_OPERATOR: Can manage a Unified System Domain (USD).
        NODE_OPERATOR: Can manage individual nodes within an USD.
        NODE_EXECUTOR: Can execute basic peer-to-peer recovery operations.

    Examples:
        >>> NodeRole.UCD_OPERATOR.value
        'ucd_operator'
        >>> NodeRole.NODE_EXECUTOR.can_execute()
        True
    """

    UCD_OPERATOR = "ucd_operator"
    USD_OPERATOR = "usd_operator"
    NODE_OPERATOR = "node_operator"
    NODE_EXECUTOR = "node_executor"

    def __str__(self) -> str:
        return self.value

    def can_manage_ucd(self) -> bool:
        """Return True if this role may manage the UCD.

        Example:
            >>> NodeRole.UCD_OPERATOR.can_manage_ucd()
            True
            >>> NodeRole.NODE_EXECUTOR.can_manage_ucd()
            False
        """
        return self == NodeRole.UCD_OPERATOR

    def can_manage_usd(self) -> bool:
        """Return True if this role may manage a USD.

        Example:
            >>> NodeRole.USD_OPERATOR.can_manage_usd()
            True
            >>> NodeRole.UCD_OPERATOR.can_manage_usd()
            False
        """
        return self == NodeRole.USD_OPERATOR

    def can_manage_nodes(self) -> bool:
        """Return True if this role may manage individual nodes.

        Example:
            >>> NodeRole.NODE_OPERATOR.can_manage_nodes()
            True
            >>> NodeRole.NODE_EXECUTOR.can_manage_nodes()
            False
        """
        return self == NodeRole.NODE_OPERATOR

    def can_execute(self) -> bool:
        """Return True if this role may perform basic peer execution tasks.

        Example:
            >>> NodeRole.NODE_EXECUTOR.can_execute()
            True
            >>> NodeRole.NODE_OPERATOR.can_execute()
            False
        """
        return self == NodeRole.NODE_EXECUTOR

    def requires_ucd_key(self) -> bool:
        """Return True if creating a node with this role requires a UCD public key.

        According to the spec, usd_operator, node_operator, and node_executor
        all require the UCD public key at creation.

        Example:
            >>> NodeRole.UCD_OPERATOR.requires_ucd_key()
            False
            >>> NodeRole.USD_OPERATOR.requires_ucd_key()
            True
        """
        return self != NodeRole.UCD_OPERATOR

    def requires_usd_key(self) -> bool:
        """Return True if creating a node with this role requires a USD public key.

        According to the spec, node_operator and node_executor additionally
        require the USD public key.

        Example:
            >>> NodeRole.NODE_OPERATOR.requires_usd_key()
            True
            >>> NodeRole.USD_OPERATOR.requires_usd_key()
            False
        """
        return self in (NodeRole.NODE_OPERATOR, NodeRole.NODE_EXECUTOR)
