"""Node state enumeration for USMD-RDSH.

A node's state reflects its current lifecycle position within its USD.
States are updated by NCP messages and local health checks.

Examples:
    >>> state = NodeState.ACTIVE
    >>> state.is_active()
    True
    >>> state.is_inactive()
    False

    >>> state = NodeState.INACTIVE_EMERGENCY_HEALTH_CHECK
    >>> state.is_inactive()
    True
    >>> state.requires_emergency()
    True
"""

from enum import Enum


class NodeState(Enum):
    """All possible states of a node within its USD.

    States fall into four top-level categories:
        - Pending: The node is waiting to be approved by an existing node.
        - Synchronising: The node is receiving initial domain data.
        - Active: The node is fully operational.
        - Inactive: The node is not currently serving its mutation.
        - Excluded: The node has been permanently banned due to security violations.

    Examples:
        >>> NodeState.ACTIVE.value
        'active'
        >>> NodeState.EXCLUDED_INVALID_NIT.is_excluded()
        True
    """

    # --- Healthy states ---
    PENDING_APPROVAL = "pending_approval"
    SYNCHRONISING = "synchronising"
    ACTIVE = "active"

    # --- Simple inactive states ---
    INACTIVE = "inactive"
    INACTIVE_MUTATING = "inactive_mutating"
    INACTIVE_TIMEOUT = "inactive_timeout"

    # --- Inactive with emergency ---
    INACTIVE_EMERGENCY = "inactive_emergency"
    INACTIVE_EMERGENCY_OUT_OF_RESOURCES = "inactive_emergency_out_of_resources"
    INACTIVE_EMERGENCY_DEPENDENCY_INACTIVE = "inactive_emergency_dependency_inactive"
    INACTIVE_EMERGENCY_HEALTH_CHECK_FAILED = "inactive_emergency_health_check_failed"
    INACTIVE_EMERGENCY_UPDATE_FAILED = "inactive_emergency_update_failed"

    # --- NNDP-related inactive ---
    INACTIVE_NNDP_NO_HIA = "inactive_nndp_no_here_i_am"

    # --- Excluded states (permanent bans) ---
    EXCLUDED_INVALID_NIT = "excluded_invalid_nit"
    EXCLUDED_INVALID_ENDORSEMENT = "excluded_invalid_endorsement"
    EXCLUDED_UNVERIFIABLE_ENDORSEMENT = "excluded_unverifiable_endorsement"
    EXCLUDED_INVALID_REVOCATION = "excluded_invalid_revocation"
    EXCLUDED_INVALID_ENDORSEMENT_REVOCATION = "excluded_invalid_endorsement_revocation"

    def __str__(self) -> str:
        return self.value

    def is_active(self) -> bool:
        """Return True if the node is fully operational.

        Example:
            >>> NodeState.ACTIVE.is_active()
            True
            >>> NodeState.INACTIVE.is_active()
            False
        """
        return self == NodeState.ACTIVE

    def is_pending(self) -> bool:
        """Return True if the node is awaiting approval or synchronisation.

        Example:
            >>> NodeState.PENDING_APPROVAL.is_pending()
            True
            >>> NodeState.SYNCHRONISING.is_pending()
            True
        """
        return self in (NodeState.PENDING_APPROVAL, NodeState.SYNCHRONISING)

    def is_inactive(self) -> bool:
        """Return True if the node is inactive (any inactive variant).

        Example:
            >>> NodeState.INACTIVE.is_inactive()
            True
            >>> NodeState.INACTIVE_EMERGENCY.is_inactive()
            True
            >>> NodeState.ACTIVE.is_inactive()
            False
        """
        return self.value.startswith("inactive")

    def is_excluded(self) -> bool:
        """Return True if the node has been permanently excluded.

        Example:
            >>> NodeState.EXCLUDED_INVALID_NIT.is_excluded()
            True
            >>> NodeState.ACTIVE.is_excluded()
            False
        """
        return self.value.startswith("excluded")

    def requires_emergency(self) -> bool:
        """Return True if this inactive state has triggered an emergency request.

        Example:
            >>> NodeState.INACTIVE_EMERGENCY.requires_emergency()
            True
            >>> NodeState.INACTIVE.requires_emergency()
            False
        """
        return self.value.startswith("inactive_emergency")
