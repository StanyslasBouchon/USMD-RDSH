"""Shared helpers for versioned-config update logic.

Both UnifiedSystemCluster and UnifiedSystemDomain use an identical
version-guarded config replacement pattern.  This module extracts the
logging call so the body of each ``update_config`` method remains a
single conditional assignment.

Examples:
    >>> log_config_update("USD", "my-domain", 1, 2)
"""

import logging


def log_config_update(label: str, name: str, old_version: int, new_version: int) -> None:
    """Log a versioned configuration update event.

    Args:
        label: Short domain-type identifier, e.g. ``"USD"`` or ``"USC"``.
        name: Domain or cluster name for display.
        old_version: Previous configuration version number.
        new_version: New (applied) configuration version number.

    Example:
        >>> log_config_update("USD", "prod", 3, 4)
    """
    logging.info(
        "[\x1b[38;5;51mUSMD\x1b[0m] %s %s config updated v%d\u2192v%d",
        label,
        name,
        old_version,
        new_version,
    )
