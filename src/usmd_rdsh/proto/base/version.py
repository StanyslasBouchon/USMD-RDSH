"""Protocol version management module.

This module provides version enumeration and management for the USMD-RDSH protocol.
It defines the Version enum that represents different protocol versions and
provides utilities for version conversion and validation.

The Version enum supports both integer and string-based version identifiers,
allowing flexible version specification throughout the protocol implementation.

Example usage:

    >>> from usmd_rdsh.proto.base.version import Version
    >>>
    >>> # Access version by enum member
    >>> version = Version.V1
    >>> version.value
    1
    >>>
    >>> # Create version from string
    >>> version = Version('V1')
    >>> version == Version.V1
    True
    >>>
    >>> # Check version value
    >>> Version.V1.value == 1
    True
"""

from enum import Enum
from typing import Union


class Version(Enum):
    """Protocol version enumeration.

    This enum represents the different versions of the protocol.
    The value of each version is automatically converted from 'VX' to integer X.

    Examples:
        >>> Version.V1.value
        1
        >>> Version.V1.name
        'V1'
        >>> str(Version.V1)
        'V1'
    """

    V1 = 1  # Protocol version 1

    @classmethod
    def _missing_(cls, value: object) -> Union["Version", None]:
        """Allows creation of Version from string 'VX'.

        Args:
            value (object): Value to convert to Version enum

        Returns:
            Union[Version, None]: The corresponding Version enum value, or None
                if conversion fails

        Examples:
            >>> Version('V1') == Version.V1
            True
        """
        if isinstance(value, str) and value.startswith("V"):
            try:
                version_num = int(value[1:])
                for member in cls:
                    if member.value == version_num:
                        return member
            except ValueError:
                pass
        return None
