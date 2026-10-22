"""NCP protocol version management.

The NCP version is encoded on **4 bytes**:

+---------+--------------------------------------------------+
| Byte    | Meaning                                          |
+=========+==================================================+
| 0       | Major version — removes features, breaking change|
| 1       | Minor version — adds features                    |
| 2       | Patch version — security fixes                   |
| 3       | Bug-fix version — bug corrections                |
+---------+--------------------------------------------------+

When a major version is released, bytes 1 to 3 are reset to 0.
Each non-major release increments the appropriate byte.

Examples:
    >>> v = NcpVersion(major=1, minor=0, patch=0, bugfix=0)
    >>> bytes(v)
    b'\\x01\\x00\\x00\\x00'
    >>> v2 = NcpVersion.from_bytes(b'\\x01\\x02\\x00\\x03')
    >>> v2.minor
    2
    >>> str(v2)
    '1.2.0.3'
"""

from dataclasses import dataclass

from ...utils.errors import Error, ErrorKind
from ...utils.result import Result

CURRENT_MAJOR = 1
CURRENT_MINOR = 0
CURRENT_PATCH = 0
CURRENT_BUGFIX = 0


@dataclass(frozen=True)
class NcpVersion:
    """Immutable 4-byte NCP protocol version.

    Attributes:
        major: Breaking-change version counter.
        minor: Additive-feature version counter.
        patch: Security-fix version counter.
        bugfix: Bug-fix version counter.

    Examples:
        >>> v = NcpVersion(1, 0, 0, 0)
        >>> str(v)
        '1.0.0.0'
        >>> v.to_bytes()
        b'\\x01\\x00\\x00\\x00'
    """

    major: int
    minor: int
    patch: int
    bugfix: int

    def to_bytes(self) -> bytes:
        """Serialise to 4 bytes (big-endian order).

        Returns:
            bytes: 4-byte version representation.

        Example:
            >>> NcpVersion(1, 2, 3, 4).to_bytes()
            b'\\x01\\x02\\x03\\x04'
        """
        return bytes([self.major, self.minor, self.patch, self.bugfix])

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}.{self.bugfix}"

    def is_compatible_with(self, other: "NcpVersion") -> bool:
        """Return True if both versions share the same major number.

        Nodes with different major versions cannot communicate.

        Args:
            other: The remote version to compare against.

        Example:
            >>> NcpVersion(1, 0, 0, 0).is_compatible_with(NcpVersion(1, 2, 0, 0))
            True
            >>> NcpVersion(1, 0, 0, 0).is_compatible_with(NcpVersion(2, 0, 0, 0))
            False
        """
        return self.major == other.major

    @staticmethod
    def from_bytes(data: bytes) -> Result["NcpVersion", Error]:
        """Deserialise a version from exactly 4 bytes.

        Args:
            data: Exactly 4 bytes.

        Returns:
            Result[NcpVersion, Error]: Ok with the version, or Err if malformed.

        Example:
            >>> NcpVersion.from_bytes(b'\\x01\\x00\\x00\\x00').unwrap()
            NcpVersion(major=1, minor=0, patch=0, bugfix=0)
        """
        if len(data) < 4:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"NCP version needs 4 bytes, got {len(data)}",
                )
            )
        return Result.Ok(NcpVersion(data[0], data[1], data[2], data[3]))

    @staticmethod
    def current() -> "NcpVersion":
        """Return the current NCP protocol version implemented by this library.

        Example:
            >>> v = NcpVersion.current()
            >>> v.major
            1
        """
        return NcpVersion(CURRENT_MAJOR, CURRENT_MINOR, CURRENT_PATCH, CURRENT_BUGFIX)
