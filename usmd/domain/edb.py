"""Easy Deployment Base (EDB) client for USMD-RDSH.

The EDB is an optional external HTTP/DNS server that lists all active node
addresses for a given USD. A newly joining node uses the EDB when no other
node is reachable on its local network (i.e. NNDP returns nothing).

EDB file format (one entry per line):
    <NodeName>: <IPv4_or_IPv6>

Example EDB file::

    Node1: 172.23.45.96
    Node1: 172.23.45.97
    Node3: 172.22.5.7

Examples:
    >>> entries = EdbParser.parse("Node1: 10.0.0.1\\nNode2: 10.0.0.2\\n")
    >>> len(entries)
    2
    >>> entries[0].name
    'Node1'
    >>> entries[0].address
    '10.0.0.1'
"""

import logging
from dataclasses import dataclass

from ..utils.errors import Error, ErrorKind
from ..utils.result import Result


@dataclass
class EdbEntry:
    """A single entry from an EDB file.

    Attributes:
        name: Human-readable label (not the UNIX timestamp name — may be any string).
        address: IPv4 or IPv6 address.

    Examples:
        >>> entry = EdbEntry(name="Node1", address="10.0.0.5")
        >>> entry.name
        'Node1'
    """

    name: str
    address: str


class EdbParser:
    """Parser for EDB (Easy Deployment Base) text files.

    The EDB format is a simple line-based key-value file:
        ``<name>: <address>``

    Blank lines and lines starting with ``#`` are ignored.

    Examples:
        >>> content = "Node1: 10.0.0.1\\nNode2: 10.0.0.2\\n"
        >>> entries = EdbParser.parse(content)
        >>> len(entries)
        2
        >>> entries[0].address
        '10.0.0.1'
    """

    @staticmethod
    def parse(content: str) -> list[EdbEntry]:
        """Parse EDB file content into a list of EdbEntry objects.

        Args:
            content: Raw text content of the EDB file.

        Returns:
            list[EdbEntry]: All valid entries found in the content.

        Examples:
            >>> EdbParser.parse("N1: 1.2.3.4\\n# comment\\nN2: 5.6.7.8\\n")
            [EdbEntry(name='N1', address='1.2.3.4'), EdbEntry(name='N2', address='5.6.7.8')]
        """
        entries: list[EdbEntry] = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if ":" not in stripped:
                logging.warning(
                    "[\x1b[38;5;51mUSMD\x1b[0m] EDB: malformed line %r (skipped)",
                    stripped,
                )
                continue
            name_part, _, addr_part = stripped.partition(":")
            entries.append(
                EdbEntry(
                    name=name_part.strip(),
                    address=addr_part.strip(),
                )
            )
        return entries

    @staticmethod
    def parse_result(content: str) -> Result[list[EdbEntry], Error]:
        """Parse EDB content and return a Result.

        Returns Err only if the content is completely empty or all lines are
        malformed (no valid entry could be extracted).

        Args:
            content: Raw text content.

        Returns:
            Result[list[EdbEntry], Error]: Ok with entries, or Err if empty.

        Example:
            >>> EdbParser.parse_result("").is_err()
            True
            >>> EdbParser.parse_result("N1: 10.0.0.1").is_ok()
            True
        """
        entries = EdbParser.parse(content)
        if not entries:
            return Result.Err(
                Error.new(ErrorKind.EDB_UNREACHABLE, "No valid EDB entries found in content")
            )
        return Result.Ok(entries)
