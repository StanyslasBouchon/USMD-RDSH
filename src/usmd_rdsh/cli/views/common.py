"""Types shared by several configuration nodes."""

import ipaddress
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator

from usmd_rdsh.cli.logbuffer import Severity
from usmd_rdsh.cli.permissions import READ, WRITE

#: Every node: changing it needs WRITE, reading it needs READ.
NODE_ACCESS = {"permissions": [WRITE], "read_permissions": [READ]}

#: Syslog severity keywords, offered by completion.
LogLevel = StrEnum("LogLevel", {s.keyword.upper(): s.keyword for s in Severity})


class Role(StrEnum):
    """NAL roles [USMD-NCP] section 7.3, spelled as the console types them."""

    USC_OPERATOR = "usc-operator"
    USD_OPERATOR = "usd-operator"
    NODE_OPERATOR = "node-operator"
    NODE_EXECUTOR = "node-executor"


def _ipv4_or_empty(value: str) -> str:
    if value:
        ipaddress.IPv4Address(value)
    return value


def _port(value: int) -> int:
    if not 1 <= value <= 65535:
        raise ValueError("a UDP/TCP port is between 1 and 65535")
    return value


#: An IPv4 address, or empty for "not set". The series is IPv4-only [ARCH 3.5].
IPv4 = Annotated[str, AfterValidator(_ipv4_or_empty)]
Port = Annotated[int, AfterValidator(_port)]
