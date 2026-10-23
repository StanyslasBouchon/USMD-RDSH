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


def _ulid_or_empty(value: str) -> str:
    from usmd_rdsh.node.wire import is_ulid  # pylint: disable=import-outside-toplevel

    if value and not is_ulid(value.upper()):
        raise ValueError("expected a ULID: 26 characters of Crockford base 32")
    return value.upper()


#: USCN, USDN, node ids: ULIDs on the wire [NCP-02 6.1].
Ulid = Annotated[str, AfterValidator(_ulid_or_empty)]


def _label(value: str) -> str:
    from usmd_rdsh.node.ncp.codec import check_label  # pylint: disable=import-outside-toplevel
    from usmd_rdsh.node.wire import WireError  # pylint: disable=import-outside-toplevel

    try:
        check_label(value)
    except WireError as exc:
        raise ValueError(str(exc)) from exc
    return value


#: Readable name of a USC or USD, signed with it [NCP-03 6.8].
Label = Annotated[str, AfterValidator(_label)]


def _generated_ulid(value: str) -> str:
    try:
        return _ulid_or_empty(value)
    except ValueError as exc:
        raise ValueError(f"{exc}. Leave it empty to have one generated, and put a "
                         f"readable name such as '{value}' in 'label'") from exc


#: USCN, USDN: a ULID the authority generates when left empty [ARCH-03 9.1].
GeneratedUlid = Annotated[str, AfterValidator(_generated_ulid)]
#: An IPv4 address, or empty for "not set". The series is IPv4-only [ARCH 3.5].
IPv4 = Annotated[str, AfterValidator(_ipv4_or_empty)]
Port = Annotated[int, AfterValidator(_port)]
