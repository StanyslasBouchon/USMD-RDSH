from dataclasses import dataclass
from enum import Enum


class NCPCommand(Enum):
    GET_STATUS = 0x01
    CHECK_DISTANCE = 0x02
    REQUEST_EMERGENCY = 0x03
    REQUEST_HELP = 0x04
    REQUEST_APPROVAL = 0x05
    SEND_UCD_PROPERTIES = 0x06
    SEND_USD_PROPERTIES = 0x07
    SEND_MUTATION_PROPERTIES = 0x08
    INFORM_REFERENCE_NODE = 0x09


@dataclass
class NCPData:
    command: NCPCommand
    eph_pub32: str
    nonce12: bytes
    salt16: bytes
    ciphertext: bytes
