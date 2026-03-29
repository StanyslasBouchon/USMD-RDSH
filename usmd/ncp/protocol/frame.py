"""NCP frame framing — serialisation and deserialisation of NCP packets.

Every NCP packet has the following binary layout:

.. code-block:: text

    [Version: 4 bytes] [CommandID: 1 byte] [PayloadLen: 4 bytes] [Payload: N bytes]

Total header = 9 bytes.

The payload is AEAD-encrypted (ChaCha20-Poly1305) once a session key has been
established. During the bootstrapping phase (approval request) the payload is
sent plaintext signed with Ed25519.

Examples:
    >>> frame = NcpFrame(
    ...     version=NcpVersion(1, 0, 0, 0),
    ...     command_id=NcpCommandId.GET_STATUS,
    ...     payload=b"hello",
    ... )
    >>> raw = frame.to_bytes()
    >>> parsed = NcpFrame.from_bytes(raw).unwrap()
    >>> parsed.command_id == NcpCommandId.GET_STATUS
    True
    >>> parsed.payload
    b'hello'
"""

import struct
from dataclasses import dataclass, field
from enum import IntEnum

from ...utils.errors import Error, ErrorKind
from ...utils.result import Result
from .versions import NcpVersion

# Header format: 4 bytes version + 1 byte command + 4 bytes payload length
_HEADER_FORMAT = "!4sBL"  # network (big-endian), 4s=4 bytes, B=uint8, L=uint32
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)  # 9 bytes


class NcpCommandId(IntEnum):
    """NCP command identifiers (0-indexed, per the spec).

    Commands:
        GET_STATUS (0): Query a node's current status and resource usage.
        CHECK_DISTANCE (1): Compute the distance score to another node.
        REQUEST_EMERGENCY (2): Notify reference nodes of a failure.
        REQUEST_HELP (3): Ask reference nodes for assistance.
        REQUEST_APPROVAL (4): Request admission into the USD.
        SEND_UCD_PROPERTIES (5): Propagate UCD configuration to reference nodes.
        SEND_USD_PROPERTIES (6): Propagate USD configuration to reference nodes.
        SEND_MUTATION_PROPERTIES (7): Propagate mutation definitions.
        INFORM_REFERENCE_NODE (8): Notify reference nodes of one's peer list.
        REQUEST_SNAPSHOT (9): Request a full JSON status snapshot (NIT, NAL, NEL, resources).
        REQUEST_VOTE (10): Quorum election — candidate solicits a vote from a peer.
        ANNOUNCE_PROMOTION (11): Quorum election — winner announces new operator role.
        GET_NQT (12): Request the peer's full Node Quorum Table for synchronisation.
        REVOKE_ENDORSEMENT (13): Departing node notifies its endorsed peers / endorser.

    Examples:
        >>> NcpCommandId.GET_STATUS.value
        0
        >>> NcpCommandId(4)
        <NcpCommandId.REQUEST_APPROVAL: 4>
    """

    GET_STATUS = 0
    CHECK_DISTANCE = 1
    REQUEST_EMERGENCY = 2
    REQUEST_HELP = 3
    REQUEST_APPROVAL = 4
    SEND_UCD_PROPERTIES = 5
    SEND_USD_PROPERTIES = 6
    SEND_MUTATION_PROPERTIES = 7
    INFORM_REFERENCE_NODE = 8
    REQUEST_SNAPSHOT = 9
    REQUEST_VOTE = 10
    ANNOUNCE_PROMOTION = 11
    GET_NQT = 12
    REVOKE_ENDORSEMENT = 13


@dataclass
class NcpFrame:
    """A complete NCP protocol frame ready for transmission.

    Attributes:
        version: 4-byte NCP version of the sender.
        command_id: The NCP command this frame carries.
        payload: Raw (possibly encrypted) payload bytes.

    Examples:
        >>> frame = NcpFrame(NcpVersion(1,0,0,0), NcpCommandId.GET_STATUS, b"")
        >>> raw = frame.to_bytes()
        >>> len(raw)
        9
    """

    version: NcpVersion
    command_id: NcpCommandId
    payload: bytes = field(default_factory=bytes)

    def to_bytes(self) -> bytes:
        """Serialise the frame to bytes for network transmission.

        Returns:
            bytes: Serialised frame (header + payload).

        Example:
            >>> frame = NcpFrame(NcpVersion(1,0,0,0), NcpCommandId.CHECK_DISTANCE, b"ts")
            >>> raw = frame.to_bytes()
            >>> len(raw)
            11
        """
        header = struct.pack(
            _HEADER_FORMAT,
            self.version.to_bytes(),
            int(self.command_id),
            len(self.payload),
        )
        return header + self.payload

    @staticmethod
    def from_bytes(data: bytes) -> Result["NcpFrame", Error]:
        """Deserialise a frame from raw bytes.

        Args:
            data: Raw bytes received from the network.

        Returns:
            Result[NcpFrame, Error]: Ok with the parsed frame, or Err on malformed input.

        Examples:
            >>> frame = NcpFrame(NcpVersion(1,0,0,0), NcpCommandId.GET_STATUS, b"p")
            >>> NcpFrame.from_bytes(frame.to_bytes()).is_ok()
            True
        """
        if len(data) < _HEADER_SIZE:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"Frame too short: {len(data)} bytes, need at least {_HEADER_SIZE}",
                )
            )

        ver_bytes, cmd_byte, payload_len = struct.unpack_from(_HEADER_FORMAT, data)

        version_result = NcpVersion.from_bytes(ver_bytes)
        if version_result.is_err():
            return Result.Err(version_result.unwrap_err())

        try:
            cmd = NcpCommandId(cmd_byte)
        except ValueError:
            return Result.Err(
                Error.new(
                    ErrorKind.INVALID_COMMAND, f"Unknown NCP command ID: {cmd_byte}"
                )
            )

        expected_total = _HEADER_SIZE + payload_len
        if len(data) < expected_total:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"Frame payload truncated: got {len(data) - _HEADER_SIZE} bytes, "
                    f"expected {payload_len}",
                )
            )

        payload = data[_HEADER_SIZE : _HEADER_SIZE + payload_len]

        return Result.Ok(
            NcpFrame(
                version=version_result.unwrap(),
                command_id=cmd,
                payload=payload,
            )
        )
