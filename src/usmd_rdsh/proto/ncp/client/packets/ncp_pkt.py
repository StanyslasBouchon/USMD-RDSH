"""HIA packet encoder for NNDP protocol.

This module provides an encoder for the "HIA" packet type in the NNDP
(Network Node Discovery Protocol). The encoder creates binary packet data from
HereIAmData structures, which are used by nodes to announce their presence on
the network.

The packet format consists of:
    - Magic number (16 bits): Protocol identifier (PROTO_MAGIC)
    - Version (8 bits): Protocol version number
    - Node ID length (16 bits): Length of the node ID in bytes
    - Node ID (variable): UTF-8 encoded node identifier
    - Next HIA packet time (64 bits): Timestamp for next packet in milliseconds
    - State (16 bits): Current node state enumeration value

Example usage:

    >>> from usmd_rdsh.proto.nndp.client.packets.here_i_am import HereIAmPacket
    >>> from usmd_rdsh.proto.base.env import HereIAmData, NNDP_VERSION
    >>> from usmd_rdsh.utils.node_state import NodeState
    >>> import time
    >>>
    >>> # Create packet data
    >>> data = HereIAmData(
    ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ...     ed25519_pub32=b"\\x00" * 32,
    ...     ip="192.168.1.100",
    ...     next_hia_pkt_time=int((time.time() + 15.0) * 1000),
    ...     state=NodeState.ACTIVE,
    ... )
    >>>
    >>> # Create and encode the packet
    >>> packet = HereIAmPacket(data)
    >>> result = packet.encode()
    >>> if result.is_ok():
    ...     encoder = packet.get_encoder()
    ...     bitvec = encoder.encode()
    ...     packet_bytes = bitvec.to_bytes()
    ...     print(f"Encoded packet: {len(packet_bytes)} bytes")
"""

from usmd_rdsh.proto.base.bitvec import Msb
from usmd_rdsh.proto.base.encoder import BitEncoder
from usmd_rdsh.proto.base.event import EventEncoder
from usmd_rdsh.proto.base.env import PROTO_MAGIC
from usmd_rdsh.proto.ncp.base.env import NCPData
from usmd_rdsh.utils.errors import Error, ErrorKind
from usmd_rdsh.utils.result import Result


class NCPPacket(EventEncoder[Msb]):
    """Encoder for NNDP "HIA" announcement packets.

    This class implements the EventEncoder interface to encode "HIA"
    packets for the NNDP protocol. It converts HereIAmData structures into
    binary packet data using MSB (Most Significant Bit) first bit ordering.

    The encoded packet structure follows this format:
        [Magic(16)] [Version(8)] [NodeIDLen(16)] [NodeID(var)] [NextTime(64)] [State(16)]

    Attributes:
        encoder: BitEncoder instance used to build the packet data
        data: HereIAmData instance containing the packet payload

    Example:
        >>> from usmd_rdsh.proto.nndp.client.packets.here_i_am import HereIAmPacket
        >>> from usmd_rdsh.proto.base.env import HereIAmData, NNDP_VERSION
        >>> from usmd_rdsh.utils.node_state import NodeState
        >>> import time
        >>>
        >>> # Create packet data
        >>> data = HereIAmData(
        ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ...     ed25519_pub32=b"\\x00" * 32,
        ...     ip="127.0.0.1",
        ...     next_hia_pkt_time=int((time.time() + 15.0) * 1000),
        ...     state=NodeState.ACTIVE,
        ... )
        >>>
        >>> # Create packet encoder
        >>> packet = HereIAmPacket(data)
        >>> assert packet.data == data
        >>> assert packet.get_event() == 0x0001
        >>>
        >>> # Encode the packet
        >>> result = packet.encode()
        >>> assert result.is_ok()
        >>> encoder = packet.get_encoder()
        >>> assert encoder is not None
    """

    def __init__(self, data: NCPData):
        """Initialize the HIA packet encoder.

        Args:
            data: HereIAmData instance containing the node information to encode

        Example:
            >>> from usmd_rdsh.proto.nndp.client.packets.here_i_am import HereIAmPacket
            >>> from usmd_rdsh.proto.base.env import HereIAmData, NNDP_VERSION
            >>> from usmd_rdsh.utils.node_state import NodeState
            >>> import time
            >>>
            >>> data = HereIAmData(
            ...     node_id="test-node-123",
            ...     ed25519_pub32=b"\\x00" * 32,
            ...     ip="192.168.1.1",
            ...     next_hia_pkt_time=int(time.time() * 1000),
            ...     state=NodeState.ACTIVE,
            ... )
            >>> packet = HereIAmPacket(data)
            >>> assert packet.data == data
        """
        super().__init__()

        self.encoder = BitEncoder[Msb]()
        self.data = data

    def encode(self) -> Result[None, Error]:
        """Encode the HIA packet data into binary format.

        This method encodes the HereIAmData structure into a binary packet
        following the NNDP protocol format. It validates the node ID length
        (must not exceed 65535 bytes) and encodes all fields in the correct
        order with appropriate bit sizes.

        The encoding process:
            1. Validates node ID length (max 65535 bytes)
            2. Encodes magic number (16 bits)
            3. Encodes protocol version (8 bits)
            4. Encodes node ID length (16 bits)
            5. Encodes node ID as UTF-8 bytes (variable length)
            6. Encodes next packet time (64 bits)
            7. Encodes node state (16 bits)

        Returns:
            Result[None, Error]: Ok(None) if encoding was successful, or
                Err(Error) if the node ID is too long or encoding fails.

        Example:
            >>> from usmd_rdsh.proto.nndp.client.packets.here_i_am import HereIAmPacket
            >>> from usmd_rdsh.proto.base.env import HereIAmData, NNDP_VERSION
            >>> from usmd_rdsh.utils.node_state import NodeState
            >>> import time
            >>>
            >>> # Valid packet
            >>> data = HereIAmData(
            ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            ...     ed25519_pub32=b"\\x00" * 32,
            ...     ip="127.0.0.1",
            ...     next_hia_pkt_time=int((time.time() + 15.0) * 1000),
            ...     state=NodeState.ACTIVE,
            ... )
            >>> packet = HereIAmPacket(data)
            >>> result = packet.encode()
            >>> assert result.is_ok()
            >>>
            >>> # Invalid packet (node ID too long)
            >>> long_node_id = "x" * (65536)  # Exceeds 16-bit limit
            >>> invalid_data = HereIAmData(
            ...     node_id=long_node_id,
            ...     ed25519_pub32=b"\\x00" * 32,
            ...     ip="127.0.0.1",
            ...     next_hia_pkt_time=int(time.time() * 1000),
            ...     state=NodeState.ACTIVE,
            ... )
            >>> invalid_packet = HereIAmPacket(invalid_data)
            >>> result = invalid_packet.encode()
            >>> assert result.is_err()
            >>> assert "too long" in str(result.unwrap_err())
        """
        Result.hide()

        if len(self.data.node_id) > 1 << 16:
            return Result.Err(
                Error.new(ErrorKind.SIZE_CONSTRAINT_VIOLATION, "Node ID is too long")
            )

        self.encoder.add_data(PROTO_MAGIC, 16)
        self.encoder.add_data(self.data.version, 8)
        self.encoder.add_data(len(self.data.node_id), 16)
        self.encoder.add_bytes(self.data.node_id.encode("utf-8"))
        self.encoder.add_data(self.data.next_hia_pkt_time, 64)
        self.encoder.add_data(self.data.state.value, 16)

        return Result.reveal()

    def get_encoder(self) -> BitEncoder[Msb]:
        """Get the BitEncoder instance used for encoding.

        Returns:
            BitEncoder[Msb]: The encoder instance containing the encoded packet data

        Example:
            >>> from usmd_rdsh.proto.nndp.client.packets.here_i_am import HereIAmPacket
            >>> from usmd_rdsh.proto.base.env import HereIAmData, NNDP_VERSION
            >>> from usmd_rdsh.utils.node_state import NodeState
            >>> import time
            >>>
            >>> data = HereIAmData(
            ...     node_id="test-node",
            ...     ed25519_pub32=b"\\x00" * 32,
            ...     ip="127.0.0.1",
            ...     next_hia_pkt_time=int(time.time() * 1000),
            ...     state=NodeState.ACTIVE,
            ... )
            >>> packet = HereIAmPacket(data)
            >>> packet.encode()
            >>> encoder = packet.get_encoder()
            >>> bitvec = encoder.encode()
            >>> packet_bytes = bitvec.to_bytes()
            >>> assert len(packet_bytes) > 0
        """
        return self.encoder

    def get_event(self) -> int:
        """Get the event ID for the HIA packet.

        Returns:
            int: The event ID (0x0001) that identifies this packet type

        Example:
            >>> from usmd_rdsh.proto.nndp.client.packets.here_i_am import HereIAmPacket
            >>> from usmd_rdsh.proto.base.env import HereIAmData, NNDP_VERSION
            >>> from usmd_rdsh.utils.node_state import NodeState
            >>> import time
            >>>
            >>> data = HereIAmData(
            ...     node_id="test-node",
            ...     ed25519_pub32=b"\\x00" * 32,
            ...     ip="127.0.0.1",
            ...     next_hia_pkt_time=int(time.time() * 1000),
            ...     state=NodeState.ACTIVE,
            ... )
            >>> packet = HereIAmPacket(data)
            >>> assert packet.get_event() == 0x0001
        """
        return 0x0001
