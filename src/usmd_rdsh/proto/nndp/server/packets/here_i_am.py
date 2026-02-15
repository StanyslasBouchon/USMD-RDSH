"""HIA packet decoder for NNDP protocol.

This module provides a decoder for the "HIA" packet type in the NNDP
(Network Node Discovery Protocol). The decoder parses incoming UDP packets
containing node discovery information and publishes events when valid packets
are received.

The packet format consists of:
    - Magic number (16 bits): Protocol identifier
    - Version (8 bits): Protocol version
    - Node name length (16 bits): Length of the node name in bytes
    - Node name (variable): UTF-8 encoded node identifier
    - Next HIA packet time (64 bits): Timestamp for next packet in milliseconds
    - State (16 bits): Current node state (e.g., ACTIVE, INACTIVE)

Examples:
    Basic usage:
    >>> from usmd_rdsh.proto.base.bitvec import BitVec, Msb
    >>> from usmd_rdsh.proto.base.decoder import BitDecoder, FrameDecoder
    >>> from usmd_rdsh.proto.base.env import PROTO_MAGIC
    >>>
    >>> # Create a frame decoder with packet data
    >>> frame_decoder = FrameDecoder[Msb](BitVec.from_bytes(packet_bytes, Msb))
    >>> decoder = HereIAmDecoder(frame_decoder.get_decoder())
    >>>
    >>> # Decode the packet
    >>> frame = frame_decoder.get_frame()
    >>> result = decoder.decode(frame)
    >>>
    >>> # If successful, a HereIAmReceivedEvent will be published to EVENT_BUS
    >>> if result.is_ok():
    ...     print("Packet decoded successfully")
"""

from typing import Any
from usmd_rdsh.managers.event import EVENT_BUS
from usmd_rdsh.proto.base.bitvec import Msb
from usmd_rdsh.proto.base.decoder import BitDecoder, Frame
from usmd_rdsh.proto.base.event import EventDecoder
from usmd_rdsh.proto.base.env import PROTO_MAGIC
from usmd_rdsh.proto.nndp.base.env import HereIAmData
from usmd_rdsh.proto.nndp.server.events.here_i_am import HereIAmReceivedEvent
from usmd_rdsh.utils.errors import Error, ErrorKind
from usmd_rdsh.utils.node_state import NodeState
from usmd_rdsh.utils.result import Result


class HereIAmDecoder(EventDecoder[Msb]):
    """Decoder for "HIA" packets in the NNDP protocol.

    This decoder parses incoming "HIA" packets from the network and
    extracts node discovery information. Upon successful decoding, it publishes
    a HereIAmReceivedEvent to the global event bus, allowing other components
    to react to node discovery events.

    The decoder expects packets in MSB (Most Significant Bit) first ordering
    and validates the magic number before processing the packet data.

    Attributes:
        decoder (BitDecoder[Msb]): The bit decoder used to read packet data

    Examples:
        >>> from usmd_rdsh.proto.base.decoder import BitDecoder, FrameDecoder
        >>> from usmd_rdsh.proto.base.bitvec import BitVec, Msb
        >>>
        >>> # Create decoder from packet bytes
        >>> frame_decoder = FrameDecoder[Msb](BitVec.from_bytes(packet_bytes, Msb))
        >>> decoder = HereIAmDecoder(frame_decoder.get_decoder())
        >>>
        >>> # Decode the packet
        >>> frame = frame_decoder.get_frame()
        >>> result = decoder.decode(frame)
        >>>
        >>> if result.is_ok():
        ...     print("Node discovered successfully")
    """

    def __init__(self, decoder: BitDecoder[Msb]) -> None:
        """Initialize the HIA decoder.

        Args:
            decoder: The bit decoder instance used to read packet data from
                the frame. The decoder must be configured for MSB-first bit
                ordering.

        Examples:
            >>> from usmd_rdsh.proto.base.decoder import BitDecoder, FrameDecoder
            >>> from usmd_rdsh.proto.base.bitvec import BitVec, Msb
            >>>
            >>> frame_decoder = FrameDecoder[Msb](BitVec.from_bytes(data, Msb))
            >>> decoder = HereIAmDecoder(frame_decoder.get_decoder())
        """
        self.decoder = decoder

    def decode(self, *args: Any, frame: Frame[Msb]) -> Result[None, Error]:
        """Decode a "HIA" packet from the frame.

        This method reads the packet structure from the frame, validates the
        magic number, extracts all fields, and publishes a HereIAmReceivedEvent
        to the global event bus upon successful decoding.

        The packet structure is:
            - Magic number (16 bits): Must match the protocol magic number
            - Version (8 bits): Protocol version number
            - Node name length (16 bits): Length of the node name in bytes
            - Node name (variable): UTF-8 encoded node identifier
            - Next HIA packet time (64 bits): Timestamp in milliseconds
            - State (16 bits): Node state enumeration value

        Args:
            *args: Additional arguments to the decoder
            frame: The frame containing the packet data to decode. The frame
                must be in MSB-first bit ordering.

        Returns:
            Result[None, Error]: Ok(None) if decoding was successful and the
                event was published, or Err(Error) if decoding failed (invalid
                magic number, read errors, etc.).

        Examples:
            >>> from usmd_rdsh.proto.base.decoder import FrameDecoder
            >>> from usmd_rdsh.proto.base.bitvec import BitVec, Msb
            >>>
            >>> # Assume packet_bytes contains a valid "HIA" packet
            >>> frame_decoder = FrameDecoder[Msb](BitVec.from_bytes(packet_bytes, Msb))
            >>> decoder = HereIAmDecoder(frame_decoder.get_decoder())
            >>>
            >>> result = decoder.decode(None, frame_decoder.get_frame())
            >>> if result.is_ok():
            ...     # Event has been published to EVENT_BUS
            ...     print("Packet decoded and event published")
            >>> else:
            ...     print(f"Decoding failed: {result.unwrap_err()}")
        """
        Result.hide()

        if len(args) != 2:
            return Result.Err(Error.new(ErrorKind.BAD_REQUEST, "Invalid arguments"))

        pub32 = args[0]
        ip = args[1]

        magic = self.decoder.read_data(16)
        if magic.is_err():
            return Result.Err(magic.unwrap_err())

        if magic.unwrap().to_int().unwrap() != PROTO_MAGIC:
            return Result.Err(
                Error.new(ErrorKind.PROTOCOL_ERROR, "Invalid magic number")
            )

        version = self.decoder.read_data(8)
        node_id_length = self.decoder.read_data(16)
        if node_id_length.is_err():
            return Result.Err(node_id_length.unwrap_err())

        node_id_bytes = self.decoder.read_bytes(
            node_id_length.unwrap().to_int().unwrap()
        )
        if node_id_bytes.is_err():
            return Result.Err(node_id_bytes.unwrap_err())

        next_hia_pkt_time = self.decoder.read_data(64)
        if next_hia_pkt_time.is_err():
            return Result.Err(next_hia_pkt_time.unwrap_err())

        state = self.decoder.read_data(16)
        if state.is_err():
            return Result.Err(state.unwrap_err())

        # Convert BitVec to bytes then to string
        node_id_str = node_id_bytes.unwrap().to_bytes().decode("utf-8")

        data = HereIAmData(
            ed25519_pub32=pub32,
            ip=ip,
            version=version.unwrap().to_int().unwrap(),
            node_id=node_id_str,
            next_hia_pkt_time=next_hia_pkt_time.unwrap().to_int().unwrap(),
            state=NodeState(state.unwrap().to_int().unwrap()),
        )
        EVENT_BUS.publish(HereIAmReceivedEvent(data))

        return Result.reveal()
