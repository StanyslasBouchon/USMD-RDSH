"""Bit-level encoder module for building protocol frames.

This module provides encoders for building binary data at the bit level within
the USMD-RDSH protocol. It includes low-level bit manipulation capabilities and
high-level frame structure encoding.

The module exposes two main classes:

    - BitEncoder: Generic encoder that builds frames of bits incrementally.
      Provides methods for adding individual bits, integers, bytes, and bit
      vectors. Supports frame size validation and bit reversal operations.

    - FrameEncoder: High-level encoder that builds complete protocol frames.
      Handles encoding of protocol-specific frame structures including version
      (8 bits), event ID (16 bits), data size (32 bits), payload data, and
      automatic padding to byte boundaries.

All encoders use generic type parameters to support different bit ordering
schemes (MSB-first or LSB-first) and return Result types for explicit error
handling, ensuring type safety and preventing runtime errors from invalid
encoding operations.

The frame format follows this structure:
    [Version(8)] [EventID(16)] [Size(32)] [Data(var)] [Padding(0-7)]

Example usage:

    >>> from usmd_rdsh.proto.base.encoder import (
    ...     BitEncoder, FrameEncoder
    ... )
    >>> from usmd_rdsh.proto.base.bitvec import Msb
    >>> from usmd_rdsh.utils.result import Result
    >>>
    >>> # Create a bit encoder
    >>> encoder = BitEncoder[Msb]()
    >>> result = encoder.add_data(42, 8)  # Add 8 bits
    >>> result = encoder.add_bytes(b"Hello")  # Add bytes
    >>> frame = encoder.encode()  # Get final encoded frame
    >>>
    >>> # Create a frame encoder
    >>> frame_encoder = FrameEncoder[Msb](version=1)
    >>> class MyEvent(EventEncoder[Msb]):
    ...     def encode(self) -> Result[None, Error]:
    ...         self.encoder.add_bytes(b"data")
    ...         return Result.Ok(None)
    ...     def get_event(self) -> int:
    ...         return 0x0001
    >>> result = frame_encoder.encode(MyEvent())
"""

import logging
from typing import TYPE_CHECKING, ForwardRef, Generic, Iterator

from usmd_rdsh.proto.base.bitvec import BitVec, R
from usmd_rdsh.utils.result import Result
from usmd_rdsh.utils.errors import Error, ErrorKind

if TYPE_CHECKING:
    from usmd_rdsh.proto.base.event import EventEncoder
else:
    EventEncoder = ForwardRef("EventEncoder")


class BitEncoder(Generic[R]):
    """An encoder that processes bits.

    This class provides functionality for building frames of bits and encoding them.
    It supports operations like adding individual bits, bytes, and bit vectors.

    Attributes:
        frame (BitVec): The current frame being built

    Examples:
        >>> encoder = BitEncoder()
        >>> encoder.add_data(42, 8)  # Add number 42 using 8 bits
        >>> encoder.add_bytes(b'Hello')  # Add text as bytes
        >>> result = encoder.encode()  # Get final encoded bits
    """

    frame: BitVec[R]

    def __init__(self) -> None:
        """Initialize a new empty bit encoder."""
        self.frame: BitVec[R] = BitVec[R]()

    def __iter__(self) -> Iterator[bool]:
        """Make the encoder iterable over its frame bits.

        Returns:
            Iterator[bool]: Iterator over the individual bits in the frame
        """
        return iter(self.frame)

    def __len__(self) -> int:
        """Get the total number of bits in the frame."""
        return len(self.frame)

    def add_data(self, data: int, n: int) -> Result[None, Error]:
        """Add n least significant bits from an integer to the frame.

        The bits are added in LSB order (least significant bit first).
        Maximum frame size is 2^32 bits.

        Args:
            data: Integer containing the bits to add
            n: Number of bits to extract from data

        Returns:
            Result[None, Error]: Ok(None) if bits were added successfully,
                               Err if frame size limit would be exceeded

        Examples:
            # Add basic data
            >>> encoder = BitEncoder()
            >>> # Add number 42 (00101010 in binary) using 8 bits
            >>> encoder.add_data(42, 8)
            >>> # Frame now contains: [0, 1, 0, 1, 0, 1, 0, 0]

            # Add big data
            >>> encoder = BitEncoder()
            >>> # Add number 42 (00101010 in binary) using 16 bits
            >>> encoder.add_data(42, 16)
            >>> # Frame now contains: [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0]
        """
        if len(self.frame) + n > 1 << 32:
            return Result.Err(
                Error.new(
                    ErrorKind.SIZE_CONSTRAINT_VIOLATION, "Frame size limit exceeded"
                )
            )

        for i in reversed(range(n)):
            bit: bool = (data >> i) & 1 == 1
            self.frame.append(bit)

        return Result.Ok(None)

    def add_bytes(self, data: bytes) -> Result[None, Error]:
        """Add a sequence of bytes to the frame.

        Each byte is added as 8 bits in LSB order.

        Args:
            data: Bytes to add to the frame

        Returns:
            Result[None, Error]: Ok(None) if bytes were added successfully

        Example:
            >>> encoder = BitEncoder()
            >>> # Add ASCII 'A' (0x41 = 01000001)
            >>> encoder.add_bytes(b'A')
            >>> # Frame now contains: [1, 0, 0, 0, 0, 0, 1, 0]
        """
        Result.hide()

        for byte in list(data):
            self.add_data(byte, 8)

        return Result.reveal()

    def add_vec(self, bitvec: BitVec[R]) -> Result[None, Error]:
        """Add a bit vector directly to the frame.

        Args:
            bitvec (BitVec): The bit vector to add

        Example:
            >>> encoder = BitEncoder()
            >>> encoder.add_vec([1, 0, 1])  # Add three bits
        """
        Result.hide()

        for bit in bitvec:
            self.add_data(bit, 1)

        return Result.reveal()

    def append_data_from(self, other: "BitEncoder[R]") -> None:
        """Append all bits from another encoder's frame.

        Args:
            other (BitEncoder[R]): Another encoder whose frame to append

        Example:
            >>> encoder1 = BitEncoder()
            >>> encoder1.add_data(0b101, 3)
            >>> encoder2 = BitEncoder()
            >>> encoder2.append_data_from(encoder1)
        """
        self.frame.extend(other.frame)

    def reverse_bits_in_bytes(self, bitvec: BitVec[R]) -> BitVec[R]:
        """Reverse the bits in each byte of the input.

        Args:
            bitvec (BitVec): The input bit vector

        Returns:
            BitVec: New bit vector with reversed bits in each byte

        Example:
            >>> encoder = BitEncoder()
            >>> encoder.reverse_bits_in_bytes([0b10100000])
            [0b00000101]  # Bits reversed within the byte
        """
        result = BitVec[R]()
        for byte in bitvec:
            result.append(int(bin(byte)[2:].zfill(8)[::-1], 2))
        return result

    def encode(self) -> BitVec[R]:
        """Encode and finalize the frame.

        Reverses bits in each byte of the frame to produce the final encoding.

        Returns:
            BitVec: The encoded frame with reversed bits in each byte

        Example:
            >>> encoder = BitEncoder()
            >>> encoder.add_data(0b10100000, 8)  # Add byte 0xA0
            >>> result = encoder.encode()
            >>> # Result contains 0b00000101 (bits reversed)
        """
        return self.reverse_bits_in_bytes(self.frame)


class FrameEncoder(Generic[R]):  # pylint: disable=too-few-public-methods
    """Encoder for complete protocol frames.

    Handles encoding of protocol frames with headers:
    - 8-bit protocol version
    - 16-bit event ID
    - 32-bit data size
    - Variable length data
    - Padding to byte boundary

    Frame format:
        [Version(8)] [EventID(16)] [Size(32)] [Data(var)] [Padding(0-7)]

    Attributes:
        encoder (BitEncoder): The underlying bit encoder
        version (Version): Protocol version to use

    Example:
        >>> encoder = FrameEncoder(Version.V1)
        >>> class PingEvent(EventEncoder):
        ...     def encode(self):
        ...         self.encoder.add_bytes(b"PING")
        ...     def get_event(self) -> int:
        ...         return 0x0001
        >>> result = encoder.encode(PingEvent())
        >>> # Result contains: [V1][0x0001][32][PING][pad]
    """

    def __init__(self, version: int) -> None:
        """Initialize a new frame encoder.

        Args:
            version: Protocol version to use for encoding

        Example:
            >>> encoder = FrameEncoder(Version.V1)
        """
        self.encoder: BitEncoder[R] = BitEncoder[R]()
        self.version: int = version

    def encode(self, frame: "EventEncoder[R]") -> Result[BitVec[R], Error]:
        """Encode a complete protocol frame.

        Process:
        1. Add 8-bit version header
        2. Encode event data
        3. Add 16-bit event ID
        4. Add 32-bit data size
        5. Add encoded data
        6. Pad to byte boundary

        Size constraints:
        - Minimum data size: 8 bits
        - Maximum data size: 2^32 bits
        - Frame is padded to multiple of 8 bits

        Args:
            frame: Event encoder containing the data to encode

        Returns:
            Result containing:
            - Ok(BitVec): Complete encoded frame if successful
            - Ok(None): If no data to encode
            - Err(Error): If size constraints are violated

        Example:
            >>> class DataEvent(EventEncoder):
            ...     def encode(self):
            ...         self.encoder.add_bytes(b"DATA")
            ...     def get_event(self) -> int:
            ...         return 0x0002
            >>> encoder = FrameEncoder(Version.V1)
            >>> result = encoder.encode(DataEvent())
            >>> # Result contains: [V1][0x0002][32][DATA][pad]
        """
        Result.hide()

        self.encoder.add_data(self.version, 8)
        frame.encode()
        data_size: int = len(frame.get_encoder().frame)

        if data_size > 1 << 32:
            return Result.Err(
                Error.new(
                    ErrorKind.SIZE_CONSTRAINT_VIOLATION, "Frame size limit exceeded"
                )
            )

        if data_size < 8:
            return Result.Err(
                Error.new(ErrorKind.SIZE_CONSTRAINT_VIOLATION, "Data size is too small")
            )

        # Add headers
        self.encoder.add_data(frame.get_event(), 16)
        self.encoder.add_data(data_size, 32)
        self.encoder.append_data_from(frame.get_encoder())

        # Pad to byte boundary
        while len(self.encoder.frame) % 8 != 0:
            self.encoder.add_data(0, 1)

        logging.debug(
            "[\x1b[38;5;227mUSMD-RDSH\x1b[0m] Sent: "
            "In-size %db / %dB, out-size %db / %dB",
            data_size,
            (data_size + 8 - (data_size % 8)) // 8,
            len(self.encoder.frame),
            len(self.encoder.frame) // 8,
        )

        r: Result[None, Error] = Result.reveal()
        if r.is_err():
            return Result[BitVec[R], Error].Err(r.unwrap_err())

        return Result.Ok(self.encoder.encode())
