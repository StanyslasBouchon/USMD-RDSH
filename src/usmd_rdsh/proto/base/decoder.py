"""Bit-level decoder module for processing protocol frames.

This module provides decoders for processing binary data at the bit level within
the USMD-RDSH protocol. It includes low-level byte reading capabilities and
high-level frame structure decoding.

The module exposes three main classes:

    - BitDecoder: Generic decoder that processes binary data byte-by-byte.
      Provides iteration over bytes and methods for reading data at specific
      positions with automatic position tracking.

    - Frame: Data structure representing a decoded protocol frame containing
      version, event ID, data size, and payload data.

    - FrameDecoder: High-level decoder that processes complete protocol frames.
      Handles decoding of protocol-specific frame structures including version
      (8 bits), event ID (16 bits), data size (32 bits), and payload data.

All decoders use generic type parameters to support different bit ordering
schemes (MSB-first or LSB-first) and return Result types for explicit error
handling, ensuring type safety and preventing runtime errors from invalid
decoding operations.

Example usage:

    >>> from usmd_rdsh.proto.base.decoder import (
    ...     BitDecoder, FrameDecoder, Frame
    ... )
    >>> from usmd_rdsh.proto.base.bitvec import BitVec, Msb
    >>> from usmd_rdsh.utils.result import Result
    >>>
    >>> # Create a bit decoder from binary data
    >>> frame_bytes = b'\\x01\\x00\\x02\\x00\\x00\\x00\\x05\\x48\\x65\\x6c\\x6c\\x6f'
    >>> frame_data = BitVec.from_bytes(frame_bytes)
    >>> decoder = BitDecoder[Msb](frame_data)
    >>>
    >>> # Read data from the decoder
    >>> result = decoder.read_data(2)
    >>> if result.is_ok():
    ...     data = result.unwrap()
    >>>
    >>> # Decode a complete frame
    >>> frame_decoder = FrameDecoder[Msb](decoder)
    >>> result = frame_decoder.decode()
    >>> if result.is_ok():
    ...     frame: Frame[Msb] = result.unwrap()
    ...     print(f"Version: {frame.version}, Event: {frame.event}")
"""

from dataclasses import dataclass
from typing import Generic, Iterator

from usmd_rdsh.proto.base.bitvec import BitVec, R
from usmd_rdsh.utils.result import Result
from usmd_rdsh.utils.errors import Error, ErrorKind


class BitDecoder(Generic[R]):
    """A generic decoder that processes bytes.

    This class implements a decoder that processes binary data. It provides iteration
    over its underlying bytes and methods for reading data at specific positions.

    Args:
        frame (BitVec[R]): The binary data to be decoded

    Examples:
        >>> decoder = BitDecoder(b'\\x0F\\x42')
        >>> list(decoder.frame)  # Access raw bytes
        [15, 66]
    """

    def __init__(self, frame: BitVec[R]):
        self.frame: BitVec[R] = frame
        self.position: int = 0

    def __iter__(self) -> Iterator[int]:
        """Allows iteration over the decoder's bytes.

        Returns:
            Iterator[int]: An iterator over the bytes in the decoder

        Examples:
            >>> decoder = BitDecoder(b'\\x0F\\x42')
            >>> list(decoder)
            [15, 66]
        """
        return iter(self.frame)

    def read_data(self, n: int) -> Result[BitVec[R], Error]:
        """Reads n bytes from the frame at the current position.

        Args:
            n (int): The number of bytes to read

        Returns:
            Result[BitVec, Error]: The bytes read from the frame
        """
        if self.position + n > len(self.frame):
            return Result.Err(
                Error.new(
                    ErrorKind.SIZE_CONSTRAINT_VIOLATION,
                    f"Out of bounds :: {self.position} + {n} > {len(self.frame)}",
                )
            )

        data = self.frame[self.position : self.position + n]
        self.position += n
        return Result.Ok(data)

    def __str__(self):
        return f"BitDecoder(frame={self.frame}, position={self.position})"

    def read_vec(self, fp: int, tp: int) -> Result[BitVec[R], Error]:
        """Reads a vector of bytes from the frame between two positions.

        Args:
            fp (int): The start position
            tp (int): The end position

        Returns:
            Result[BitVec, Error]: The bytes read from the frame
        """
        if fp >= len(self.frame):
            return Result.Err(
                Error.new(
                    ErrorKind.SIZE_CONSTRAINT_VIOLATION,
                    f"Out of bounds :: {fp} >= {len(self.frame)}",
                )
            )

        return Result.Ok(self.frame[fp:tp])

    def read_bytes(self, n: int) -> Result[BitVec[R], Error]:
        """Reads n bytes (n*8 bits) from the frame at the current position.

        Args:
            n: The number of bytes to read

        Returns:
            Result[BitVec[R], Error]: The bits read from the frame (n*8 bits)

        Examples:
            >>> decoder = BitDecoder(BitVec.from_bytes(b'Hello'))
            >>> result = decoder.read_bytes(2)  # Read 2 bytes (16 bits)
            >>> if result.is_ok():
            ...     bits = result.unwrap()
        """
        return self.read_data(n * 8)


@dataclass
class Frame(Generic[R]):
    """A frame of decoded data.

    This class represents a frame of data that has been decoded.
    It contains the version, event, data size, and data fields.
    """

    version: int
    event: int
    data_size: int
    data: BitVec[R]


class FrameDecoder(Generic[R]):
    """A decoder that processes frames of data.

    This class extends BitDecoder to provide additional functionality for processing
    frames of data. It handles decoding of protocol-specific frame structures including
    version, event ID, and data size headers.
    """

    def __init__(self, decoder: BitDecoder[R]):
        self.decoder: BitDecoder[R] = decoder

    def get_decoder(self) -> BitDecoder[R]:
        """Returns the underlying decoder.

        Returns:
            BitDecoder: The underlying decoder
        """
        return self.decoder

    def decode(self) -> Result[Frame[R], Error]:
        """Decodes the frame according to the specified bit order.

        Returns:
            Result[Frame, Error]: A Frame object containing the decoded version,
                                     event, data size, and data
        """

        result_version_data: Result[BitVec[R], Error] = self.decoder.read_data(8)
        if result_version_data.is_ok():
            version: int = result_version_data.unwrap().to_int().unwrap()
        else:
            return Result.Err(result_version_data.unwrap_err())

        result_event_data: Result[BitVec[R], Error] = self.decoder.read_data(16)
        if result_event_data.is_ok():
            event: int = result_event_data.unwrap().to_int().unwrap()
        else:
            return Result.Err(result_event_data.unwrap_err())

        result_data_size_data: Result[BitVec[R], Error] = self.decoder.read_data(32)
        if result_data_size_data.is_ok():
            data_size: int = result_data_size_data.unwrap().to_int().unwrap()
        else:
            return Result.Err(result_data_size_data.unwrap_err())

        result_data: Result[BitVec[R], Error] = self.decoder.read_vec(
            56, 56 + data_size
        )
        if result_data.is_err():
            return Result.Err(result_data.unwrap_err())

        return Result.Ok(Frame[R](version, event, data_size, result_data.unwrap()))
