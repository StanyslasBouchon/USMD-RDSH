"""BitVec implementation for handling bit vectors.

This module provides a specialized list type for handling bit vectors,
with utility methods for bit manipulation and conversion to various formats.

Examples:
    Basic usage:
    >>> bits = BitVec([1, 0, 1])  # Create from list
    >>> bits.append(1)            # Add a bit
    >>> bits
    [1, 0, 1, 1]
    >>> bits.extend([0, 0])      # Add multiple bits
    >>> bits
    [1, 0, 1, 1, 0, 0]

    Bit ordering:
    >>> class MsbBitVec(BitVec[Msb]): pass  # MSB-first ordering
    >>> class LsbBitVec(BitVec[Lsb]): pass  # LSB-first ordering

    >>> # MSB-first: bits are read from left to right
    >>> msb = MsbBitVec([1,0,1,0, 0,0,0,0])
    >>> msb.to_bytes()
    [160]  # 10100000 = 0xA0
    >>> msb.to_int()
    Ok(160)

    >>> # LSB-first: bits are read from right to left
    >>> lsb = LsbBitVec([1,0,1,0, 0,0,0,0])
    >>> lsb.to_bytes()
    [5]    # 00001010 = 0x05
    >>> lsb.to_int()
    Ok(5)
"""

from enum import Enum
from typing import Generic, SupportsIndex, Type, TypeVar, Union, overload

from usmd_rdsh.utils.result import Result
from usmd_rdsh.utils.errors import Error, ErrorKind


class BitOrder(Enum):
    """Bit ordering enumeration.

    Attributes:
        LSB: Least Significant Bit first
        MSB: Most Significant Bit first
    """

    LSB = 0
    MSB = 1


class Msb:  # pylint: disable=too-few-public-methods
    """Marker class for MSB-first bit ordering.

    Used as a type parameter for BitVec to indicate that bits should be processed
    from most significant (leftmost) to least significant (rightmost).
    """


class Lsb:  # pylint: disable=too-few-public-methods
    """Marker class for LSB-first bit ordering.

    Used as a type parameter for BitVec to indicate that bits should be processed
    from least significant (rightmost) to most significant (leftmost).
    """


R = TypeVar("R", Lsb, Msb)
ReversedR = TypeVar("ReversedR", Lsb, Msb)  # pylint: disable=invalid-name


def reverse_bit_order(order: Type[R]) -> Type[Union[Lsb, Msb]]:
    """Reverses the bit ordering.

    Args:
        order: Current bit order (Lsb or Msb)

    Returns:
        The opposite bit order
    """
    if order is Lsb:
        return Msb
    return Lsb


class BitVec(Generic[R], list[bool]):
    """A specialized list for handling bit vectors with configurable bit ordering.

    BitVec extends the built-in list to provide specialized handling of boolean values
    representing bits. It supports both MSB-first and LSB-first bit ordering through
    type parameters.

    The bit ordering affects how the bits are interpreted when converting to other
    formats (bytes, integers).

    Examples:
        Basic operations:
        >>> bits = BitVec([1, 0, 1])
        >>> bits.append(0)
        >>> bits
        [1, 0, 1, 0]
        >>> bits[1:3]  # Slicing returns a new BitVec
        [0, 1]

        Converting to other formats:
        >>> class MsbBits(BitVec[Msb]): pass
        >>> bits = MsbBits([1,1,0,0, 0,1,0,1])
        >>> bits.to_bytes()  # Convert to bytes
        [197]  # 11000101 = 0xC5
        >>> bits.to_int()    # Convert to integer
        Ok(197)
        >>> bits.to_hex()    # Convert to hex string
        ['c5']
    """

    def __init__(self, *args, **kwargs) -> None:
        """Initialize a new bit vector.

        Args:
            *args: Arguments passed to list constructor
            **kwargs: Keyword arguments passed to list constructor
        """
        super().__init__(*args, **kwargs)

    @property
    def is_msb(self) -> bool:
        """Check if this BitVec uses MSB-first ordering.

        Returns:
            bool: True if MSB-first, False otherwise
        """
        return isinstance(self, Msb)

    @property
    def is_lsb(self) -> bool:
        """Check if this BitVec uses LSB-first ordering.

        Returns:
            bool: True if LSB-first, False otherwise
        """
        return isinstance(self, Lsb)

    @overload
    def __getitem__(self, index: SupportsIndex) -> bool: ...

    @overload
    def __getitem__(self, index: slice) -> "BitVec[R]": ...

    def __getitem__(
        self, index: Union[SupportsIndex, slice]
    ) -> Union[bool, "list[bool]"]:
        """Get a bit or slice of bits at the specified index.

        Args:
            index: An integer index or slice object

        Returns:
            bool: Single bit if index is integer
            BitVec: New BitVec if index is slice

        Examples:
            >>> bits = BitVec([1,1,1,1, 0,0,0,0])
            >>> bits[2]  # Get single bit
            1
            >>> bits[2:5]  # Get slice
            BitVec([1,1,0])
        """
        result = super().__getitem__(index)
        if isinstance(index, slice):
            return type(self)(result)
        return result

    def __setitem__(self, index, value) -> None:
        """Set a bit at the specified index, ensuring boolean value.

        Args:
            index: The index to set
            value: The value to set (converted to bool)
        """
        super().__setitem__(index, bool(value))

    def __str__(self) -> str:
        return str([1 if bit else 0 for bit in self])

    def append(self, value) -> None:
        """Append a new bit, ensuring boolean value.

        Args:
            value: The value to append (converted to bool)
        """
        super().append(bool(value))

    def extend(self, values) -> None:
        """Extend with multiple bits, ensuring boolean values.

        Args:
            values: Iterable of values to append (each converted to bool)
        """
        super().extend(bool(v) for v in values)

    def to_int(self) -> Result[int, Error]:
        """Convert the bit vector to an integer value.

        This method converts the BitVec to an integer, with the following constraints:
        - The length must be a multiple of 8 bits
        - The maximum length is 64 bits (8 bytes)

        The conversion is performed using big-endian byte order.

        Returns:
            Result[int, Error]: A Result containing either:
                - Ok(int): The integer value if conversion succeeds
                - Err(Error): An error if length constraints are violated

        Examples:
            >>> bits = BitVec([0,0,0,0, 1,0,1,0])  # 8 bits = 0x0A
            >>> bits.to_int()
            Ok(10)

            >>> bits = BitVec([1,1,1,1, 0,0,0,0, 1,0,1,0, 0,0,0,0])  # 16 bits = 0xF0A0
            >>> bits.to_int()
            Ok(61600)

            >>> bits = BitVec([1,0,1])  # Not multiple of 8
            >>> bits.to_int()
            Err(Error(SIZE_CONSTRAINT_VIOLATION, "BitVec length must be a multiple of 8, got 3"))  # noqa: E501 pylint: disable=line-too-long

            >>> # 72 bits (9 bytes) exceeds maximum
            >>> long_bits = BitVec([1] * 72)
            >>> long_bits.to_int()
            Err(Error(SIZE_CONSTRAINT_VIOLATION, "BitVec length must be less than 64 bits, got 72"))  # noqa: E501 pylint: disable=line-too-long
        """
        if len(self) % 8 != 0:
            for _ in range(len(self) % 8):
                self.insert(0, False)

        if len(self) > 8 * 8:
            return Result.Err(
                Error.new(
                    ErrorKind.SIZE_CONSTRAINT_VIOLATION,
                    f"BitVec length must be less than 64 bits, got {len(self)}",
                )
            )

        result: int = 0
        for i, bit in enumerate(self):
            if self.is_msb:
                result |= bit << i
            else:
                result |= bit << (len(self) - i - 1)
        return Result.Ok(result)

    def to_byte_list(self) -> list[int]:
        """Converts the list of bits to a list of bytes.

        The conversion uses MSB-first or LSB-first ordering based on the class type.

        Returns:
            list[int]: List of bytes (0-255)
        """
        bytes_list: list[int] = []
        for i in range(0, len(self), 8):
            byte = 0
            for j in range(min(8, len(self) - i)):
                if self[i + j]:
                    if self.is_msb:
                        byte |= 1 << j  # LSB: bits from right to left
                    else:
                        byte |= 1 << (7 - j)  # MSB: bits from left to right
            bytes_list.append(byte)
        return bytes_list

    def to_bytes(self) -> bytes:
        """Convert the bit vector to a bytes object.

        The conversion uses MSB-first or LSB-first ordering based on the class type.

        Returns:
            bytes: The converted bytes object

        Examples:
            >>> # MSB-first ordering
            >>> msb_bits = MsbBitVec([1,1,0,0, 0,1,0,1])
            >>> msb_bits.to_bytes()
            b'\\xc5'  # 11000101 = 0xC5

            >>> # LSB-first ordering
            >>> lsb_bits = LsbBitVec([1,1,0,0, 0,1,0,1])
            >>> lsb_bits.to_bytes()
            b'\\xa3'  # 10100011 = 0xA3
        """
        return bytes(self.to_byte_list())

    def to_hex(self) -> str:
        """Convert the bit vector to a hexadecimal string representation.

        The conversion uses MSB-first or LSB-first ordering based on the class type.
        Each byte is represented as a two-digit hexadecimal number.

        Returns:
            str: The hexadecimal string representation

        Examples:
            >>> # MSB-first ordering
            >>> msb_bits = MsbBitVec([1,1,0,0, 0,1,0,1])
            >>> msb_bits.to_hex()
            'c5'

            >>> # Multiple bytes
            >>> bits = MsbBitVec([1,1,0,0, 0,1,0,1, 1,0,1,0, 1,1,1,1])
            >>> bits.to_hex()
            'c5af'
        """
        return "".join([f"{byte:02x}" for byte in self.to_byte_list()])

    @staticmethod
    def from_bytes(msg_bytes: bytes, order: Type[R] = Msb) -> "BitVec[R]":
        """Convert a bytes object to a BitVec.

        Creates a new BitVec from a bytes object using the specified bit ordering.

        Args:
            msg_bytes: The bytes object to convert
            order: The bit ordering to use (Msb or Lsb), defaults to Msb

        Returns:
            BitVec[R]: A new BitVec with the specified ordering

        Examples:
            >>> # MSB-first ordering (default)
            >>> msg_bytes = b'\\xc5'  # 11000101
            >>> bits = BitVec.from_bytes(msg_bytes)
            >>> bits  # MSB ordering: bits read left-to-right
            [1, 1, 0, 0, 0, 1, 0, 1]

            >>> # LSB-first ordering
            >>> bits = BitVec.from_bytes(msg_bytes, Lsb)
            >>> bits  # LSB ordering: bits read right-to-left
            [1, 0, 1, 0, 0, 0, 1, 1]

            >>> # Multiple bytes
            >>> msg_bytes = b'\\xc5\\xaf'  # 11000101 10101111
            >>> bits = BitVec.from_bytes(msg_bytes)
            >>> bits.to_hex()
            'c5af'
        """
        result = BitVec[R]()
        for byte in msg_bytes:
            for i in range(8):
                if order is Lsb:
                    bit: bool = (byte & (1 << i)) != 0
                else:
                    bit: bool = (byte & (1 << (7 - i))) != 0  # type: ignore[no-redef]
                result.append(bit)
        return result

    @staticmethod
    def from_str(s: str, order: Type[R] = Msb) -> "BitVec[R]":
        """Convert a string to a BitVec.

        Args:
            s: The string to convert
            order: The bit ordering to use (Msb or Lsb), defaults to Msb

        Returns:
            BitVec[R]: A new BitVec with the specified ordering

        Examples:
            >>> BitVec.from_str("1011")
            [1, 0, 1, 1]
            >>> BitVec.from_str("000")
            [0, 0, 0]
            >>> BitVec.from_str("11001")
            [1, 1, 0, 0, 1]
            >>> BitVec.from_str("1011", Lsb)
            [1, 1, 0, 1, 0]
            >>> BitVec.from_str("000", Lsb)
            [0, 0, 0]
            >>> BitVec.from_str("11001", Lsb)
            [1, 0, 0, 1, 1]
        """
        if order is Lsb:
            return BitVec[R]([1 if d == "1" else 0 for d in s[::-1]])

        return BitVec[R]([1 if d == "1" else 0 for d in s])
