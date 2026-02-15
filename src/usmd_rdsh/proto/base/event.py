"""Event encoding and decoding interfaces for the USMD-RDSH protocol.

This module provides abstract base classes for encoding and decoding protocol
events. It defines the core interfaces that all event types must implement to
participate in the protocol's event system.

The module exposes two main interfaces:

    - EventEncoder: Abstract base class for encoding events into bit frames.
      Implementations must specify how event data is encoded and provide access
      to the bit encoder and event identifier.

    - EventDecoder: Abstract base class for decoding events from bit frames.
      Implementations must specify how event data is decoded and what response
      types are possible for the event.

Both classes use generic type parameters to support different bit ordering
schemes (MSB-first or LSB-first) and ensure type safety throughout the
encoding/decoding process.

Example usage:

    >>> from usmd_rdsh.proto.base.event import EventEncoder, EventDecoder
    >>> from usmd_rdsh.proto.base.bitvec import Msb
    >>> from usmd_rdsh.utils.result import Result
    >>>
    >>> # Implementing an event encoder
    >>> class MyEvent(EventEncoder[Msb]):
    ...     def encode(self) -> Result[None, Error]:
    ...         # Encode event data
    ...         return Result.Ok(None)
    ...
    >>> # Implementing an event decoder
    >>> class MyDecoder(EventDecoder[Msb]):
    ...     def decode(self, frame: Frame[Msb]) -> Result[None, Error]:
    ...         # Decode event data
    ...         return Result.Ok(None)
"""

from abc import ABC, abstractmethod
from typing import Any, Generic

from usmd_rdsh.proto.base.bitvec import R
from usmd_rdsh.utils.result import Result
from usmd_rdsh.utils.errors import Error
from usmd_rdsh.proto.base.decoder import Frame
from usmd_rdsh.proto.base.encoder import BitEncoder


class EventEncoder(Generic[R], ABC):
    """Abstract base class for encoding protocol events.

    This class defines the interface for encoding events in the protocol.
    Each event type should implement this interface to specify how it should
    be encoded into bits.

    Example:
        >>> class LoginEvent(EventEncoder[R]):
        ...     def encode(self):
        ...         self.encoder.add_data(0x01, 8)  # Add event data
        ...
        ...     def get_encoder(self) -> BitEncoder[R]:
        ...         return self.encoder
        ...
        ...     def get_event(self) -> int:
        ...         return 0x0001  # Event ID for login
    """

    @abstractmethod
    def encode(self) -> Result[None, Error]:
        """Encode the event data into bits.

        This method should use the encoder to add the event's data
        to the bit frame.
        """

    @abstractmethod
    def get_encoder(self) -> BitEncoder[R]:
        """Get the bit encoder used by this event.

        Returns:
            BitEncoder[R]: The encoder instance for this event
        """

    @abstractmethod
    def get_event(self) -> int:
        """Get the event identifier.

        Returns:
            int: The unique 16-bit identifier for this event type
        """


class EventDecoder(Generic[R], ABC):
    """Abstract base class for decoding protocol events.

    This class defines the interface for decoding events in the protocol.
    Each event type should implement this interface to specify how it should
    be decoded from bits and what responses it can generate.

    Example:
        >>> class LoginDecoder(EventDecoder[R]):
        ...     def decode(self, *args: Any, frame: Frame[R]) -> Result[None, Error]:
        ...         user_id = frame.read_int(8)  # Read event data
        ...         return Result.Ok(None)
        ...
        ...     def get_responses(self) -> Result[list[EventEncoder[ReversedR]], Error]:
        ...         return Result.Ok([LoginSuccessEvent, LoginFailedEvent])
    """

    @abstractmethod
    def decode(self, *args: Any, frame: Frame[R]) -> Result[None, Error]:
        """Decode event data from a frame.

        Args:
            *args: Additional arguments to the decoder
            frame (Frame): The frame containing the event data
        """
        return Result.Ok(None)
