"""Error handling for USMD-RDSH protocol.

This module provides error types and handling for the USMD-RDSH protocol,
including standard error kinds and custom error creation.
"""

from enum import Enum


class ErrorKind(Enum):
    """Enumeration of standard error types in the USMD-RDSH protocol.

    This enum defines standard error categories that can occur during protocol
    operations. Each error kind maps to a specific error scenario.

    Examples:
        >>> error = ErrorKind.NOT_FOUND
        >>> str(error)
        'NotFound'
        >>> custom_error = ErrorKind.USER_DEFINED("Custom error message")
        >>> str(custom_error)
        'Custom error message'
    """

    # Client errors (4xx)
    BAD_REQUEST = "BadRequest"  # Invalid request format or parameters
    UNAUTHORIZED = "Unauthorized"  # Authentication required
    PAYMENT_REQUIRED = "PaymentRequired"  # Payment needed for operation
    FORBIDDEN = "Forbidden"  # Client lacks necessary permissions
    NOT_FOUND = "NotFound"  # Requested resource doesn't exist
    METHOD_NOT_ALLOWED = "MethodNotAllowed"  # Operation not supported
    REQUEST_TIMEOUT = "RequestTimeout"  # Request took too long
    CONFLICT = "Conflict"  # Request conflicts with current state
    GONE = "Gone"  # Resource no longer available
    REQUEST_ENTITY_TOO_LARGE = "RequestEntityTooLarge"  # Request data too large
    REQUESTED_RANGE_NOT_SATISFIABLE = (
        "RequestedRangeNotSatisfiable"  # Invalid range request
    )
    EXPECTATION_FAILED = "ExpectationFailed"  # Server can't meet expectations
    EXPIRED = "Expired"  # Resource or token has expired
    LOCKED = "Locked"  # Resource is locked

    # Communication errors
    NO_RESPONSE = "NoResponse"  # No response received
    CANCELLED = "Cancelled"  # Operation was cancelled

    # Server errors (5xx)
    NOT_IMPLEMENTED = "NotImplemented"  # Operation not implemented
    SERVICE_UNAVAILABLE = "ServiceUnavailable"  # Service temporarily unavailable

    # Protocol errors
    SIZE_CONSTRAINT_VIOLATION = "SizeConstraintViolation"  # Data size limits exceeded
    PROTOCOL_ERROR = "ProtocolError"  # Protocol-level error
    UNKNOWN_VERSION = "UnknownVersion"  # Unsupported protocol version
    USER_DEFINED = "UserDefined"  # Base for custom errors
    INTERACTION_ERROR = "InteractionError"  # Error during interaction

    def __str__(self) -> str:
        """Get string representation of the error kind.

        Returns:
            str: The error message or kind name
        """
        return self.value


class Error:
    """Represents an error in the USMD-RDSH protocol.

    This class combines an error code, kind, and message to provide detailed
    error information for protocol operations.

    Attributes:
        code (int): Numeric error code
        kind (ErrorKind): The category of error
        message (str): Detailed error message

    Examples:
        >>> # Create a not found error
        >>> error = Error(404, ErrorKind.NOT_FOUND, "User profile not found")
        >>> str(error)
        'Error: [NotFound]:404 -> User profile not found'

        >>> # Create a custom error
        >>> custom = Error(
        ...     500,
        ...     ErrorKind.USER_DEFINED,
        ...     "Database connection failed"
        ... )
        >>> str(custom)
        'Error: [UserDefined]:500 -> Database connection failed'
    """

    def __init__(self, code: int, kind: ErrorKind, message: str):
        """Initialize a new Error instance.

        Args:
            code: Numeric error code
            kind: Category of the error
            message: Detailed error description
        """
        self.code = code
        self.kind = kind
        self.message = message

    def __str__(self) -> str:
        """Get string representation of the error.

        Returns:
            str: Formatted error string with kind, code and message
        """
        return f"Error: [{self.kind}]:{self.code} -> {self.message}"

    @classmethod
    def new(cls, kind: ErrorKind, message: str) -> "Error":
        """Create a new Error instance with an automatically assigned code.

        Args:
            kind: The error kind
            message: Detailed error message

        Returns:
            Error: A new Error instance

        Examples:
            >>> error = Error.new(ErrorKind.NOT_FOUND, "User not found")
            >>> str(error)
            'Error: [NotFound]:404 -> User not found'

            >>> custom = Error.new(ErrorKind.USER_DEFINED, "Custom error")
            >>> str(custom)
            'Error: [UserDefined]:500 -> Custom error'
        """
        # Map error kinds to appropriate codes
        code_map = {
            ErrorKind.BAD_REQUEST: 400,
            ErrorKind.UNAUTHORIZED: 401,
            ErrorKind.PAYMENT_REQUIRED: 402,
            ErrorKind.FORBIDDEN: 403,
            ErrorKind.NOT_FOUND: 404,
            ErrorKind.METHOD_NOT_ALLOWED: 405,
            ErrorKind.REQUEST_TIMEOUT: 408,
            ErrorKind.CONFLICT: 409,
            ErrorKind.GONE: 410,
            ErrorKind.REQUEST_ENTITY_TOO_LARGE: 413,
            ErrorKind.REQUESTED_RANGE_NOT_SATISFIABLE: 416,
            ErrorKind.EXPECTATION_FAILED: 417,
            ErrorKind.USER_DEFINED: 500,  # Custom errors use 500 by default
            ErrorKind.NOT_IMPLEMENTED: 501,
            ErrorKind.SERVICE_UNAVAILABLE: 503,
            ErrorKind.INTERACTION_ERROR: 460,
        }

        code = code_map.get(kind, 500)  # Default to 500 for unknown kinds
        return cls(code, kind, message)
