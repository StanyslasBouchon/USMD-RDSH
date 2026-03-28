"""Error handling for USMD-RDSH.

This module defines all error kinds and the Error class used throughout
the USMD-RDSH system for explicit, structured error reporting.

Examples:
    >>> err = Error.new(ErrorKind.NODE_NOT_FOUND, "Node 1234 not found")
    >>> str(err)
    'Error: [NodeNotFound]:404 -> Node 1234 not found'

    >>> err = Error.new(ErrorKind.INVALID_SIGNATURE, "Ed25519 verification failed")
    >>> str(err)
    'Error: [InvalidSignature]:401 -> Ed25519 verification failed'
"""

from enum import Enum


class ErrorKind(Enum):
    """Enumeration of all error kinds in the USMD-RDSH system.

    Categories:
        - Node errors: Problems with node state, identity or endorsement.
        - Domain errors: Problems with USD/USC configuration.
        - Protocol errors: NCP/NNDP framing or version issues.
        - Crypto errors: Signature or encryption failures.
        - Mutation errors: Transmutation or service lifecycle problems.
        - General errors: Generic failures.

    Examples:
        >>> str(ErrorKind.NODE_NOT_FOUND)
        'NodeNotFound'
        >>> str(ErrorKind.INVALID_SIGNATURE)
        'InvalidSignature'
    """

    # --- Node errors ---
    NODE_NOT_FOUND = "NodeNotFound"
    NODE_ALREADY_EXISTS = "NodeAlreadyExists"
    NODE_EXCLUDED = "NodeExcluded"
    NODE_PENDING_APPROVAL = "NodePendingApproval"
    NODE_INACTIVE = "NodeInactive"
    NODE_NAME_CONFLICT = "NodeNameConflict"

    # --- Identity / endorsement errors ---
    INVALID_SIGNATURE = "InvalidSignature"
    INVALID_NIT_ASSOCIATION = "InvalidNitAssociation"
    INVALID_ENDORSEMENT_PACKET = "InvalidEndorsementPacket"
    UNVERIFIABLE_ENDORSEMENT = "UnverifiableEndorsement"
    INVALID_REVOCATION_REQUEST = "InvalidRevocationRequest"
    ENDORSER_NOT_FOUND = "EndorserNotFound"

    # --- Domain errors ---
    DOMAIN_NOT_FOUND = "DomainNotFound"
    CLUSTER_NOT_FOUND = "ClusterNotFound"
    EDB_UNREACHABLE = "EdbUnreachable"

    # --- Protocol errors ---
    UNKNOWN_VERSION = "UnknownVersion"
    PROTOCOL_ERROR = "ProtocolError"
    INVALID_COMMAND = "InvalidCommand"
    NOT_A_REFERENCE_NODE = "NotAReferenceNode"

    # --- Crypto errors ---
    CRYPTO_ERROR = "CryptoError"
    KEY_GENERATION_FAILED = "KeyGenerationFailed"

    # --- Mutation errors ---
    MUTATION_FAILED = "MutationFailed"
    SERVICE_BUILD_FAILED = "ServiceBuildFailed"
    SERVICE_UPDATE_FAILED = "ServiceUpdateFailed"
    SERVICE_NOT_FOUND = "ServiceNotFound"
    DEPENDENCY_INACTIVE = "DependencyInactive"
    HEALTH_CHECK_FAILED = "HealthCheckFailed"

    # --- Connection errors ---
    CONNECTION_ERROR = "ConnectionError"

    # --- General errors ---
    BAD_REQUEST = "BadRequest"
    UNAUTHORIZED = "Unauthorized"
    FORBIDDEN = "Forbidden"
    NOT_FOUND = "NotFound"
    TIMEOUT = "Timeout"
    CONFLICT = "Conflict"
    SERVICE_UNAVAILABLE = "ServiceUnavailable"
    NOT_IMPLEMENTED = "NotImplemented"
    USER_DEFINED = "UserDefined"

    def __str__(self) -> str:
        return self.value


class Error:
    """Represents a structured error in USMD-RDSH.

    Attributes:
        code: HTTP-style numeric error code.
        kind: The error category.
        message: Human-readable description.

    Examples:
        >>> error = Error(404, ErrorKind.NODE_NOT_FOUND, "Node 1234 not found")
        >>> str(error)
        'Error: [NodeNotFound]:404 -> Node 1234 not found'

        >>> error = Error.new(ErrorKind.INVALID_SIGNATURE, "Bad signature")
        >>> error.code
        401
    """

    _CODE_MAP: dict[ErrorKind, int] = {
        ErrorKind.NODE_NOT_FOUND: 404,
        ErrorKind.NODE_ALREADY_EXISTS: 409,
        ErrorKind.NODE_EXCLUDED: 403,
        ErrorKind.NODE_PENDING_APPROVAL: 202,
        ErrorKind.NODE_INACTIVE: 503,
        ErrorKind.NODE_NAME_CONFLICT: 409,
        ErrorKind.INVALID_SIGNATURE: 401,
        ErrorKind.INVALID_NIT_ASSOCIATION: 403,
        ErrorKind.INVALID_ENDORSEMENT_PACKET: 400,
        ErrorKind.UNVERIFIABLE_ENDORSEMENT: 401,
        ErrorKind.INVALID_REVOCATION_REQUEST: 400,
        ErrorKind.ENDORSER_NOT_FOUND: 404,
        ErrorKind.DOMAIN_NOT_FOUND: 404,
        ErrorKind.CLUSTER_NOT_FOUND: 404,
        ErrorKind.EDB_UNREACHABLE: 503,
        ErrorKind.UNKNOWN_VERSION: 400,
        ErrorKind.PROTOCOL_ERROR: 400,
        ErrorKind.INVALID_COMMAND: 400,
        ErrorKind.NOT_A_REFERENCE_NODE: 403,
        ErrorKind.CRYPTO_ERROR: 500,
        ErrorKind.KEY_GENERATION_FAILED: 500,
        ErrorKind.MUTATION_FAILED: 500,
        ErrorKind.SERVICE_BUILD_FAILED: 500,
        ErrorKind.SERVICE_UPDATE_FAILED: 500,
        ErrorKind.SERVICE_NOT_FOUND: 404,
        ErrorKind.DEPENDENCY_INACTIVE: 503,
        ErrorKind.HEALTH_CHECK_FAILED: 503,
        ErrorKind.BAD_REQUEST: 400,
        ErrorKind.UNAUTHORIZED: 401,
        ErrorKind.FORBIDDEN: 403,
        ErrorKind.NOT_FOUND: 404,
        ErrorKind.TIMEOUT: 408,
        ErrorKind.CONFLICT: 409,
        ErrorKind.SERVICE_UNAVAILABLE: 503,
        ErrorKind.NOT_IMPLEMENTED: 501,
        ErrorKind.USER_DEFINED: 500,
        ErrorKind.CONNECTION_ERROR: 503,
    }

    def __init__(self, code: int, kind: ErrorKind, message: str) -> None:
        """Initialise a new Error.

        Args:
            code: Numeric error code.
            kind: Error category.
            message: Human-readable description.
        """
        self.code = code
        self.kind = kind
        self.message = message

    def __str__(self) -> str:
        return f"Error: [{self.kind}]:{self.code} -> {self.message}"

    def __repr__(self) -> str:
        return self.__str__()

    @classmethod
    def new(cls, kind: ErrorKind, message: str) -> "Error":
        """Create an Error with an automatically assigned HTTP-style code.

        Args:
            kind: The error category.
            message: Human-readable description.

        Returns:
            Error: A new Error instance.

        Examples:
            >>> err = Error.new(ErrorKind.NODE_NOT_FOUND, "Node 42 missing")
            >>> err.code
            404
            >>> err = Error.new(ErrorKind.CRYPTO_ERROR, "HKDF failed")
            >>> err.code
            500
        """
        code = cls._CODE_MAP.get(kind, 500)
        return cls(code, kind, message)
