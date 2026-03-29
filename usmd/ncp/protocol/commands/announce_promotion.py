"""NCP Command 11 — Announce_promotion (quorum election result).

Broadcast by the winner of a quorum election to notify all peers that it
has been promoted to a specific operator role.  Receiving nodes update their
local NAL to grant that role to the announced public key.

Request payload: UTF-8 JSON object with four keys:

    ``epoch``     – election epoch (int).
    ``role``      – promoted role name (str): ``"node_operator"``,
                    ``"usd_operator"`` or ``"ucd_operator"``.
    ``pub_key_hex`` – hex-encoded Ed25519 public key (64 hex chars = 32 bytes).
    ``address``   – IP address of the promoted node (str).

Response payload: empty (acknowledgement only).

Backward compatibility: the legacy binary format
(4-byte epoch + 32-byte pub_key + UTF-8 address) is still accepted on
``from_payload`` and treated as a ``node_operator`` promotion.

Examples:
    >>> import json
    >>> key = b'k' * 32
    >>> req = AnnouncePromotionRequest(epoch=1, role="usd_operator",
    ...                                pub_key=key, address="10.0.0.2")
    >>> data = json.loads(req.to_payload())
    >>> data["role"]
    'usd_operator'
    >>> data["address"]
    '10.0.0.2'
    >>> parsed = AnnouncePromotionRequest.from_payload(req.to_payload()).unwrap()
    >>> parsed.pub_key == key
    True
"""

import json
import struct

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result

_LEGACY_EPOCH_SIZE  = 4   # uint32 big-endian
_LEGACY_PUBKEY_SIZE = 32  # Ed25519 key length
_LEGACY_HEADER_SIZE = _LEGACY_EPOCH_SIZE + _LEGACY_PUBKEY_SIZE  # 36 bytes


class AnnouncePromotionRequest:
    """NCP command 11 request — winner announces its new operator role.

    Attributes:
        epoch: Election epoch the promotion belongs to.
        role: Promoted role name (e.g. ``"usd_operator"``).
        pub_key: Ed25519 public key of the promoted node (32 bytes).
        address: IP address of the promoted node.

    Examples:
        >>> key = b'\\x00' * 32
        >>> req = AnnouncePromotionRequest(2, "node_operator", key, "1.2.3.4")
        >>> import json; json.loads(req.to_payload())["epoch"]
        2
    """

    def __init__(
        self,
        epoch: int,
        role: str,
        pub_key: bytes,
        address: str,
    ) -> None:
        self.epoch = epoch
        self.role = role
        self.pub_key = pub_key
        self.address = address

    def to_payload(self) -> bytes:
        """Serialise the announcement as a UTF-8 JSON object.

        Returns:
            bytes: UTF-8 JSON with epoch, role, pub_key_hex, address.

        Example:
            >>> AnnouncePromotionRequest(1,"node_operator",b'k'*32,"1.2.3.4").to_payload()[:1]
            b'{'
        """
        return json.dumps(
            {
                "epoch":       self.epoch,
                "role":        self.role,
                "pub_key_hex": self.pub_key.hex(),
                "address":     self.address,
            },
            ensure_ascii=False,
        ).encode("utf-8")

    @staticmethod
    def from_payload(
        payload: bytes,
    ) -> "Result[AnnouncePromotionRequest, Error]":
        """Deserialise an Announce_promotion request.

        Accepts the current JSON format and the legacy binary format
        (4-byte epoch + 32-byte pub_key + UTF-8 address → ``node_operator``).

        Args:
            payload: Raw bytes from the network.

        Returns:
            Result[AnnouncePromotionRequest, Error]: Ok or Err.

        Examples:
            >>> key = b'x' * 32
            >>> req = AnnouncePromotionRequest(1, "ucd_operator", key, "5.5.5.5")
            >>> AnnouncePromotionRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        # Try JSON first (current format)
        try:
            data = json.loads(payload.decode("utf-8"))
            if isinstance(data, dict):
                try:
                    pub_key = bytes.fromhex(data.get("pub_key_hex", ""))
                except ValueError:
                    pub_key = b""
                return Result.Ok(
                    AnnouncePromotionRequest(
                        epoch=int(data.get("epoch", 0)),
                        role=str(data.get("role", "node_operator")),
                        pub_key=pub_key,
                        address=str(data.get("address", "")),
                    )
                )
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            pass

        # Legacy binary: [epoch uint32 BE][pub_key 32 bytes][address UTF-8]
        if len(payload) < 36:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"AnnouncePromotionRequest too short: {len(payload)} bytes",
                )
            )
        epoch = struct.unpack("!I", payload[:4])[0]
        pub_key = payload[4:36]
        address = payload[36:].decode("utf-8", errors="replace")
        return Result.Ok(
            AnnouncePromotionRequest(
                epoch=epoch,
                role="node_operator",
                pub_key=pub_key,
                address=address,
            )
        )


class AnnouncePromotionResponse:
    """NCP command 11 response acknowledgement.

    Examples:
        >>> AnnouncePromotionResponse().to_payload()
        b''
        >>> AnnouncePromotionResponse.from_payload(b"").is_ok()
        True
    """

    def to_payload(self) -> bytes:
        """Return an empty payload (acknowledgement only).

        Returns:
            bytes: Always b"".
        """
        return b""

    @staticmethod
    def from_payload(_payload: bytes) -> "Result[AnnouncePromotionResponse, Error]":
        """Deserialise the response (always succeeds).

        Args:
            _payload: Ignored.

        Returns:
            Result[AnnouncePromotionResponse, Error]: Always Ok.
        """
        return Result.Ok(AnnouncePromotionResponse())
