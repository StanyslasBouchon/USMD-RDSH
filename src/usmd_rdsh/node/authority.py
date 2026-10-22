"""Keys of the authority (USC) and of the USD operator, when this node holds them.

[ARCH-02 3.3, 12]: the USC private key signs every configuration object and
DOIT be kept offline or in an HSM; the USD private key signs creation tokens
and DOIT be protected likewise. A node normally holds neither. An operator
workstation running USMD-RDSH may hold one or both under
``<state>/authority/`` (owner-only); the management plane then offers to sign
and inject configuration and to mint creation tokens. The private keys are
never printed and never sent.

The same directory keeps the authority's memory: founder tokens minted per
USD [NCP 7.7] (``founders.json``) and service identifiers retired from the
catalogue [ARCH 11.1] (``retired.json``). :func:`export_signed` and
:func:`import_signed` carry signed objects from an offline authority to the
network [ARCH 3.3, 14].
"""

from __future__ import annotations

import os
from pathlib import Path

from nan_runtime.state import StateDirectory

from usmd_rdsh.node.crypto import SigningKey, b64u, unb64u
from usmd_rdsh.node.ncp.codec import (
    CreationToken,
    MutationProperties,
    Role,
    UscProperties,
    UsdProperties,
)
from usmd_rdsh.node.signed import SignedConfig
from usmd_rdsh.node.wire import Reader, WireError, now_ms

MAX_TOKEN_VALIDITY_MS = 7 * 24 * 3600 * 1000
#: [ARCH 11.1] a retired service identifier is not reused before the NNDP
#: entries announcing it have expired; one hour bounds that conservatively.
SERVICE_ID_QUARANTINE_MS = 3600 * 1000


class Authority:
    """The USC and USD private keys present on this node, if any."""

    def __init__(self, state: StateDirectory) -> None:
        self._state = state
        self.usc: SigningKey | None = self._load("usc.key")
        self.usd: SigningKey | None = self._load("usd.key")

    def _path(self, name: str) -> Path:
        return self._state.path("authority", name)

    def _load(self, name: str) -> SigningKey | None:
        path = self._path(name)
        if not path.exists():
            return None
        return SigningKey(unb64u(path.read_text(encoding="ascii").strip()))

    def generate(self, which: str) -> SigningKey:
        """Create the USC or USD key pair here; refuses to overwrite one."""
        if which not in ("usc", "usd"):
            raise ValueError("usc or usd")
        if getattr(self, which) is not None:
            raise ValueError(f"this node already holds a {which.upper()} key")
        key = SigningKey.generate()
        self._state.ensure("authority")
        path = self._state.write_text(b64u(key.seed) + "\n", "authority", f"{which}.key",
                                      mode=0o600)
        if os.name != "nt":
            os.chmod(path, 0o600)
        setattr(self, which, key)
        return key

    def mint_token(  # pylint: disable=too-many-arguments
        self, usdn: str, node_key: bytes, roles: list[Role], *, validity_ms: int,
        founder: bool = False, allow_second_founder: bool = False,
    ) -> CreationToken:
        """A creation token [NCP 7.7]; at most 7 days.

        The USD operator SHOULD issue only one founder token per USD [NCP 7.7]:
        the founder tokens minted here are recorded per USDN in
        ``<state>/authority/founders.json`` and a second one is refused unless
        ``allow_second_founder`` (e.g. the first was lost before use).
        """
        if self.usd is None:
            raise ValueError("this node does not hold the USD key")
        if not 0 < validity_ms <= MAX_TOKEN_VALIDITY_MS:
            raise ValueError("a creation token is valid at most 7 days")
        founders = self._read("founders.json")
        if founder and usdn in founders and not allow_second_founder:
            raise ValueError(
                f"a founder token was already issued for {usdn} "
                f"(node {founders[usdn][-1]['node_key']}); only one SHOULD exist [NCP 7.7]"
            )
        issued = now_ms()
        token = CreationToken(usdn, node_key, [int(r) for r in roles], issued,
                              issued + validity_ms, self.usd.public, founder=founder)
        token.sign(self.usd)
        if founder:
            founders.setdefault(usdn, []).append({"node_key": b64u(node_key), "issued": issued})
            self._write("founders.json", founders)
        return token

    # -- retired service identifiers [ARCH 11.1] ---------------------------------

    def retire_service(self, service_id: int, *, now: int | None = None) -> None:
        """Record that ``service_id`` left the catalogue (``retired.json``)."""
        retired = self._read("retired.json")
        retired[f"{service_id:03x}"] = now_ms() if now is None else now
        self._write("retired.json", retired)

    def reuse_allowed(self, service_id: int, *, now: int | None = None) -> bool:
        """Whether a retired identifier may designate a service again [ARCH 11.1].

        Reuse waits until no NNDP announcement of the old service can still be
        held; :data:`SERVICE_ID_QUARANTINE_MS` (1 h) bounds that conservatively.
        """
        retired_at = self._read("retired.json").get(f"{service_id:03x}")
        if retired_at is None:
            return True
        current = now_ms() if now is None else now
        return current - int(retired_at) >= SERVICE_ID_QUARANTINE_MS

    # -- state files ---------------------------------------------------------------

    def _read(self, name: str) -> dict:
        data = self._state.read_json("authority", name, default=None)
        return data if isinstance(data, dict) else {}

    def _write(self, name: str, data: dict) -> None:
        self._state.ensure("authority")
        self._state.write_json(data, "authority", name)


# ---------------------------------------------------------------------------
# Offline signing [ARCH 3.3, 14]
# ---------------------------------------------------------------------------


def export_signed(signed: SignedConfig) -> dict:
    """The signed objects in force, each as the hex of its encoding.

    An offline authority signs on a machine that never joins the network;
    the export is carried to a node and given to :func:`import_signed`.
    """
    return {
        "usc": signed.usc.encode().hex() if signed.usc else None,
        "usd": signed.usd.encode().hex() if signed.usd else None,
        "mutations": [m.encode().hex() for m in signed.mutations.values()],
    }


def import_signed(
    data: dict,
) -> tuple[UscProperties | None, UsdProperties | None, list[MutationProperties]]:
    """Decode an :func:`export_signed` document; signatures are checked on injection."""
    try:
        usc = UscProperties.decode(bytes.fromhex(data["usc"])) if data.get("usc") else None
        usd = UsdProperties.decode(bytes.fromhex(data["usd"])) if data.get("usd") else None
        mutations = []
        for raw in data.get("mutations") or []:
            reader = Reader(bytes.fromhex(raw))
            mutations.append(MutationProperties.read(reader))
            reader.end()
    except (KeyError, TypeError, ValueError, WireError) as exc:
        raise ValueError(f"not an export of signed objects: {exc}") from exc
    return usc, usd, mutations
