"""Signed configuration objects in force on this node [ARCH-02 3.3, 9].

The USC properties, the USD properties (areas, catalogue, parameters) and the
mutation properties are signed by the authority and versioned by the date of
their last change (ms). A node applies an object only when the signature is
valid for the authority key it knows and the version is strictly later than
the one it holds [9.3]. They survive restarts in ``signed.json``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from nan_runtime.state import StateDirectory

from usmd_rdsh.node.crypto import CryptoError
from usmd_rdsh.node.ncp.codec import MutationProperties, UscProperties, UsdProperties
from usmd_rdsh.node.wire import Reader, WireError

#: [ARCH-02 9.2] codes with their default and valid range.
USD_PARAMETERS: dict[int, tuple[str, int | None, int, int]] = {
    0x0001: ("reference_nodes", 5, 1, 64),
    0x0002: ("ping_tolerance", 1000, 1, 3_600_000),
    0x0003: ("solicited_nodes", 5, 1, 64),
    0x0004: ("weakened_threshold", 800, 1, 1000),
    0x0005: ("emergency_threshold", 950, 1, 1000),
    0x0006: ("distance_interval", 300, 1, 86_400),
    0x0007: ("load_sample_interval", 5, 1, 3600),
    0x0008: ("delegation_timeout", 30, 1, 3600),
    0x0009: ("dependency_interval", 30, 1, 3600),
    0x000A: ("instances_per_service", 3, 1, 64),
    0x000B: ("healing_interval", 60, 1, 3600),
    0x000C: ("health_check_interval", 30, 1, 3600),
    0x000D: ("endorsement_validity", 2_592_000, 60, 2**32 - 1),
    0x0010: ("sp_port", None, 1, 65535),
    0x0013: ("sp_mtu", 1412, 576, 9000),
    0x0014: ("voters", 5, 1, 15),
    0x0015: ("voter_removal_delay", 600, 1, 86_400),
}


def parameter(usd: UsdProperties | None, code: int) -> int | None:
    """A parameter in force; an absent one takes its default [9.2]."""
    name, default, _low, _high = USD_PARAMETERS[code]
    del name
    if usd is not None and code in usd.parameters:
        return usd.parameters[code]
    return default


def check_ranges(usd: UsdProperties) -> None:
    """A value out of range keeps the properties in force [9.2] (caller reports)."""
    for code, value in usd.parameters.items():
        if code in USD_PARAMETERS:  # unknown codes are ignored
            _name, _default, low, high = USD_PARAMETERS[code]
            if not low <= value <= high:
                raise WireError(f"parameter 0x{code:04X} = {value} out of {low}..{high}")
    x, nnr = parameter(usd, 0x0003), parameter(usd, 0x0001)
    if x is not None and nnr is not None and x > nnr:
        raise WireError("X (0x0003) cannot exceed NNR (0x0001)")


def is_retired(mutation: MutationProperties) -> bool:
    """A mutation the authority withdrew: a newer version signed with no service
    at all (an empty service file). It stays held so that the newer version
    keeps going round and every host unbuilds what it ran; nothing else uses it.
    A mutation in force runs at least one service (the authority refuses less)."""
    return not mutation.service_file.strip()


@dataclass
class SignedConfig:
    """What this node applies; only the authority can change it."""

    usc: UscProperties | None = None
    usd: UsdProperties | None = None
    mutations: dict[str, MutationProperties] = field(default_factory=dict)

    # -- application rules [9.3] -------------------------------------------------

    def offer_usc(self, obj: UscProperties, authority: bytes) -> bool:
        obj.verify(authority)
        if self.usc is not None and obj.version <= self.usc.version:
            return False
        obj.validate()
        self.usc = obj
        return True

    def offer_usd(self, obj: UsdProperties, authority: bytes) -> bool:
        obj.verify(authority)
        if self.usd is not None and obj.version <= self.usd.version:
            return False
        obj.validate()
        check_ranges(obj)
        self.usd = obj
        return True

    def offer_mutation(self, obj: MutationProperties, authority: bytes) -> bool:
        obj.verify(authority)
        held = self.mutations.get(obj.name)
        if held is not None and obj.version <= held.version:
            return False
        self.mutations[obj.name] = obj
        return True

    # -- derived views --------------------------------------------------------------

    def in_force(self) -> dict[str, MutationProperties]:
        """The mutations a node may hold: those the authority has not retired."""
        return {name: m for name, m in self.mutations.items() if not is_retired(m)}

    def areas(self) -> dict[int, ipaddress.IPv4Network]:
        if self.usd is None:
            return {}
        return {a.area_id: ipaddress.IPv4Network(f"{a.prefix}/{a.length}", strict=False)
                for a in self.usd.areas}

    def catalog(self):
        return {e.service_id: e for e in (self.usd.catalog if self.usd else [])}

    def service_by_name(self, name: str):
        return next((e for e in self.catalog().values() if e.name == name), None)

    def mutation_services(self, mutation: str) -> list[str]:
        """Names of the services a mutation's service file declares."""
        from usmd_rdsh.node.services import parse_service_file  # pylint: disable=import-outside-toplevel

        props = self.mutations.get(mutation)
        if props is None:
            return []
        try:
            return [s.name for s in parse_service_file(props.service_file)]
        except ValueError:
            return []

    def areas_of_mutation(self, mutation: str) -> set[int]:
        """[ARCH 11.2]: a node belongs to the areas of its mutation's services."""
        out = set()
        for name in self.mutation_services(mutation):
            entry = self.service_by_name(name)
            if entry is not None:
                out.add(entry.area_id)
        return out

    def services_in_areas(self, areas: set[int]) -> set[int]:
        return {e.service_id for e in self.catalog().values() if e.area_id in areas}

    # -- persistence -----------------------------------------------------------------

    def save(self, state: StateDirectory) -> None:
        state.write_json({
            "usc": self.usc.encode().hex() if self.usc else None,
            "usd": self.usd.encode().hex() if self.usd else None,
            "mutations": {n: m.encode().hex() for n, m in self.mutations.items()},
        }, "signed.json")

    @classmethod
    def load(cls, state: StateDirectory) -> "SignedConfig":
        data = state.read_json("signed.json", default=None) or {}
        out = cls()
        try:
            if data.get("usc"):
                out.usc = UscProperties.decode(bytes.fromhex(data["usc"]))
            if data.get("usd"):
                out.usd = UsdProperties.decode(bytes.fromhex(data["usd"]))
            for name, raw in (data.get("mutations") or {}).items():
                out.mutations[name] = MutationProperties.read(Reader(bytes.fromhex(raw)))
        except (WireError, CryptoError, ValueError):
            return cls()
        return out
