"""Node state registry [ARCH-02 5.5]: 16 bits, family in the top 4 bits."""

from __future__ import annotations

from enum import IntEnum


class State(IntEnum):
    """Every registered state."""

    APPROVAL_REQUIRED = 0x0000
    SYNCHRONISING = 0x1000
    ACTIVE = 0x2000
    INACTIVE = 0x3000
    INACTIVE_MUTATING = 0x3100
    INACTIVE_TIMEOUT = 0x3200
    INACTIVE_EMERGENCY = 0x3300
    INACTIVE_EMERGENCY_RESOURCES = 0x3301
    INACTIVE_EMERGENCY_DEPENDENCIES = 0x3302
    INACTIVE_EMERGENCY_HEALTH_CHECK = 0x3303
    INACTIVE_EMERGENCY_UPDATE = 0x3304
    INACTIVE_NNDP_TIMEOUT = 0x3400
    EXCLUDED_NIT_ASSOCIATION = 0x4000
    EXCLUDED_INVALID_ENDORSEMENT = 0x4100
    EXCLUDED_UNVERIFIABLE_ENDORSEMENT = 0x4200
    EXCLUDED_INVALID_END_OF_SERVICE = 0x4300
    EXCLUDED_INVALID_REVOCATION = 0x4400

    @property
    def family(self) -> int:
        return self.value >> 12

    @property
    def observed(self) -> bool:
        """Origin O: attributed by a peer, never declared [ARCH 5.5]."""
        return self.family == 0x4 or self in (State.INACTIVE_TIMEOUT, State.INACTIVE_NNDP_TIMEOUT)

    @property
    def declarable(self) -> bool:
        """Whether a node may declare this state about itself."""
        return not self.observed

    @property
    def excluded(self) -> bool:
        """Family 0x4000: local to the node pronouncing it, never announced."""
        return self.family == 0x4

    @property
    def inactive(self) -> bool:
        return self.family == 0x3

    @property
    def label(self) -> str:
        return LABELS[self]


#: French labels of the registry table.
LABELS: dict[State, str] = {
    State.APPROVAL_REQUIRED: "En attente d'approbation",
    State.SYNCHRONISING: "En cours de synchronisation",
    State.ACTIVE: "Actif",
    State.INACTIVE: "Inactif",
    State.INACTIVE_MUTATING: "Inactif : en cours de mutation",
    State.INACTIVE_TIMEOUT: "Inactif : délai d'attente dépassé",
    State.INACTIVE_EMERGENCY: "Inactif : demande d'urgence créée",
    State.INACTIVE_EMERGENCY_RESOURCES: "Inactif : urgence : à court de ressources matérielles",
    State.INACTIVE_EMERGENCY_DEPENDENCIES: "Inactif : urgence : dépendances inactives",
    State.INACTIVE_EMERGENCY_HEALTH_CHECK: "Inactif : urgence : contrôle de santé échoué",
    State.INACTIVE_EMERGENCY_UPDATE: "Inactif : urgence : mise à jour non réussie",
    State.INACTIVE_NNDP_TIMEOUT: "Inactif : NNDP : aucun HIA reçu dans le délai imparti",
    State.EXCLUDED_NIT_ASSOCIATION: "Exclu : association NIT incorrecte",
    State.EXCLUDED_INVALID_ENDORSEMENT: "Exclu : paquet d'endossement invalide",
    State.EXCLUDED_UNVERIFIABLE_ENDORSEMENT: "Exclu : paquet d'endossement invérifiable",
    State.EXCLUDED_INVALID_END_OF_SERVICE: "Exclu : demande de fin de service invalide",
    State.EXCLUDED_INVALID_REVOCATION: "Exclu : demande de révocation invalide",
}


def transition_allowed(current: State, new: State) -> bool:
    """[ARCH 5.6]: 0x0000 -> 0x1000 -> 0x2000 <-> 0x3xxx; any -> 0x0000 (new
    admission). Family 0x4000 is never a node's own state."""
    if new == current:
        return True
    if new.excluded or new.observed:
        return False
    if new == State.APPROVAL_REQUIRED:
        return True
    if current == State.APPROVAL_REQUIRED:
        return new == State.SYNCHRONISING
    if current == State.SYNCHRONISING:
        return new in (State.ACTIVE, State.APPROVAL_REQUIRED)
    if current == State.ACTIVE or current.inactive:
        return new == State.ACTIVE or new.inactive
    return False


def parse_state(value: int) -> State:
    """A registered state, or ValueError for a reserved code (0x5xxx-0xFxxx...)."""
    return State(value)
