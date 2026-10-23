"""``config mutation`` and ``config service``: roles and what they run [ARCH 8]."""

from enum import StrEnum
from typing import Self

from nan_actions.views import ConfigNode, view
from pydantic import BaseModel, Field, field_validator, model_validator

from usmd_rdsh.cli.bridge import AUTHORITY
from usmd_rdsh.cli.views.common import NODE_ACCESS, IPv4


class MutationConfig(BaseModel):
    """A mutation: a role a node takes, the services it runs [ARCH 8, 8.6].

    A node takes it by transmutation (``execute node transmute mutation=<name>``
    or a delegation); the bounds say how many nodes of the USD hold it.
    """

    name: str = Field(description="Role name, e.g. web; given to 'execute node transmute'")
    services: list[str] = Field(
        [], description="Catalogue services ('config service') a node of this role runs"
    )
    min_instances: int = Field(1, ge=0, description="Nodes of the USD that should hold this role")
    max_instances: int = Field(
        0, ge=0, description="Nodes that may hold it at most; beyond, delegations are refused "
                             "(0 = no limit)"
    )
    average_transmutation: int = Field(
        60, ge=0, description="Seconds a node takes to adopt the role, builds included "
                              "(Tmoy) [ARCH 7.1]"
    )

    @model_validator(mode="after")
    def _bounds(self) -> Self:
        if self.max_instances and self.max_instances < self.min_instances:
            raise ValueError("max-instances cannot be below min-instances")
        if len(set(self.services)) != len(self.services):
            raise ValueError("a service is listed twice")
        return self


@view("mutation", model=MutationConfig, table=True, key="name", **NODE_ACCESS)
class MutationView(ConfigNode):
    """Mutations: roles a node can take, their services and how many nodes hold them."""

    async def apply(self, config) -> None:
        AUTHORITY.record("mutation", config)

    async def settle(self) -> None:
        await AUTHORITY.settle()


class ServiceType(StrEnum):
    """[ARCH 8.2]."""

    STATIC = "static"
    DYNAMIC = "dynamic"


class ServiceConfig(BaseModel):
    """A service: its catalogue entry [ARCH-02 11.1] and its service file [ARCH 8.3].

    Since ARCH-02 the VIP and the group address belong to the USD's catalogue,
    not to the service file; both halves are configured on one row here.
    """

    name: str = Field(description="Application name, unique in the USD, e.g. nginx")
    id: str = Field(description="3 hex digits, 001 to ffe, unique: SP addresses are sss.nnnn")
    area: str = Field(description="Service area ('config service-area'); its dependencies share it")
    type: ServiceType = Field(
        ServiceType.STATIC, description="static: identical instances; dynamic: own data per instance"
    )
    dependencies: list[str] = Field(
        [], description="Services of the same area it needs; they may run on other nodes"
    )
    vip: IPv4 = Field("", description="Address reaching the nearest instance (sss.0000), in the "
                                      "area prefix")
    group: IPv4 = Field("", description="Multicast address reaching every instance (sss.ffff), "
                                        "in 239.0.0.0/8; optional")
    service_file: str = Field("", description="YAML file of the build, unbuild, check_health, "
                                              "emergency, update sequences; empty: no command")
    files: list[str] = Field(
        [], description="Files on the authority the sequences use (scripts, SQL...): signed with "
                        "the mutation, written to $USMD_FILES_DIR on every node hosting it")
    step_timeout: int = Field(300, ge=1, description="Unused: set 'timeout:' per step in the "
                                                     "service file (300 s by default)")

    @field_validator("id")
    @classmethod
    def _service_id(cls, value: str) -> str:
        try:
            number = int(value, 16)
        except ValueError as exc:
            raise ValueError("id is three hexadecimal digits, e.g. 0a1") from exc
        if not 0x001 <= number <= 0xFFE:
            raise ValueError("id ranges from 001 to ffe (000 and fff are reserved)")
        return f"{number:03x}"

    @model_validator(mode="after")
    def _coherent(self) -> Self:
        if self.group and not self.group.startswith("239."):
            raise ValueError("group must be in 239.0.0.0/8")
        if self.name in self.dependencies:
            raise ValueError("a service cannot depend on itself")
        return self


@view("service", model=ServiceConfig, table=True, key="name", **NODE_ACCESS)
class ServiceView(ConfigNode):
    """Services: applications nodes run, their catalogue entry and how to build them."""

    async def settle(self) -> None:
        await AUTHORITY.settle()

    async def apply(self, config: dict[str, ServiceConfig]) -> None:
        AUTHORITY.record("service", config)
        # Uniqueness spans rows; the area and dependency checks span nodes and
        # are reported by 'show service catalog' rather than refused here,
        # because the areas may be committed in the same block.
        for attribute in ("id", "vip", "group"):
            seen: dict[str, str] = {}
            for service in config.values():
                value = getattr(service, attribute)
                if value and value in seen:
                    raise ValueError(
                        f"services '{seen[value]}' and '{service.name}' share {attribute} {value}"
                    )
                seen[value] = service.name