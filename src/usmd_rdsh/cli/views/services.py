"""``config mutation`` and ``config service``: roles and what they run [ARCH 8]."""

from enum import StrEnum
from typing import Self

from nan_actions.views import ConfigNode, view
from pydantic import BaseModel, Field, field_validator, model_validator

from usmd_rdsh.cli.views.common import NODE_ACCESS, IPv4


class MutationConfig(BaseModel):
    """A mutation: a set of services and their instance bounds [ARCH 8.6]."""

    name: str = Field(description="Mutation name")
    services: list[str] = Field([], description="Services hosted by this mutation")
    min_instances: int = Field(1, ge=0, description="Lowest number in the USD")
    max_instances: int = Field(0, ge=0, description="Highest number (0 = unbounded)")
    average_transmutation: int = Field(60, ge=0, description="Tmoy, seconds [ARCH 7.1]")

    @model_validator(mode="after")
    def _bounds(self) -> Self:
        if self.max_instances and self.max_instances < self.min_instances:
            raise ValueError("max-instances cannot be below min-instances")
        return self


@view("mutation", model=MutationConfig, table=True, key="name", **NODE_ACCESS)
class MutationView(ConfigNode):
    """Mutations: services and instance bounds."""


class ServiceType(StrEnum):
    """[ARCH 8.2]."""

    STATIC = "static"
    DYNAMIC = "dynamic"


class ServiceConfig(BaseModel):
    """A service: its catalogue entry [ARCH-02 11.1] and its service file [ARCH 8.3].

    Since ARCH-02 the VIP and the group address belong to the USD's catalogue,
    not to the service file; both halves are configured on one row here.
    """

    name: str = Field(description="Service name, unique in the USD")
    id: str = Field(description="12-bit identifier, 3 hex digits: 001 to ffe")
    area: str = Field(description="Service area the service belongs to")
    type: ServiceType = Field(ServiceType.STATIC, description="static or dynamic")
    dependencies: list[str] = Field([], description="Services of the same area it needs")
    vip: IPv4 = Field("", description="SP virtual address, in the area prefix (sss.0000)")
    group: IPv4 = Field("", description="SP group address in 239.0.0.0/8 (sss.ffff)")
    service_file: str = Field("", description="YAML file: build, unbuild, emergency...")
    step_timeout: int = Field(300, ge=1, description="Default step timeout, seconds")

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
    """Service catalogue and service files: id, area, VIP, type, dependencies."""

    async def apply(self, config: dict[str, ServiceConfig]) -> None:
        # Uniqueness spans rows; the area and dependency checks span nodes and
        # are reported by 'show service catalog' rather than refused here,
        # because the areas may be committed in the same block.
        for attribute in ("id", "vip"):
            seen: dict[str, str] = {}
            for service in config.values():
                value = getattr(service, attribute)
                if value and value in seen:
                    raise ValueError(
                        f"services '{seen[value]}' and '{service.name}' share {attribute} {value}"
                    )
                seen[value] = service.name