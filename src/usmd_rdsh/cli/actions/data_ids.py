"""Service instances and their data identifiers [ARCH-03 8.7, 11.6]:

    show service environment          the USMD_* variables a service's sequences get
    show data-id                      decode an identifier: instance and creation time
    execute data-id generate          identifiers for an instance hosted here
    show data-id postgresql           the PostgreSQL generator (usmd_id())
"""

from __future__ import annotations

from nan_actions import action
from nan_actions.errors import SdkError
from pydantic import BaseModel, Field

from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import fields, printer, table
from usmd_rdsh.node import addresses, dataid
from usmd_rdsh.node.services import ServiceSpec

#: One generator per instance, so identifiers of this node never repeat.
_GENERATORS: dict[int, dataid.DataIdGenerator] = {}


def _address(service: str) -> int:
    node = RUNTIME.node
    if node is None:
        raise SdkError("the node is not running")
    if node.signed.service_by_name(service) is None:
        raise SdkError(f"no service '{service}' in the catalogue [ARCH 11.1]")
    address = node.service_address(service)
    if address is None:
        raise SdkError(f"no management id for '{service}' yet: "
                       "'execute management-id request' [ARCH 11.4]")
    return address


class ServiceInput(BaseModel):
    service: str = Field(description="Service name, as in the catalogue")


@action(cli="show service environment",
        description="Variables given to a service's sequences [ARCH-03 8.7]",
        permissions=[READ], cli_output=printer(lambda r: fields(sorted(r.items()))))
async def show_service_environment(data: ServiceInput) -> dict:
    _address(data.service)
    env = RUNTIME.node.service_environment(ServiceSpec(data.service), "build")
    env["USMD_SEQUENCE"] = "(the running sequence)"
    return env


class DataIdInput(BaseModel):
    id: str = Field(description="Data identifier (UUID)")


@action(cli="show data-id", description="Instance and creation time of a data identifier "
        "[ARCH-03 11.6]", permissions=[READ], cli_output=printer(lambda r: fields([
            ("Identifier", r["id"]), ("SP address", r["sp_address"]),
            ("Service", r["service"]), ("Management id", r["management_id"]),
            ("Created", r["created"]), ("Sequence", r["sequence"])])))
async def show_data_id(data: DataIdInput) -> dict:
    try:
        decoded = dataid.decode(data.id)
    except ValueError as exc:
        raise SdkError(f"not a USMD-RDSH data identifier: {exc}") from exc
    node = RUNTIME.node
    entry = node.signed.catalog().get(decoded.service_id) if node else None
    return {"id": data.id.strip().lower(), "sp_address": decoded.sp_text,
            "service": f"{decoded.service_id:03x}" + (f" ({entry.name})" if entry else ""),
            "management_id": f"{decoded.management_id:04x}", "created": decoded.created,
            "sequence": decoded.sequence}


class GenerateInput(BaseModel):
    service: str = Field(description="Service name, as in the catalogue")
    count: int = Field(1, ge=1, le=1000, description="How many identifiers")


@action(cli="execute data-id generate",
        description="Data identifiers of this node's instance of a service [ARCH-03 11.6]",
        permissions=[WRITE], cli_output=printer(lambda rows: table(rows, [("id", "Identifier")])))
async def execute_data_id_generate(data: GenerateInput) -> list[dict]:
    address = _address(data.service)
    generator = _GENERATORS.setdefault(address, dataid.DataIdGenerator(address))
    return [{"id": str(generator.next())} for _ in range(data.count)]


class PostgresInput(BaseModel):
    service: str = Field("", description="Service whose prefix is set; empty for none")
    database: str = Field("app", description="Database that gets the prefix")


@action(cli="show data-id postgresql",
        description="PostgreSQL generator usmd_id() of the data identifiers [ARCH-03 11.6]",
        permissions=[READ], cli_output=printer(lambda r: r["sql"].rstrip()))
async def show_data_id_postgresql(data: PostgresInput) -> dict:
    address = _address(data.service) if data.service else None
    try:
        sql = dataid.postgresql(address, data.database)
    except ValueError as exc:
        raise SdkError(str(exc)) from exc
    return {"sql": sql, "prefix": dataid.prefix(address) if address is not None else "",
            "sp_address": addresses.to_text(address) if address is not None else ""}
