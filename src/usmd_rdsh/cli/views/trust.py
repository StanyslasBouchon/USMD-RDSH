"""``config trust nal``: statically granted roles [ARCH 4.3, NCP 7.3]."""

from nan_actions.views import ConfigNode, view
from pydantic import BaseModel, Field

from usmd_rdsh.cli.bridge import apply_local
from usmd_rdsh.cli.views.common import NODE_ACCESS, Role


class NalEntryConfig(BaseModel):
    """One NAL entry."""

    public_key: str = Field(description="Ed25519 public key (base64url)")
    roles: list[Role] = Field([], description="usc-operator usd-operator node-operator ...")


@view("trust nal", model=NalEntryConfig, table=True, key="public-key", **NODE_ACCESS)
class NalView(ConfigNode):
    """Node Access List entries configured by the administrator (permanent)."""

    async def apply(self, config: dict[str, NalEntryConfig]) -> None:
        await apply_local("trust nal", config)