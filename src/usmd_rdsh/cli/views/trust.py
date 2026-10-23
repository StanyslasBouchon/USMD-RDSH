"""``config trust nal``: statically granted roles [ARCH 4.3, NCP 7.3]."""

from nan_actions.views import ConfigNode, view
from pydantic import BaseModel, Field

from usmd_rdsh.cli.bridge import apply_local
from usmd_rdsh.cli.views.common import NODE_ACCESS, IPv4, Role, Ulid


class NalEntryConfig(BaseModel):
    """One NAL entry."""

    public_key: str = Field(description="Ed25519 public key (base64url)")
    roles: list[Role] = Field([], description="usc-operator usd-operator node-operator ...")


@view("trust nal", model=NalEntryConfig, table=True, key="public-key", **NODE_ACCESS)
class NalView(ConfigNode):
    """Node Access List entries configured by the administrator (permanent)."""

    async def apply(self, config: dict[str, NalEntryConfig]) -> None:
        await apply_local("trust nal", config)


class UscPeerConfig(BaseModel):
    """A contact node of another USD of the USC."""

    usdn: Ulid = Field(description="USDN of the other USD (member of the USC in force)")
    address: IPv4 = Field("", description="IPv4 address of a node of that USD")
    public_key: str = Field("", description="Its Ed25519 public key (base64url)")
    x25519_key: str = Field("", description="Its X25519 public key (base64url)")


@view("trust usc-peer", model=UscPeerConfig, table=True, key="usdn", **NODE_ACCESS)
class UscPeerView(ConfigNode):
    """How an elected usc-operator reaches the other USDs [ARCH 12.5]: one contact
    node each; it names the usc-operator elected there, which relays."""

    async def apply(self, config: dict[str, UscPeerConfig]) -> None:
        await apply_local("trust usc-peer", config)
