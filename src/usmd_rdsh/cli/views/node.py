"""``config system bootstrap`` / ``trust-anchor``: what the administrator hands a node at creation [ARCH 5.1, 4.4]."""

from typing import Annotated

from nan_actions.views import ConfigNode, Secret, view
from pydantic import BaseModel, Field

from usmd_rdsh.cli.bridge import apply_local
from usmd_rdsh.cli.views.common import NODE_ACCESS, IPv4, Role


class BootstrapConfig(BaseModel):
    """Roles, creation token and where to look for an admitted node."""

    roles: list[Role] = Field(
        [Role.NODE_EXECUTOR],
        description="Roles the node is authorised for; every node is an executor, "
                    "operators are elected by the USD master [ARCH 12.4]",
    )
    creation_token: Annotated[str, Secret] = Field(
        "", description="Token signed by the USD operator [NCP 7.7]"
    )
    contact_node: IPv4 = Field("", description="Admitted node to contact first")
    contact_node_ed25519: str = Field("", description="Its Ed25519 public key (base64url)")
    contact_node_x25519: str = Field("", description="Its X25519 public key (base64url)")
    edb_domain: str = Field("", description="Domain publishing /.well-known/usmd/edb")


@view("system bootstrap", model=BootstrapConfig, **NODE_ACCESS)
class BootstrapView(ConfigNode):
    """Roles, creation token, contact node and EDB used to join the USD."""

    async def apply(self, config: BootstrapConfig) -> None:
        await apply_local("system bootstrap", config)


class TrustAnchorConfig(BaseModel):
    """Public keys recorded permanently in the NAL at creation."""

    usc_public_key: str = Field("", description="Ed25519 key of the USC (base64url)")
    usd_public_key: str = Field("", description="Ed25519 key of the USD (base64url)")


@view("system trust-anchor", model=TrustAnchorConfig, **NODE_ACCESS)
class TrustAnchorView(ConfigNode):
    """USC and USD public keys this node trusts."""

    async def apply(self, config: TrustAnchorConfig) -> None:
        await apply_local("system trust-anchor", config)
