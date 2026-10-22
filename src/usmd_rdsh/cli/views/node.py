"""``config system bootstrap`` / ``trust-anchor``: what the administrator hands a node at creation [ARCH 5.1, 4.4]."""

from typing import Annotated

from nan_actions.views import ConfigNode, Secret, view
from pydantic import BaseModel, Field

from usmd_rdsh.cli.views.common import NODE_ACCESS, IPv4, Role


class BootstrapConfig(BaseModel):
    """Role, creation token and where to look for an admitted node."""

    role: Role = Field(Role.NODE_EXECUTOR, description="Role given at creation")
    creation_token: Annotated[str, Secret] = Field(
        "", description="Token signed by the USD operator [NCP 7.7]"
    )
    founder: bool = Field(
        False, description="Token carries the founder flag: first node of the USD [NCP-02 7.7]"
    )
    contact_node: IPv4 = Field("", description="Admitted node to contact first")
    edb_domain: str = Field("", description="Domain publishing /.well-known/usmd/edb")


@view("system bootstrap", model=BootstrapConfig, **NODE_ACCESS)
class BootstrapView(ConfigNode):
    """Role, creation token, contact node and EDB used to join the USD."""


class TrustAnchorConfig(BaseModel):
    """Public keys recorded permanently in the NAL at creation."""

    usc_public_key: str = Field("", description="Ed25519 key of the USC (base64url)")
    usd_public_key: str = Field("", description="Ed25519 key of the USD (base64url)")


@view("system trust-anchor", model=TrustAnchorConfig, **NODE_ACCESS)
class TrustAnchorView(ConfigNode):
    """USC and USD public keys this node trusts."""
