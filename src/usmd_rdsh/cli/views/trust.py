"""``config trust nal``: statically granted roles [ARCH 4.3, NCP 7.3]."""

from nan_actions.views import ConfigNode, view
from pydantic import BaseModel, Field

from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.views.common import NODE_ACCESS, Role
from usmd_rdsh.sys.nal import NodeAccess
from usmd_rdsh.sys.nal import Role as NalRole


class NalEntryConfig(BaseModel):
    """One NAL entry."""

    public_key: str = Field(description="Ed25519 public key (base64url)")
    roles: list[Role] = Field([], description="usc-operator usd-operator node-operator ...")


@view("trust nal", model=NalEntryConfig, table=True, key="public-key", **NODE_ACCESS)
class NalView(ConfigNode):
    """Node Access List entries configured by the administrator."""

    #: Keys this node put in the NAL at the previous apply.
    _keys: frozenset[str] = frozenset()

    async def apply(self, config: dict[str, NalEntryConfig]) -> None:
        if RUNTIME.core is None:
            return
        # Configured entries replace the configured ones of the previous commit;
        # entries learnt from endorsements are left alone.
        nal = RUNTIME.core.tables.nal
        nal[:] = [entry for entry in nal if entry.ed25519_pub_key_32 not in self._keys]
        for key, entry in config.items():
            nal.append(
                NodeAccess(
                    ed25519_pub_key_32=key,
                    roles=[NalRole[role.name] for role in entry.roles],
                )
            )
        self._keys = frozenset(config)
