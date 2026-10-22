"""Who may do what on the management plane.

Two operator permissions plus the two the token API defines. The console is
one local operator holding all of them; a web/API token holds what it was
minted with, never ``api:manage``, so a token can neither mint another token nor
switch the web interface off and on behind the administrator's back.
"""

from nan_actions import ActionActor
from nan_actions.api.permissions import ApiPermission

#: Read the node: every ``show`` and every ``get`` of the configuration tree.
READ = "usmd:read"
#: Change the node: ``config``, ``clear``, ``execute``.
WRITE = "usmd:write"

VOCABULARY: tuple[str, ...] = (READ, WRITE, *ApiPermission.ALL)

#: What a token may be minted with, by profile name.
TOKEN_PROFILES: dict[str, tuple[str, ...]] = {
    "monitor": (READ, ApiPermission.ACCESS),
    "admin": (READ, WRITE, ApiPermission.ACCESS),
}


def console_actor() -> ActionActor:
    """The operator at the local console: everything."""
    return ActionActor.authenticated(
        user_id="console",
        username="console",
        permissions=VOCABULARY,
        source="cli",
    )
