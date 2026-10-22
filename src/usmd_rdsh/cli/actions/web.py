"""``show web-interface``, ``show api-tokens``, ``execute api-token create|revoke``.

Minting and revoking tokens require ``api:manage``, which no token holds: the
token API refuses those actions outright, so a leaked token cannot mint its
own successor. They are run from the console.
"""

from __future__ import annotations

import time
from enum import StrEnum

from nan_actions import action
from nan_actions.api.permissions import ApiPermission
from nan_actions.errors import SdkError
from pydantic import BaseModel, Field

from usmd_rdsh.cli.permissions import READ, TOKEN_PROFILES
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import fields, printer, table


@action(cli="show web-interface", description="Web interface status and address",
        permissions=[READ], cli_output=printer(lambda r: fields([
            ("Web interface", r["status"]),
            ("Configured", "enabled" if r["enabled"] else "disabled"),
            ("URL", r["url"] or "-"),
            ("TLS", "yes" if r["tls"] else "no"),
            ("Requests served", r["served"]),
            ("Requests rejected", r["rejected"]),
            ("Tokens", r["tokens"]),
        ])))
async def show_web_interface() -> dict:
    """Web interface status."""
    config = RUNTIME.config("system web-interface")
    web = RUNTIME.web
    return {
        "enabled": config.status,
        "status": "listening" if web and web.listening else "down",
        "url": web.url if web and web.listening else None,
        "tls": bool(config.tls_certificate),
        "served": web.served if web else 0,
        "rejected": web.rejected if web else 0,
        "tokens": len(RUNTIME.tokens.all()),
    }


def _when(stamp: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stamp)) if stamp else "never"


@action(cli="show api-tokens", description="Tokens accepted by the web interface",
        permissions=[READ], cli_output=printer(lambda rows: table(rows, [
            ("key_id", "Key ID"), ("name", "Name"), ("profile", "Profile"),
            ("created", "Created"), ("last_used", "Last used")])))
async def show_api_tokens() -> list[dict]:
    """Tokens; the secrets themselves are never stored and never shown."""
    return [
        {
            "key_id": t.key_id,
            "name": t.name,
            "profile": t.profile,
            "created": _when(t.created),
            "last_used": _when(RUNTIME.tokens.last_used.get(t.key_id)),
        }
        for t in RUNTIME.tokens.all()
    ]


Profile = StrEnum("Profile", {name.upper(): name for name in TOKEN_PROFILES})


class TokenCreateInput(BaseModel):
    """A new token."""

    name: str = Field(description="Who or what will use it")
    profile: Profile = Field(Profile.MONITOR, description="monitor (read) or admin")


@action(cli="execute api-token create", description="Mint a web/API token (shown once)",
        permissions=[ApiPermission.MANAGE],
        cli_output=printer(lambda r: (
            f"Token for '{r['name']}' ({r['profile']}), key id {r['key_id']}:\n\n"
            f"    {r['token']}\n\n"
            "It is shown once and cannot be recovered. Paste it into the web "
            "interface login, or send it as 'Authorization: Bearer <token>'.")))
async def execute_api_token_create(data: TokenCreateInput) -> dict:
    """Mint a token."""
    token = RUNTIME.tokens.mint(data.name, str(data.profile))
    return {"name": data.name, "profile": str(data.profile), "key_id": token.key_id,
            "token": token.plaintext}


class TokenRevokeInput(BaseModel):
    """The token to revoke."""

    key_id: str = Field(description="Key id, as 'show api-tokens' lists it")


@action(cli="execute api-token revoke", description="Revoke a web/API token",
        permissions=[ApiPermission.MANAGE], cli_confirm="Revoke token {key_id}?")
async def execute_api_token_revoke(data: TokenRevokeInput) -> dict:
    """Revoke a token; the next request presenting it is refused."""
    if not RUNTIME.tokens.revoke(data.key_id):
        raise SdkError(f"no token with key id '{data.key_id}'")
    return {"revoked": data.key_id}
