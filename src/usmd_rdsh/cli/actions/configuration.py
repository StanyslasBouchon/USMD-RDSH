"""``show configuration``, ``show running-config``, ``show startup-config``,
``write memory``, ``write erase``.

The configuration is the view tree's document. A commit (``end``) already
saves it, so ``write memory`` is only there for the operator whose fingers type
it anyway - and for the node whose file was removed under it.
"""

from __future__ import annotations

from nan_actions import action
from nan_actions.views import ConfigDocument, ConfigRenderer, views

from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import printer


def _render(document: ConfigDocument, *, full: bool) -> str:
    body = ConfigRenderer(views, document).show(full=full)
    header = [
        "Building configuration...",
        "",
        f"Current configuration of {RUNTIME.hostname()}:",
        "!",
    ]
    return "\n".join(header + [body or "! (all values at their defaults)", "!", "end"])


@action(cli="show configuration", permissions=[READ],
        description="The whole configuration, defaults included",
        cli_output=printer(lambda r: r["text"]))
async def show_configuration() -> dict:
    """The whole configuration, defaults included."""
    return {"text": _render(RUNTIME.document, full=True),
            "document": RUNTIME.document.to_dict()}


@action(cli="show running-config", permissions=[READ],
        description="What differs from the defaults (like 'show')",
        cli_output=printer(lambda r: r["text"]))
async def show_running_config() -> dict:
    """What differs from the defaults."""
    return {"text": _render(RUNTIME.document, full=False),
            "document": RUNTIME.document.to_dict()}


@action(cli="show startup-config", permissions=[READ],
        description="The configuration saved on disk",
        cli_output=printer(lambda r: r["text"]))
async def show_startup_config() -> dict:
    """The configuration saved on disk, as the next start will read it."""
    saved = RUNTIME.config_store.load()
    return {"text": _render(saved, full=False), "document": saved.to_dict(),
            "path": str(RUNTIME.config_store.path)}


@action(cli="write memory", permissions=[WRITE],
        description="Save the running configuration to disk",
        cli_output=printer(lambda r: f"Building configuration...\n[OK] {r['path']}"))
async def write_memory() -> dict:
    """Save the running configuration."""
    await RUNTIME.config_store.save(RUNTIME.document)
    return {"path": str(RUNTIME.config_store.path)}


@action(cli="write erase", permissions=[WRITE],
        description="Reset every configured value to its default and save",
        cli_confirm="Erasing the configuration resets every value to its default. Continue?",
        cli_output=printer(lambda r: "[OK] Configuration erased; defaults applied."))
async def write_erase() -> dict:
    """Reset the configuration to its defaults, apply and save."""
    RUNTIME.document.replace_with(ConfigDocument())
    await RUNTIME.apply_all()
    await RUNTIME.config_store.save(RUNTIME.document)
    return {"erased": True}
