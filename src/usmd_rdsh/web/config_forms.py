"""Configuration forms of the web interface, generated from the view tree.

    GET  /web/config   every node the token may read: fields, types, defaults,
                       choices, and the committed values (rows for a table)
    POST /web/config   one node's changes, applied through a view session

Nothing here knows a node by name. The schema is read off the same
``ViewRegistry`` the console walks, so a node declared tomorrow has a form
tomorrow; and a change is turned into the console lines an operator would have
typed (``config <path>`` / ``edit <key>`` / ``set`` / ``unset`` / ``end``) and run
in a view session of its own, so the model validation, the ``apply`` of each
subsystem, the rollback and the save on commit are exactly the console's.
"""

from __future__ import annotations

import enum
from typing import Any

from nan_actions import ActionActor, action_is_available
from nan_actions.views import UNSET, ViewSession, views
from nan_actions.views.errors import ViewError
from nan_actions.views.node import ViewDef

from usmd_rdsh.cli.bridge import after_commit
from usmd_rdsh.cli.runtime import RUNTIME


def _kind(spec) -> str:
    """The input a form draws for one field."""
    if spec.is_bool:
        return "bool"
    if spec.is_list:
        return "list"
    if spec.choices:
        return "choice"
    if spec.base in (int,):
        return "int"
    if spec.base in (float,):
        return "float"
    return "text"


def _plain(value: Any) -> Any:
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(v) for v in value]
    return value


def _field(spec) -> dict[str, Any]:
    default = None if spec.default is UNSET else _plain(spec.default)
    return {
        "name": spec.name,
        "cli": spec.cli_name,
        "kind": _kind(spec),
        "choices": list(spec.choices or []),
        "default": None if spec.is_secret else default,
        "required": spec.required,
        "secret": spec.is_secret,
        "description": spec.description,
    }


def _values(node: ViewDef, stored: dict[str, Any]) -> dict[str, Any]:
    effective = node.fields.effective(stored)
    out: dict[str, Any] = {}
    for spec in node.fields.specs():
        value = effective.get(spec.name, UNSET)
        if spec.is_secret:
            out[spec.name] = "" if not stored.get(spec.name) else "********"
        else:
            out[spec.name] = None if value is UNSET else _plain(value)
    return out


def schema(actor: ActionActor) -> dict[str, Any]:
    """Every readable node, with its committed values."""
    nodes = []
    for node in views.nodes():
        if not views.is_visible(node.path, actor, write=False):
            continue
        entry: dict[str, Any] = {
            "path": node.cli_path,
            "description": node.description,
            "table": node.table,
            "key": node.key,
            "writable": views.is_visible(node.path, actor, write=True),
            "fields": [_field(spec) for spec in node.fields.specs()],
        }
        if node.table:
            entry["rows"] = {
                key: _values(node, stored)
                for key, stored in RUNTIME.document.rows(node.path).items()
            }
        else:
            stored = RUNTIME.document.fields(node.path)
            entry["values"] = _values(node, stored)
            entry["explicit"] = sorted(stored)
        nodes.append(entry)
    return {"nodes": nodes}


def _quote(value: Any) -> str:
    text = str(value)
    return '"' + text.replace('"', '""') + '"'


def _set_line(spec, value: Any) -> str | None:
    """The console line setting one field, or None for "back to default"."""
    if value is None or value == "" and not spec.is_list:
        return f"unset {spec.cli_name}"
    if spec.is_bool:
        return f"set {spec.cli_name} {'enable' if value else 'disable'}"
    if spec.is_list:
        items = value if isinstance(value, list) else str(value).split()
        if not items:
            return f"unset {spec.cli_name}"
        return f"set {spec.cli_name} " + " ".join(_quote(v) for v in items)
    return f"set {spec.cli_name} {_quote(value)}"


def lines_for(request: dict[str, Any]) -> list[str]:
    """The console lines one form submission stands for."""
    node = views.get(tuple(str(request.get("path", "")).split()))
    if node is None:
        raise ViewError(f"no configuration node '{request.get('path')}'")
    lines = [f"config {node.cli_path}"]
    key = request.get("key")
    if node.table:
        if not key:
            raise ViewError("a table entry needs its key")
        if request.get("delete"):
            return lines + [f"delete {_quote(key)}", "end"]
        lines.append(f"edit {_quote(key)}")
    values = request.get("values") or {}
    for spec in node.fields.specs():
        if node.table and spec.cli_name == node.key:
            continue
        if spec.name not in values:
            continue
        value = values[spec.name]
        if spec.is_secret and value == "********":
            continue  # unchanged secret, shown masked
        line = _set_line(spec, value)
        if line:
            lines.append(line)
    if node.table:
        lines.append("next")
    lines.append("end")
    return lines


async def apply(actor: ActionActor, request: dict[str, Any]) -> dict[str, Any]:
    """Run one submission in a view session of its own; all or nothing."""
    if not action_is_available([], actor):
        raise ViewError("not authenticated")
    session = ViewSession(
        views,
        RUNTIME.document,
        on_commit=after_commit,
        actor_factory=lambda: actor,
    )
    output: list[str] = []
    try:
        for line in lines_for(request):
            text = await session.execute(line)
            if text:
                output.append(str(text))
    except ViewError as exc:
        # Leave nothing half-open: the next submission starts clean.
        while session.active:
            await session.execute("abort")
        return {"ok": False, "error": exc.message, "output": output}
    return {"ok": True, "output": output}
