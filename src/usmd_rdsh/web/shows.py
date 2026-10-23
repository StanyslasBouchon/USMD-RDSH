"""Every ``show`` of the console, for the web interface's Commands page.

    GET  /web/shows        the ``show`` commands the token may run, with their
                           inputs (name, type, choices, default, description)
    POST /web/shows        {"cli": "show nndp", "args": {...}}: one of them,
                           run as the token's holder

The answer is what the console prints, cut into segments: the tables and the
``Label : value`` blocks of :mod:`usmd_rdsh.cli.text` come back as data (the
page draws them as sortable tables), the rest as text, plus the action's own
answer as JSON for the shows whose console output is free text. A new ``show`` is on the
page as soon as its action exists: nothing here names one.
"""

from __future__ import annotations

import json
import re
from typing import Any

from nan_actions import ActionActor, action_is_available, registry
from nan_actions.access import reset_current_action_actor, set_current_action_actor
from nan_runtime.log import reset_log_sink, set_log_sink, strip_level_prefix
from pydantic import BaseModel, ValidationError

from usmd_rdsh.cli.text import fields, recording, table

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_MAX_DATA = 256 * 1024


class ShowError(ValueError):
    """A ``show`` the page cannot run, with the HTTP status that says why."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _inputs(schema: type[BaseModel] | None) -> list[dict[str, Any]]:
    """The fields of an input model, as the page's form draws them."""
    if schema is None:
        return []
    document = schema.model_json_schema()
    definitions = document.get("$defs", {})
    required = set(document.get("required", []))
    out = []
    for name, spec in document.get("properties", {}).items():
        options = [s for s in spec.get("anyOf", [spec]) if s.get("type") != "null"]
        resolved = options[0] if options else {}
        if "$ref" in resolved:
            resolved = definitions.get(resolved["$ref"].rsplit("/", 1)[-1], {})
        out.append({
            "name": name,
            "type": "enum" if "enum" in resolved else resolved.get("type", "string"),
            "choices": [str(c) for c in resolved.get("enum", [])],
            "default": spec.get("default"),
            "required": name in required,
            "description": spec.get("description", ""),
        })
    return out


def catalog(actor: ActionActor) -> list[dict[str, Any]]:
    """The ``show`` commands *actor* may run, in console order."""
    shows = [d for d in registry.visible_actions(actor) if d.cli_path[:1] == ("show",)]
    return [{"cli": " ".join(d.cli_path), "description": d.description,
             "inputs": _inputs(d.input_schema)}
            for d in sorted(shows, key=lambda d: d.cli_path)]


def _generic(result: object) -> None:
    """What the console prints for an action without its own output."""
    from nan_runtime.log import emit  # pylint: disable=import-outside-toplevel

    if isinstance(result, list) and result and all(isinstance(r, dict) for r in result):
        keys = list(dict.fromkeys(k for r in result for k in r))
        emit(table(result, [(k, k) for k in keys]))
    elif isinstance(result, dict):
        emit(fields(list(result.items())))
    elif result is not None:
        emit(str(result))


def _segments(text: str, blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """*text* cut around the recorded blocks it contains, in order.

    A block inside another (fields rendered into a field's value) stays text of
    the outer one; a block the output does not contain as rendered is dropped.
    """
    outer = [b for b in blocks
             if b["text"] and not any(b is not o and b["text"] in o["text"]
                                      and len(o["text"]) > len(b["text"]) for o in blocks)]
    segments: list[dict[str, Any]] = []
    cursor = 0
    for block in outer:
        at = text.find(block["text"], cursor)
        if at < 0:
            continue
        before = text[cursor:at].strip("\n")
        if before.strip():
            segments.append({"kind": "text", "text": before})
        segments.append({k: v for k, v in block.items() if k != "text"})
        cursor = at + len(block["text"])
    rest = text[cursor:].strip("\n")
    if rest.strip():
        segments.append({"kind": "text", "text": rest})
    return segments


async def run(actor: ActionActor, cli: str, args: dict[str, Any]) -> dict[str, Any]:
    """One ``show``, as the console would print it, cut into segments."""
    words = tuple(cli.split())
    definition = registry.get_by_cli_path(*words) if words[:1] == ("show",) else None
    if definition is None:
        raise ShowError(404, f"No command '{cli}'.")
    if not action_is_available(definition.permissions, actor):
        raise ShowError(403, f"'{cli}' needs {', '.join(definition.permissions or [])}.")
    given = {k: v for k, v in args.items() if v not in ("", None)}
    try:
        data = definition.input_schema.model_validate(given) \
            if definition.input_schema else None
    except ValidationError as exc:
        raise ShowError(422, "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())) from exc

    lines: list[str] = []
    sink = set_log_sink(lambda text: lines.append(_ANSI.sub("", strip_level_prefix(text))))
    context = set_current_action_actor(actor)
    try:
        with recording() as blocks:
            result = await (definition.handler(data) if data is not None
                            else definition.handler())
            (definition.cli_output or _generic)(result)
    except Exception as exc:  # pylint: disable=broad-except
        raise ShowError(422, getattr(exc, "message", None) or str(exc)) from exc
    finally:
        reset_current_action_actor(context)
        reset_log_sink(sink)
    text = "\n".join(lines)
    return {"cli": cli, "text": text, "segments": _segments(text, blocks), "data": _data(result)}


def _data(result: object) -> Any:
    """The action's own answer as JSON, for a ``show`` whose console output is
    free text (``show version``): the page draws its fields instead. None when
    it does not serialise or is too large to be worth sending twice."""
    try:
        encoded = json.dumps(result, default=str)
    except (TypeError, ValueError):
        return None
    return json.loads(encoded) if len(encoded) <= _MAX_DATA else None
