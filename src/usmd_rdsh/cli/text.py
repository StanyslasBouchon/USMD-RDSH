"""Console output in the IOS idiom: fixed-width columns, no box drawing.

Every action returns data, which is what the token API serialises and what
pipes filter. These helpers are its ``cli_output``: the way the same data
reads on a console.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterable, Iterator, Sequence

from nan_runtime.log import emit

#: While the web interface runs a ``show``, every table and field block it
#: renders, as data: the page draws them as tables instead of fixed columns.
_RECORDED: ContextVar[list[dict[str, Any]] | None] = ContextVar("recorded", default=None)


@contextmanager
def recording() -> Iterator[list[dict[str, Any]]]:
    """The blocks :func:`table` and :func:`fields` render inside the ``with``."""
    blocks: list[dict[str, Any]] = []
    token = _RECORDED.set(blocks)
    try:
        yield blocks
    finally:
        _RECORDED.reset(token)


def table(rows: Iterable[dict[str, Any]], columns: Sequence[tuple[str, str]]) -> str:
    """Rows as left-aligned columns under a header; ``columns`` is (key, title)."""
    materialised = [
        ["" if row.get(key) is None else str(row.get(key)) for key, _ in columns]
        for row in rows
    ]
    titles = [title for _, title in columns]
    widths = [
        max([len(title), *(len(r[i]) for r in materialised)])
        for i, title in enumerate(titles)
    ]
    lines = ["  ".join(t.ljust(w) for t, w in zip(titles, widths)).rstrip()]
    for row in materialised:
        lines.append("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip())
    text = "\n".join(lines)
    recorded = _RECORDED.get()
    if recorded is not None:
        recorded.append({"kind": "table", "text": text, "columns": titles,
                         "rows": materialised})
    return text


def fields(pairs: Sequence[tuple[str, Any]], indent: int = 0) -> str:
    """``Label : value`` lines with the colons aligned."""
    width = max((len(label) for label, _ in pairs), default=0)
    pad = " " * indent
    text = "\n".join(
        f"{pad}{label.ljust(width)} : {'' if value is None else value}"
        for label, value in pairs
    )
    recorded = _RECORDED.get()
    if recorded is not None:
        recorded.append({"kind": "fields", "text": text, "pairs": [
            [str(label), "" if value is None else str(value)] for label, value in pairs]})
    return text


def printer(render):
    """Wrap a ``data -> str`` renderer into a ``cli_output`` callable."""

    def output(result: Any) -> None:
        emit(render(result))

    return output
