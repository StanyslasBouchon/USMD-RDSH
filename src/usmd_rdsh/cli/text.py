"""Console output in the IOS idiom: fixed-width columns, no box drawing.

Every action returns data, which is what the token API serialises and what
pipes filter. These helpers are its ``cli_output``: the way the same data
reads on a console.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from nan_runtime.log import emit


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
    return "\n".join(lines)


def fields(pairs: Sequence[tuple[str, Any]], indent: int = 0) -> str:
    """``Label : value`` lines with the colons aligned."""
    width = max((len(label) for label, _ in pairs), default=0)
    pad = " " * indent
    return "\n".join(
        f"{pad}{label.ljust(width)} : {'' if value is None else value}"
        for label, value in pairs
    )


def printer(render):
    """Wrap a ``data -> str`` renderer into a ``cli_output`` callable."""

    def output(result: Any) -> None:
        emit(render(result))

    return output
