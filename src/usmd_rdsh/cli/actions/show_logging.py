"""``show logging`` and ``clear logging``, in the IOS layout."""

from __future__ import annotations

from nan_actions import action
from pydantic import BaseModel, Field

from usmd_rdsh.cli.logbuffer import SEVERITY_KEYWORDS
from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import printer
from usmd_rdsh.cli.views.common import LogLevel


class ShowLoggingInput(BaseModel):
    """Optional narrowing of ``show logging``."""

    level: LogLevel | None = Field(None, description="Only this severity and above")
    facility: str | None = Field(None, description="Only this facility (NNDP, NCP...)")
    last: int | None = Field(None, ge=1, description="Only the last N messages")


class LogRow(BaseModel):
    """One message, as ``| filter`` and ``| display`` see it."""

    seq: int
    time: str
    facility: str
    severity: int
    level: str
    mnemonic: str
    message: str
    line: str


def _render(rows: list[dict]) -> str:
    buffer = RUNTIME.logbuffer
    header = [
        f"Syslog logging: {'enabled' if buffer.enabled else 'disabled'} "
        f"({buffer.dropped} messages dropped, 0 flushes)",
        f"    Console logging: "
        + (f"level {buffer.console_level.keyword}, {buffer.console_logged} messages logged"
           if buffer.console_enabled else "disabled"),
        f"    Buffer logging:  level {buffer.buffered_level.keyword}, "
        f"{buffer.logged} messages logged",
        f"    Timestamp logging: {'msec' if buffer.timestamp_msec else 'sec'}, "
        f"sequence numbers {'on' if buffer.sequence_numbers else 'off'}",
        "",
        f"Log Buffer ({buffer.capacity} messages, {len(buffer.messages())} held):",
        "",
    ]
    return "\n".join(header + [row["line"] for row in rows])


@action(cli="show logging", description="Logging settings and the log buffer",
        permissions=[READ], rows=LogRow, cli_output=printer(_render))
async def show_logging(data: ShowLoggingInput) -> list[dict]:
    """Logging settings and the buffered messages, oldest first."""
    buffer = RUNTIME.logbuffer
    messages = buffer.messages()
    if data.level is not None:
        ceiling = SEVERITY_KEYWORDS[str(data.level)]
        messages = [m for m in messages if m.severity <= ceiling]
    if data.facility:
        messages = [m for m in messages if m.facility == data.facility.upper()]
    if data.last:
        messages = messages[-data.last:]
    return [
        {
            **m.as_row(),
            "line": m.render(
                msec=buffer.timestamp_msec, sequence=buffer.sequence_numbers
            ),
        }
        for m in messages
    ]


@action(cli="clear logging", description="Empty the log buffer", permissions=[WRITE],
        cli_confirm="Clear logging buffer [confirm]")
async def clear_logging() -> dict:
    """Empty the log buffer."""
    return {"cleared": RUNTIME.logbuffer.clear()}
