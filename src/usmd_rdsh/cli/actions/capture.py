"""``show capture``, ``show capture fields``, ``clear capture``: the frames of
NNDP, NCP and SP as Wireshark lists them, with its display-filter syntax.

    show capture filter="ncp && ncp.type == ERROR" last=20
    show capture detail=42
"""

from __future__ import annotations

import time

from nan_actions import action
from nan_actions.errors import SdkError
from pydantic import BaseModel, Field

from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.text import fields, printer, table
from usmd_rdsh.node.capture import CAPTURE, FilterError, compile_filter, field_names


class ShowCaptureInput(BaseModel):
    """What ``show capture`` lists."""

    filter: str | None = Field(None, description='Display filter, e.g. "nndp && ip.src == '
                                                 '127.0.0.2"')
    last: int = Field(50, ge=1, le=100000, description="Only the last N matching frames")
    detail: int | None = Field(None, ge=1, description="Dissect this frame number")


class CaptureRow(BaseModel):
    """One frame, as ``| filter`` and ``| display`` see it."""

    number: int
    time: float
    protocol: str
    direction: str
    source: str
    destination: str
    length: int
    info: str
    status: str
    reason: str


def _tree_lines(items: list[dict], depth: int = 0) -> list[str]:
    lines = []
    for item in items:
        text = f"{item['l']}: {item['v']}" if item["v"] else item["l"]
        lines.append("    " * depth + text)
        lines.extend(_tree_lines(item["c"], depth + 1))
    return lines


def _hexdump(data: bytes) -> list[str]:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hexes = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hexes:<47}  {text}")
    return lines


def _render(result: list[dict]) -> str:
    if result and "tree" in result[0]:
        packet = result[0]
        lines = _tree_lines(packet["tree"])
        for buffer in packet["buffers"]:
            data = bytes.fromhex(buffer["hex"])
            if data:
                lines += ["", f"{buffer['name']} ({len(data)} bytes):"] + _hexdump(data)
        return "\n".join(lines)
    start = CAPTURE.started
    rows = [{**r, "time": f"{r['time'] - start:.3f}",
             "info": r["info"] + (f"  [{r['status']}: {r['reason']}]"
                                  if r["status"] != "ok" else "")} for r in result]
    head = (f"Capture: {'running' if CAPTURE.enabled else 'stopped'}, "
            f"{CAPTURE.held()} of {CAPTURE.capacity} frames held, "
            f"protocols {' '.join(sorted(CAPTURE.protocols)) or 'none'}\n\n")
    return head + table(rows, [("number", "No."), ("time", "Time"), ("source", "Source"),
                               ("destination", "Destination"), ("protocol", "Protocol"),
                               ("length", "Length"), ("info", "Info")])


@action(cli="show capture", description="Captured NNDP, NCP and SP frames (Wireshark filters)",
        permissions=[READ], rows=CaptureRow, cli_output=printer(_render))
async def show_capture(data: ShowCaptureInput) -> list[dict]:
    """The last matching frames, oldest first; with ``detail``, one frame dissected."""
    if data.detail is not None:
        packet = CAPTURE.get(data.detail)
        if packet is None:
            raise SdkError(f"frame {data.detail} is not (or no longer) in the capture buffer")
        return [packet.detail()]
    try:
        flt = compile_filter(data.filter)
    except FilterError as exc:
        raise SdkError(f"invalid filter: {exc}") from exc
    return [p.row() for p in CAPTURE.packets(flt=flt, last=data.last)]


class FieldRow(BaseModel):
    name: str
    label: str


@action(cli="show capture fields", description="Field names usable in capture filters",
        permissions=[READ], rows=FieldRow,
        cli_output=printer(lambda rows: table(rows, [("name", "Field"), ("label", "Meaning")])))
async def show_capture_fields() -> list[dict]:
    """Every field a display filter may name."""
    return [{"name": name, "label": label} for name, label in field_names()]


@action(cli="show capture statistics", description="Frames captured per protocol and status",
        permissions=[READ],
        cli_output=printer(lambda r: fields([(k, v) for k, v in r.items()])))
async def show_capture_statistics() -> dict:
    """Counters since the capture was last cleared."""
    counts = CAPTURE.counts
    return {
        "status": "running" if CAPTURE.enabled else "stopped",
        "held": CAPTURE.held(),
        "capacity": CAPTURE.capacity,
        "last_number": CAPTURE.last_number,
        "since": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(CAPTURE.started)),
        **{p.lower(): counts.get(p, 0) for p in CAPTURE.PROTOCOLS},
        **{s: counts.get(s, 0) for s in ("ok", "dropped", "malformed", "ignored",
                                         "retransmission")},
    }


@action(cli="clear capture", description="Empty the capture buffer", permissions=[WRITE],
        cli_confirm="Clear capture buffer [confirm]")
async def clear_capture() -> dict:
    """Empty the capture buffer; numbering goes on."""
    return {"cleared": CAPTURE.clear()}
