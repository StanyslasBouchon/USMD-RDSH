"""Cisco-like logging: syslog severities, a bounded buffer and per-sink levels.

Every record emitted through the standard ``logging`` module is turned into a
syslog message of the form::

    *Oct 22 14:03:12.123: %NNDP-6-HIA: Received HIA packet from 01JAB..., table updated

where ``NNDP`` is the facility (read from a ``[NNDP]`` prefix in the message or
from the logger name), ``6`` the severity and ``HIA`` the mnemonic. Messages are
kept in a ring buffer read by ``show logging`` and by the web interface, and are
copied to the console only from the configured console level up.

Example:
    >>> import logging
    >>> buffer = LogBuffer(capacity=10)
    >>> buffer.attach(logging.getLogger("demo"))
    >>> logging.getLogger("demo").warning("[NCP] Peer 10.0.0.1 is busy")
    >>> buffer.messages()[-1].facility
    'NCP'
"""

from __future__ import annotations

import logging
import re
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Callable


class Severity(IntEnum):
    """Syslog severities (RFC 5424), named the way IOS names them."""

    EMERGENCIES = 0
    ALERTS = 1
    CRITICAL = 2
    ERRORS = 3
    WARNINGS = 4
    NOTIFICATIONS = 5
    INFORMATIONAL = 6
    DEBUGGING = 7

    @classmethod
    def of_record(cls, record: logging.LogRecord) -> "Severity":
        """Map a Python logging level onto the closest syslog severity."""
        if record.levelno >= logging.CRITICAL:
            return cls.CRITICAL
        if record.levelno >= logging.ERROR:
            return cls.ERRORS
        if record.levelno >= logging.WARNING:
            return cls.WARNINGS
        if record.levelno >= logging.INFO:
            return cls.INFORMATIONAL
        return cls.DEBUGGING

    @property
    def keyword(self) -> str:
        """The lower-case name typed in the configuration (``warnings``)."""
        return self.name.lower()


#: The configuration spells a level by its keyword; this maps it back.
SEVERITY_KEYWORDS: dict[str, Severity] = {s.keyword: s for s in Severity}

_FACILITY_PREFIX = re.compile(r"^\[([A-Za-z0-9_-]+)\]\s*")


@dataclass(frozen=True, slots=True)
class SyslogMessage:
    """One buffered message."""

    sequence: int
    timestamp: datetime
    facility: str
    severity: Severity
    mnemonic: str
    text: str

    def render(self, *, msec: bool = True, sequence: bool = False) -> str:
        """The line as IOS prints it in ``show logging``."""
        stamp = self.timestamp.strftime("%b %d %H:%M:%S")
        if msec:
            stamp += f".{self.timestamp.microsecond // 1000:03d}"
        head = f"{self.sequence:06d}: " if sequence else ""
        return (
            f"{head}*{stamp}: %{self.facility}-{int(self.severity)}-"
            f"{self.mnemonic}: {self.text}"
        )

    def as_row(self) -> dict[str, object]:
        """The message as data, for pipes and for the web interface."""
        return {
            "seq": self.sequence,
            "time": self.timestamp.isoformat(timespec="milliseconds"),
            "facility": self.facility,
            "severity": int(self.severity),
            "level": self.severity.keyword,
            "mnemonic": self.mnemonic,
            "message": self.text,
        }


class LogBuffer(logging.Handler):
    """A logging handler holding the last *capacity* syslog messages.

    Thread-safe: NNDP and NCP log from their own threads while the console and
    the web interface read from the event loop.
    """

    def __init__(self, capacity: int = 4096) -> None:
        super().__init__(level=logging.DEBUG)
        self._lock_buffer = threading.Lock()
        self._messages: deque[SyslogMessage] = deque(maxlen=capacity)
        self._sequence = 0
        self.buffered_level = Severity.DEBUGGING
        self.console_level = Severity.WARNINGS
        self.console_enabled = True
        self.timestamp_msec = True
        self.sequence_numbers = False
        self.enabled = True
        self.logged = 0
        self.dropped = 0
        self.console_logged = 0
        self._console: Callable[[str], None] | None = None

    # -- configuration -----------------------------------------------------

    @property
    def capacity(self) -> int:
        """How many messages the buffer keeps."""
        return self._messages.maxlen or 0

    def resize(self, capacity: int) -> None:
        """Change the buffer size, keeping the most recent messages."""
        with self._lock_buffer:
            self._messages = deque(self._messages, maxlen=max(16, int(capacity)))

    def set_console(self, writer: Callable[[str], None] | None) -> None:
        """Where console-level messages are printed; None silences the console."""
        self._console = writer

    def attach(self, logger: logging.Logger | None = None) -> None:
        """Install the buffer on *logger* (the root logger by default)."""
        target = logger or logging.getLogger()
        if self not in target.handlers:
            target.addHandler(self)
        target.setLevel(logging.DEBUG)

    # -- logging.Handler ---------------------------------------------------

    def emit(self, record: logging.LogRecord) -> None:
        if not self.enabled:
            self.dropped += 1
            return
        try:
            message = self._convert(record)
        except Exception:  # pylint: disable=broad-except
            self.handleError(record)
            return

        if message.severity <= self.buffered_level:
            with self._lock_buffer:
                self._messages.append(message)
            self.logged += 1
        if (
            self._console is not None
            and self.console_enabled
            and message.severity <= self.console_level
        ):
            self.console_logged += 1
            self._console(
                message.render(msec=self.timestamp_msec, sequence=self.sequence_numbers)
            )

    def _convert(self, record: logging.LogRecord) -> SyslogMessage:
        text = record.getMessage()
        match = _FACILITY_PREFIX.match(text)
        if match:
            facility = match.group(1).upper()
            text = text[match.end():]
        else:
            facility = _facility_of_logger(record.name)
        if record.exc_info:
            text += " | " + self.formatException(record.exc_info).splitlines()[-1]
        with self._lock_buffer:
            self._sequence += 1
            sequence = self._sequence
        return SyslogMessage(
            sequence=sequence,
            timestamp=datetime.fromtimestamp(record.created),
            facility=facility,
            severity=Severity.of_record(record),
            mnemonic=_mnemonic(text, record),
            text=text,
        )

    # -- reading -----------------------------------------------------------

    def messages(self) -> list[SyslogMessage]:
        """Every buffered message, oldest first."""
        with self._lock_buffer:
            return list(self._messages)

    def clear(self) -> int:
        """Empty the buffer; returns how many messages were dropped."""
        with self._lock_buffer:
            count = len(self._messages)
            self._messages.clear()
        return count


def _facility_of_logger(name: str) -> str:
    """``usmd_rdsh.proto.ncp.server`` -> ``NCP``; ``root`` -> ``SYS``."""
    if name in ("", "root"):
        return "SYS"
    parts = name.split(".")
    for known in ("nndp", "ncp", "sp", "web", "api", "cli"):
        if known in parts:
            return known.upper()
    if parts[0] == "nan_actions" and "api" in parts:
        return "API"
    return parts[-1].upper()[:12]


def _mnemonic(text: str, record: logging.LogRecord) -> str:
    """A short upper-case tag, IOS style: the first significant words."""
    words = re.findall(r"[A-Za-z]+", text)
    stop = {"the", "a", "an", "from", "to", "of", "is", "for", "on", "in", "and"}
    picked = [w.upper() for w in words if w.lower() not in stop][:2]
    return "_".join(picked) or record.levelname
