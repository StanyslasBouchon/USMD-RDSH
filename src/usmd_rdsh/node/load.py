"""Reference load [ARCH-02 6.1] and weakness detection [7.1].

Every 0x0007 seconds (5 by default) the node measures four rates in per mille
- memory, CPU, disk of the volumes its services use, network throughput over
the interface's nominal speed - smooths each over its last three samples, and
takes the highest as its reference load c.

Weakened: the load reaches 0x0004 (800) at three consecutive measures, or,
for a dynamic service, its linear trend over the last three reaches it within
Tm = Tmoy + V / D. Emergency: the load reaches 0x0005 (950).
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

import psutil


@dataclass
class LoadSample:
    memory: int
    cpu: int
    disk: int
    network: int

    @property
    def reference(self) -> int:
        return max(self.memory, self.cpu, self.disk, self.network)


@dataclass
class LoadMonitor:  # pylint: disable=too-many-instance-attributes
    """Samples, smooths and judges the node's load."""

    volumes: list[str] = field(default_factory=lambda: ["/"])
    history: deque = field(default_factory=lambda: deque(maxlen=3))
    references: deque = field(default_factory=lambda: deque(maxlen=3))
    sample_times: deque = field(default_factory=lambda: deque(maxlen=3))
    _net_bytes: int | None = None
    _net_time: float | None = None
    override: LoadSample | None = None  # tests and simulation

    def measure(self) -> LoadSample:
        """One raw sample, per mille."""
        if self.override is not None:
            return self.override
        disks = []
        for volume in self.volumes or ["/"]:
            try:
                disks.append(psutil.disk_usage(volume).percent)
            except OSError:
                continue
        return LoadSample(
            memory=int(psutil.virtual_memory().percent * 10),
            cpu=int(psutil.cpu_percent(interval=None) * 10),
            disk=int(max(disks or [0]) * 10),
            network=self._network(),
        )

    def _network(self) -> int:
        counters = psutil.net_io_counters()
        total = counters.bytes_sent + counters.bytes_recv
        now = time.monotonic()
        rate = 0
        if self._net_bytes is not None and self._net_time is not None and now > self._net_time:
            speeds = [s.speed for s in psutil.net_if_stats().values() if s.isup and s.speed]
            nominal_bits = max(speeds or [1000]) * 1_000_000
            observed_bits = (total - self._net_bytes) * 8 / (now - self._net_time)
            rate = min(1000, int(observed_bits / nominal_bits * 1000))
        self._net_bytes, self._net_time = total, now
        return rate

    def sample(self, now: float | None = None) -> int:
        """Take a sample; return the smoothed reference load."""
        self.history.append(self.measure())
        smoothed = self.smoothed()
        self.references.append(smoothed.reference)
        self.sample_times.append(time.monotonic() if now is None else now)
        return smoothed.reference

    def smoothed(self) -> LoadSample:
        if not self.history:
            return LoadSample(0, 0, 0, 0)
        n = len(self.history)
        return LoadSample(
            sum(s.memory for s in self.history) // n,
            sum(s.cpu for s in self.history) // n,
            sum(s.disk for s in self.history) // n,
            sum(s.network for s in self.history) // n,
        )

    @property
    def reference(self) -> int:
        return self.references[-1] if self.references else 0

    def weakened(self, threshold: int, *, transmutation_s: float | None = None) -> bool:
        """[7.1]: three consecutive measures at the threshold, or the trend."""
        if len(self.references) == 3 and all(r >= threshold for r in self.references):
            return True
        if transmutation_s is not None and len(self.references) == 3:
            first, last = self.references[0], self.references[-1]
            span = self.sample_times[-1] - self.sample_times[0]
            if span > 0 and last > first:
                slope = (last - first) / span
                return (threshold - last) / slope < transmutation_s
        return False

    def emergency(self, threshold: int) -> bool:
        return self.reference >= threshold


def useful_transmutation_time(average_s: float, volume_bytes: int, rate_bps: float) -> float:
    """Tm = Tmoy + V / D [ARCH 7.1]."""
    return average_s + (volume_bytes / rate_bps if rate_bps > 0 else 0)
