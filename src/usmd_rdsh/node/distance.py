"""Distance between nodes and reference-node choice [ARCH-02 6.2-6.4].

    d = p + c + t / T + n

    p  1 if the candidate hosts the same service as us, else 0
    c  the candidate's reference load, 0..1
    t  round-trip time we measured, ms;  T  ping tolerance (0x0002), ms
    n  2 if the candidate already has us as a reference node, else 0

A candidate with t > T is not eligible. Lower is better. The NNR (0x0001)
eligible active candidates of minimal distance are the reference nodes; a
periodic measure (0x0006) replaces one only for a candidate at least 0.2
closer; a reference node leaving "Active" is replaced at once.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

HYSTERESIS = 0.2
SAMPLE = 32


@dataclass(frozen=True, slots=True)
class Measure:
    """One Check_distance_to_node exchange, as the measuring node sees it."""

    node_id: str
    rtt_ms: float
    load_per_mille: int
    service: str
    has_us_as_reference: bool


def distance(measure: Measure, my_service: str, tolerance_ms: int) -> float | None:
    """d, or None when the candidate is not eligible (t > T)."""
    if measure.rtt_ms > tolerance_ms:
        return None
    p = 1.0 if my_service and measure.service == my_service else 0.0
    c = measure.load_per_mille / 1000
    n = 2.0 if measure.has_us_as_reference else 0.0
    return p + c + measure.rtt_ms / tolerance_ms + n


def choose(distances: dict[str, float], count: int) -> list[str]:
    """The *count* closest candidates [6.3]."""
    return [node for node, _ in sorted(distances.items(), key=lambda kv: (kv[1], kv[0]))][:count]


def reselect(current: list[str], distances: dict[str, float], count: int,
             inactive: set[str]) -> list[str]:
    """Periodic re-evaluation with hysteresis [6.4]."""
    kept = [n for n in current if n not in inactive and n in distances]
    candidates = sorted(
        ((d, n) for n, d in distances.items() if n not in kept and n not in inactive),
    )
    # Fill free slots first (an inactive reference is replaced at once).
    while len(kept) < count and candidates:
        kept.append(candidates.pop(0)[1])
    # Then replace a reference by a candidate at least 0.2 closer.
    for d_new, new in candidates:
        worst = max(kept, key=lambda n: distances[n], default=None)
        if worst is not None and distances[worst] - d_new >= HYSTERESIS:
            kept[kept.index(worst)] = new
    return kept


def sample(active: list[str], references: list[str], size: int = SAMPLE) -> list[str]:
    """References plus up to 32 other active nodes at random [6.4]."""
    others = [n for n in active if n not in references]
    return list(references) + random.sample(others, min(size, len(others)))
