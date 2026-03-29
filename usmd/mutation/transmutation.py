"""Transmutation logic and distance formula for USMD-RDSH.

A **transmutation** is the act of a node changing its active service — either
by the administrator's request, or automatically in response to a peer's
emergency request.

Distance formula (from the spec):

.. math::

    d = \\frac{t}{T} + c + p + n \\in [0; 5]

Where:

- **t**: Ping latency to the candidate node (ms).
- **T**: Maximum tolerated ping defined in the USD config (ms).
- **c**: Normalised reference load of the candidate node ∈ [0, 1].
- **p**: 1 if the candidate hosts the *same* service, 0 otherwise.
- **n**: 2 if the candidate's reference-node list already includes the
  requesting node, 0 otherwise.

Lower ``d`` means a *better* candidate for recovery.

Examples:
    >>> calc = DistanceCalculator(ping_tolerance_ms=200)
    >>> d = calc.compute(
    ...     ping_ms=50,
    ...     reference_load=0.3,
    ...     same_service=False,
    ...     is_already_reference=False,
    ... )
    >>> round(d, 4)
    0.55
"""

import logging
from dataclasses import dataclass


@dataclass
class DistanceResult:
    """The result of a distance computation between two nodes.

    Attributes:
        d: The distance score in [0, 5]. Lower is better.
        ping_component: t/T term.
        load_component: c term (reference load).
        service_penalty: p term (1 if same service, 0 otherwise).
        reference_penalty: n term (2 if requesting node already in candidate's refs).

    Examples:
        >>> dr = DistanceResult(d=1.25, ping_component=0.25,
        ...                     load_component=0.5, service_penalty=0,
        ...                     reference_penalty=0.5)
        >>> dr.d
        1.25
    """

    d: float
    ping_component: float
    load_component: float
    service_penalty: float
    reference_penalty: float


class DistanceCalculator:
    """Computes the NCP distance score between two nodes.

    The distance is used by nodes to rank candidates for recovery when an
    emergency request is triggered.

    Attributes:
        ping_tolerance_ms: T — the maximum allowed ping (ms), set in the USD config.

    Examples:
        >>> calc = DistanceCalculator(ping_tolerance_ms=200)
        >>> result = calc.compute(ping_ms=100, reference_load=0.5,
        ...                       same_service=False, is_already_reference=False)
        >>> round(result.d, 4)
        1.0
    """

    def __init__(self, ping_tolerance_ms: int) -> None:
        """Initialise the calculator with the domain's ping tolerance.

        Args:
            ping_tolerance_ms: Maximum tolerated ping T (milliseconds).
                               Must be > 0.

        Example:
            >>> calc = DistanceCalculator(ping_tolerance_ms=500)
        """
        if ping_tolerance_ms <= 0:
            raise ValueError("ping_tolerance_ms must be greater than zero")
        self.ping_tolerance_ms = ping_tolerance_ms

    def compute(
        self,
        ping_ms: float,
        reference_load: float,
        same_service: bool,
        is_already_reference: bool,
    ) -> float:
        """Compute the distance score d ∈ [0, 5].

        Args:
            ping_ms: Measured ping latency to the candidate node (ms).
            reference_load: Normalised load of the candidate node ∈ [0, 1].
            same_service: True if the candidate currently hosts the same
                          service as the node making the request.
            is_already_reference: True if the requesting node is already in
                                  the candidate's reference-node list.

        Returns:
            float: The distance score. Lower is better.

        Examples:
            >>> calc = DistanceCalculator(ping_tolerance_ms=200)
            >>> calc.compute(ping_ms=0, reference_load=0,
            ...              same_service=False, is_already_reference=False)
            0.0
            >>> calc.compute(ping_ms=200, reference_load=1,
            ...              same_service=True, is_already_reference=True)
            5.0
        """
        ping_ratio = min(ping_ms / self.ping_tolerance_ms, 1.0)
        c = max(0.0, min(1.0, reference_load))
        p = 1.0 if same_service else 0.0
        n = 2.0 if is_already_reference else 0.0

        d = ping_ratio + c + p + n
        d = min(5.0, max(0.0, d))

        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] distance: "
            "t/T=%.3f c=%.3f p=%.1f n=%.1f → d=%.4f",
            ping_ratio,
            c,
            p,
            n,
            d,
        )
        return d

    def compute_detailed(
        self,
        ping_ms: float,
        reference_load: float,
        same_service: bool,
        is_already_reference: bool,
    ) -> DistanceResult:
        """Compute the distance and return a detailed breakdown.

        Args:
            ping_ms: Ping latency in milliseconds.
            reference_load: Normalised load ∈ [0, 1].
            same_service: True if same service.
            is_already_reference: True if already a reference node.

        Returns:
            DistanceResult: Full breakdown of each term.

        Example:
            >>> calc = DistanceCalculator(200)
            >>> r = calc.compute_detailed(100, 0.5, False, False)
            >>> round(r.d, 4)
            1.0
        """
        ping_ratio = min(ping_ms / self.ping_tolerance_ms, 1.0)
        c = max(0.0, min(1.0, reference_load))
        p = 1.0 if same_service else 0.0
        n = 2.0 if is_already_reference else 0.0
        d = min(5.0, max(0.0, ping_ratio + c + p + n))

        return DistanceResult(
            d=d,
            ping_component=ping_ratio,
            load_component=c,
            service_penalty=p,
            reference_penalty=n,
        )


@dataclass
class ResourceUsage:
    """Snapshot of a node's resource utilisation.

    Attributes:
        ram_percent: RAM usage as a percentage in [0, 1].
        cpu_percent: CPU usage as a percentage in [0, 1].
        disk_percent: Disk usage as a percentage in [0, 1].
        network_percent: Network card utilisation in [0, 1].

    The **reference load** sent to peers is the maximum of all four metrics.

    Examples:
        >>> usage = ResourceUsage(ram_percent=0.6, cpu_percent=0.4,
        ...                       disk_percent=0.2, network_percent=0.1)
        >>> usage.reference_load()
        0.6
    """

    ram_percent: float
    cpu_percent: float
    disk_percent: float
    network_percent: float

    def reference_load(self) -> float:
        """Return the reference load: the maximum of all four metrics.

        Returns:
            float: Normalised reference load ∈ [0, 1].

        Example:
            >>> ResourceUsage(0.3, 0.7, 0.5, 0.1).reference_load()
            0.7
        """
        return max(
            self.ram_percent,
            self.cpu_percent,
            self.disk_percent,
            self.network_percent,
        )

    def is_weakened(self, threshold: float) -> bool:
        """Return True if the reference load has reached or exceeded the threshold.

        Args:
            threshold: Load threshold ∈ [0, 1] from the USD config.

        Example:
            >>> ResourceUsage(0.9, 0.5, 0.3, 0.1).is_weakened(0.8)
            True
            >>> ResourceUsage(0.4, 0.4, 0.4, 0.4).is_weakened(0.8)
            False
        """
        return self.reference_load() >= threshold


def dynamic_service_effective_reference_load(
    base_reference_load: float,
    data_bytes: float,
    *,
    nominal_capacity_bytes: float = 1e9,
    transfer_bytes_per_sec: float = 0.0,
    nominal_transfer_bps: float = 12.5e6,
) -> float:
    """Raise the advertised reference load for a weakened dynamic service host.

    Combines how full local data is (vs a nominal capacity) and how far current
    ingest throughput is from a nominal target. Both factors are clamped to
    ``[0, 1]`` and averaged with the base CPU/RAM/disk/net reference load.

    Args:
        base_reference_load: ``ResourceUsage.reference_load()`` ∈ [0, 1].
        data_bytes: Estimated quantity of data held for the dynamic service.
        nominal_capacity_bytes: Scale for the data term (default 1 GiB).
        transfer_bytes_per_sec: Observed transfer throughput (0 = ignore).
        nominal_transfer_bps: Target throughput in bytes/s (default ~100 Mbit/s).

    Returns:
        float: Adjusted load ∈ [0, 1].

    Example:
        >>> round(dynamic_service_effective_reference_load(0.3, 800e6), 4)
        0.7
    """
    cap = max(nominal_capacity_bytes, 1.0)
    data_factor = min(1.0, max(0.0, data_bytes / cap))
    xfer_term = 0.0
    if transfer_bytes_per_sec > 0 and nominal_transfer_bps > 0:
        ratio = min(1.0, transfer_bytes_per_sec / nominal_transfer_bps)
        xfer_term = 1.0 - ratio
    extra = 0.5 * data_factor + 0.5 * xfer_term
    return min(1.0, max(base_reference_load, extra))


def dynamic_transmutation_delay_scale(
    data_bytes: float,
    transfer_bytes_per_sec: float,
    *,
    nominal_capacity_bytes: float = 1e9,
    nominal_transfer_bps: float = 12.5e6,
) -> float:
    """Scale transmutation timing: slower sync / fuller disk → closer to 1.0 (longer wait).

    Returns a multiplier ≥ 1.0.

    Example:
        >>> dynamic_transmutation_delay_scale(0, 12.5e6)
        1.0
    """
    cap = max(nominal_capacity_bytes, 1.0)
    data_part = min(1.0, data_bytes / cap)
    xfer_part = 0.0
    if transfer_bytes_per_sec > 0 and nominal_transfer_bps > 0:
        xfer_part = max(0.0, 1.0 - min(1.0, transfer_bytes_per_sec / nominal_transfer_bps))
    stress = 0.5 * data_part + 0.5 * xfer_part
    return 1.0 + stress
