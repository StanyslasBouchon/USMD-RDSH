"""Flow affinity [SP-01 6.3].

A flow keeps its destination instance while it is active: 300 s of
inactivity, or 10 s once a TCP FIN or RST has been seen in each direction.
The table is consulted before any new selection.
"""

from __future__ import annotations

from dataclasses import dataclass

from usmd_rdsh.node.sp.packets import TCP_FIN, TCP_RST, IPv4

FlowKey = tuple[int, str, int, str, int]
IDLE_S = 300.0
CLOSING_S = 10.0


@dataclass(slots=True)
class Flow:
    """One direction of a flow."""

    peer_address: int  # SP address of the correspondent instance
    outbound: bool
    last_activity: float
    closing_since: float | None = None
    fin_out: bool = False
    fin_in: bool = False


def reverse(key: FlowKey) -> FlowKey:
    protocol, src, sport, dst, dport = key
    return protocol, dst, dport, src, sport


class FlowTable:
    """Flows keyed by their 5-tuple."""

    def __init__(self, idle_s: float = IDLE_S) -> None:
        self.idle_s = idle_s
        self.flows: dict[FlowKey, Flow] = {}

    def lookup(self, packet: IPv4, now: float) -> int | None:
        """The SP address recorded for this packet's flow, if alive."""
        flow = self.flows.get(packet.flow())
        if flow is None or self._expired(flow, now):
            return None
        return flow.peer_address

    def record_outbound(self, packet: IPv4, address: int, now: float) -> None:
        self._touch(packet.flow(), address, True, packet, now, outgoing=True)

    def record_inbound(self, packet: IPv4, source_address: int, now: float) -> None:
        """Record the reverse flow so the reply reaches the exact instance."""
        self._touch(reverse(packet.flow()), source_address, False, packet, now, outgoing=False)

    def drop_address(self, address: int) -> int:
        """An instance stopped being eligible: forget its outbound flows."""
        doomed = [k for k, f in self.flows.items() if f.outbound and f.peer_address == address]
        for key in doomed:
            del self.flows[key]
        return len(doomed)

    def expire(self, now: float) -> None:
        self.flows = {k: f for k, f in self.flows.items() if not self._expired(f, now)}

    def _touch(  # pylint: disable=too-many-arguments
        self, key: FlowKey, address: int, outbound: bool, packet: IPv4, now: float,
        *, outgoing: bool,
    ) -> None:
        flow = self.flows.get(key)
        if flow is None or flow.peer_address != address:
            flow = Flow(address, outbound, now)
            self.flows[key] = flow
        flow.last_activity = now
        if packet.tcp_flags() & (TCP_FIN | TCP_RST):
            if outgoing:
                flow.fin_out = True
            else:
                flow.fin_in = True
            if flow.fin_out and flow.fin_in and flow.closing_since is None:
                flow.closing_since = now

    def _expired(self, flow: Flow, now: float) -> bool:
        if flow.closing_since is not None and now - flow.closing_since > CLOSING_S:
            return True
        return now - flow.last_activity > self.idle_s
