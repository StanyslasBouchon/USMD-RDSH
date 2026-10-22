"""``config protocol``: NNDP, NCP and SP parameters local to this node.

The USD-wide values (SP port, services prefix, SP MTU) are USD parameters and
live under ``config usd``; what is here is what [NCP] section 8 and [SP]
section 10 leave to each implementation.
"""

from typing import Self

from nan_actions.views import ConfigNode, view
from pydantic import BaseModel, Field, model_validator

from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.views.common import NODE_ACCESS, Port


class NndpConfig(BaseModel):
    """Neighbour discovery, [NNDP-01] section 7.

    The inactivity delay is 2 x I and not configurable. The ports are fixed by
    the specification; they stay settable only to run several nodes on one
    host while testing.
    """

    status: bool = Field(True, description="Announce and listen for HIA")
    hia_interval: int = Field(15, ge=1, le=3600, description="I, seconds between two HIA")
    freshness_window: int = Field(30, ge=1, le=600, description="F, accepted clock skew, s")
    client_port: Port = Field(5222, description="Destination port (5222, fixed by NNDP)")
    server_port: Port = Field(5221, description="Source port (5221, fixed by NNDP)")


@view("protocol nndp", model=NndpConfig, **NODE_ACCESS)
class NndpView(ConfigNode):
    """Neighbour discovery: HIA interval, freshness window, ports."""

    async def apply(self, config: NndpConfig) -> None:
        if config.client_port == config.server_port:
            raise ValueError("client-port and server-port must differ")
        if RUNTIME.core is not None:
            RUNTIME.core.reconfigure_nndp(
                enabled=config.status,
                client_port=config.client_port,
                server_port=config.server_port,
                hia_interval=config.hia_interval,
                # [NNDP-01 7]: inactive 2 x I after the previous HIA, that is
                # I after the announced time of the next one.
                inactive_tolerance=config.hia_interval,
            )


class NcpConfig(BaseModel):
    """Encrypted control protocol, [NCP] section 8."""

    port: Port = Field(9992, description="UDP port")
    max_udp_payload: int = Field(1200, ge=576, le=65507, description="Bytes")
    max_fragments: int = Field(1024, ge=1, le=65535, description="Per message")
    reassembly_timeout: int = Field(10, ge=1, description="Seconds")
    retransmit_timeout: int = Field(2, ge=1, description="Seconds, doubled each try")
    retransmit_attempts: int = Field(3, ge=0, le=10, description="Tries")
    fragment_ack_delay: int = Field(100, ge=1, description="Milliseconds")
    freshness_window: int = Field(30, ge=1, le=300, description="Seconds")
    response_cache: int = Field(60, ge=1, description="Seconds responses are kept")
    reassembly_per_address: int = Field(16, ge=1, description="Messages")
    properties_interval: int = Field(60, ge=1, description="Seconds (25 % jitter)")
    exclusion_duration: int = Field(600, ge=1, description="Temporary exclusion, s")
    node_table_relay_delay: int = Field(1, ge=0, description="Seconds")
    node_table_reconcile: int = Field(600, ge=1, description="Seconds (25 % jitter)")
    raft_heartbeat: int = Field(1, ge=1, description="Raft heartbeat interval, s")
    raft_election_min: int = Field(5, ge=1, description="Raft election timeout, low bound, s")
    raft_election_max: int = Field(10, ge=1, description="Raft election timeout, high bound, s")

    @model_validator(mode="after")
    def _raft(self) -> Self:
        if self.raft_election_min >= self.raft_election_max:
            raise ValueError("raft-election-min must be below raft-election-max")
        if self.raft_heartbeat >= self.raft_election_min:
            raise ValueError("raft-heartbeat must be shorter than the election timeout")
        return self


@view("protocol ncp", model=NcpConfig, **NODE_ACCESS)
class NcpView(ConfigNode):
    """Control protocol transport and timers."""


class SpConfig(BaseModel):
    """Service protocol, the parameters [SP] section 10 marks as local."""

    selection_margin: float = Field(0.1, ge=0, le=5, description="Delta between candidates")
    flow_idle_timeout: int = Field(300, ge=1, description="Seconds")
    pending_per_peer: int = Field(32, ge=1, description="Packets queued per peer")
    ineligible_after_failure: int = Field(30, ge=1, description="Seconds")
    replay_window: int = Field(2048, ge=2048, description="Frames")


@view("protocol sp", model=SpConfig, **NODE_ACCESS)
class SpView(ConfigNode):
    """Service protocol local parameters."""
