import logging
import ulid
import time
from usmd_rdsh.proto.nndp.base.env import HereIAmData
from usmd_rdsh.proto.nndp.server.events.here_i_am import HereIAmReceivedEvent
from usmd_rdsh.self.nndp import NNDPController
from usmd_rdsh.utils.node_state import NodeState


class Core:
    """Core class."""

    id: str = ulid.new().str
    state: NodeState = NodeState.ACTIVE

    def __init__(self) -> None:
        self._nndp: NNDPController = NNDPController(
            cb_hia=self._nndp_cb_hia, client_pp=self._nndp_client_pp
        )

    def _nndp_cb_hia(self, hia_event: HereIAmReceivedEvent) -> None:
        if hia_event.data.node_name == self.id:
            return

        logging.info(
            "[CORE] Received Here I Am packet from %s (state: %s, next HIA packet time: %d, version: %d)",
            hia_event.data.node_name,
            hia_event.data.state.name,
            hia_event.data.next_hia_pkt_time,
            hia_event.data.version,
        )

    def _nndp_client_pp(self) -> HereIAmData:
        return HereIAmData(
            node_name=self.id,
            next_hia_pkt_time=int((time.time() + 15.0) * 1000),
            state=self.state,
        )

    def start(self) -> None:
        """Start the core."""
        self._nndp.start()

    def stop(self) -> None:
        """Stop the core."""
        self._nndp.stop()

    def is_running(self) -> bool:
        """Check if the core is running."""
        return self._nndp.is_running()
