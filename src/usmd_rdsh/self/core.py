"""Core module for the USMD-RDSH application.

This module provides the Core class, which serves as the central orchestrator
for the USMD-RDSH node. It manages node properties, state, and coordinates
the NNDP (Network Node Discovery Protocol) client and server services.

The Core class handles:
    - Node identity and cryptographic properties
    - Node state management
    - NNDP packet broadcasting and reception
    - Event handling for incoming "Here I Am" packets

Example usage:

    >>> from usmd_rdsh.self.core import Core
    >>> import time
    >>>
    >>> # Create a core instance
    >>> core = Core()
    >>>
    >>> # Start the core (begins NNDP services)
    >>> core.start()
    >>> assert core.is_running()
    >>>
    >>> # The core will now broadcast "Here I Am" packets and listen for others
    >>> time.sleep(2)  # Let it run for a bit
    >>>
    >>> # Stop the core
    >>> core.stop()
    >>> assert not core.is_running()
"""

import logging
import time
from usmd_rdsh.proto.nndp.base.env import (
    HereIAmData,
    get_node_properties,
    NodeProperties,
)
from usmd_rdsh.proto.nndp.server.events.here_i_am import HereIAmReceivedEvent
from usmd_rdsh.self.nndp import NNDPController
from usmd_rdsh.sys.tables import TableAggregator
from usmd_rdsh.utils.node_state import NodeState


class Core:
    """Core orchestrator for the USMD-RDSH node.

    The Core class is the central component that manages the node's lifecycle,
    identity, and network discovery services. It automatically loads or creates
    node properties (including cryptographic keys) and coordinates the NNDP
    protocol for network node discovery.

    Attributes:
        properties: Persistent node properties including node ID and Ed25519
                   key pair (loaded from or created in ~/.usmd/node.properties)
        state: Current state of the node (defaults to ACTIVE)

    Note:
        The node properties are loaded at class definition time, ensuring that
        the node identity is consistent across all instances. The properties
        include a unique node ID (ULID) and an Ed25519 key pair for cryptographic
        operations.

    Example:
        >>> from usmd_rdsh.self.core import Core
        >>> from usmd_rdsh.utils.node_state import NodeState
        >>> import time
        >>>
        >>> # Create a core instance
        >>> core = Core()
        >>>
        >>> # Access node properties
        >>> node_id = core.properties.node_id
        >>> public_key = core.properties.ed25519_keypair.pub32_b64u
        >>> assert len(node_id) > 0
        >>> assert len(public_key) > 0
        >>>
        >>> # Check initial state
        >>> assert core.state == NodeState.ACTIVE
        >>>
        >>> # Start the core
        >>> core.start()
        >>> assert core.is_running()
        >>>
        >>> # The core is now broadcasting and listening for NNDP packets
        >>> time.sleep(1)
        >>>
        >>> # Stop the core
        >>> core.stop()
        >>> assert not core.is_running()
    """

    properties: NodeProperties = get_node_properties()
    state: NodeState = NodeState.ACTIVE
    tables: TableAggregator = TableAggregator()

    def __init__(self) -> None:
        """Initialize the Core instance.

        Creates and configures the NNDP controller with callback functions
        for handling incoming "Here I Am" packets and providing payload data
        for outgoing packets.

        Example:
            >>> core = Core()
            >>> assert core.properties is not None
            >>> assert core.state == NodeState.ACTIVE
            >>> assert core._nndp is not None
        """
        self._nndp: NNDPController = NNDPController(
            cb_hia=self._nndp_cb_hia,
            client_pp=self._nndp_client_pp,
            ed25519_keypair=self.properties.ed25519_keypair,
        )

    def _nndp_cb_hia(self, hia_event: HereIAmReceivedEvent) -> None:
        """Callback for handling received "Here I Am" packets.

        This method is called by the NNDP controller whenever a "Here I Am"
        packet is received from another node. It filters out packets from the
        current node itself and logs information about packets from other nodes.

        Args:
            hia_event: Event containing the decoded "Here I Am" packet data

        Note:
            Packets from the current node (matching self.properties.node_id)
            are silently ignored to prevent processing our own announcements.

        Example:
            >>> from usmd_rdsh.proto.nndp.server.events.here_i_am import (
            ...     HereIAmReceivedEvent
            ... )
            >>> from usmd_rdsh.proto.nndp.base.env import HereIAmData
            >>> from usmd_rdsh.utils.node_state import NodeState
            >>> import time
            >>>
            >>> core = Core()
            >>> other_node_data = HereIAmData(
            ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            ...     next_hia_pkt_time=int((time.time() + 15.0) * 1000),
            ...     state=NodeState.ACTIVE,
            ... )
            >>> event = HereIAmReceivedEvent(data=other_node_data)
            >>> core._nndp_cb_hia(event)  # Logs the received packet
        """
        if hia_event.data.node_id == self.properties.node_id:
            return

        logging.info(
            "[CORE] Received Here I Am packet from %s (state: %s, "
            "next HIA packet time: %d, version: %d)",
            hia_event.data.node_id,
            hia_event.data.state.name,
            hia_event.data.next_hia_pkt_time,
            hia_event.data.version,
        )

    def _nndp_client_pp(self) -> HereIAmData:
        """Payload provider for NNDP "Here I Am" packets.

        This method is called by the NNDP client service to generate the
        payload data for outgoing "Here I Am" packets. It creates a HereIAmData
        instance with the current node's identity, state, and the timestamp
        for the next packet (15 seconds in the future).

        Returns:
            HereIAmData: Data structure containing node name, next packet time,
                        current state, and protocol version

        Example:
            >>> core = Core()
            >>> hia_data = core._nndp_client_pp()
            >>> assert hia_data.node_id == core.properties.node_id
            >>> assert hia_data.state == core.state
            >>> assert hia_data.version > 0
            >>> # next_hia_pkt_time should be approximately 15 seconds in the future
            >>> import time
            >>> expected_time = int((time.time() + 15.0) * 1000)
            >>> # Allow 1 second tolerance
            >>> assert abs(hia_data.next_hia_pkt_time - expected_time) < 1000
        """
        return HereIAmData(
            node_id=self.properties.node_id,
            next_hia_pkt_time=int((time.time() + 15.0) * 1000),
            state=self.state,
        )

    def start(self) -> None:
        """Start the core and begin NNDP services.

        This method starts the NNDP controller, which begins:
            - Broadcasting "Here I Am" packets periodically
            - Listening for incoming "Here I Am" packets from other nodes

        The core must be started before it can participate in network discovery.

        Example:
            >>> core = Core()
            >>> assert not core.is_running()
            >>> core.start()
            >>> assert core.is_running()
            >>> # Core is now active and participating in NNDP
        """
        self._nndp.start()

    def stop(self) -> None:
        """Stop the core and shutdown NNDP services.

        This method stops the NNDP controller, which halts:
            - Broadcasting "Here I Am" packets
            - Listening for incoming packets

        After stopping, the core can be restarted by calling start() again.

        Example:
            >>> core = Core()
            >>> core.start()
            >>> assert core.is_running()
            >>> core.stop()
            >>> assert not core.is_running()
            >>> # Core can be restarted
            >>> core.start()
            >>> assert core.is_running()
        """
        self._nndp.stop()

    def is_running(self) -> bool:
        """Check if the core is currently running.

        Returns:
            bool: True if the core is running (NNDP services active),
                  False otherwise

        Example:
            >>> core = Core()
            >>> assert not core.is_running()
            >>> core.start()
            >>> assert core.is_running()
            >>> core.stop()
            >>> assert not core.is_running()
        """
        return self._nndp.is_running()
