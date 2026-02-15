"""NNDP (Network Node Discovery Protocol) controller.

This module provides a controller class for managing NNDP client and server services,
allowing nodes to discover each other on the network by broadcasting and receiving
"HIA" packets.

Examples:
    Basic usage:
    >>> import os
    >>> from usmd_rdsh.proto.nndp.base.env import HereIAmData, VERSION
    >>> from usmd_rdsh.utils.node_state import NodeState
    >>>
    >>> # Set environment variables for ports
    >>> os.environ["NNDP_CLIENT_PORT"] = "8080"
    >>> os.environ["NNDP_SERVER_PORT"] = "8081"
    >>>
    >>> # Define callback for received HIA packets
    >>> def on_here_i_am(data: HereIAmData) -> None:
    ...     print(f"Received from: {data.node_id}, state: {data.state}")
    >>>
    >>> # Define payload provider for client
    >>> def payload_provider() -> HereIAmData:
    ...     return HereIAmData(
    ...         version=VERSION,
    ...         node_id="my-node",
    ...         next_hia_pkt_time=int((time.time() + 15.0) * 1000),
    ...         state=NodeState.ACTIVE,
    ...     )
    >>>
    >>> # Create and start controller
    >>> controller = NNDPController(cb_hia=on_here_i_am, client_pp=payload_provider)
    >>> controller.start()
    >>> # Controller is now broadcasting and listening for packets
    >>>
    >>> # Stop controller when done
    >>> controller.stop()
"""

import os
from typing import Callable, Optional

from usmd_rdsh.managers.event import EVENT_BUS, Subscription
from usmd_rdsh.proto.nndp.base.env import HereIAmData
from usmd_rdsh.proto.nndp.client.mount import MountService as ClientMountService
from usmd_rdsh.proto.nndp.client.mount import PayloadProvider
from usmd_rdsh.proto.nndp.server.events.here_i_am import HereIAmReceivedEvent
from usmd_rdsh.proto.nndp.server.mount import MountService as ServerMountService
from usmd_rdsh.security.ed25519 import Ed25519KeyPair


class NNDPController:
    """Controller for managing NNDP client and server services.

    This class coordinates both the client (broadcasting "HIA" packets) and
    server (listening for incoming packets) components of the NNDP protocol. It
    manages the lifecycle of both services and handles event subscriptions.

    Attributes:
        nndp_ports (dict[str, int]): Dictionary containing client and server port
            numbers read from environment variables.

    Examples:
        >>> import os
        >>> from usmd_rdsh.proto.nndp.base.env import HereIAmData
        >>> from usmd_rdsh.proto.base.env import NNDP_VERSION
        >>> from usmd_rdsh.utils.node_state import NodeState
        >>>
        >>> os.environ["NNDP_CLIENT_PORT"] = "8080"
        >>> os.environ["NNDP_SERVER_PORT"] = "8081"
        >>>
        >>> def on_here_i_am(data: HereIAmData) -> None:
        ...     print(f"Node discovered: {data.node_id}")
        >>>
        >>> def payload_provider() -> HereIAmData:
        ...     return HereIAmData(
        ...         version=NNDP_VERSION,
        ...         node_id="my-node",
        ...         next_hia_pkt_time=int((time.time() + 15.0) * 1000),
        ...         state=NodeState.ACTIVE,
        ...     )
        >>>
        >>> controller = NNDPController(cb_hia=on_here_i_am, client_pp=payload_provider)
        >>> controller.start()
        >>> # Services are now running
        >>> controller.stop()
    """

    def __init__(
        self,
        cb_hia: Callable[[HereIAmData], None],
        client_pp: PayloadProvider,
        ed25519_keypair: Ed25519KeyPair,
    ) -> None:
        """Initialize the NNDP controller.

        Args:
            cb_hia: Callback function called when a "HIA" packet is received.
                The callback receives a HereIAmData object containing the node
                information.
            client_pp: Payload provider function that returns HereIAmData for
                the client to broadcast. This function is called each time a packet
                needs to be sent.
            ed25519_keypair: Ed25519 key pair for the node.

        Examples:
            >>> def on_here_i_am(data: HereIAmData) -> None:
            ...     print(f"Received: {data.node_id}")
            >>>
            >>> def payload_provider() -> HereIAmData:
            ...     return HereIAmData(
            ...         version=NNDP_VERSION,
            ...         node_id="my-node",
            ...         next_hia_pkt_time=int((time.time() + 15.0) * 1000),
            ...         state=NodeState.ACTIVE,
            ...     )
            >>>
            >>> ed25519_keypair = Ed25519Certificate.generate("my-node", "~/.usmd/")
        >>> controller = NNDPController(cb_hia=on_here_i_am, client_pp=payload_provider, ed25519_keypair=ed25519_keypair)
        """
        self._cb_hia = cb_hia
        self._client_pp = client_pp
        self._ed25519_keypair = ed25519_keypair

        self.nndp_ports = {
            "client": int(os.getenv("NNDP_CLIENT_PORT")),
            "server": int(os.getenv("NNDP_SERVER_PORT")),
        }

        self._client: Optional[ClientMountService] = None
        self._server: Optional[ServerMountService] = None
        self._subscription: Optional[Subscription] = None

    def _create_client(self) -> None:
        """Create the NNDP client service.

        Initializes the client mount service that will broadcast "HIA"
        packets using the configured payload provider.

        Examples:
            >>> controller._create_client()
            >>> controller._client is not None
            True
        """
        self._client = ClientMountService(
            payload_provider=self._client_pp,
            send_port=self.nndp_ports["client"],
            receive_port=self.nndp_ports["server"],
            ed25519_keypair=self._ed25519_keypair,
        )

    def _create_server(self) -> None:
        """Create the NNDP server service.

        Initializes the server mount service that will listen for incoming
        "HIA" packets and subscribes to the event bus to receive decoded
        packets.

        Examples:
            >>> controller._create_server()
            >>> controller._server is not None
            True
            >>> controller._subscription is not None
            True
        """
        self._subscription = EVENT_BUS.subscribe(HereIAmReceivedEvent, self._cb_hia)

        self._server = ServerMountService(
            receive_port=self.nndp_ports["client"],
            source_port=self.nndp_ports["server"],
        )

    def start(self) -> None:
        """Start the NNDP controller.

        Creates and starts both the client and server services. The client will
        begin broadcasting "HIA" packets periodically, and the server will
        start listening for incoming packets.

        Examples:
            >>> controller.start()
            >>> controller._client is not None and controller._server is not None
            True
        """
        self._create_client()
        self._create_server()

        if self._client is not None:
            self._client.start()
        if self._server is not None:
            self._server.start()

    def stop(self) -> None:
        """Stop the NNDP controller.

        Stops both the client and server services and unsubscribes from the
        event bus. This method is safe to call even if services are not running.

        Examples:
            >>> controller.start()
            >>> controller.stop()
            >>> # Services are now stopped and cleaned up
        """
        if self._client is not None:
            self._client.stop()
        if self._server is not None:
            self._server.stop()
        if self._subscription is not None:
            self._subscription.unsubscribe()

    def is_running(self) -> bool:
        """Check if the NNDP controller is running."""

        if self._client is not None and self._client.running:
            return True
        if self._server is not None and self._server.running:
            return True
        return False
