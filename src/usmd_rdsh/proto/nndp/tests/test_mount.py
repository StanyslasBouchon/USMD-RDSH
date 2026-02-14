"""Tests for NNDP mount services.

This module provides tests for the NNDP client and server mount services,
verifying that packets can be sent and received correctly.
"""

import threading
import time

import pytest

from usmd_rdsh.managers.event import EVENT_BUS
from usmd_rdsh.proto.nndp.base.env import HereIAmData, VERSION
from usmd_rdsh.proto.nndp.client.mount import MountService as ClientMountService
from usmd_rdsh.proto.nndp.server.events.here_i_am import HereIAmReceivedEvent
from usmd_rdsh.proto.nndp.server.mount import MountService as ServerMountService
from usmd_rdsh.utils.node_state import NodeState


@pytest.fixture
def nndp_ports():
    """Provide test ports that don't conflict."""
    return {
        "client_send": 15000,
        "client_receive": 15001,
        "server_receive": 15000,  # Same as client_send
        "server_source": 15001,  # Same as client_receive
    }


def test_nndp_packet_send_receive(nndp_ports):  # pylint: disable=redefined-outer-name
    """Test that NNDP packets can be sent and received correctly.

    This test creates a server that listens for Here I Am packets and a client
    that sends them. It verifies that the data received matches the data sent.

    Args:
        nndp_ports: Dictionary of port numbers for client and server
    """
    # Data to send
    node_id = "test-node"
    state = NodeState.ACTIVE
    next_hia_pkt_time = int((time.time() + 0.1) * 1000)  # Short interval for test

    # Event capture
    received_data = []
    lock = threading.Lock()

    def on_here_i_am_received(event: HereIAmReceivedEvent) -> None:
        """Capture received Here I Am event."""
        with lock:
            received_data.append(event.data)

    # Subscribe to Here I Am events on the global EVENT_BUS
    subscription = EVENT_BUS.subscribe(HereIAmReceivedEvent, on_here_i_am_received)

    try:
        # Create payload provider function
        def payload_provider() -> HereIAmData:
            """Provide Here I Am data for the client."""
            return HereIAmData(
                version=VERSION,
                node_id=node_id,
                next_hia_pkt_time=int((time.time() + 0.1) * 1000),
                state=state,
            )

        # Create and start server
        server = ServerMountService(
            receive_port=nndp_ports["server_receive"],
            source_port=nndp_ports["server_source"],
        )
        server.start()

        # Wait a bit for server to be ready
        time.sleep(0.1)

        # Create and start client with short interval for testing
        client = ClientMountService(
            payload_provider=payload_provider,
            send_port=nndp_ports["client_send"],
            receive_port=nndp_ports["client_receive"],
            interval=0.1,  # Short interval for test
        )
        client.start()

        # Wait for client to send packet automatically
        time.sleep(0.3)

        # Verify data was received
        assert len(received_data) > 0, "No data was received"
        received_here_i_am = received_data[-1]

        # Verify all fields match
        assert (
            received_here_i_am.node_id == node_id
        ), f"Node name mismatch: expected {node_id}, got {received_here_i_am.node_id}"
        assert (
            received_here_i_am.state == state
        ), f"State mismatch: expected {state}, got {received_here_i_am.state}"
        assert (
            received_here_i_am.version == VERSION
        ), f"Version mismatch: expected {VERSION}, got {received_here_i_am.version}"

        # Verify next_hia_pkt_time is close (within 1 second)
        time_diff = abs(received_here_i_am.next_hia_pkt_time - next_hia_pkt_time)
        assert time_diff < 1000, (
            f"Time mismatch: expected ~{next_hia_pkt_time}, "
            f"got {received_here_i_am.next_hia_pkt_time}"
        )

    finally:
        # Cleanup
        subscription.unsubscribe()
        client.stop()
        server.stop()
        time.sleep(0.1)  # Give services time to stop
