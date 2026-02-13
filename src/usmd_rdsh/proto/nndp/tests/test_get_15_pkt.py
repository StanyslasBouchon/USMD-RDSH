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
    that sends them. It verifies that 15 packets are received and that the data
    received matches the data sent.

    Args:
        nndp_ports: Dictionary of port numbers for client and server
    """
    # Data to send
    node_name = "test-node"
    state = NodeState.ACTIVE
    expected_packets = 15
    interval = 0.1  # Short interval for test

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
                node_name=node_name,
                next_hia_pkt_time=int((time.time() + interval) * 1000),
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
            interval=interval,
        )
        client.start()

        # Wait for 15 packets to be received
        # Each packet is sent every 0.1 seconds, so 15 packets = 1.5 seconds
        # Add some buffer time for network delays
        timeout = (expected_packets * interval) + 2.0
        start_time = time.time()

        while len(received_data) < expected_packets:
            if time.time() - start_time > timeout:
                assert False, (
                    f"Timeout waiting for {expected_packets} packets. "
                    f"Only received {len(received_data)} packets"
                )
            time.sleep(0.05)  # Check every 50ms

        # Verify we received exactly 15 packets
        assert (
            len(received_data) >= expected_packets
        ), f"Expected at least {expected_packets} packets, got {len(received_data)}"

        # Verify all packets have correct data
        for i, received_here_i_am in enumerate(received_data[:expected_packets]):
            assert received_here_i_am.node_name == node_name, (
                f"Packet {i+1}: Node name mismatch: expected {node_name}, "
                f"got {received_here_i_am.node_name}"
            )
            assert received_here_i_am.state == state, (
                f"Packet {i+1}: State mismatch: expected {state}, "
                f"got {received_here_i_am.state}"
            )
            assert received_here_i_am.version == VERSION, (
                f"Packet {i+1}: Version mismatch: expected {VERSION}, "
                f"got {received_here_i_am.version}"
            )

    finally:
        # Cleanup
        subscription.unsubscribe()
        client.stop()
        server.stop()
        time.sleep(0.1)  # Give services time to stop
