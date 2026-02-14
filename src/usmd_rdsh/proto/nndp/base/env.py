"""NNDP (Network Node Discovery Protocol) environment and data structures.

This module defines the core data structures and constants used by the NNDP protocol,
including the "Here I Am" packet data format and node properties management.

The module provides:
    - Protocol constants (MAGIC, VERSION) for packet identification
    - HereIAmData: Data structure for node announcement packets
    - NodeProperties: Persistent node identity and cryptographic keys
    - get_node_properties(): Function to load or create node properties

Node properties are stored in `~/.usmd/node.properties` and include:
    - A unique node ID (ULID)
    - Ed25519 cryptographic key pair for authentication

Example usage:

    >>> from usmd_rdsh.proto.nndp.base.env import (
    ...     HereIAmData, get_node_properties, MAGIC, VERSION
    ... )
    >>> from usmd_rdsh.utils.node_state import NodeState
    >>> import time
    >>>
    >>> # Create a Here I Am data packet
    >>> hia_data = HereIAmData(
    ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ...     next_hia_pkt_time=int((time.time() + 15.0) * 1000),
    ...     state=NodeState.ACTIVE,
    ... )
    >>> print(f"Node: {hia_data.node_id}, State: {hia_data.state.name}")
    >>>
    >>> # Get or create node properties
    >>> props = get_node_properties()
    >>> print(f"Node ID: {props.node_id}")
    >>> print(f"Public key: {props.ed25519_keypair.pub32_b64u}")
"""

from dataclasses import dataclass
import logging
import os
import subprocess

import ulid

from usmd_rdsh.security.ed25519 import Ed25519KeyPair
from usmd_rdsh.utils.node_state import NodeState


MAGIC = 0xD5C1
"""Magic number for NNDP "Here I Am" packets.

This 16-bit value (0xD5C1) is used to identify valid NNDP packets at the
protocol level. It must appear at the beginning of every "Here I Am" packet
payload.

Example:
    >>> from usmd_rdsh.proto.nndp.base.env import MAGIC
    >>> hex(MAGIC)
    '0xd5c1'
    >>> MAGIC == 0xD5C1
    True
"""

VERSION = 0x0001
"""Protocol version number for NNDP packets.

This 8-bit value (0x01) indicates the version of the NNDP protocol being used.
It is included in every "Here I Am" packet to allow for protocol evolution
and backward compatibility.

Example:
    >>> from usmd_rdsh.proto.nndp.base.env import VERSION
    >>> VERSION == 0x0001
    True
    >>> VERSION == 1
    True
"""


@dataclass
class HereIAmData:
    """Data structure for NNDP "Here I Am" announcement packets.

    This dataclass represents the payload data sent by nodes to announce their
    presence on the network. It contains information about the node's identity,
    current state, and when the next announcement will be sent.

    Attributes:
        node_id: Unique identifier for the node (typically a ULID string)
        next_hia_pkt_time: Timestamp (in milliseconds) when the next "Here I Am"
                          packet will be sent
        state: Current state of the node (e.g., ACTIVE, INACTIVE, SYNCHRONISING)
        version: Protocol version (defaults to VERSION constant)

    Note:
        The `next_hia_pkt_time` is typically calculated as the current time
        plus the announcement interval (e.g., 15 seconds) in milliseconds.

    Example:
        >>> from usmd_rdsh.proto.nndp.base.env import HereIAmData, VERSION
        >>> from usmd_rdsh.utils.node_state import NodeState
        >>> import time
        >>>
        >>> # Create a Here I Am data packet
        >>> hia_data = HereIAmData(
        ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ...     next_hia_pkt_time=int((time.time() + 15.0) * 1000),
        ...     state=NodeState.ACTIVE,
        ... )
        >>>
        >>> # Access the fields
        >>> assert hia_data.node_id == "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        >>> assert hia_data.state == NodeState.ACTIVE
        >>> assert hia_data.version == VERSION
        >>> assert hia_data.next_hia_pkt_time > int(time.time() * 1000)
        >>>
        >>> # Version is optional and defaults to VERSION
        >>> hia_data2 = HereIAmData(
        ...     node_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ...     next_hia_pkt_time=int(time.time() * 1000),
        ...     state=NodeState.SYNCHRONISING,
        ... )
        >>> assert hia_data2.version == VERSION
    """

    node_id: str
    next_hia_pkt_time: int
    state: NodeState
    version: int = VERSION


@dataclass
class NodeProperties:
    """Persistent node properties including identity and cryptographic keys.

    This dataclass stores the essential properties of a node that persist across
    application restarts. It includes a unique node identifier and an Ed25519
    key pair used for cryptographic operations and authentication.

    The properties are typically loaded from or saved to `~/.usmd/node.properties`
    using the `get_node_properties()` function.

    Attributes:
        node_id: Unique node identifier (typically a ULID string)
        ed25519_keypair: Ed25519 cryptographic key pair for signing and verification

    Example:
        >>> from usmd_rdsh.proto.nndp.base.env import (
        ...     NodeProperties, get_node_properties
        ... )
        >>> from usmd_rdsh.security.ed25519 import Ed25519KeyPair
        >>>
        >>> # Get node properties (creates if doesn't exist)
        >>> props = get_node_properties()
        >>>
        >>> # Access the node ID
        >>> node_id = props.node_id
        >>> assert len(node_id) > 0
        >>>
        >>> # Access the cryptographic keys
        >>> public_key = props.ed25519_keypair.pub32_b64u
        >>> private_key = props.ed25519_keypair.priv64_b64u
        >>> seed = props.ed25519_keypair.seed32_b64u
        >>>
        >>> # All keys are Base64URL-encoded strings
        >>> assert isinstance(public_key, str)
        >>> assert isinstance(private_key, str)
        >>> assert isinstance(seed, str)
    """

    node_id: str
    ed25519_keypair: Ed25519KeyPair


def get_node_properties() -> "NodeProperties":
    """Load or create node properties from persistent storage.

    This function manages the node's persistent identity and cryptographic keys.
    If the properties file exists at `~/.usmd/node.properties`, it loads the
    stored node ID and Ed25519 key pair. Otherwise, it generates new properties
    and saves them to disk.

    The properties file format is a simple text file with one value per line:
        Line 1: node_id (ULID string)
        Line 2: public_key (Base64URL-encoded 32 bytes)
        Line 3: private_key (Base64URL-encoded 64 bytes)
        Line 4: seed (Base64URL-encoded 32 bytes)

    Returns:
        NodeProperties: The node's properties, either loaded from disk or
                       newly generated

    Note:
        The function automatically creates the `~/.usmd/` directory if it
        doesn't exist when generating new properties.

    Example:
        >>> from usmd_rdsh.proto.nndp.base.env import get_node_properties
        >>> import os
        >>>
        >>> # First call: creates new properties if file doesn't exist
        >>> props1 = get_node_properties()
        >>> node_id_1 = props1.node_id
        >>> public_key_1 = props1.ed25519_keypair.pub32_b64u
        >>>
        >>> # Second call: loads existing properties
        >>> props2 = get_node_properties()
        >>> assert props2.node_id == node_id_1
        >>> assert props2.ed25519_keypair.pub32_b64u == public_key_1
        >>>
        >>> # Properties are consistent across calls
        >>> assert props1.node_id == props2.node_id
        >>>
        >>> # Check that the file exists
        >>> properties_path = os.path.expanduser("~/.usmd/node.properties")
        >>> assert os.path.exists(properties_path)
    """
    if not os.path.exists(os.path.expanduser("~/.usmd/node.properties")):

        node_id = ulid.new().str
        ed25519_keypair = Ed25519KeyPair.generate()

        properties_dir = os.path.expanduser("~/.usmd")
        os.makedirs(properties_dir, exist_ok=True)
        subprocess.run(["attrib", "+H", properties_dir], check=True)

        with open(
            os.path.expanduser("~/.usmd/node.properties"), "w", encoding="utf-8"
        ) as f:
            f.write(f"{node_id}\n")
            f.write(f"{ed25519_keypair.pub32_b64u}\n")
            f.write(f"{ed25519_keypair.priv64_b64u}\n")
            f.write(f"{ed25519_keypair.seed32_b64u}\n")

        logging.info("Created new node properties: %s", node_id)
        logging.info("Public key: %s", ed25519_keypair.pub32_b64u)
        logging.info("Private key: %s", ed25519_keypair.priv64_b64u)
        logging.info("Seed: %s", ed25519_keypair.seed32_b64u)

        logging.info("Node properties created successfully")

        return NodeProperties(
            node_id=node_id,
            ed25519_keypair=ed25519_keypair,
        )

    with open(
        os.path.expanduser("~/.usmd/node.properties"), "r", encoding="utf-8"
    ) as f:
        properties = f.read().split("\n")

    ed25519_keypair = Ed25519KeyPair.from_b64u(priv64_b64u=properties[2])

    if (
        ed25519_keypair.priv64_b64u != properties[2]
        or ed25519_keypair.seed32_b64u != properties[3]
        or ed25519_keypair.pub32_b64u != properties[1]
    ):
        logging.error("Node properties are corrupted, deleting and creating new ones")
        os.remove(os.path.expanduser("~/.usmd/node.properties"))
        return get_node_properties()

    return NodeProperties(
        node_id=properties[0],
        ed25519_keypair=Ed25519KeyPair.from_b64u(priv64_b64u=properties[2]),
    )
