"""Base protocol environment and data structures.

This module defines the core data structures and constants used by the USMD-RDSH
protocols, including protocol constants and node properties management.

The module provides:
    - Protocol constants (PROTO_MAGIC, NNDP_VERSION) for packet identification
    - NodeProperties: Persistent node identity and cryptographic keys
    - get_node_properties(): Function to load or create node properties

Node properties are stored in `~/.usmd/node.properties` and include:
    - A unique node ID (ULID)
    - Ed25519 cryptographic key pair for authentication

Example usage:

    >>> from usmd_rdsh.proto.base.env import (
    ...     get_node_properties, PROTO_MAGIC, NNDP_VERSION
    ... )
    >>>
    >>> # Access protocol constants
    >>> assert PROTO_MAGIC == 0xD5C1
    >>> assert NNDP_VERSION == 0x0001
    >>>
    >>> # Get or create node properties
    >>> props = get_node_properties()
    >>> print(f"Node ID: {props.node_id}")
    >>> print(f"Public key: {props.ed25519_keypair.pub32_b64u}")
    >>>
    >>> # Properties persist across application restarts
    >>> props2 = get_node_properties()
    >>> assert props2.node_id == props.node_id
"""

from dataclasses import dataclass
import logging
import os
import subprocess

import ulid

from usmd_rdsh.security.ed25519 import Ed25519Certificate, Ed25519KeyPair
from usmd_rdsh.sys.usc import USC
from usmd_rdsh.sys.usd import USD, USDSettings


PROTO_MAGIC = 0xD5C1
"""Magic number for protocol packets.

This 16-bit value (0xD5C1) is used to identify valid protocol packets at the
protocol level. It must appear at the beginning of every protocol packet.
"""

NNDP_VERSION = 0x0001
"""Protocol version number for NNDP packets.

This 8-bit value (0x01) indicates the version of the NNDP protocol being used.
It is included in every "HIA" packet to allow for protocol evolution
and backward compatibility.

Example:
    >>> from usmd_rdsh.proto.base.env import NNDP_VERSION
    >>> NNDP_VERSION == 0x0001
    True
    >>> NNDP_VERSION == 1
    True
"""


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
        >>> from usmd_rdsh.proto.base.env import (
        ...     NodeProperties, get_node_properties
        ... )
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
    self_ed25519_keypair: Ed25519KeyPair
    ucd: USC
    usd: USD


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
        >>> from usmd_rdsh.proto.base.env import get_node_properties
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
        usdn = ulid.new().str
        ucdn = ulid.new().str
        ed25519_keypair = Ed25519Certificate.generate(
            node_id, os.path.expanduser("~/.usmd/")
        )

        usd = USD(
            usdn=usdn,
            version=1,
            settings=USDSettings(nnr=2, ptms=1000),
            neighbors=[],
            ed25519_pub_key_32=ed25519_keypair.pub32_b64u,
        )

        ucd = USC(
            uscn=ucdn,
            version=1,
            ed25519_pub_key_32=ed25519_keypair.pub32_b64u,
            usd_list=[usd],
        )

        properties_dir = os.path.expanduser("~/.usmd")
        os.makedirs(properties_dir, exist_ok=True)
        subprocess.run(["attrib", "+H", properties_dir], check=True)

        with open(
            os.path.expanduser("~/.usmd/node.properties"), "w", encoding="utf-8"
        ) as f:
            f.write(f"{node_id}\n")
            f.write(f"{ed25519_keypair.pub32_b64u}\n")

        with open(
            os.path.expanduser("~/.usmd/ucd.properties"), "w", encoding="utf-8"
        ) as f:
            f.write(f"{ucdn}\n")
            f.write("1\n")
            f.write(f"{ed25519_keypair.pub32_b64u}\n")
            f.write(f"[{usdn}]\n")

        with open(
            os.path.expanduser(f"~/.usmd/{usdn}.properties"), "w", encoding="utf-8"
        ) as f:
            f.write(f"{usdn}\n")
            f.write("1\n")
            f.write(f"{ed25519_keypair.pub32_b64u}\n")
            f.write("2\n")
            f.write("1000\n")

        logging.info("Created new node properties: %s", node_id)
        logging.info("Public key: %s", ed25519_keypair.pub32_b64u)
        logging.info("Private key: %s", ed25519_keypair.priv64_b64u)
        logging.info("Seed: %s", ed25519_keypair.seed32_b64u)
        logging.info("UCDN: %s", ucdn)
        logging.info("USDN: %s", usdn)
        logging.info("UCD key: %s", ucd.ed25519_pub_key_32)
        logging.info("USD key: %s", usd.ed25519_pub_key_32)

        logging.info("Node properties created successfully")

        return NodeProperties(
            node_id=node_id,
            self_ed25519_keypair=ed25519_keypair,
            ucd=ucd,
            usd=usd,
        )

    with open(
        os.path.expanduser("~/.usmd/node.properties"), "r", encoding="utf-8"
    ) as f:
        properties = f.read().split("\n")

    with open(os.path.expanduser("~/.usmd/ucd.properties"), "r", encoding="utf-8") as f:
        ucd_properties = f.read().split("\n")
        usd_arr = ucd_properties[3].split("[")[1].split("]")[0].split(",")

    with open(
        os.path.expanduser(f"~/.usmd/{usd_arr[0]}.properties"), "r", encoding="utf-8"
    ) as f:
        usd_properties = f.read().split("\n")

    usd = USD(
        usdn=usd_properties[0],
        version=int(usd_properties[1]),
        settings=USDSettings(nnr=int(usd_properties[3]), ptms=int(usd_properties[4])),
        neighbors=[],
        ed25519_pub_key_32=usd_properties[2],
    )

    ucd = USC(
        uscn=ucd_properties[0],
        version=int(ucd_properties[1]),
        ed25519_pub_key_32=ucd_properties[2],
        usd_list=[usd],
    )

    ed25519_keypair = Ed25519Certificate.load(os.path.expanduser("~/.usmd/"))

    logging.info("Node ID: %s", properties[0])
    logging.info("Public key: %s", ed25519_keypair.pub32_b64u)
    logging.info("Private key: %s", ed25519_keypair.priv64_b64u)
    logging.info("Seed: %s", ed25519_keypair.seed32_b64u)
    logging.info("UCDN: %s", ucd_properties[0])
    logging.info("USDN: %s", usd_properties[0])
    logging.info("UCD key: %s", ucd_properties[2])
    logging.info("USD key: %s", usd_properties[2])

    return NodeProperties(
        node_id=properties[0],
        self_ed25519_keypair=ed25519_keypair,
        ucd=ucd,
        usd=usd,
    )
