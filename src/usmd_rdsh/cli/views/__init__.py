"""The configuration tree of a USMD-RDSH node.

Walked with ``config`` / ``set`` / ``unset`` / ``edit`` / ``next`` / ``end``::

    config system
        config global            hostname, banner
        config logging           buffer, console and timestamp settings
        config capture           live capture of NNDP, NCP and SP frames
        config web-interface     management web interface and token API
        config bootstrap         roles, creation token, contact node, EDB [ARCH 5.1]
        config trust-anchor      USC and USD public keys                  [ARCH 4.4]
    config usc                   USCN, public key, member USDs            [ARCH 9.1]
    config usd                   USDN, public key, parameters 0x0001-0x0015 [ARCH-02 9.2]
    config service-area          (table) id and prefix of each area      [ARCH-02 11.2]
    config protocol
        config nndp              HIA interval, freshness window, ports    [NNDP-01 7]
        config ncp               transport, timers, Raft timers           [NCP-02 8]
        config sp                local SP parameters                      [SP-01 10]
    config mutation              (table) roles: services, instance bounds [ARCH 8]
    config service               (table) catalogue entry and service file [ARCH-02 11.1]
    config trust
        config nal               (table) public key -> roles             [ARCH 4.3]

Importing this package registers every node; ``main`` does it once.
"""

# One import per line, in this order: declaration order is the print order of
# ``show configuration``, and a sorted import list would scramble it.
# pylint: disable=unused-import,wrong-import-order
from usmd_rdsh.cli.views import system  # noqa: F401, I001
from usmd_rdsh.cli.views import node  # noqa: F401
from usmd_rdsh.cli.views import domain  # noqa: F401
from usmd_rdsh.cli.views import protocol  # noqa: F401
from usmd_rdsh.cli.views import services  # noqa: F401
from usmd_rdsh.cli.views import trust  # noqa: F401
