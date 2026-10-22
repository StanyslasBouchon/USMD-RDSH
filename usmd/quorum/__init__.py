"""Quorum-based operator election for USMD-RDSH.

When no active operator node is detected in the USD, this module orchestrates
a distributed election so that one of the executor nodes can promote itself to
the NODE_OPERATOR role, maintaining USD governance.

The election algorithm is a simplified Raft-like leader election:

1. Each node monitors the NIT every ``check_interval`` seconds.
2. When no live operator is found, a node starts a candidacy with a random
   delay (1 to 8 seconds) to reduce simultaneous elections.
3. The candidate sends ``REQUEST_VOTE`` (NCP 10) to every live peer.
4. Peers vote YES if they have not yet voted in this epoch; NO otherwise.
5. If the candidate receives a majority of YES votes it promotes itself and
   broadcasts ``ANNOUNCE_PROMOTION`` (NCP 11).
6. Receiving nodes update their NAL to grant the operator role to the winner.
"""

from .manager import QuorumManager

__all__ = ["QuorumManager"]
