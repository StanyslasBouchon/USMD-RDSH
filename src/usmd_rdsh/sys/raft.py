from dataclasses import dataclass


@dataclass
class RaftState:
    quorum: int
    term: int
    leader_ed25519_pub_key_32: str
