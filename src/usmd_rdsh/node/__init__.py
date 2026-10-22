"""The USMD-RDSH node as specified by the draft series.

    wire        common frame header [ARCH-02 10.1], big-endian readers/writers
    crypto      Ed25519, X25519, HKDF-SHA-256, ChaCha20-Poly1305 [ARCH 4.5]
    identity    node identifier (ULID) and key pairs [ARCH 4.1, 4.2]
    states      node state registry [ARCH 5.5]
    nndp        neighbour discovery [NNDP-01]
    ncp         encrypted control protocol [NCP-02]
    sp          service protocol [SP-01]
    node        the orchestrator tying them to the configuration

Everything runs on one asyncio loop: the console, the web interface and the
protocols share it, which keeps every table single-writer.
"""
