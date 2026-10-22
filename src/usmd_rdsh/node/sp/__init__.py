"""SP: encrypted service traffic between nodes [SP-01].

    handshake   initiation / response and the key schedule [7.3, 7.4]
    session     data frames, counters and anti-replay [7.5, 7.6]
    packets     IPv4 parsing, ICMP, fragmentation, ECN [5, 9]
    flows       flow affinity [6.3]
    engine      SAT, destination choice, sessions, broadcast [5, 6, 7, 8]
    tun         the SP interface (Linux /dev/net/tun, Windows Wintun, memory)
"""
