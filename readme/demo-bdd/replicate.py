#!/usr/bin/env python3
"""Replication of the demo's "db" service through its group address (sss.ffff).

Every minute each instance sends the rows IT created - their identifiers
start with its SP address, $USMD_DATA_ID_PREFIX - to the group address; the
other instances insert them, ignoring those they hold. Identifiers of two
instances never collide, so there is nothing to arbitrate. On start an
instance asks the others to send their rows of the last 24 hours again, and
asks once more one and three minutes later (answers already held are ignored).
"""

import json
import os
import socket
import threading
import time

import psycopg

VIP, GROUP = os.environ["USMD_VIP"], os.environ["USMD_GROUP"]
PREFIX, ME = os.environ["USMD_DATA_ID_PREFIX"], os.environ["USMD_SP_ADDRESS"]
PORT, PERIOD, WINDOW = 7000, 60, 180  # the window overlaps: a lost datagram is resent
# The catch-up request is sent on start and again a little later: when the
# nodes start together, the first one may leave before SP reaches the others.
SYNC_SPAN, SYNC_AGAIN = 86400, (60, 180)
DSN = "host=127.0.0.1 dbname=app user=app"  # the VIP appears only once the service is hosted


def log(*parts):
    print(time.strftime("%H:%M:%S"), ME, *parts, flush=True)


def send(message):
    """SP only carries packets whose source is the service's own VIP."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((VIP, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(VIP))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        s.sendto(json.dumps(message).encode(), (GROUP, PORT))


def push(seconds):
    """Our own rows of the last *seconds*, in datagrams below the SP MTU."""
    with psycopg.connect(DSN) as db:
        rows = db.execute(
            "SELECT id::text, payload, created_at::text FROM events"
            " WHERE id::text LIKE %s AND usmd_id_created(id) > now() - make_interval(secs => %s)"
            " ORDER BY id", (PREFIX + "%", seconds)).fetchall()
    batch = []
    for row in rows:
        batch.append(row)
        if len(json.dumps(batch)) > 1000:
            send({"rows": batch})
            batch = []
    if batch:
        send({"rows": batch})
    return len(rows)


def listen():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", PORT))
        while True:  # the VIP exists once the first check_health has passed
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                             socket.inet_aton(GROUP) + socket.inet_aton(VIP))
                break
            except OSError:
                time.sleep(2)
        log("listening on", f"{GROUP}:{PORT}")
        with psycopg.connect(DSN, autocommit=True) as db:
            while True:
                message = json.loads(s.recv(65535))
                if "sync" in message:
                    threading.Thread(target=push, args=(message["sync"],), daemon=True).start()
                    continue
                received = 0
                for row_id, payload, created in message["rows"]:
                    received += db.execute(
                        "INSERT INTO events (id, payload, created_at) VALUES (%s, %s, %s)"
                        " ON CONFLICT (id) DO NOTHING", (row_id, payload, created)).rowcount
                if received:
                    log("received", received, "new rows")


def main():
    threading.Thread(target=listen, daemon=True).start()
    while True:
        try:
            send({"sync": SYNC_SPAN})
            break
        except OSError:
            time.sleep(2)
    started = time.monotonic()
    pending = list(SYNC_AGAIN)
    while True:
        time.sleep(PERIOD)
        try:
            log("sent", push(WINDOW), "own rows")
            while pending and time.monotonic() - started >= pending[0]:
                pending.pop(0)
                send({"sync": SYNC_SPAN})
                log("asked the other instances for their rows again")
        except (OSError, psycopg.Error) as exc:
            log("replication failed:", exc)


if __name__ == "__main__":
    main()
