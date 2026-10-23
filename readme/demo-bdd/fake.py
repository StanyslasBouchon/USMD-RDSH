#!/usr/bin/env python3
"""The demo's "fake" client: one INSERT a second on the nearest "db" (its VIP).

Prints each identifier the database generated and the instance it names: the
first 8 hexadecimal digits are that instance's SP address (sss.nnnn). When an
instance fails, the connection breaks, the next one reaches another instance,
and the identifiers change prefix.
"""

import os
import sys
import time

import psycopg

DB_VIP = sys.argv[1]
ME = os.environ.get("USMD_SP_ADDRESS", "?")


def main():
    count = 0
    while True:
        try:
            with psycopg.connect(f"host={DB_VIP} dbname=app user=app connect_timeout=3",
                                 autocommit=True) as db:
                while True:
                    count += 1
                    (row_id,) = db.execute(
                        "INSERT INTO events (payload) VALUES (%s) RETURNING id::text",
                        (f"fake #{count} from {ME}",)).fetchone()
                    print(time.strftime("%H:%M:%S"), row_id, "-> db instance",
                          f"{row_id[1:4]}.{row_id[4:8]}", flush=True)
                    time.sleep(1)
        except psycopg.Error as exc:
            print(time.strftime("%H:%M:%S"), "connection lost:", str(exc).strip(), flush=True)
            time.sleep(1)


if __name__ == "__main__":
    main()
