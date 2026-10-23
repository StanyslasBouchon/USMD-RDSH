#!/bin/sh
# Service "db" of the demo: one PostgreSQL per instance, plus its replicator.
#   db.sh start | stop | check     (called by db.yaml with the USMD_* variables)
# The data stays in $USMD_DATA_DIR across unbuilds; the scripts come from
# $USMD_FILES_DIR, written by the node from the signed mutation.
set -eu

# Debian/Ubuntu keep initdb and pg_ctl out of PATH.
for dir in /usr/lib/postgresql/*/bin; do [ -x "$dir/pg_ctl" ] && PATH="$dir:$PATH"; done
export PATH

PGDATA="$USMD_DATA_DIR/pg"
PIDFILE="$USMD_DATA_DIR/replicate.pid"
AREA_PREFIX="${DEMO_AREA_PREFIX:-10.80.0.0/16}"
PSQL="psql -h $USMD_DATA_DIR -U postgres -v ON_ERROR_STOP=1 -q"

start() {
    if [ ! -s "$PGDATA/PG_VERSION" ]; then
        initdb -D "$PGDATA" -U postgres --auth=trust >/dev/null
        echo "host all all $AREA_PREFIX trust" >>"$PGDATA/pg_hba.conf"
    fi
    # Listen everywhere: the VIP is put on the SP interface only once the
    # first check_health has passed, after the build.
    pg_ctl -D "$PGDATA" -l "$USMD_DATA_DIR/pg.log" -w \
        -o "-c listen_addresses=* -c unix_socket_directories=$USMD_DATA_DIR" start >/dev/null || \
        pg_ctl -D "$PGDATA" status >/dev/null

    $PSQL -tc "SELECT 1 FROM pg_roles WHERE rolname = 'app'" | grep -q 1 || $PSQL -c "CREATE ROLE app LOGIN"
    $PSQL -tc "SELECT 1 FROM pg_database WHERE datname = 'app'" | grep -q 1 || \
        $PSQL -c "CREATE DATABASE app OWNER app"
    $PSQL -d app -f "$USMD_FILES_DIR/usmd_id.sql"
    # The identifier prefix is this instance's SP address [ARCH-03 11.6].
    $PSQL -d app -c "ALTER DATABASE app SET usmd.data_id_prefix = '$USMD_DATA_ID_PREFIX'"
    $PSQL -d app -c "CREATE TABLE IF NOT EXISTS events (
            id uuid PRIMARY KEY DEFAULT usmd_id(),
            payload text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp());
        GRANT ALL ON events TO app;
        GRANT USAGE ON SEQUENCE usmd_id_seq TO app"

    stop_replicator
    setsid nohup python3 "$USMD_FILES_DIR/replicate.py" >>"$USMD_DATA_DIR/replicate.log" 2>&1 &
    echo $! >"$PIDFILE"
}

stop_replicator() {
    [ -s "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
}

stop() {
    stop_replicator
    pg_ctl -D "$PGDATA" -m fast stop >/dev/null 2>&1 || true
}

check() {
    pg_isready -q -h 127.0.0.1 -t 3
    kill -0 "$(cat "$PIDFILE")"
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    check) check ;;
    *) echo "usage: db.sh start|stop|check" >&2; exit 2 ;;
esac
