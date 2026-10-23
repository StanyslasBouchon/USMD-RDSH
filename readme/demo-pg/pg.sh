#!/bin/sh
# Service "pg": a PostgreSQL cluster, one primary and streaming replicas.
#   pg.sh start | stop | check | probe      (called by pg.yaml)
#
# USMD gives the means, this script decides:
#   $USMD_PEERS   the other Active nodes running "pg", as address:60000+id;
#                 each one reaches its instance there (expose)
#   probe         exit 0 on the primary only: the balance VIP sends the
#                 clients to it, and to it alone
#   check         every health check: a replica follows the primary it
#                 finds; with none for PG_PROMOTE_AFTER checks in a row, the
#                 most advanced replica (lowest address on a tie) promotes
#                 itself; two primaries: the newer timeline stays, the other
#                 fails its check and is withdrawn
#   start         first instance: initdb; the others: a copy of the primary
#                 (pg_basebackup); a former primary that finds another one
#                 puts its data aside (pg.before-<date>) and copies it
# The data stays in $USMD_DATA_DIR across unbuilds.
set -eu

# Debian/Ubuntu keep initdb and pg_ctl out of PATH.
for dir in /usr/lib/postgresql/*/bin; do [ -x "$dir/pg_ctl" ] && PATH="$dir:$PATH"; done
export PATH

. "$USMD_FILES_DIR/pg.env"
PORT="${PG_LOCAL_PORT:-5432}"  # the instance's own port, expose: port
PGDATA="$USMD_DATA_DIR/pg"
RUN="$USMD_DATA_DIR/run"  # the Unix socket, this account only
PASSFILE="$USMD_DATA_DIR/pgpass"
MISSING="$USMD_DATA_DIR/primary-missing"  # checks in a row without a primary
LOG="$USMD_DATA_DIR/cluster.log"
NAME=$(echo "${USMD_NODE_ID:-pg}" | tr 'A-Z' 'a-z')

log() { echo "$(date '+%F %T') $*" >>"$LOG"; }
sql() { psql -X -qAt -v ON_ERROR_STOP=1 -h "$RUN" -p "$PORT" -U postgres -d postgres -c "$1"; }
# sql_remote ADDRESS PORT QUERY: "" when the instance does not answer.
sql_remote() {
    PGPASSFILE="$PASSFILE" PGCONNECT_TIMEOUT=2 psql -X -qAt \
        "host=$1 port=$2 user=repl dbname=postgres" -c "$3" 2>/dev/null || true
}
peers() { echo "${USMD_PEERS:-}" | tr ',' '\n' | grep . || true; }
running() { pg_ctl -D "$PGDATA" status >/dev/null 2>&1; }
is_primary() { [ "$(sql 'SELECT pg_is_in_recovery()')" = f ]; }
lower_address() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" = "$1" ]; }

# The primary among the other instances: "address port", or nothing.
find_primary() {
    for peer in $(peers); do
        if [ "$(sql_remote "${peer%:*}" "${peer##*:}" 'SELECT pg_is_in_recovery()')" = f ]; then
            echo "${peer%:*} ${peer##*:}"
            return 0
        fi
    done
    return 1
}

start_server() {
    mkdir -p "$RUN" && chmod 700 "$RUN"
    running && return 0
    pg_ctl -D "$PGDATA" -l "$USMD_DATA_DIR/pg.log" -w -t 300 -o "-c listen_addresses=* \
        -c port=$PORT -c unix_socket_directories=$RUN -c wal_keep_size=512MB \
        -c wal_log_hints=on -c hot_standby=on -c cluster_name=${USMD_NODE_ADDRESS:-pg}" \
        start >/dev/null
}

# follow ADDRESS PORT: stream from that primary (reloaded, no restart).
follow() {
    conninfo="host=$1 port=$2 user=repl passfile=$PASSFILE application_name=$NAME"
    [ "$(sql 'SHOW primary_conninfo')" = "$conninfo" ] && return 0
    sql "ALTER SYSTEM SET primary_conninfo = '$conninfo'" >/dev/null
    sql "SELECT pg_reload_conf()" >/dev/null
    log "replica of the primary at $1:$2"
}

# clone ADDRESS PORT: this instance's data becomes a copy of that primary.
clone() {
    if running; then pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null; fi
    if [ -d "$PGDATA" ]; then
        aside="$USMD_DATA_DIR/pg.before-$(date +%Y%m%d-%H%M%S)"
        mv "$PGDATA" "$aside"
        log "former data put aside in $aside"
    fi
    PGPASSFILE="$PASSFILE" pg_basebackup -h "$1" -p "$2" -U repl -D "$PGDATA" -X stream -c fast
    touch "$PGDATA/standby.signal"
    chmod 700 "$PGDATA"
    log "copied from the primary at $1:$2"
}

init_primary() {
    initdb -D "$PGDATA" -U postgres --auth-local=trust --auth-host=scram-sha-256 >/dev/null
    for prefix in ${PG_ALLOW:-0.0.0.0/0}; do
        printf 'host replication repl %s scram-sha-256\nhost all all %s scram-sha-256\n' \
            "$prefix" "$prefix" >>"$PGDATA/pg_hba.conf"
    done
    log "new cluster: this instance is the primary"
}

# Roles, passwords (pg.env may change them) and the application's database.
roles() {
    sql "SELECT 1 FROM pg_roles WHERE rolname = 'repl'" | grep -q 1 || sql "CREATE ROLE repl" >/dev/null
    sql "ALTER ROLE repl WITH REPLICATION LOGIN PASSWORD '$PG_REPL_PASSWORD'" >/dev/null
    sql "SELECT 1 FROM pg_roles WHERE rolname = 'app'" | grep -q 1 || sql "CREATE ROLE app" >/dev/null
    sql "ALTER ROLE app WITH LOGIN PASSWORD '$PG_APP_PASSWORD'" >/dev/null
    sql "SELECT 1 FROM pg_database WHERE datname = 'app'" | grep -q 1 || \
        sql "CREATE DATABASE app OWNER app" >/dev/null
}

start() {
    umask 077
    echo "*:*:*:repl:$PG_REPL_PASSWORD" >"$PASSFILE"
    if [ ! -s "$PGDATA/PG_VERSION" ]; then
        if primary=$(find_primary); then
            # shellcheck disable=SC2086
            clone $primary; start_server; follow $primary
        else
            init_primary; start_server
        fi
    elif running && is_primary; then
        :  # update of the running primary: two primaries are check's business
    elif primary=$(find_primary); then
        if [ ! -f "$PGDATA/standby.signal" ]; then
            # shellcheck disable=SC2086
            clone $primary  # it was a primary: another one took over since
        fi
        # shellcheck disable=SC2086
        start_server; follow $primary
    else
        start_server  # a replica without primary: check decides whether it promotes
    fi
    if is_primary; then roles; fi
}

# The most advanced replica of those answering (lowest address on a tie)?
most_advanced() {
    mine=$(sql "SELECT coalesce(pg_last_wal_replay_lsn(), pg_last_wal_receive_lsn(), '0/0')")
    for peer in $(peers); do
        answer=$(sql_remote "${peer%:*}" "${peer##*:}" "SELECT pg_is_in_recovery(), \
            coalesce(pg_last_wal_replay_lsn(), pg_last_wal_receive_lsn(), '0/0')")
        [ "${answer%%|*}" = t ] || continue
        ahead=$(sql "SELECT pg_wal_lsn_diff('${answer#*|}', '$mine')")
        case "$ahead" in
            -*) ;;
            0) if lower_address "${peer%:*}" "$USMD_NODE_ADDRESS"; then return 1; fi ;;
            *) return 1 ;;
        esac
    done
    return 0
}

check() {
    pg_isready -q -h "$RUN" -p "$PORT" -t 3 || { echo "PostgreSQL does not answer" >&2; exit 1; }
    if is_primary; then
        rm -f "$MISSING"
        mine=$(sql "SELECT substr(pg_walfile_name(pg_current_wal_lsn()), 1, 8)")
        for peer in $(peers); do
            theirs=$(sql_remote "${peer%:*}" "${peer##*:}" "SELECT CASE WHEN pg_is_in_recovery() \
                THEN '' ELSE substr(pg_walfile_name(pg_current_wal_lsn()), 1, 8) END")
            [ -n "$theirs" ] || continue
            # Two primaries: the newer timeline stays (lowest address on a tie).
            if [ $((0x$theirs)) -gt $((0x$mine)) ] || { [ $((0x$theirs)) -eq $((0x$mine)) ] && \
                    lower_address "${peer%:*}" "$USMD_NODE_ADDRESS"; }; then
                log "another primary at $peer (timeline $theirs): this one steps aside"
                echo "another primary at $peer: transmute this node again to rejoin" >&2
                exit 1
            fi
        done
        return 0
    fi
    if primary=$(find_primary); then
        rm -f "$MISSING"
        # shellcheck disable=SC2086
        follow $primary
        return 0
    fi
    missing=$(( $(cat "$MISSING" 2>/dev/null || echo 0) + 1 ))
    echo "$missing" >"$MISSING"
    log "no primary answers ($missing)"
    [ "$missing" -ge "${PG_PROMOTE_AFTER:-3}" ] || return 0
    most_advanced || return 0
    pg_ctl -D "$PGDATA" -w promote >/dev/null
    rm -f "$MISSING"
    log "promoted: no primary for $missing checks, most advanced replica"
}

probe() { is_primary; }

stop() {
    if running; then pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null; fi
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    check) check ;;
    probe) probe ;;
    *) echo "usage: pg.sh start|stop|check|probe" >&2; exit 2 ;;
esac
