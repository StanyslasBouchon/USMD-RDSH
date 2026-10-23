#!/usr/bin/env bash
# =============================================================================
# USMD-RDSH — Node Installer
# =============================================================================
# Installs the USMD-RDSH node on a Linux machine:
#   - A dedicated system user    : usmd
#   - A Python virtualenv        : /opt/usmd/venv
#   - The configuration          : /etc/usmd/usmd.yaml (the node rewrites it
#                                  on each commit, so it owns /etc/usmd)
#   - A data directory           : /var/lib/usmd (identity, keys, services)
#   - A systemd service          : usmd.service (auto-start), allowed to
#                                  create the SP interface (CAP_NET_ADMIN)
#   - The console command        : /usr/local/bin/usmd — the console of the
#                                  running node (Tab, '?', 'usmd -c "<line>"')
#   - System commands for services: the sequences of a service may run, as
#                                  root, the commands of /etc/usmd-root/commands
#                                  (systemctl, apt-get, ip...): 'sudo usmd-root
#                                  <command> ...' (sudoers: /etc/sudoers.d/usmd)
#
# Usage :
#   sudo bash scripts/install.sh [--source <path>] [--address <ipv4>]
#                                [--found [--usd-label <name>]]
#                                [--reset-config] [--import-state <dir>]
#                                [--no-start]
#
#   --source <path>      Source directory (default: this repository)
#   --address <ipv4>     The node's IPv4 address (default: auto, the outbound one)
#   --found              This node founds a new USD: it generates the USC and
#                        USD keys and holds the four roles (usc-operator,
#                        usd-operator, node-operator, node-executor)
#   --usd-label <name>   With --found: the readable name of the USD (default: usd)
#   --reset-config       Rewrite /etc/usmd/usmd.yaml (kept otherwise); the
#                        node's identity in /var/lib/usmd is kept
#   --import-state <dir> Take over a node that was run by hand ('usmd' in a
#                        terminal, state in <dir>, e.g. /home/me/.usmd): its
#                        identity, USD, tokens, tables and configuration become
#                        the service's. Stop that node first ('exit').
#   --no-start           Install without starting the service
#
# Run again to upgrade: the package, the service and the console command are
# rewritten, the configuration and the data are kept.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors & helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[USMD]${NC} $*"; }
success() { echo -e "${GREEN}[USMD] ✔${NC} $*"; }
warn()    { echo -e "${YELLOW}[USMD] ⚠${NC} $*"; }
die()     { echo -e "${RED}[USMD] ✘${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NO_START=false
FOUND=false
RESET_CONFIG=false
ADDRESS="auto"
USD_LABEL="usd"
IMPORT_STATE=""

INSTALL_DIR="/opt/usmd"
VENV_DIR="${INSTALL_DIR}/venv"
CONFIG_DIR="/etc/usmd"
CONFIG_FILE="${CONFIG_DIR}/usmd.yaml"
DATA_DIR="/var/lib/usmd"
STATE_DIR="${DATA_DIR}/.usmd"      # the node's state: ~/.usmd of the usmd user
SERVICE_FILE="/etc/systemd/system/usmd.service"
COMMAND_FILE="/usr/local/bin/usmd"
ROOT_RELAY="/usr/local/sbin/usmd-root"
ROOT_COMMANDS_DIR="/etc/usmd-root"
ROOT_COMMANDS="${ROOT_COMMANDS_DIR}/commands"
SUDOERS_FILE="/etc/sudoers.d/usmd"
#: Commands the services' sequences may run as root unless the list exists already.
DEFAULT_ROOT_COMMANDS="systemctl journalctl apt-get apt dpkg ip sysctl install"
SERVICE_USER="usmd"
PYTHON_MIN="3.13"   # requires-python of pyproject.toml

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --source)       SOURCE_DIR="$(realpath "$2")"; shift 2 ;;
        --address)      ADDRESS="$2"; shift 2 ;;
        --found)        FOUND=true; shift ;;
        --usd-label)    USD_LABEL="$2"; shift 2 ;;
        --reset-config) RESET_CONFIG=true; shift ;;
        --import-state) IMPORT_STATE="$(realpath "$2")"; shift 2 ;;
        --no-start)     NO_START=true; shift ;;
        -h|--help)
            sed -n '/^# Usage/,/^# ===/p' "$0" | head -n -1 | sed 's/^# \?//'
            exit 0
            ;;
        *)
            die "Unknown argument: $1  (use --help)"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Preliminary checks
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "This script must be run as root (sudo)."

command -v systemctl &>/dev/null || die "systemd is required but was not found."
command -v ip &>/dev/null || die "'ip' (iproute2) is required: the node configures its SP interface with it."
[[ -e /dev/net/tun ]] || warn "/dev/net/tun is missing: SP (the services' data plane) will not start."

[[ -f "${SOURCE_DIR}/pyproject.toml" ]] \
    || die "No pyproject.toml in '${SOURCE_DIR}'. Use --source <path>."
# pyproject.toml takes nan-actions from the directory beside the repository.
[[ -f "${SOURCE_DIR}/../nan-actions/pyproject.toml" ]] \
    || die "nan-actions is needed beside the repository: clone it as '$(dirname "${SOURCE_DIR}")/nan-actions'."

if [[ "${ADDRESS}" != "auto" ]]; then
    [[ "${ADDRESS}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "--address: an IPv4 address, e.g. 192.168.1.11"
fi
[[ "${USD_LABEL}" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "--usd-label: letters, digits, . _ - (64 at most)"

if [[ -f "${CONFIG_FILE}" && "${RESET_CONFIG}" == "false" && -z "${IMPORT_STATE}" ]]; then
    if [[ "${FOUND}" == "true" || "${ADDRESS}" != "auto" ]]; then
        die "${CONFIG_FILE} exists: --found and --address only write a new one. Add --reset-config."
    fi
fi
if [[ -n "${IMPORT_STATE}" ]]; then
    [[ "${FOUND}" == "false" ]] || die "--import-state takes over a node: it cannot also --found."
    [[ -f "${IMPORT_STATE}/identity.json" ]] \
        || die "--import-state: no identity.json in '${IMPORT_STATE}' (the node's state directory)."
    [[ -f "${IMPORT_STATE}/config.json" || -f "${IMPORT_STATE}/usmd.yaml" ]] \
        || die "--import-state: no config.json in '${IMPORT_STATE}'."
    # The node run by hand must be stopped: two nodes cannot hold one identity.
    if ss -Hlun 2>/dev/null | awk '{print $4}' | grep -Eq ':(9992|5222)$' \
            && ! systemctl is-active --quiet usmd.service; then
        die "A node still runs on this machine (UDP 9992/5222): 'exit' its console first."
    fi
fi

# Find Python 3.11+
PYTHON=""
for candidate in python3.14 python3.13 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major="${ver%%.*}"
        minor="${ver#*.}"
        if [[ $major -ge 3 && $minor -ge 13 ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done
[[ -n "$PYTHON" ]] || die "Python >= ${PYTHON_MIN} is required but was not found."
info "Python detected: $("$PYTHON" --version)"

# ---------------------------------------------------------------------------
# System user creation
# ---------------------------------------------------------------------------
if id "${SERVICE_USER}" &>/dev/null; then
    warn "User '${SERVICE_USER}' already exists — kept."
else
    info "Creating system user '${SERVICE_USER}'..."
    useradd \
        --system \
        --no-create-home \
        --home-dir "${DATA_DIR}" \
        --shell /usr/sbin/nologin \
        --comment "USMD-RDSH daemon" \
        "${SERVICE_USER}"
    success "User '${SERVICE_USER}' created."
fi

# ---------------------------------------------------------------------------
# Directories — the node writes its configuration back on every commit
# ---------------------------------------------------------------------------
info "Creating directories..."

install -d -m 755 -o root               -g root               "${INSTALL_DIR}"
install -d -m 750 -o "${SERVICE_USER}"  -g "${SERVICE_USER}"  "${CONFIG_DIR}"
install -d -m 750 -o "${SERVICE_USER}"  -g "${SERVICE_USER}"  "${DATA_DIR}"

success "Directories created."

# ---------------------------------------------------------------------------
# Virtualenv + package install
# ---------------------------------------------------------------------------
if systemctl is-active --quiet usmd.service; then
    info "Stopping the running node for the upgrade..."
    systemctl stop usmd.service
fi

info "Creating virtualenv in '${VENV_DIR}'..."
"$PYTHON" -m venv "${VENV_DIR}"

info "Upgrading pip..."
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip

info "Installing usmd-rdsh from '${SOURCE_DIR}'..."
"${VENV_DIR}/bin/pip" install --quiet --upgrade "${SOURCE_DIR}"

chown -R root:root "${INSTALL_DIR}"
chmod -R o-w "${INSTALL_DIR}"

success "Package installed. Version: $("${VENV_DIR}/bin/python" -c 'import importlib.metadata; print(importlib.metadata.version("usmd-rdsh"))' 2>/dev/null || echo '(unknown)')"

# ---------------------------------------------------------------------------
# Configuration file (kept unless --reset-config or --import-state)
# ---------------------------------------------------------------------------
STAMP="$(date +%Y%m%d%H%M%S)"
if [[ -n "${IMPORT_STATE}" ]]; then
    info "Taking over the node of '${IMPORT_STATE}'..."
    if [[ -d "${STATE_DIR}" ]]; then
        mv "${STATE_DIR}" "${STATE_DIR}.${STAMP}.bak"
        info "Previous service state saved as ${STATE_DIR}.${STAMP}.bak"
    fi
    cp -a "${IMPORT_STATE}" "${STATE_DIR}"
    rm -f "${STATE_DIR}/usmd.sock"
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "${STATE_DIR}"
    [[ -f "${CONFIG_FILE}" ]] && cp -p "${CONFIG_FILE}" "${CONFIG_FILE}.${STAMP}.bak"
    if [[ -f "${IMPORT_STATE}/usmd.yaml" ]]; then
        cp "${IMPORT_STATE}/usmd.yaml" "${CONFIG_FILE}"
    else
        # The configuration the node saved (config.json), in the usmd.yaml layout;
        # already founded or admitted: no bootstrap, the identity stays identity.json.
        USMD_STATE_DIR="${STATE_DIR}" "${VENV_DIR}/bin/python" - > "${CONFIG_FILE}" <<'EOF'
from usmd_rdsh.cli import yaml_config
from usmd_rdsh.cli.store import ConfigStore

print("# /etc/usmd/usmd.yaml — taken over from a node run by hand (install.sh --import-state)")
print(yaml_config.dump(ConfigStore().load()), end="")
EOF
    fi
    success "Node taken over: identity, USD and configuration in ${STATE_DIR} and ${CONFIG_FILE}."
    info "'${IMPORT_STATE}' is left as it was; remove it once the service runs."
elif [[ -f "${CONFIG_FILE}" && "${RESET_CONFIG}" == "false" ]]; then
    warn "Existing configuration kept: ${CONFIG_FILE}"
else
    if [[ -f "${CONFIG_FILE}" ]]; then
        cp -p "${CONFIG_FILE}" "${CONFIG_FILE}.${STAMP}.bak"
        info "Previous configuration saved beside it (.bak)."
    fi
    if [[ "${FOUND}" == "true" ]]; then
        ROLES="[usc-operator, usd-operator, node-operator, node-executor]"
        BOOTSTRAP="true"
    else
        ROLES="[node-executor]"
        BOOTSTRAP="false"
    fi
    info "Writing the configuration..."
    cat > "${CONFIG_FILE}" <<EOF
# /etc/usmd/usmd.yaml — USMD-RDSH node configuration
#
# The node rewrites this file on every commit: configure it from its
# console ('usmd'), not here, while it runs.

node:
  address: ${ADDRESS}          # this node's IPv4, or auto (the outbound interface)
  roles: ${ROLES}

usd:
  name: ${USD_LABEL}           # with bootstrap: the USD's label; its USDN is generated

# true: this node founds a new USD (USC and USD keys, founder token);
# false: it joins one with a creation token ('config system bootstrap').
bootstrap: ${BOOTSTRAP}
nndp_ttl: 15

ports:
  ncp: 9992                    # NCP-02 section 4; the same on every node

web:
  enabled: false               # the web interface; 'config system web-interface'
EOF
    chown "${SERVICE_USER}:${SERVICE_USER}" "${CONFIG_FILE}"
    chmod 600 "${CONFIG_FILE}"
    success "Configuration written: ${CONFIG_FILE}"
fi
# A configuration from an earlier installer: the node must be able to rewrite it.
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${CONFIG_DIR}"
chmod 600 "${CONFIG_FILE}"

# ---------------------------------------------------------------------------
# systemd unit file
# ---------------------------------------------------------------------------
info "Writing systemd service..."
cat > "${SERVICE_FILE}" <<EOF
# /etc/systemd/system/usmd.service
# Generated by scripts/install.sh — rewritten on each install.

[Unit]
Description=USMD-RDSH Node Daemon
Documentation=https://github.com/StanyslasBouchon/USMD-RDSH
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${DATA_DIR}
Environment=HOME=${DATA_DIR}

# No terminal: the console is 'usmd', through /run/usmd/usmd.sock.
ExecStart=${VENV_DIR}/bin/python -m usmd_rdsh --config ${CONFIG_FILE} --no-console
ExecReload=/bin/kill -HUP \$MAINPID

Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Logging via journald
StandardOutput=journal
StandardError=journal
SyslogIdentifier=usmd

# /run/usmd: the console socket (mode 0660, group ${SERVICE_USER})
RuntimeDirectory=usmd
RuntimeDirectoryMode=0755

# The SP interface (tun, its addresses and routes) needs CAP_NET_ADMIN: the
# node holds it and nothing else. The bounding set also lets 'sudo' change
# user, so that a sequence can reach ${ROOT_RELAY} (sudoers: ${SUDOERS_FILE}).
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_AUDIT_WRITE

# Security hardening: the node and the services it runs write only its
# configuration and its data (services keep theirs in \$USMD_DATA_DIR).
# A system change goes through 'sudo usmd-root <command>', which systemd runs
# outside this sandbox, and only for the commands of ${ROOT_COMMANDS}.
# NoNewPrivileges is off: it would stop sudo, a setuid program.
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_DIR} ${CONFIG_DIR} -/run/sudo

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "${SERVICE_FILE}"
success "systemd service written: ${SERVICE_FILE}"

# ---------------------------------------------------------------------------
# Console command
# ---------------------------------------------------------------------------
info "Installing the console command ${COMMAND_FILE}..."
cat > "${COMMAND_FILE}" <<EOF
#!/bin/sh
# The console of the USMD-RDSH node running on this machine (usmd.service).
#   usmd                     interactive console (Tab, '?', 'exit')
#   usmd -c "show node"      one line, then exit (repeatable; -y answers yes)
# Root and the members of the '${SERVICE_USER}' group may use it.
USMD_ATTACH_ONLY=1 exec ${VENV_DIR}/bin/python -m usmd_rdsh "\$@"
EOF
chmod 755 "${COMMAND_FILE}"

# The administrator who ran the installer may use the console without sudo.
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    if ! id -nG "${SUDO_USER}" | tr ' ' '\n' | grep -qx "${SERVICE_USER}"; then
        usermod -aG "${SERVICE_USER}" "${SUDO_USER}"
        info "'${SUDO_USER}' joined the '${SERVICE_USER}' group: 'usmd' without sudo after the next login."
    fi
fi
success "Console command installed."

# ---------------------------------------------------------------------------
# System commands for the services: sudo -> usmd-root -> systemd-run
# ---------------------------------------------------------------------------
# A command started by the node inherits its sandbox (read-only system, its
# capabilities only), sudo or not: 'sudo apt-get' would find /usr read-only.
# usmd-root asks systemd to run the command as a transient unit instead,
# outside the sandbox, and only if root listed it in ${ROOT_COMMANDS}.
info "Installing the system command relay ${ROOT_RELAY}..."
cat > "${ROOT_RELAY}" <<'EOF'
#!/bin/sh
# Runs one system command for the services of the USMD-RDSH node: as root and
# outside the node's sandbox (a transient systemd unit, logged in the journal),
# only if /etc/usmd-root/commands lists it (absolute paths, one per line).
#   sudo usmd-root <command> [args...]    e.g. sudo usmd-root systemctl restart nginx
# Written by scripts/install.sh; the list is root's to edit.
set -eu
LIST=/etc/usmd-root/commands
[ "$(id -u)" -eq 0 ] || { echo "usmd-root: run it with sudo" >&2; exit 126; }
[ "$#" -ge 1 ] || { echo "usage: sudo usmd-root <command> [args...]" >&2; exit 2; }
# The list decides what root runs: it must be root's alone.
[ "$(stat -c %u "$LIST")" = 0 ] && [ -z "$(find "$LIST" -perm /022)" ] \
    || { echo "usmd-root: $LIST must be owned by root and writable by root only" >&2; exit 126; }
name=$1
shift
path=""
while IFS= read -r line || [ -n "$line" ]; do
    line=${line%%#*}
    line=$(printf '%s' "$line" | tr -d '[:space:]')
    [ -n "$line" ] || continue
    case "$name" in
        /*) [ "$line" = "$name" ] && path=$line ;;
        *) [ "${line##*/}" = "$name" ] && path=$line ;;
    esac
    [ -z "$path" ] || break
done < "$LIST"
[ -n "$path" ] || { echo "usmd-root: '$name' is not in $LIST" >&2; exit 126; }
[ -x "$path" ] || { echo "usmd-root: $path is not installed" >&2; exit 127; }
exec systemd-run --quiet --wait --pipe --collect --service-type=exec \
    --description="USMD service command: $name" \
    --setenv=DEBIAN_FRONTEND=noninteractive \
    -- "$path" "$@"
EOF
chown root:root "${ROOT_RELAY}"
chmod 755 "${ROOT_RELAY}"

install -d -m 755 -o root -g root "${ROOT_COMMANDS_DIR}"
if [[ -f "${ROOT_COMMANDS}" ]]; then
    warn "Existing list kept: ${ROOT_COMMANDS}"
else
    {
        echo "# Commands the sequences of USMD-RDSH services may run as root:"
        echo "#   sudo usmd-root <name or path> [args...]"
        echo "# One absolute path per line. Every command listed gives root to whoever"
        echo "# writes a service file the authority signs: list only what services need."
        for name in ${DEFAULT_ROOT_COMMANDS}; do
            path="$(command -v "${name}" || true)"
            [[ -n "${path}" ]] && echo "${path}"
        done
    } > "${ROOT_COMMANDS}"
    success "Commands allowed: ${ROOT_COMMANDS} ($(grep -c '^/' "${ROOT_COMMANDS}") listed)"
fi
chown root:root "${ROOT_COMMANDS}"
chmod 644 "${ROOT_COMMANDS}"

if command -v sudo &>/dev/null && command -v visudo &>/dev/null; then
    SUDOERS_TMP="$(mktemp)"
    cat > "${SUDOERS_TMP}" <<EOF
# Written by USMD-RDSH scripts/install.sh.
# The node's account may run usmd-root, and through it only the commands of
# ${ROOT_COMMANDS}.
Defaults:${SERVICE_USER} !lecture
${SERVICE_USER} ALL=(root) NOPASSWD: ${ROOT_RELAY}
EOF
    if visudo -cqf "${SUDOERS_TMP}"; then
        install -m 440 -o root -g root "${SUDOERS_TMP}" "${SUDOERS_FILE}"
        success "sudoers rule installed: ${SUDOERS_FILE}"
    else
        warn "sudoers rule refused by visudo: services cannot run system commands."
    fi
    rm -f "${SUDOERS_TMP}"
else
    warn "sudo is not installed: services cannot run system commands ('apt install sudo', then install again)."
fi

# ---------------------------------------------------------------------------
# Enable and start service
# ---------------------------------------------------------------------------
info "Reloading systemd..."
systemctl daemon-reload

info "Enabling service at boot..."
systemctl enable usmd.service

if [[ "${NO_START}" == "true" ]]; then
    warn "Option --no-start: service was not started."
else
    info "Starting service..."
    systemctl restart usmd.service
    sleep 2
    if systemctl is-active --quiet usmd.service; then
        success "Service started and active."
    else
        warn "Service may have failed to stay active. Check: journalctl -u usmd -n 50"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  USMD-RDSH installed successfully!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo
echo -e "  Configuration   : ${CYAN}${CONFIG_FILE}${NC}"
echo -e "  Data / keys     : ${CYAN}${DATA_DIR}${NC}"
echo -e "  Virtualenv      : ${CYAN}${VENV_DIR}${NC}"
echo
echo -e "  Useful commands:"
echo -e "    ${YELLOW}sudo usmd${NC}                      — console of the running node"
echo -e "    ${YELLOW}sudo usmd -c \"show node\"${NC}       — one console line"
echo -e "    ${YELLOW}systemctl status usmd${NC}          — service status"
echo -e "    ${YELLOW}journalctl -u usmd -f${NC}          — live logs"
echo -e "    ${YELLOW}systemctl restart usmd${NC}         — restart"
echo
echo -e "  In a service file, a system command: ${YELLOW}sudo usmd-root systemctl restart nginx${NC}"
echo -e "  Allowed commands (root edits it): ${CYAN}${ROOT_COMMANDS}${NC}"
echo
