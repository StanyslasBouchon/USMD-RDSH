#!/usr/bin/env bash
# =============================================================================
# USMD-RDSH — Node Installer
# =============================================================================
# Installs the USMD-RDSH daemon on a Linux machine by creating:
#   - A dedicated system user    : usmd
#   - A Python virtualenv        : /opt/usmd/venv
#   - Default configuration      : /etc/usmd/usmd.yaml
#   - A data directory           : /var/lib/usmd
#   - A systemd service          : usmd.service (auto-start)
#
# Usage :
#   sudo bash scripts/install.sh [--source <path>] [--no-start]
#
#   --source <path>   Source directory containing setup.py (default: .)
#   --no-start        Install without starting the service
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

INSTALL_DIR="/opt/usmd"
VENV_DIR="${INSTALL_DIR}/venv"
CONFIG_DIR="/etc/usmd"
CONFIG_FILE="${CONFIG_DIR}/usmd.yaml"
DATA_DIR="/var/lib/usmd"
SERVICE_FILE="/etc/systemd/system/usmd.service"
SERVICE_USER="usmd"
PYTHON_MIN="3.11"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --source)
            SOURCE_DIR="$(realpath "$2")"
            shift 2
            ;;
        --no-start)
            NO_START=true
            shift
            ;;
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

[[ -f "${SOURCE_DIR}/setup.py" ]] \
    || die "setup.py not found in '${SOURCE_DIR}'. Use --source <path>."

# Find Python 3.11+
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major="${ver%%.*}"
        minor="${ver#*.}"
        if [[ $major -ge 3 && $minor -ge 11 ]]; then
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
    warn "User '${SERVICE_USER}' already exists — skipped."
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
# Directory creation
# ---------------------------------------------------------------------------
info "Creating directories..."

install -d -m 755 -o root      -g root      "${INSTALL_DIR}"
install -d -m 755 -o root      -g root      "${CONFIG_DIR}"
install -d -m 750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${DATA_DIR}"

success "Directories created."

# ---------------------------------------------------------------------------
# Virtualenv + package install
# ---------------------------------------------------------------------------
info "Creating virtualenv in '${VENV_DIR}'..."
"$PYTHON" -m venv "${VENV_DIR}"

info "Upgrading pip..."
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip

info "Installing usmd-rdsh from '${SOURCE_DIR}'..."
"${VENV_DIR}/bin/pip" install --quiet "${SOURCE_DIR}"

chown -R root:root "${INSTALL_DIR}"
chmod -R o-w "${INSTALL_DIR}"

success "Package installed. Version: $("${VENV_DIR}/bin/python" -c 'import importlib.metadata; print(importlib.metadata.version("usmd-rdsh"))' 2>/dev/null || echo '(unknown)')"

# ---------------------------------------------------------------------------
# Configuration file (do not overwrite if already present)
# ---------------------------------------------------------------------------
if [[ -f "${CONFIG_FILE}" ]]; then
    warn "Existing configuration kept: ${CONFIG_FILE}"
else
    info "Writing default configuration..."
    cat > "${CONFIG_FILE}" <<'EOF'
# /etc/usmd/usmd.yaml — USMD-RDSH node configuration
# Edit this file then restart: systemctl restart usmd

# -----------------------------------------------------------------------
# Network identity
# -----------------------------------------------------------------------
node:
  address: auto          # "auto" = detect outgoing interface; or "192.168.1.5"
  role: executor         # executor | operator | usd_operator | ucd_operator

# -----------------------------------------------------------------------
# USD domain
# -----------------------------------------------------------------------
usd:
  name: my-domain        # Domain name (USDN)
  cluster_name: ""       # USCN — leave empty if no cluster
  edb_address: null      # Easy Deployment Base DNS/IP (optional)
  max_reference_nodes: 5
  load_threshold: 0.8
  ping_tolerance_ms: 200
  load_check_interval: 30
  emergency_threshold: 0.9

# -----------------------------------------------------------------------
# Startup behavior
# -----------------------------------------------------------------------
bootstrap: false         # true = create a new USD; false = join existing
keys_file: /var/lib/usmd/usmd_keys.json
nndp_ttl: 30
ctl_socket: /run/usmd/usmd.sock

# -----------------------------------------------------------------------
# Ports (spec values — change only on conflict)
# -----------------------------------------------------------------------
ports:
  ncp: 5626
  nndp_listen: 5221
  nndp_send: 5222
  broadcast: auto        # "auto" = diffuse sur toutes les interfaces ; ou "192.168.1.255"
EOF
    chown root:"${SERVICE_USER}" "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"
    success "Configuration written: ${CONFIG_FILE}"
fi

# ---------------------------------------------------------------------------
# systemd unit file
# ---------------------------------------------------------------------------
info "Writing systemd service..."
cat > "${SERVICE_FILE}" <<EOF
# /etc/systemd/system/usmd.service
# Generated by scripts/install.sh — do not edit manually.
# To customize: systemctl edit usmd

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

ExecStart=${VENV_DIR}/bin/python -m usmd --config ${CONFIG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID

Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Logging via journald
StandardOutput=journal
StandardError=journal
SyslogIdentifier=usmd

# Runtime directory (creates /run/usmd, owned by usmd, cleared on reboot)
RuntimeDirectory=usmd
RuntimeDirectoryMode=0755

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_DIR}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "${SERVICE_FILE}"
success "systemd service written: ${SERVICE_FILE}"

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
    systemctl start usmd.service
    sleep 1
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
echo -e "    ${YELLOW}systemctl status usmd${NC}          — service status"
echo -e "    ${YELLOW}journalctl -u usmd -f${NC}          — live logs"
echo -e "    ${YELLOW}systemctl restart usmd${NC}         — restart"
echo -e "    ${YELLOW}systemctl stop usmd${NC}            — stop"
echo
echo -e "  Edit ${CYAN}${CONFIG_FILE}${NC} then restart the service."
echo
                                                                                                                                                                                                                                                                                                                                                                                                             