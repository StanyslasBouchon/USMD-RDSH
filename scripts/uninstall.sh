#!/usr/bin/env bash
# =============================================================================
# USMD-RDSH — Uninstaller
# =============================================================================
# Stops and completely removes the USMD-RDSH daemon from a Linux machine.
#
# Usage :
#   sudo bash scripts/uninstall.sh [--keep-config] [--keep-data] [--yes]
#
#   --keep-config   Keep /etc/usmd/usmd.yaml
#   --keep-data     Keep /var/lib/usmd (keys, state)
#   --yes           Uninstall without interactive confirmation
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
KEEP_CONFIG=false
KEEP_DATA=false
AUTO_YES=false

INSTALL_DIR="/opt/usmd"
CONFIG_DIR="/etc/usmd"
DATA_DIR="/var/lib/usmd"
SERVICE_FILE="/etc/systemd/system/usmd.service"
SERVICE_USER="usmd"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-config) KEEP_CONFIG=true;  shift ;;
        --keep-data)   KEEP_DATA=true;    shift ;;
        --yes|-y)      AUTO_YES=true;     shift ;;
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
# Checks
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "This script must be run as root (sudo)."

# ---------------------------------------------------------------------------
# Interactive confirmation
# ---------------------------------------------------------------------------
if [[ "${AUTO_YES}" == "false" ]]; then
    echo
    echo -e "${RED}Warning:${NC} this will remove:"
    echo -e "  • systemd service       ${CYAN}usmd.service${NC}"
    echo -e "  • Virtualenv            ${CYAN}${INSTALL_DIR}${NC}"
    [[ "${KEEP_CONFIG}" == "false" ]] && echo -e "  • Configuration         ${CYAN}${CONFIG_DIR}${NC}"
    [[ "${KEEP_DATA}"   == "false" ]] && echo -e "  • Data / keys           ${CYAN}${DATA_DIR}${NC}"
    echo -e "  • System user           ${CYAN}${SERVICE_USER}${NC}"
    echo
    read -rp "Confirm uninstall? [y/N] " confirm
    [[ "${confirm,,}" =~ ^(y|yes)$ ]] || { info "Cancelled."; exit 0; }
fi

# ---------------------------------------------------------------------------
# Stop and disable service
# ---------------------------------------------------------------------------
if systemctl list-unit-files usmd.service &>/dev/null 2>&1 | grep -q usmd; then
    info "Stopping usmd service..."
    systemctl stop usmd.service  2>/dev/null || true
    systemctl disable usmd.service 2>/dev/null || true
    success "Service stopped and disabled."
else
    warn "usmd service not found — skipped."
fi

# ---------------------------------------------------------------------------
# Remove service file
# ---------------------------------------------------------------------------
if [[ -f "${SERVICE_FILE}" ]]; then
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload
    success "Service file removed."
else
    warn "${SERVICE_FILE} not found — skipped."
fi

# ---------------------------------------------------------------------------
# Remove virtualenv / install directory
# ---------------------------------------------------------------------------
if [[ -d "${INSTALL_DIR}" ]]; then
    info "Removing '${INSTALL_DIR}'..."
    rm -rf "${INSTALL_DIR}"
    success "Virtualenv removed."
else
    warn "${INSTALL_DIR} not found — skipped."
fi

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
if [[ "${KEEP_CONFIG}" == "true" ]]; then
    warn "Configuration kept: ${CONFIG_DIR}"
elif [[ -d "${CONFIG_DIR}" ]]; then
    info "Removing configuration '${CONFIG_DIR}'..."
    rm -rf "${CONFIG_DIR}"
    success "Configuration removed."
fi

# ---------------------------------------------------------------------------
# Data / keys
# ---------------------------------------------------------------------------
if [[ "${KEEP_DATA}" == "true" ]]; then
    warn "Data kept: ${DATA_DIR}"
elif [[ -d "${DATA_DIR}" ]]; then
    info "Removing data '${DATA_DIR}'..."
    rm -rf "${DATA_DIR}"
    success "Data removed."
fi

# ---------------------------------------------------------------------------
# Remove system user
# ---------------------------------------------------------------------------
if id "${SERVICE_USER}" &>/dev/null; then
    info "Removing user '${SERVICE_USER}'..."
    userdel "${SERVICE_USER}" 2>/dev/null || true
    success "User '${SERVICE_USER}' removed."
else
    warn "User '${SERVICE_USER}' not found — skipped."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  USMD-RDSH uninstalled successfully.${NC}"
echo -e "${GREEN}============================================================${NC}"
echo
