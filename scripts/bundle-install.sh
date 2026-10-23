#!/usr/bin/env bash
# =============================================================================
# USMD-RDSH — Install a bundle built by scripts/package.py
# =============================================================================
# Creates (or updates) a virtualenv holding the node and links the `usmd`
# command into the PATH. Run again with a newer bundle to upgrade; the node's
# state (~/.usmd or $USMD_STATE_DIR) is not touched.
#
# Usage :
#   ./install.sh [--prefix <dir>] [--bin <dir>] [--python <exe>]
#
#   --prefix <dir>   Virtualenv location parent
#                    (root: /opt/usmd-rdsh, otherwise ~/.local/share/usmd-rdsh)
#   --bin <dir>      Where to link `usmd` (root: /usr/local/bin, otherwise ~/.local/bin)
#   --python <exe>   Python >= 3.13 to use (default: first found)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[USMD]${NC} $*"; }
success() { echo -e "${GREEN}[USMD] ✔${NC} $*"; }
warn()    { echo -e "${YELLOW}[USMD] ⚠${NC} $*"; }
die()     { echo -e "${RED}[USMD] ✘${NC} $*" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ $EUID -eq 0 ]]; then
    PREFIX="/opt/usmd-rdsh"
    BIN_DIR="/usr/local/bin"
else
    PREFIX="${HOME}/.local/share/usmd-rdsh"
    BIN_DIR="${HOME}/.local/bin"
fi
PYTHON=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --bin)    BIN_DIR="$2"; shift 2 ;;
        --python) PYTHON="$2"; shift 2 ;;
        -h|--help)
            sed -n '/^# Usage/,/^# ===/p' "$0" | head -n -1 | sed 's/^# \?//'
            exit 0
            ;;
        *) die "Unknown argument: $1  (use --help)" ;;
    esac
done

python_ok() {
    "$1" -c 'import sys; sys.exit(sys.version_info < (3, 13))' 2>/dev/null
}

if [[ -n "$PYTHON" ]]; then
    python_ok "$PYTHON" || die "'$PYTHON' is not Python >= 3.13."
else
    for candidate in python3.14 python3.13 python3; do
        if command -v "$candidate" &>/dev/null && python_ok "$candidate"; then
            PYTHON="$candidate"
            break
        fi
    done
    [[ -n "$PYTHON" ]] || die "Python >= 3.13 is required but was not found (use --python)."
fi
info "Python: $("$PYTHON" --version) ($(command -v "$PYTHON"))"

VENV="${PREFIX}/venv"
info "Virtualenv: ${VENV}"
mkdir -p "${PREFIX}"
"$PYTHON" -m venv "${VENV}" \
    || die "venv creation failed (Debian/Ubuntu: apt install python3-venv)."

PIP=("${VENV}/bin/python" -m pip install --quiet --disable-pip-version-check)
if [[ -f "${HERE}/wheels/OFFLINE" ]]; then
    info "Offline bundle: $(cat "${HERE}/wheels/OFFLINE")"
    PIP+=(--no-index --find-links "${HERE}/wheels")
fi

info "Installing dependencies..."
"${PIP[@]}" -r "${HERE}/requirements.txt"

info "Installing usmd-rdsh and nan-actions..."
"${PIP[@]}" --no-deps --force-reinstall "${HERE}"/wheels/nan_actions-*.whl \
    "${HERE}"/wheels/usmd_rdsh-*.whl

mkdir -p "${BIN_DIR}"
ln -sf "${VENV}/bin/usmd" "${BIN_DIR}/usmd"
success "usmd-rdsh $("${VENV}/bin/python" -c 'import importlib.metadata as m; print(m.version("usmd-rdsh"))') installed."

case ":${PATH}:" in
    *":${BIN_DIR}:"*) ;;
    *) warn "${BIN_DIR} is not in PATH — run ${BIN_DIR}/usmd or add it to PATH." ;;
esac

echo
echo -e "  ${YELLOW}usmd${NC}                      — start the node and its console"
echo -e "  ${YELLOW}usmd --no-console${NC}         — start the node only (service mode)"
echo -e "  ${YELLOW}usmd -c \"show version\"${NC}    — run a console line and exit"
echo
