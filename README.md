# USMD-RDSH

**Unified System Management and Deployment for Relative and Dynamic Service Hosting**

USMD-RDSH is a distributed system for managing self-organizing nodes. Each node on the network identifies itself, discovers peers via UDP broadcast, and joins or creates a management domain (USD) using the NCP protocol. The daemon is designed to run in the background on Linux machines and start automatically with the system.

---

## Table of contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Linux installation (production)](#linux-installation-production)
- [Bundle for scp](#bundle-for-scp)
- [Uninstall](#uninstall)
- [Running from source (development)](#running-from-source-development)
- [Configuration](#configuration)
- [Command-line options](#command-line-options)
- [Node roles](#node-roles)
- [Web dashboard](#web-dashboard)
- [Mutation service definitions (YAML)](#mutation-service-definitions-yaml)
- [Tests](#tests)

---

## Architecture

| Component                                   | Role                                                                          |
| ------------------------------------------- | ----------------------------------------------------------------------------- |
| **NCP** — Node Cohesion Protocol            | Inter-node communication (TCP/5626) — 10 commands                             |
| **NNDP** — Node Neighbor Discovery Protocol | Neighbor discovery via UDP broadcast (src 5222 → dst 5221)                  |
| **USD** — Unified System Domain             | Management domain grouping a set of nodes                                     |
| **USC** — Unified System Cluster            | Cluster of USD domains                                                        |
| **NIT** — Node Identity Table               | Identity and public-key table for nodes                                       |
| **NAL** — Node Access List                  | Node access control list                                                      |
| **NEL** — Node Endorsement List             | List of Ed25519 endorsements issued and received                              |
| **CTL** — Control Socket                    | Local Unix socket for live introspection (`python -m usmd status`)          |
| **Web Dashboard**                           | Optional Django UI for multi-node real-time supervision                       |

Each node generates an **Ed25519** (signing) and **X25519** (key exchange) key pair on first start. Keys are persisted locally and form the node’s cryptographic identity.

---

## Prerequisites

- Python **≥ 3.13**
- Linux with **systemd** (Ubuntu 20.04+, Debian 11+, RHEL 8+, Arch, …)
- `python3-venv` installed (`apt install python3-venv` or equivalent)
- **root** access for service installation

---

## Linux installation (production)

The installer creates a dedicated system user, an isolated Python virtualenv, and registers a systemd service that starts automatically with the machine.

```bash
# 1. Clone the repository
git clone https://github.com/StanyslasBouchon/USMD-RDSH.git
cd USMD-RDSH

# 2. Run the installer (requires root)
sudo bash scripts/install.sh
```

The installer performs the following:

- Creates the `usmd` system user (no shell, no interactive login); the node runs as this account
- Creates `/opt/usmd/venv` — Python virtualenv with the package installed (Python ≥ 3.13, `nan-actions` cloned beside the repository)
- Creates `/etc/usmd/usmd.yaml` — default configuration (not overwritten if already present), owned by `usmd`: the node rewrites it on each commit
- Creates `/var/lib/usmd/` — data directory (identity, keys, state in `/var/lib/usmd/.usmd`)
- Installs and enables `/etc/systemd/system/usmd.service`, sandboxed, with `CAP_NET_ADMIN` for the SP interface
- Installs `/usr/local/bin/usmd` — the console of the running node (`sudo usmd`, `sudo usmd -c "show node"`)
- Installs the system command relay for services: `/usr/local/sbin/usmd-root`, the list `/etc/usmd-root/commands` and `/etc/sudoers.d/usmd`

**Installer options:**

```bash
# Use a different source directory
sudo bash scripts/install.sh --source /path/to/USMD-RDSH

# This node founds a new USD (USC and USD keys, the four roles)
sudo bash scripts/install.sh --found --usd-label prod --address 192.168.1.11

# Take over a node that was run by hand in a terminal (state in ~/.usmd)
sudo bash scripts/install.sh --import-state /home/me/.usmd

# Rewrite /etc/usmd/usmd.yaml (the identity is kept)
sudo bash scripts/install.sh --reset-config

# Install without starting the service immediately
sudo bash scripts/install.sh --no-start
```

**System commands in service files.** The sequences of a service run as `usmd`, inside the service's sandbox (read-only system). A step that must change the system goes through the relay, which systemd runs as root outside the sandbox, for the commands listed in `/etc/usmd-root/commands` only:

```yaml
build:
  - command: sudo usmd-root apt-get install -y nginx
  - command: sudo usmd-root install -m 644 "$USMD_FILES_DIR/site.conf" /etc/nginx/conf.d/
  - command: sudo usmd-root systemctl restart nginx
```

The installer lists `systemctl`, `journalctl`, `apt-get`, `apt`, `dpkg`, `ip`, `sysctl` and `install` the first time; the list is root's to edit, and an upgrade keeps it. Each command listed gives root to whoever writes a service file the authority signs: list only what the services need.

**Useful commands after installation:**

```bash
# Service status
systemctl status usmd

# Live logs
journalctl -u usmd -f

# Restart after config change
systemctl restart usmd

# Stop the service
systemctl stop usmd

# Disable auto-start
systemctl disable usmd
```

Configuration lives in `/etc/usmd/usmd.yaml`. After any change, run `systemctl restart usmd`.

---

## Bundle for scp

`scripts/package.py` puts the node into one archive (the `usmd-rdsh` and `nan-actions` wheels, the runtime requirements and an installer), so a machine needs neither the repository nor `../nan-actions`:

```bash
# On the development machine (Windows or Linux), from the repository root
python scripts/package.py                 # dist/usmd-rdsh-<version>.tar.gz, dependencies from PyPI at install
python scripts/package.py --offline       # every dependency wheel included (Linux x86_64, CPython 3.13)
python scripts/package.py --offline --arch aarch64
python scripts/package.py --offline --with-python   # also a standalone CPython 3.13 (~35 MB more)

# Copy and install
scp dist/usmd-rdsh-0.0.1.0.tar.gz user@host:
ssh user@host 'tar xzf usmd-rdsh-0.0.1.0.tar.gz && usmd-rdsh-0.0.1.0/install.sh'
```

`install.sh` creates (or updates) a virtualenv and links `usmd` into the PATH: `/opt/usmd-rdsh/venv` and `/usr/local/bin` as root, `~/.local/share/usmd-rdsh/venv` and `~/.local/bin` otherwise (`--prefix`, `--bin`, `--python` to change them). Running it again with a newer archive upgrades the node; its state (`~/.usmd` or `$USMD_STATE_DIR`) is kept. The target needs Python ≥ 3.13 with `venv`, unless the archive was built with `--with-python`: `install.sh` then installs that Python (a [python-build-standalone](https://github.com/astral-sh/python-build-standalone) build, cached in `dist/cache`) next to the virtualenv and uses it, which suits distributions shipping an older Python (Ubuntu 24.04, Debian 12).

---

## Uninstall

```bash
sudo bash scripts/uninstall.sh
```

The script asks for confirmation before removing the service, virtualenv, configuration, and data. Options let you keep some of that:

```bash
# Keep configuration (/etc/usmd/usmd.yaml)
sudo bash scripts/uninstall.sh --keep-config

# Keep data and keys (/var/lib/usmd)
sudo bash scripts/uninstall.sh --keep-data

# Uninstall without interactive confirmation
sudo bash scripts/uninstall.sh --yes

# Upgrade without losing config or cryptographic identity
sudo bash scripts/uninstall.sh --keep-config --keep-data --yes
sudo bash scripts/install.sh
```

---

## Running from source (development)

```bash
# 1. Clone the repository
git clone https://github.com/StanyslasBouchon/USMD-RDSH.git
cd USMD-RDSH

# 2. Create and activate a virtualenv
python3 -m venv .venv
source .venv/bin/activate       # Linux / macOS
# .venv\Scripts\activate        # Windows

# 3. Install dependencies
pip install -e .
pip install pytest pytest-asyncio pytest-cov tox pylint djlint  # for tests

# 4a. Start the first node (bootstrap — creates a new USD)
python -m usmd --config usmd.yaml --bootstrap

# 4b. Join an existing USD (on another terminal / machine)
python -m usmd --config usmd.yaml

# 4c. Override role and address without editing the config file
python -m usmd --role usd_operator --address 192.168.1.5
```

Ed25519/X25519 keys are generated automatically on first run and saved to the `keys_file` from configuration (default: `usmd_keys.json` in the current directory).

---

## Configuration

The configuration file is YAML. All keys are optional; unset values fall back to built-in defaults.

```yaml
# usmd.yaml

# Network identity
node:
  address: auto          # "auto" = detect outbound interface; or "192.168.1.5"
  role: executor         # executor | operator | usd_operator | ucd_operator

# USD domain
usd:
  name: my-domain        # Domain name (USDN)
  cluster_name: ""       # USCN — leave empty if not in a cluster
  edb_address: null      # Easy Deployment Base DNS/IP (optional)
  max_reference_nodes: 5
  load_threshold: 0.8    # Normalized load above which the node is "weakened"
  ping_tolerance_ms: 200 # Max ping T (ms) in the distance formula
  load_check_interval: 30
  emergency_threshold: 0.9
  min_services: 0        # optional — minimum mutation services in the catalogue (0 = no check)
  max_services: null     # optional — maximum services (null = unlimited)

# Startup behaviour
bootstrap: false         # true = create a new USD; false = join existing
keys_file: usmd_keys.json
nndp_ttl: 30             # Seconds between Here-I-Am broadcasts

# Ports (spec defaults — change only on conflict)
ports:
  ncp: 5626
  nndp_listen: 5221
  nndp_send: 5222
  broadcast: auto        # "auto" = all interfaces; or "192.168.1.255"

# CTL socket (local introspection)
ctl_socket: usmd.sock    # Unix socket path

# Web dashboard (optional)
web:
  enabled: false         # true to enable
  host: 0.0.0.0
  port: 8443
  username: admin
  password: changeme     # Change this!
  ssl_cert: ""           # PEM path; empty = auto-generated self-signed
  ssl_key:  ""
```

In a service install, the config file is `/etc/usmd/usmd.yaml` and keys are `/var/lib/usmd/usmd_keys.json`.

---

## Command-line options

```
python -m usmd [OPTIONS]                  # Run the daemon
python -m usmd status [OPTIONS]         # Query a running daemon

Daemon:
  --config PATH         YAML configuration file (default: usmd.yaml)
  --bootstrap           Create a new USD instead of joining one
  --role ROLE           Override role (executor|operator|usd_operator|ucd_operator)
  --address IP          Override the node’s network address
  --log-level LEVEL     Log verbosity: DEBUG|INFO|WARNING|ERROR (default: INFO)

status subcommand:
  --socket PATH         CTL socket path (default: ctl_socket from config)
  --config PATH         Config file to read the socket path from
  --json                Print raw JSON snapshot instead of formatted output
```

CLI options override the configuration file.

---

## Node roles

| Role           | Description                                       |
| -------------- | ------------------------------------------------- |
| `executor`     | Node running services (default role)              |
| `operator`     | Management node without domain responsibility     |
| `usd_operator` | Node responsible for managing a USD               |
| `ucd_operator` | Node responsible for managing a USC (cluster)     |

---

## Web dashboard

The dashboard is an optional Django service that runs on **each node** and provides an aggregated real-time view of the whole USD.

### Features

- Lists all known nodes (via NIT) with state, role, and resources
- Auto-refresh every 5 seconds (Server-Sent Events)
- Per-node detail: NIT, NAL, NEL, USD, CPU/RAM/Disk/Network history chart
- Username/password authentication (signed session cookie)
- HTTPS by default — self-signed cert generated if none provided (needs `openssl` on PATH); HTTP if openssl is missing

### Enabling

Install extra dependencies:

```bash
pip install "django>=4.2" "uvicorn[standard]>=0.29"
```

Then enable in configuration (`usmd.yaml`):

```yaml
web:
  enabled: true
  port: 8443
  username: admin
  password: YourPassword   # Change this!
```

The dashboard is available at `https://<node-address>:8443/`.

### Data collection

When node A’s dashboard shows node B, it sends NCP **REQUEST_SNAPSHOT** (ID 9) to port 5626. Node B replies with its full snapshot (NIT, NAL, NEL, resources) as JSON. No shared database is required.

### Security

- Change `web.password` before any production deployment.
- In production, provide a TLS certificate from a trusted CA via `web.ssl_cert` and `web.ssl_key`.
- The dashboard exposes internal data — restrict access to the admin network.

---

## Mutation service definitions (YAML)

A **mutation** is a service definition stored in the domain’s **mutation catalogue**. Each definition is a **single YAML document** describing how to bring a named service up, tear it down, handle emergencies, health-check it, and update it in place. The daemon uses this catalogue for **transmutation** (which service a node runs) and for **propagating** definitions to reference peers over NCP.

### Static vs dynamic

| Type       | Meaning |
| ---------- | ------- |
| **static** | All nodes that host the service share the same parameters, data, and commands. The catalogue expects all static services to be present domain-wide. |
| **dynamic** | Parameters and commands are shared; **data is per-node**. Assignment avoids duplicate dynamic names across reference peers (see assignment logic in the codebase). |

Set `type: static` or `type: dynamic` in YAML (default is **static** if omitted).

### Who may publish

Publishing mutations (web form or programmatic path) requires the **`usd_operator`** role on **this node’s Ed25519 key in the local NAL** (Node Access List). A node may hold **several roles** at once (for example `node_operator` and `usd_operator`); only the NAL matters for authorization, not the single `role:` field in `usmd.yaml` alone.

### Using the web dashboard

1. Enable the dashboard (`web.enabled: true`) and open `https://<node>:<port>/mutation/` (or follow **Mutation** in the nav).
2. Sign in with `web.username` / `web.password`.
3. Enter a **service name** (identifier for this service in the catalogue, e.g. `backend`).
4. Paste the **YAML** body (one service per submit).
5. Optionally check **Run build / update / health on this node now** to execute lifecycle phases **locally** immediately. If left unchecked, the daemon only updates the **catalogue** and **broadcasts** to reference nodes (useful for dry runs or when another node will apply the workload).

On success, the USD **version** is bumped and the daemon sends **`SEND_USD_PROPERTIES`** and **`SEND_MUTATION_PROPERTIES`** to **reference nodes** so they can merge the new definitions (including YAML when provided).

### YAML shape

Each file is one service. The **service name** in the form is the canonical name (not the filename on disk). Minimal skeleton:

```yaml
type: static              # optional: static | dynamic
dependencies: []          # optional — other service names this one depends on
build:
  - command: echo start
unbuild:
  - command: echo stop
emergency: []             # optional — failure / resource pressure path
check_health: []          # optional — commands that must succeed for “healthy”
update: []                # optional — in-place update when a newer definition is applied
```

- **Lists** under each phase are ordered. Each item is either:
  - `command: <shell string>` — run via the configured lifecycle runner (shell), or  
  - `action: unbuild` — run the service’s **unbuild** phase (used from `emergency`, with a depth limit to avoid infinite recursion).

- **Dependencies** are names of other services in the same catalogue (used for placement / dependency resolution between nodes).

### Lifecycle phases

| Phase        | YAML key        | Typical use |
| ------------ | --------------- | ----------- |
| Build        | `build`         | Install or start the service (transmutation bring-up). |
| Unbuild      | `unbuild`       | Stop or remove the service (tear-down). |
| Emergency    | `emergency`     | Degraded shutdown or backup when the node is in trouble. |
| Health       | `check_health`  | Probes that must pass for the service to be considered healthy. |
| Update       | `update`        | In-place upgrade when the definition changes while the service is active. |

If **Apply locally** is enabled, the daemon runs the relevant phases on **this node** according to the update flow (including rollback when possible). Catalogue size may be constrained by **`usd.min_services`** and **`usd.max_services`** in configuration (see [Configuration](#configuration)).

### Files on disk (optional)

You can maintain the same YAML in a repository and paste it into the form, or use the same structure in automation. The parser also supports `ServiceYamlParser.parse_file(path)` in code, where the **service name** is taken from the **file name without extension**.

---

## Tests

```bash
# Run all tests
pytest tests/

# Verbose subtests
pytest tests/ -v

# tox (multiple Python versions)
tox

# Pylint
pylint usmd/
```

The test suite covers NCP and NNDP protocols, frame serialization, the command handler, the daemon, and cryptography (counts vary as the suite grows).

---

## Draft-conformant node (`src/usmd_rdsh`)

This repository also holds a second implementation, written against the
current Internet-Draft series in `readme/drafts` (ARCH-03, NCP-02, NNDP-01,
SP-01): `src/usmd_rdsh/node` implements NNDP, the encrypted UDP NCP with Raft,
SP with its TUN interface, and every procedure of the architecture draft. Its
console (Cisco-like `show` / `execute`, `config` / `set` / `end`) and its web
interface with configuration forms are built on the `nan-actions` SDK, a
sibling repository (`../nan-actions`).

```bash
pdm install
pdm run usmd                          # node + console
pdm run usmd --config usmd.yaml       # configuration file (layout of usmd.example.yaml)
pdm run usmd --no-console             # node only
pdm run python -m usmd_rdsh.dev --nodes 3 --reset   # 3 virtual nodes on this machine
pdm run pytest -q tests               # both implementations' tests
```

**Configuration file.** `usmd --config usmd.yaml` reads and writes a file in
the layout of `usmd.example.yaml` (`node`, `usd`, `bootstrap`, `ports`, `web`),
extended with every other setting of the configuration tree under its own
path (`system: logging: ...`, `protocol: ncp: ...`, `mutation: ...`). Roles are
the spec's: `usc-operator`, `usd-operator`, `node-operator`, `node-executor`
(the daemon's names are read and reported). Values the drafts fix (NNDP
ports, broadcast) are reported and kept. `bootstrap: true` creates a new USD:
the node generates the authority keys and founds the USD. `web.username` /
`web.password` enable a login form; an empty `ssl_cert` means a self-signed
certificate.

**Development cluster.** `python -m usmd_rdsh.dev --nodes N` starts N virtual
nodes, each on its own loopback address (node *i* on 127.0.0.*i*+1) with its
own state in `.usmd-dev/node`*i*; NNDP sends to the other virtual nodes instead
of broadcasting, node 1 founds the USD and the others join it. Each node's web
interface is at `http://127.0.0.`*i*+1`:8080/` (admin / admin). A single node:
`usmd --dev 2 --dev-nodes 3`. The shared development authority makes this
unsafe outside development.

**Stateful services and data identifiers.** Every command of a service
sequence gets the instance's identity in `USMD_*` variables: `USMD_SP_ADDRESS`
(`0b2.0003`), `USMD_DATA_ID_PREFIX` (`00b20003`), `USMD_VIP`, `USMD_GROUP`,
`USMD_AREA`, `USMD_DATA_DIR` (kept across unbuilds and transmutations) and
more; `build`, `update` and `check_health` are refused until the node holds a
management id for the service, and two sequences of one service never overlap
[ARCH-03 8.7]. Data identifiers are Snowflake-like version 8 UUIDs whose first
32 bits are the instance's SP address, followed by the creation time in
milliseconds, a sequence and random bits [ARCH-03 11.6]: an identifier created
by instance `0b2.0003` reads `00b20003-…`. For PostgreSQL,
`show data-id postgresql service=db database=app` prints the `usmd_id()`
function; a build sequence loads it and sets the prefix
(`ALTER DATABASE app SET usmd.data_id_prefix = '$USMD_DATA_ID_PREFIX'`), and
tables use `id uuid PRIMARY KEY DEFAULT usmd_id()`. `show data-id id=<uuid>`
tells which instance created a row, and when.

**Protocol capture.** Every NNDP datagram, NCP message (reassembled and
decrypted) and SP frame the node sends or receives is kept in a ring buffer
and dissected into named fields, Wireshark style. The **Capture** tab of the
web interface lists them live (packet list, field tree, bytes with the
selected field highlighted) and filters them with Wireshark's display-filter
syntax: `nndp && ip.src == 127.0.0.2`, `ncp.command == DECLARE_STATE`,
`ncp.type == ERROR`, `sp && !sp.keepalive`, `frame.status != ok`,
`ip.addr == 127.0.0.0/8`, `nndp.node_id contains "01JAB"`. On the console:
`show capture filter="..." last=50`, `show capture detail=<n>`,
`show capture fields`, `show capture statistics`, `clear capture`; settings
(on/off, buffer size, bytes kept, protocols) under `config system capture`.

The acceptance checklist mapping every requirement of the drafts to the code
and its tests is `readme/recette.md`.
