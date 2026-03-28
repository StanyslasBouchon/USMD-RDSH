# USMD-RDSH

**Unified System Management and Deployment for Relative and Dynamic Service Hosting**

USMD-RDSH est un système distribué de gestion de nœuds auto-organisés. Chaque nœud du réseau s'identifie, se découvre via broadcast UDP et s'intègre ou crée un domaine de gestion (USD) à l'aide du protocole NCP. Le daemon est conçu pour fonctionner en arrière-plan sur des machines Linux, en démarrant automatiquement avec le système.

---

## Table des matières

- [Architecture](#architecture)
- [Prérequis](#prérequis)
- [Installation Linux (production)](#installation-linux-production)
- [Désinstallation](#désinstallation)
- [Lancer depuis les sources (développement)](#lancer-depuis-les-sources-développement)
- [Configuration](#configuration)
- [Options de la ligne de commande](#options-de-la-ligne-de-commande)
- [Rôles des nœuds](#rôles-des-nœuds)
- [Tests](#tests)

---

## Architecture

| Composant | Rôle |
|-----------|------|
| **NCP** — Node Cohesion Protocol | Communication inter-nœuds (TCP/5626) — 9 commandes |
| **NNDP** — Node Neighbor Discovery Protocol | Découverte de voisins par broadcast UDP (src 5222 → dst 5221) |
| **USD** — Unified System Domain | Domaine de gestion regroupant un ensemble de nœuds |
| **USC** — Unified System Cluster | Grappe de domaines USD |
| **NIT** — Node Identity Table | Table d'identité et de clés publiques des nœuds |
| **NAL** — Node Access List | Liste de contrôle d'accès des nœuds |
| **NEL** — Node Endorsement List | Liste des endorsements Ed25519 émis et reçus |

Chaque nœud génère une paire de clés **Ed25519** (signature) et **X25519** (échange de clés) au premier démarrage. Ces clés sont persistées localement et constituent l'identité cryptographique du nœud.

---

## Prérequis

- Python **≥ 3.11**
- Linux avec **systemd** (Ubuntu 20.04+, Debian 11+, RHEL 8+, Arch, …)
- `python3-venv` installé (`apt install python3-venv` ou équivalent)
- Accès **root** pour l'installation en service

---

## Installation Linux (production)

L'installateur crée un utilisateur système dédié, un virtualenv Python isolé, et enregistre un service systemd qui démarre automatiquement avec la machine.

```bash
# 1. Cloner le dépôt
git clone https://github.com/StanyslasBouchon/USMD-RDSH.git
cd USMD-RDSH

# 2. Lancer l'installateur (nécessite root)
sudo bash scripts/install.sh
```

L'installateur effectue les opérations suivantes :

- Crée l'utilisateur système `usmd` (sans shell, sans accès interactif)
- Crée `/opt/usmd/venv` — virtualenv Python avec le package installé
- Crée `/etc/usmd/usmd.yaml` — configuration par défaut (non écrasée si déjà présente)
- Crée `/var/lib/usmd/` — répertoire de données (clés, état)
- Installe et active `/etc/systemd/system/usmd.service`

**Options de l'installateur :**

```bash
# Utiliser un répertoire source différent
sudo bash scripts/install.sh --source /chemin/vers/USMD-RDSH

# Installer sans démarrer le service immédiatement
sudo bash scripts/install.sh --no-start
```

**Commandes utiles après installation :**

```bash
# État du service
systemctl status usmd

# Logs en direct
journalctl -u usmd -f

# Redémarrer après modification de la config
systemctl restart usmd

# Arrêter le service
systemctl stop usmd

# Désactiver le démarrage automatique
systemctl disable usmd
```

La configuration se trouve dans `/etc/usmd/usmd.yaml`. Après toute modification, relancez `systemctl restart usmd`.

---

## Désinstallation

```bash
sudo bash scripts/uninstall.sh
```

Le script demande confirmation avant de supprimer le service, le virtualenv, la configuration et les données. Des options permettent de conserver certains éléments :

```bash
# Conserver la configuration (/etc/usmd/usmd.yaml)
sudo bash scripts/uninstall.sh --keep-config

# Conserver les données et clés (/var/lib/usmd)
sudo bash scripts/uninstall.sh --keep-data

# Désinstaller sans confirmation interactive
sudo bash scripts/uninstall.sh --yes

# Mettre à jour sans perdre config ni identité cryptographique
sudo bash scripts/uninstall.sh --keep-config --keep-data --yes
sudo bash scripts/install.sh
```

---

## Lancer depuis les sources (développement)

```bash
# 1. Cloner le dépôt
git clone https://github.com/StanyslasBouchon/USMD-RDSH.git
cd USMD-RDSH

# 2. Créer et activer un virtualenv
python3 -m venv .venv
source .venv/bin/activate       # Linux / macOS
# .venv\Scripts\activate        # Windows

# 3. Installer les dépendances
pip install -e .
pip install pytest pytest-asyncio tox pylint  # pour les tests

# 4a. Démarrer le premier nœud (bootstrap — crée un nouveau USD)
python -m usmd --config usmd.yaml --bootstrap

# 4b. Rejoindre un USD existant (sur un autre terminal / une autre machine)
python -m usmd --config usmd.yaml

# 4c. Remplacer role et adresse sans modifier le fichier de config
python -m usmd --role usd_operator --address 192.168.1.5
```

Les clés Ed25519/X25519 sont générées automatiquement au premier lancement et sauvegardées dans le fichier `keys_file` défini dans la configuration (défaut : `usmd_keys.json` dans le répertoire courant).

---

## Configuration

Le fichier de configuration est au format YAML. Toutes les clés sont optionnelles ; les valeurs non renseignées reviennent aux valeurs par défaut intégrées.

```yaml
# usmd.yaml

# Identité réseau
node:
  address: auto          # "auto" = détecte l'interface sortante ; ou "192.168.1.5"
  role: executor         # executor | operator | usd_operator | ucd_operator

# Domaine USD
usd:
  name: my-domain        # Nom du domaine (USDN)
  cluster_name: ""       # USCN — laisser vide si pas de cluster
  edb_address: null      # DNS/IP du Easy Deployment Base (optionnel)
  max_reference_nodes: 5
  load_threshold: 0.8    # Charge normalisée au-delà de laquelle le nœud est "affaibli"
  ping_tolerance_ms: 200 # Ping T max (ms) dans la formule de distance
  load_check_interval: 30
  emergency_threshold: 0.9

# Comportement au démarrage
bootstrap: false         # true = créer un nouvel USD ; false = rejoindre
keys_file: usmd_keys.json
nndp_ttl: 30             # Secondes entre deux broadcasts Here-I-Am

# Ports (valeurs spec — modifier uniquement en cas de conflit)
ports:
  ncp: 5626
  nndp_listen: 5221
  nndp_send: 5222
```

En installation service, le fichier de configuration est `/etc/usmd/usmd.yaml` et le fichier de clés est `/var/lib/usmd/usmd_keys.json`.

---

## Options de la ligne de commande

```
python -m usmd [OPTIONS]

Options :
  --config PATH         Fichier de configuration YAML (défaut : usmd.yaml)
  --bootstrap           Créer un nouvel USD au lieu d'en rejoindre un
  --role ROLE           Remplacer le rôle (executor|operator|usd_operator|ucd_operator)
  --address IP          Remplacer l'adresse réseau du nœud
  --log-level LEVEL     Verbosité des logs : DEBUG|INFO|WARNING|ERROR (défaut : INFO)
```

Les options CLI ont priorité sur le fichier de configuration.

---

## Rôles des nœuds

| Rôle | Description |
|------|-------------|
| `executor` | Nœud exécutant des services (rôle par défaut) |
| `operator` | Nœud de gestion sans responsabilité de domaine |
| `usd_operator` | Nœud responsable de la gestion d'un USD |
| `ucd_operator` | Nœud responsable de la gestion d'un USC (cluster) |

---

## Tests

```bash
# Lancer tous les tests
pytest tests/

# Avec détail des sous-tests
pytest tests/ -v

# Via tox (teste sur plusieurs versions de Python)
tox

# Pylint
pylint usmd/
```

La suite de tests couvre les protocoles NCP et NNDP, la sérialisation des frames, le handler de commandes, le daemon et la cryptographie (246 tests, 28 sous-tests).
