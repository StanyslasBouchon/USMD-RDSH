# Cluster PostgreSQL derrière une VIP de répartition

Un primaire et des réplicas en streaming, un par nœud, joignables par les clients hors USMD à une seule adresse : la VIP de répartition, qui envoie les connexions au primaire seul.

| Fichier | Rôle |
|---|---|
| `pg.yaml` | Fichier de service : `expose` (5432), `balance` (la VIP), séquences |
| `pg.sh` | Démarrage, copie du primaire, suivi, promotion, sonde |
| `pg.env` | Mots de passe, sources autorisées, seuil de promotion |

## Ce que fait chaque nœud

- **Premier nœud** : `initdb`. Il devient le primaire.
- **Nœuds suivants** : ils copient le primaire (`pg_basebackup`), qu'ils joignent à son adresse, port 60000 + id. Ce sont des réplicas.
- **`probe`** ne réussit que sur le primaire. La VIP n'envoie les clients qu'à lui.
- **`check`**, à chaque contrôle de santé :
  - un réplica suit le primaire qu'il trouve ;
  - sans primaire pendant `PG_PROMOTE_AFTER` contrôles d'affilée, le réplica le plus avancé se promeut ; à égalité, c'est celui de plus petite adresse ;
  - s'il y a deux primaires, celui de la timeline la plus récente reste, et l'autre échoue à son contrôle.
- **Un ancien primaire qui revient** et trouve un autre primaire met ses données de côté (`pg.before-<date>`), puis copie le nouveau primaire.

Scénario vérifié sur PostgreSQL 16 : trois instances, création, copie, panne et promotion, retour de l'ancien primaire, double primaire, `update`.

## Topologie

- **node1** : autorité, et première instance (le primaire au départ).
- **node2** et **node3** : réplicas.
- **Catalogue** : service `pg`, id `0e1`, donc port exposé 60225 ; VIP SP 10.80.0.40 dans l'aire `front`.
- **VIP de répartition** : une adresse libre du réseau physique des VM, par exemple `172.27.191.240/20`.

## 1. Paquets (les trois nœuds)

```bash
sudo apt install -y postgresql
```
```bash
sudo systemctl disable --now postgresql
```
Le PostgreSQL du système occuperait le port 5432 : chaque instance `pg` lance le sien dans `/var/lib/usmd/.usmd/services/pg`.

## 2. node1 : les fichiers

1. Choisir la VIP : une adresse du sous-réseau des VM (`ip -4 addr`), qu'aucune machine n'utilise. La reporter dans `pg.yaml` (`balance: vip`).
2. Changer les deux mots de passe de `pg.env`.
3. Copier les fichiers là où l'autorité les lit :

```bash
sudo install -d -o usmd -g usmd -m 755 /etc/usmd/services
```
```bash
sudo install -o usmd -g usmd -m 644 ~/USMD-RDSH/readme/demo-pg/{pg.yaml,pg.sh,pg.env} /etc/usmd/services/
```

## 3. node1 : le service et la mutation (`sudo usmd`)

Si `show service-area summary` ne liste pas `front` :
```
config service-area
edit front
set id 1
set prefix 10.80.0.0
set prefix-length 16
next
end
```
Le service et sa mutation :
```
config service
edit pg
set id 0e1
set area front
set type dynamic
set vip 10.80.0.40
set service-file /etc/usmd/services/pg.yaml
set files /etc/usmd/services/pg.sh /etc/usmd/services/pg.env
next
end
config mutation
edit pgcluster
set services pg
set min-instances 2
set max-instances 3
next
end
```
Chaque `end` doit répondre `Committed`. Contrôles : `show service catalog` (`pg` en `ok`) ; `show service balance` (`pg`, owner `none`).

## 4. node1 : le primaire

1. `execute node transmute mutation=pgcluster`
2. `show mutation status` : `pg build`, `pg check_health` à `ok`.
3. `show service exposure` : port `60225/tcp`, instance `10.80.0.40:5432`, Clients `yes`.
4. `show service balance` : owner node1 `(self)`, interface `eth0`, connexions vers `10.80.0.40:5432`.
5. Sur la machine, la VIP est posée : `ip -4 addr show eth0`.

## 5. node2, puis node3 : les réplicas

1. `execute node transmute mutation=pgcluster`, sur un nœud à la fois.
2. Contrôles :
   - `show mutation status` : `ok` ;
   - `show service exposure` : Clients `no (probe)` ;
   - le journal du cluster doit afficher `copied from the primary` puis `replica of the primary` :
     ```bash
     sudo tail /var/lib/usmd/.usmd/services/pg/cluster.log
     ```
3. Sur node1, les réplicas en streaming :
   ```bash
   sudo -u usmd psql -h /var/lib/usmd/.usmd/services/pg/run -U postgres -c "SELECT application_name, client_addr, state FROM pg_stat_replication"
   ```

## 6. Un client hors USMD

Depuis n'importe quelle machine du réseau ayant `psql` (ici node3), avec le mot de passe `app` de `pg.env`. Remplacer la VIP par la vôtre :
```bash
export PGPASSWORD=change-me-app
```
```bash
psql "host=172.27.191.240 user=app dbname=app" -c "CREATE TABLE IF NOT EXISTS t (id serial PRIMARY KEY, at timestamptz DEFAULT now(), served_by text DEFAULT current_setting('cluster_name'))"
```
Une insertion par seconde ; `served_by` est l'adresse du nœud primaire :
```bash
while true; do psql "host=172.27.191.240 user=app dbname=app connect_timeout=2" -qAtc "INSERT INTO t DEFAULT VALUES RETURNING id, served_by"; sleep 1; done
```

## 7. La panne du primaire (node1)

1. Arrêter brutalement son PostgreSQL. Le chemin dépend de la version (`ls /usr/lib/postgresql`) :
   ```bash
   sudo -u usmd /usr/lib/postgresql/15/bin/pg_ctl -D /var/lib/usmd/.usmd/services/pg/pg -m immediate stop
   ```
2. La boucle du client échoue pendant environ 30 à 40 s : trois contrôles de santé à 10 s, puis la promotion.
3. Les insertions reprennent, avec `served_by` à l'adresse de node2. node2 est le réplica le plus avancé ; à égalité, c'est celui de plus petite adresse.
4. Sur node2, `cluster.log` affiche `promoted`. Sur node3, il affiche `replica of the primary at <node2>`.
5. `show service balance` montre les connexions vers le nouveau primaire. Le porteur de la VIP n'a pas changé tant que node1 reste Actif.
6. Sur node1, après trois contrôles ratés, le nœud passe en urgence et démonte `pg`.

## 8. Retour de node1

1. `execute node transmute mutation=pgcluster`
2. `cluster.log` affiche, dans l'ordre :
   - `former data put aside` ;
   - `copied from the primary at <node2>` ;
   - `replica of the primary`.
   node1 est maintenant un réplica de node2. Ses anciennes données restent dans `pg.before-<date>`, à supprimer à la main une fois inutiles.

## 9. Panne du porteur de la VIP

Arrêter le nœud qui porte la VIP (`sudo systemctl stop usmd`, ou couper la VM) :
- `show service balance`, sur un autre nœud, montre un nouveau porteur ;
- la VIP passe sur son interface (ARP gratuit) ;
- la boucle du client reprend.

## Limites

- **Substitution d'adresse** : PostgreSQL voit l'adresse du porteur de la VIP, pas celle du client. `pg_hba` (`PG_ALLOW`) doit donc autoriser les adresses des nœuds.
- **Pertes à la bascule** : la réplication est asynchrone, donc les dernières transactions du primaire tombé peuvent manquer au nouveau. Elles restent dans `pg.before-<date>` de l'ancien primaire.
- **Partition** : un primaire isolé reste primaire de son côté. Le contrôle de double primaire ne joue qu'une fois le réseau rétabli.
- **Default Switch Hyper-V** : il change de sous-réseau au redémarrage de l'hôte ; il faut alors choisir une nouvelle VIP et re-signer `pg.yaml`.
