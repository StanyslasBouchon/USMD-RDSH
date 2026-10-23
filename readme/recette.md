# Cahier de recette USMD-RDSH

Référentiel : les drafts courants de `readme/drafts` — `draft-usmd-rdsh-architecture-03`, `draft-usmd-ncp-02`, `draft-usmd-nndp-01`, `draft-usmd-sp-01`.

Chaque ligne est une exigence (DOIT, DEVRAIT, PEUT) ou une définition normative (DEF) d'un draft. Son état dit où en est le code (`src/usmd_rdsh/node/**`, `src/usmd_rdsh/cli/**`, `src/usmd_rdsh/web/**`) :

- **done** : implémenté et conforme ; la remarque cite la fonction et le test qui le couvre ;
- **partial** : implémenté en partie, le manque est indiqué ;
- **missing** / **config-only** : absent / seulement configurable ;
- **open** : point ouvert ou incohérence du draft, à trancher par l'auteur ;
- **n/a** : exigence d'exploitation, d'IANA, ou option (PEUT) non retenue, hors du code.

Une exigence est cochée quand son état est **done**. Les tests se lancent avec `pdm run pytest -q tests`.

## Bilan

| Partie | Draft | done | partial | missing | config-only | open | n/a |
|---|---|---|---|---|---|---|---|
| [1 — Architecture](#partie-1--architecture) | draft-usmd-rdsh-architecture-03 | 328 | 3 | 0 | 0 | 12 | 11 |
| [2 — NCP](#partie-2--ncp) | draft-usmd-ncp-02 | 281 | 0 | 0 | 0 | 0 | 12 |
| [3 — NNDP](#partie-3--nndp) | draft-usmd-nndp-01 | 125 | 0 | 0 | 0 | 1 | 4 |
| [4 — SP](#partie-4--sp) | draft-usmd-sp-01 | 187 | 3 | 0 | 0 | 0 | 1 |
| **Total** | | **921** | **6** | **0** | **0** | **13** | **28** |

Exigences applicables (hors open et n/a) : 927, dont 921 cochées (99.4 %).

---

# Partie 1 — Architecture

## Cahier de recette — draft-usmd-rdsh-architecture-03 (ARCH)

Source : `draft-usmd-rdsh-architecture-03.docx` (23 octobre 2026) ; les sections 8.7 et 11.6 et le point B-10 sont nouveaux dans cette révision, le reste est inchangé depuis -02.
Code examiné : `src/usmd_rdsh/node/**` (nouvelle implémentation : `node.py`, `handlers.py`, `tables.py`, `signed.py`, `authority.py`, `identity.py`, `crypto.py`, `wire.py`, `states.py`, `addresses.py`, `nndp.py`, `ncp/codec.py`, `ncp/transport.py`, `load.py`, `distance.py`, `services.py`, `raft.py`, `sp/*.py`), `src/usmd_rdsh/cli/**` (`bridge.py`, `views/**`, `actions/**`), `src/usmd_rdsh/web/**`, `src/usmd_rdsh/main.py`, et les tests `tests/test_nndp01.py`, `test_sp01.py`, `test_sp01_engine.py`, `test_node_integration.py`, `test_cli.py`, `test_authority_services.py`, `test_ncp02_transport.py` (80 tests passants) — branche `feature/cli-web-interface`, arbre de travail non commité. L'ancien prototype (`proto/`, `self/`, `sys/`, `security/`, `utils/node_state.py`) n'est plus utilisé par l'application (seul `identity._prototype` lit `security/ed25519` pour migrer une ancienne identité).

Légende des niveaux : DOIT (DOIT / NE DOIT PAS / OBLIGATOIRE), DEVRAIT (DEVRAIT / NE DEVRAIT PAS / RECOMMANDÉ), PEUT (PEUT / FACULTATIF), DEF (définition normative impliquant un comportement : formule, défaut, registre, table, transition, format, procédure).

Légende des états :
- **done** : implémenté et conforme (fichier:fonction en remarque, et test couvrant s'il existe).
- **partial** : implémenté en partie (le manque est indiqué).
- **missing** : absent du code.
- **config-only** : seulement configurable ou affiché, sans comportement associé.
- **open** : point ouvert de l'annexe B (non normatif, à suivre).
- **n/a** : exigence d'exploitation ou de rédaction, hors du code.

Ré-audit final (22 octobre 2026, après les corrections de `node/**`, `services.py`, `authority.py`, `cli/bridge.py`, `cli/actions/security.py`, `cli/views/system.py`, `raft.py`) : toutes les lignes non « done » ont été revérifiées sur le code, et les lignes « done » touchées par les modifications ont été relues. Bilan : 303 done, 11 partial, 0 missing, 0 config-only, 10 open, 10 n/a (334 exigences).

Constats transverses (à lire avant les tableaux) :
- `main.py` crée un `node.node.Node` unique (asyncio) qui démarre NCP (UDP 9992, X25519 + HKDF-SHA-256 + ChaCha20-Poly1305, `ncp/transport.py`), NNDP (`nndp.py`, HIA signés en diffusion et en unicast vers les nœuds de référence, vecteur de services), SP (`sp/engine.py` + interface TUN, si le paramètre 0x0010 est défini) et Raft (`raft.py`), puis neuf boucles : amorçage, charge, distances, propriétés, réconciliation, cicatrisation, santé, dépendances, maintenance (électeurs, expiration de la NIT, minuteries SP, changement d'adresse, retour à 0x2000 après une délégation). NCP écoute aussi en IPv6 (`Node._start_ncp`, faculté de [NCP 4]) ; tout le reste est IPv4.
- Le nœud démarre à 0x0000, suit amorçage → admission (Request_approval / paquet d'endossement) → synchronisation (table complète, propriétés signées, nœuds de référence) → 0x2000 ; un jeton « fondateur » permet l'auto-admission et l'initialisation du journal Raft. Le parcours fondateur + admission + synchronisation + transmutation + identifiant de gestion est couvert par `tests/test_node_integration.py::test_founder_admission_sync_and_master` (deux nœuds sur 127.0.0.2/3, NNDP désactivé).
- La configuration de l'autorité (USC, USD, aires, catalogue, mutations) n'est plus locale : `cli/bridge.AuthorityBridge.settle` la signe et l'injecte seulement sur un nœud qui détient la clé USC (`node/authority.py`), et la refuse ailleurs ; avant de signer, elle refuse une aire contenant l'adresse d'un nœud (`_check_node_addresses`), la réutilisation d'un identifiant de service retiré depuis moins d'une heure (`_check_service_ids`, `Authority.retire_service/reuse_allowed`), une mutation citant un service hors catalogue ou une dépendance hors catalogue ou d'une autre aire (`_check_mutation`). Les objets signés sont versionnés (date en ms), vérifiés et propagés (`signed.SignedConfig.offer_*`, `Node.push_properties`, `handlers._relay_properties`) ; une autorité hors ligne exporte et une autre machine importe (`authority.export_signed/import_signed`, `execute properties export/import`).
- Les manques du premier audit sont comblés : expiration de délégation (`handlers._delegation_deadline`, 0x0008, 0x3200), reprise des services d'un nœud muet (`Node.take_over`), retour à 0x2000 après une délégation (`_maintenance_loop`, `DelegationState.handed_over`), garde des transitions (`Node.set_state` + `states.transition_allowed`), mise à jour rejouée puis annulée en cas d'échec (`Node.offer_mutation` / `apply_mutation_update`), signature d'autorité et catalogue vérifiés avant toute commande (`Node.mutation_specs`, `uncatalogued`, `transmute`), pas de build sans identifiant de gestion, TTL de la NIT (`tables.Nit.associate` défaut 300 s, `Node.renew_nit`, `Nit.expire`), renouvellement de clés (`Node.rekey`), révocation NAL (`execute nal revoke`), limitation des demandes d'aide (`handlers._request_rate_ok`), utilisateur non privilégié (`ServiceRunner.run_as`), Tm = Tmoy + V/D (`Node.useful_transmutation_time`), EDB validée hors boucle (`parse_edb`, `_fetch_edb`), YAML 1.2 (`services.Yaml12Loader`).
- Les anomalies du premier audit sont corrigées (`_dependency_loop` ne s'arrête plus, plus de `_applied_versions`, attribution inscrite seulement après commit avec `Raft.free_id_for`, masque 8..32 partout, EDB via `asyncio.to_thread`, volumes déclarés par `config system service-host`) et la docstring obsolète de `cli/views/domain.py` a disparu.
- Restent incomplets (11 lignes partial) : l'expiration de délégation est déclenchée chez chaque nœud favorable qui n'a pas lui-même reçu Confirm_delegation, y compris quand le nœud défaillant a confirmé auprès d'un autre (prise en charge en double jusqu'à la borne max) et elle n'est pas attribuée par les références non favorables ; une nouvelle version de mutation peut être propagée avant le résultat de « update » (`Node.inject` → `push_properties` immédiat, `_properties_loop` pendant l'exécution) ; `AuthorityBridge.settle` ne recontrôle pas les mutations inchangées quand le catalogue change d'aire ; D (débit vers les références) n'est jamais mesuré (`Node.transfer_rate` reste 0, débit nominal de l'interface à la place) ; `Node.transmute` force 0x3100 depuis tout état ; deux fiches revendiquant une adresse SP ne déclenchent pas d'interrogation d'un autre électeur (B-3) ; l'EDB n'est utilisable qu'avec un HIA entendu.
- Anomalies relevées en lisant le code (sans ligne propre) : `handlers._check_sender` associe (clé, adresse) avec `ttl_ms=None` quand la fiche de la table porte l'adresse (association permanente, voir 4.3-1) ; `Node.apply_mutation_update` ne reconstruit que le service dont « update » a échoué (ceux déjà mis à jour avant lui restent dans la nouvelle version) ; `_on_neighbor_inactive` retire une référence et ne republie la fiche que si `measure_distances` change encore la liste. Aucun test ne couvre `take_over`, `_delegation_deadline`, `rekey`, `execute nal revoke`, `parse_edb`, `_request_rate_ok`, le retour à 0x2000 ni l'échec d'une mise à jour.

---

### 1. Introduction

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-1.2-1 | DEF | Autogestion : les nœuds observent leur charge et celle des voisins et se délèguent des services sans intervention humaine | done | `node.Node._load_loop` → `check_weakness` → `request_help` / `emergency` ; charge des voisins via `Check_distance_to_node` (`Node.measure`) et `handlers._can_take` |
| ARCH-1.2-2 | DEF | Autorité unique de configuration : propriétés USC/USD/mutations signées par l'autorité, propagées de pair en pair, seule la version la plus récente s'applique | done | `cli/bridge.AuthorityBridge.settle` (signature), `signed.SignedConfig.offer_usc/offer_usd/offer_mutation` (signature + version strictement postérieure), `Node.push_properties`, `handlers._relay_properties` ; tests `test_cli.py::test_authority_commit_signs_and_others_refuse`, `test_node_integration.py` (USD périmé refusé) |
| ARCH-1.2-3 | DEF | Localité : coopération directe avec un petit nombre de nœuds de référence choisis par distance | done | `node/distance.py` (`distance`, `reselect`), `Node.measure_distances`, `inform_references` |
| ARCH-1.2-4 | DEF | Résilience à la partition et cicatrisation à la reconnexion | done | Cicatrisation (`Node._healing_loop`, `_on_neighbor`, `enforce_instance_bounds`) ; reprise des services d'un nœud muet par une de ses références (`Node._on_neighbor_inactive` → `take_over`, sous la borne min) ou après une délégation non confirmée (`handlers._delegation_deadline`) ; pas de test |
| ARCH-1.2-5 | DEF | Confiance explicite : clés propres à chaque nœud, admission attestée par un paquet d'endossement signé | done | `identity.load_identity` (Ed25519 + X25519), `handlers._on_request_approval` (`EndorsementPacket.sign`), `Node.verify_endorsement_of` |

### 2. Conventions et terminologie

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-2-1 | DEF | Mots-clés BCP 14 (RFC 2119/8174) en majuscules | n/a | Convention de rédaction |
| ARCH-2-2 | DEF | Charge de référence exprimée en pour mille (‰) | done | `load.LoadMonitor.measure` / `LoadSample.reference` en ‰ |
| ARCH-2-3 | DEF | Identifiant de service : 0x000 à 0xFFF, noté en 3 chiffres hexadécimaux | done | `addresses.pack` (12 bits), `cli/views/services.ServiceConfig._service_id` (`f"{n:03x}"`) |
| ARCH-2-4 | DEF | Identifiant de gestion : numéro de 16 bits attribué à un nœud pour un service de son aire | done | `Node.management`, `raft.StateMachine.free_id` (0x0001–0xFFFE), `Node.allocate_management_ids` |
| ARCH-2-5 | DEF | Adresse SP = (identifiant de service, identifiant de gestion), notée `0a1.5d68` | done | `addresses.to_text/from_text` ; test `test_nndp01.py::test_sp_address_text_form` |
| ARCH-2-6 | DEF | Maître USD élu par Raft ; électeur = nœud participant à l'élection et à la réplication | done | `raft.Raft` (élection avec pré-vote, réplication, ensemble des électeurs) |
| ARCH-2-7 | DEF | Aire de service = plan d'adressage IPv4 portant un WVNN, sans communication inter-aires | done | Interface SP (`sp/tun.py`, routes `Node.sp_routes`), isolation `sp/engine.SpEngine.from_tun` / `_deliver` ; test `test_sp01_engine.py::test_area_isolation_and_unknown_destination_are_dropped` |

### 3. Modèle du système

#### 3.1 Hiérarchie

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-3.1-1 | DEF | Un nœud appartient à un seul USD ; un USD appartient à une seule USC | done | Un seul `SignedConfig.usd` / `usc` par nœud ; jeton lié à un USDN (`CreationToken.usdn`) |
| ARCH-3.1-2 | DEF | Chaque nœud connaît tous les nœuds de son USD | done | `tables.NodeTable` remplie par la synchronisation (`handlers._synchronise`), le relais (`Node.schedule_relay`) et la réconciliation (`_reconcile_loop`) ; test `test_node_integration.py` |
| ARCH-3.1-3 | DEF | Chaque USD connaît les autres USD de son USC par les propriétés de l'USC | done | `codec.UscProperties.usd`, propagé avec les autres objets signés |
| ARCH-3.1-4 | DEF | Les protocoles n'échangent du trafic qu'entre nœuds d'un même USD | done | NCP : `handlers._check_sender` (clé absente de la NIT → 0x0005 ; seule Request_approval est admise d'un inconnu) ; NNDP : vecteur fusionné seulement si `is_admitted_key` (`nndp.NndpService.accept`) ; SP : `SpEngine._on_initiation` (adresse dans la NIT, `initiator_allowed`) |

#### 3.2 Nœud

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-3.2-1 | DEF | Nœud identifié par un identifiant unique (4.1) et possédant deux paires de clés (4.2) | done | `identity.Identity` (ULID, `SigningKey`, `AgreementKey`) |
| ARCH-3.2-2 | DEF | À tout instant, le nœud est dans un état du registre 5.5 | done | `Node.state: states.State` |
| ARCH-3.2-3 | DEF | Le nœud héberge au plus une mutation | done | `Node.mutation` (chaîne unique) ; `handlers._can_take` refuse une autre mutation |
| ARCH-3.2-4 | DEF | Le nœud tient la NIT, la NAL et la NEL | done | `tables.Tables` (`Nit`, `Nal`, `nel`) |
| ARCH-3.2-5 | DEF | Le nœud tient la table des nœuds de l'USD, complétée des états observés et de la charge de référence de chaque nœud | done | Table des nœuds + états observés (`Node.observed`) + charge de référence mesurée de chaque nœud (`Node.loads`, rempli par `Node.measure`) ; colonne « load » de `show node-table` (`cli/actions/tables.py`) |
| ARCH-3.2-6 | DEF | Le nœud tient la liste de ses propres nœuds de référence | done | `Node.references` (persistée dans `admission.json`), `show references` |
| ARCH-3.2-7 | DEF | Le nœud tient les propriétés de l'USC, de l'USD et des mutations | done | `signed.SignedConfig` (persistées dans `signed.json`) |
| ARCH-3.2-8 | DEF | Le nœud tient les tables de [USMD-SP] | done | `sp/engine.SpEngine` (sessions, flux, diffusion), `_NodeSpContext` (SAT, table des adresses SP) ; tests `test_sp01_engine.py` |

#### 3.3 Autorité et configuration

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-3.3-1 | DEF | L'autorité détient la clé privée Ed25519 de l'USC ; la NAL lui associe le rôle Usc_operator | done | `authority.Authority.usc` ; `Node.apply_anchors` accorde `Role.USC_OPERATOR` à la clé USC |
| ARCH-3.3-2 | DEF | L'autorité signe les propriétés de l'USC, de chaque USD et de chaque mutation | done | `cli/bridge.AuthorityBridge.settle` (`UscProperties/UsdProperties/MutationProperties.sign`) ; test `test_cli.py::test_authority_commit_signs_and_others_refuse` |
| ARCH-3.3-3 | DEF | Les nœuds ne prennent aucune décision de configuration : ils propagent et appliquent les propriétés signées | done | `AuthorityBridge.settle` refuse toute modification sans clé USC ; `bridge.reflect` remplace l'arbre par ce qui est en vigueur ; même test |
| ARCH-3.3-4 | DEF | Le maître USD est distinct de l'autorité ; seule fonction : attribuer les identifiants de gestion et tenir la table des adresses SP ; aucune décision de configuration | done | `Node.allocate_management_ids` (leader Raft) ; l'état répliqué ne porte que les attributions et les électeurs (`raft.StateMachine`) |

#### 3.4 Base de déploiement (EDB)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-3.4-1 | PEUT | Un USD peut être associé à un nom de domaine désignant une EDB | done | `config system bootstrap edb-domain` → `LocalSettings.edb_domain`, lu par `Node.edb_addresses` |
| ARCH-3.4-2 | DEF | EDB publiée en HTTPS (RFC 9110) à `https://<domaine>/.well-known/usmd/edb`, texte UTF-8 | done | `Node.edb_addresses` (URL `https://<domaine>/.well-known/usmd/edb`, cache 5 min) → `Node._fetch_edb` (décodage UTF-8, hors boucle par `asyncio.to_thread`) ; pas de test |
| ARCH-3.4-3 | DEF | Format : chaque ligne non vide hors commentaire `#` est `<identifiant>: <adresse IPv4>` | done | `node.parse_edb` : commentaires `#` retirés, lignes vides ignorées, identifiant validé par `wire.is_ulid`, adresse par `ipaddress.IPv4Address`, ligne malformée ignorée ; pas de test |
| ARCH-3.4-4 | DOIT | Chaque nœud référencé par l'EDB DOIT être joignable depuis tout réseau où un nœud peut être créé | n/a | Exigence d'exploitation |
| ARCH-3.4-5 | DOIT | Le client DOIT valider le certificat du serveur EDB | done | `ssl.create_default_context()` dans `Node._fetch_edb` |
| ARCH-3.4-6 | DEF | Les entrées EDB ne sont que des indications de contact, n'accordent aucune confiance ; l'authentification relève de NCP | done | `Node.candidates` n'utilise que l'adresse ; la clé vient du HIA et toute réponse est authentifiée par `ncp/transport` / `EndorsementPacket.verify` |

#### 3.5 Pile de protocoles

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-3.5-1 | DEF | NNDP : UDP, diffusion IPv4, port source 5221 vers port destination 5222 | done | `nndp.NndpService.start/emit`, `check_datagram` (port source) ; test `test_nndp01.py::test_reception_checks` |
| ARCH-3.5-2 | DEF | NNDP : unicast vers les nœuds de référence | done | `NndpService.emit` (boucle `reference_addresses`, empoisonnement `towards`) |
| ARCH-3.5-3 | DEF | NCP : UDP IPv4, port 9992 | done | `Node._start_ncp`, `ncp/transport.PORT` |
| ARCH-3.5-4 | DEF | SP : UDP IPv4, port défini par l'USD (paramètre 0x0010) | done | `Node.start_sp` (`parameter(usd, 0x0010)`) |
| ARCH-3.5-5 | DEF | Les trois protocoles utilisent l'en-tête de trame commun (section 10) | done | `wire.frame/FrameHeader` dans `nndp.HereIAm.sign`, `ncp/transport.seal_message`/`parse_fragment`, `SpEngine.from_udp` |
| ARCH-3.5-6 | DEF | IPv4 uniquement dans cette version | done | Sockets NNDP/SP `AF_INET`, adresses codées `ipaddress.IPv4Address` (`ncp/codec.py`) ; NCP écoute en plus sur `::` (`Node._start_ncp`), faculté prévue par [NCP 4], sans adresse IPv6 dans les fiches ni la NIT |

### 4. Identité et confiance

#### 4.1 Identifiant de nœud

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-4.1-1 | DEF | Identifiant = ULID, forme textuelle canonique de 26 caractères | done | `identity.load_identity` (`ulid.new().str`), `wire.is_ulid`, `Reader.ident` |
| ARCH-4.1-2 | DEF | 48 premiers bits = date de génération en ms, 80 bits aléatoires | done | Bibliothèque `ulid-py` |
| ARCH-4.1-3 | DEF | Généré par le nœud lors de sa demande d'admission (à l'installation selon 5.1) | done | `identity.load_identity` au premier démarrage, conservé dans `identity.json` |
| ARCH-4.1-4 | DOIT | Si l'identifiant est déjà utilisé dans l'USD, le nœud DOIT en générer un nouveau et recommencer son admission | done | `Node.request_approval` sur erreur 0x0008 : `Identity.regenerate_id` + `save_identity`, nouvelle tentative au tour suivant ; pas de test |

#### 4.2 Clés d'un nœud

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-4.2-1 | DEF | Le nœud génère lui-même une paire Ed25519 (RFC 8032), son identité cryptographique | done | `crypto.SigningKey.generate` dans `identity.load_identity` |
| ARCH-4.2-2 | DEF | Ed25519 signe les HIA, les messages NCP et les poignées de main SP | done | `nndp.HereIAm.sign`, `codec.Message.encode`, `sp/handshake.build_initiation/build_response` |
| ARCH-4.2-3 | DEF | Le nœud génère une paire X25519 (RFC 7748) statique pour le chiffrement NCP et les sessions SP | done | `crypto.AgreementKey.generate` (`Identity.agreement`), utilisée par `NcpTransport` et `SpEngine` |
| ARCH-4.2-4 | DOIT | Les clés privées NE DOIVENT JAMAIS quitter le nœud | done | `identity.save_identity` (fichier 0600) ; aucune commande n'affiche ni n'envoie graine ou clé privée (`show node` : clés publiques seules) |
| ARCH-4.2-5 | DEF | Le renouvellement d'une paire de clés s'effectue par une nouvelle admission | done | `Node.rekey` (délégation des services, nouvelles paires Ed25519 et X25519, jeton/endossement/identifiants de gestion effacés, retour à 0x0000, redémarrage NNDP) ; `execute node rekey` (`cli/actions/security.py`) ; pas de test |

#### 4.3 Tables de confiance

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-4.3-1 | DEF | NIT : clé publique Ed25519, identifiant, adresse IPv4, clé X25519, TTL (300 s par défaut) | done | `node.py:_learn_entry`, `renew_nit`, `handlers._check_sender` : TTL de 300 s (`tables.NIT_TTL_MS`) pour toute association, renouvelée par les HIA valides et les messages NCP authentifiés, expirée par `Nit.expire` dans `_maintenance_loop`. |
| ARCH-4.3-2 | DEF | Une clé peut être associée à plusieurs adresses et une adresse à plusieurs clés | done | `NitEntry.addresses` (dict adresse → échéance) par clé |
| ARCH-4.3-3 | DEF | Un message authentifié provenant d'une association (adresse, clé) inconnue alors que la clé est connue est ignoré et son émetteur exclu (0x4000) [NCP 7.6] | done | `handlers._check_sender` (exclusion `EXCLUDED_NIT_ASSOCIATION`, pas de réponse) ; NNDP rejette le HIA (`NndpService.accept`) ; test `test_nndp01.py::test_replay_ordering_nit_and_inactivity` (côté NNDP) |
| ARCH-4.3-4 | DEF | NAL : clé publique Ed25519 et liste de rôles | done | `tables.Nal`, `show nal` |
| ARCH-4.3-5 | DEF | Rôles : Usc_operator, Usd_operator, Node_operator, Node_executor [NCP 7.3] | done | `codec.Role` (0x01–0x04), `Nal.allows` (hiérarchie) |
| ARCH-4.3-6 | DEF | NEL : paquets d'endossement émis par le nœud, pour vérification et révocation [NCP 7] | done | `Tables.nel` alimentée par `handlers._on_request_approval`, lue par `_on_verify_endorsement` et `_on_request_revocation` |
| ARCH-4.3-7 | DEF | Table des nœuds : pour chaque nœud, jeton de création + fiche la plus récente (identifiant, adresse, clé X25519, état déclaré, mutation, nœuds de référence) | done | `tables.NodeTable` / `Entry(token, record)`, `codec.NodeRecord` |
| ARCH-4.3-8 | DEF | Chaque entrée de la table des nœuds est signée par le nœud décrit, rattachée à la clé de l'USD par le jeton, propagée par Send_node_table [NCP 7.8, 7.9] | done | `codec.TableEntry.verify`, `Node.accept_entry`, `Node.send_table` / `schedule_relay` ; test `test_node_integration.py` |
| ARCH-4.3-9 | DEF | La table des nœuds alimente la NIT | done | `Node._learn_entry` |

#### 4.4 Ancres de confiance

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-4.4-1 | DEF | À sa création, le nœud reçoit de l'administrateur un rôle | done | `config system bootstrap role` → `LocalSettings.role`, accordé à la propre clé par `Node.apply_anchors` |
| ARCH-4.4-2 | DEF | Clés fournies selon le rôle : Usc_operator aucune ; Usd_operator clé USC ; Node_operator et Node_executor clés USC et USD | done | `cli/bridge._check_anchors` (appelée par `apply_local` pour `system bootstrap` et `system trust-anchor`) refuse un Usd_operator sans clé USC et un Node_operator/Node_executor sans clés USC et USD, dès qu'un jeton est configuré ; test `test_authority_services.py::test_inconsistent_anchors_refused_once_a_token_is_set` |
| ARCH-4.4-3 | DEF | Ces clés sont enregistrées de façon permanente dans la NAL | done | `Node.apply_anchors` (`Nal.grant(..., anchor=True)`), `Nal.revoke` épargne les ancres |
| ARCH-4.4-4 | DEF | La clé de l'USC permet de vérifier toutes les propriétés de configuration | done | `SignedConfig.offer_*` avec `Node.usc_key` ; `handlers._authority` |
| ARCH-4.4-5 | DEF | La clé de l'USD signe les jetons de création et permet de vérifier les entrées de la table des nœuds | done | `authority.Authority.mint_token`, `Node.check_token` (émetteur = `usd_key`), `TableEntry.verify` |

#### 4.5 Primitives cryptographiques

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-4.5-1 | DEF | Signatures : exclusivement Ed25519 (RFC 8032) | done | `crypto.SigningKey` / `verify` |
| ARCH-4.5-2 | DEF | Accord de clé : X25519 (RFC 7748) | done | `crypto.AgreementKey.agree` (refus du point d'ordre faible) |
| ARCH-4.5-3 | DEF | Dérivation : HKDF-SHA-256 (RFC 5869) | done | `crypto.hkdf` (NCP `transport._key`, SP) |
| ARCH-4.5-4 | DEF | Chiffrement authentifié : ChaCha20-Poly1305 (RFC 8439) | done | `crypto.seal/open_sealed` (NCP, SP) ; tests `test_sp01.py` |
| ARCH-4.5-5 | DEF | Aucune négociation ; tout changement de primitive exige une nouvelle version majeure | done | Primitives fixes dans `crypto.py`, aucun champ de négociation |

### 5. Cycle de vie d'un nœud

#### 5.1 Création

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-5.1-1 | DEF | Étape 1 : le nœud installé génère ses clés (4.2) et son identifiant (4.1) | done | `identity.load_identity` |
| ARCH-5.1-2 | DEF | Le nœud expose sa clé publique Ed25519 à l'administrateur (console ou fichier) | done | `show node` (`cli/actions/show_system.show_node`) |
| ARCH-5.1-3 | DEF | Étape 2 : jeton de création [NCP 7.7] signé par l'opérateur de l'USD, lié à la clé Ed25519 du nœud, indiquant USDN, rôles autorisés, date d'émission, date d'expiration (≤ 7 jours) | done | `codec.CreationToken`, `authority.Authority.mint_token` (≤ 7 j), `execute authority token create`, `Node.check_token` |
| ARCH-5.1-4 | DEF | Signature de préférence hors ligne ; la clé privée de l'USD n'est jamais transmise aux nœuds | done | Le jeton est signé sur le poste qui détient `authority/usd.key` et remis en base64url ; aucune commande n'envoie la clé |
| ARCH-5.1-5 | DEF | Étape 3 : l'administrateur remet le jeton, le rôle, les clés publiques et facultativement un nœud de contact et le domaine de l'EDB | done | `config system bootstrap` (`cli/views/node.BootstrapConfig`), `config system trust-anchor`, `execute node token install` |
| ARCH-5.1-6 | DEF | Le nœud passe à l'état 0x0000 « En attente d'approbation » et prépare sa fiche de nœud initiale [NCP 7.8] | done | `Node.__init__` (`State.APPROVAL_REQUIRED`), `Node.initial_record` |
| ARCH-5.1-7 | DOIT | Le nœud DOIT obtenir son admission avant l'expiration du jeton ; au-delà, un nouveau jeton est nécessaire | done | `Node.check_token(for_admission=True)` refuse un jeton expiré (0x0007) |

#### 5.2 Amorçage

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-5.2-1 | DEF | Recherche d'un nœud admis dans l'ordre : nœud de contact, puis nœuds de l'EDB, puis découverte NNDP | partial | Ordre respecté par `Node.candidates` ; mais une adresse EDB n'est utilisée que si un HIA a été reçu de cette adresse (seule source de sa clé X25519), et un nœud de contact hors segment exige ses clés en configuration (`contact_ed25519`/`contact_x25519`) : l'EDB est inutilisable au-delà du segment (lacune du draft, cf. partie NCP) |
| ARCH-5.2-2 | DEF | Pendant l'amorçage, le nœud émet lui-même des HIA à l'état 0x0000 | done | NNDP démarré dès `Node.start` ; `NndpService.build` (listes vides à 0x0000) ; test `test_nndp01.py::test_unadmitted_node_announces_empty_lists` |
| ARCH-5.2-3 | DOIT | Horloges DOIVENT être synchronisées sur l'heure réelle par un moyen externe (ex. NTP) avant l'amorçage | n/a | Moyen externe ; `show clock` n'indique pas l'état de synchronisation |
| ARCH-5.2-4 | DEF | NNDP, NCP et SP rejettent les messages dont l'horodatage s'écarte de plus de 30 s de l'heure locale | done | `nndp.check_datagram`, `handlers.handle_request` (0x0002), `SpEngine._on_initiation` ; test `test_nndp01.py::test_freshness_interval_and_excluded_state` |

#### 5.3 Admission

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-5.3-1 | DEF | Le nœud adresse Request_approval à un nœud admis avec son jeton et sa fiche initiale | done | `Node.request_approval` ; test `test_node_integration.py` |
| ARCH-5.3-2 | DEF | L'endosseur vérifie : jeton signé par la clé de l'USD, non expiré, lié à la clé du demandeur, autorisant les rôles demandés | done | `handlers._on_request_approval` + `Node.check_token` |
| ARCH-5.3-3 | DEF | L'endosseur vérifie : fiche signée par cette clé, portant l'adresse source de la requête, identifiant non utilisé par une autre clé | done | `handlers._on_request_approval` (`record.verify`, `record.address != ip`, `by_id` → 0x0008) |
| ARCH-5.3-4 | DEF | En cas de succès : paquet d'endossement, inscription dans NIT, NAL, NEL et table des nœuds, propagation (jeton, fiche) aux nœuds de référence | done | `handlers._on_request_approval` (`nel.append`, `nodes.merge`, `_learn_entry`, `schedule_relay`) ; test `test_node_integration.py` (NEL) |
| ARCH-5.3-5 | DEF | En cas de refus : erreur 0x0007 (jeton refusé) ou 0x0008 (identifiant déjà utilisé) | done | `handlers._on_request_approval` (`BAD_CREATION_TOKEN`, `ID_IN_USE`) |
| ARCH-5.3-6 | DEF | Sur 0x0008, le nœud génère un nouvel identifiant et recommence avec le même jeton | done | `Node.request_approval` (`regenerate_id`, jeton conservé) |
| ARCH-5.3-7 | DOIT | Un nœud NE DOIT PAS endosser un nœud dont le jeton de création est refusé | done | `handlers._on_request_approval` retourne 0x0007 avant tout endossement |

#### 5.4 Synchronisation

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-5.4-1 | DEF | Passage à l'état 0x1000 dès réception du paquet d'endossement | done | `Node.request_approval` ; test `test_node_integration.py` |
| ARCH-5.4-2 | DEF | L'endosseur transmet la table des nœuds par Send_node_table en mode table complète (exception NCP 6.1) | done | `handlers._synchronise` (`send_table(mode=0x00)`), exception `ENDORSER_EXCEPTION` |
| ARCH-5.4-3 | DEF | Le nouveau nœud vérifie chaque entrée et remplit sa NIT | done | `handlers._on_send_node_table` → `Node.accept_entry` → `_learn_entry` |
| ARCH-5.4-4 | DEF | L'endosseur transmet les propriétés USC (Send_usc_properties), USD (Send_usd_properties) et mutations (Send_mutation_properties), avec fichiers de service et temps de transmutation moyens | done | `handlers._synchronise` ; `MutationProperties` porte `service_file` et `average_transmutation_ms` ; test `test_node_integration.py` |
| ARCH-5.4-5 | DEF | Le nœud choisit ses nœuds de référence (6.3) et les informe par Inform_reference_node | done | `Node.finish_synchronisation` → `measure_distances`, `inform_references` ; test `test_node_integration.py` |
| ARCH-5.4-6 | DEF | Le nœud émet une nouvelle fiche à l'état 0x2000 et la propage à ses nœuds de référence | done | `Node.finish_synchronisation` → `publish_record` → `schedule_relay` ; test `test_node_integration.py` |
| ARCH-5.4-7 | DEF | Le nœud reste sans mutation tant qu'aucune délégation ni décision de l'administrateur ne lui en attribue une | done | `Node.mutation = ""` ; seul `transmute` la change |
| ARCH-5.4-8 | DEF | Nouvelle fiche à chaque changement d'adresse, d'état déclaré, de mutation ou de nœuds de référence | done | `node.py:publish_record` à chaque changement d'état, de mutation, de nœuds de référence (y compris retrait sans remplaçant dans `_on_neighbor_inactive`), d'adresses SP, d'indicateur électeur (`_on_voter_change`) et d'adresse (`_maintenance_loop`) ; réconciliation `_reconcile_loop` toutes les 600 s ±25 %. |
| ARCH-5.4-9 | DEF | Toutes les 600 s, réconciliation de la table avec un nœud de référence tiré au hasard [NCP 7.9] | done | `Node._reconcile_loop` (gigue ±25 %), `execute table reconcile` |

#### 5.5 Registre des états

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-5.5-1 | DEF | État codé sur 16 bits ; 4 bits de poids fort = famille | done | `states.State.family` |
| ARCH-5.5-2 | DEF | Codes : 0x0000 attente d'approbation (D), 0x1000 synchronisation (D), 0x2000 actif (D), 0x3000 inactif (D), 0x3100 mutation (D), 0x3200 délai dépassé (O), 0x3300 urgence (D), 0x3301 ressources (D), 0x3302 dépendances (D), 0x3303 santé (D), 0x3304 mise à jour (D), 0x3400 aucun HIA (O), 0x4000 association NIT (O), 0x4100 endossement invalide (O), 0x4200 endossement invérifiable + date (O), 0x4300 fin de service NEL invalide (O), 0x4400 révocation invalide (O) | done | `states.State` (17 codes, `observed`/`declarable`), `show node states` |
| ARCH-5.5-3 | DOIT | Un nœud NE DOIT PAS se déclarer dans un état d'origine O | done | `cli/actions/domain.DeclaredState._declarable`, `Node.set_state` (`transition_allowed` refuse un état O), `Node.publish_record` et `_on_get_status` remplacent un état O par 0x3000 ; test `test_cli.py::test_observed_state_cannot_be_declared` |
| ARCH-5.5-4 | DEF | Les états 0x4xxx sont locaux au nœud qui les prononce ; jamais déclarés ni annoncés | done | `tables.Exclusions` séparée de `Node.state` ; `HereIAm.encode_payload` et `Node.accept_entry` refusent 0x4xxx |
| ARCH-5.5-5 | DEF | L'état 0x4200 porte la date de l'exclusion | done | `tables.Exclusion.since/until`, `show exclusions` |
| ARCH-5.5-6 | DEF | Un état O est attribué par un pair qui l'observe (table locale des états observés) | done | `Node.observed`, `Node._on_neighbor_inactive` (0x3400) |

#### 5.6 Transitions

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-5.6-1 | DEF | 0x0000 → 0x1000 par admission | done | `Node.request_approval` ; test `test_node_integration.py` |
| ARCH-5.6-2 | DEF | 0x1000 → 0x2000 par synchronisation | done | `Node.finish_synchronisation` ; test `test_node_integration.py` |
| ARCH-5.6-3 | DEF | 0x2000 → 0x3100 par transmutation | done | `Node.transmute` ; test `test_node_integration.py` |
| ARCH-5.6-4 | DEF | 0x2000 → 0x330x par urgence | done | `Node.check_weakness` (0x3301), `_dependency_loop` (0x3302), `_health_loop`/`transmute` (0x3303), `apply_mutation_update` (0x3304) |
| ARCH-5.6-5 | DEF | 0x2000 → 0x3200 / 0x3400 par inactivité observée | done | 0x3400 par `Node._on_neighbor_inactive` (2 × I) ; 0x3200 par `handlers._delegation_deadline` (voir 7.5-1 pour sa portée) ; pas de test de 0x3200 |
| ARCH-5.6-6 | DEF | 0x3xxx → 0x2000 par reprise ou cicatrisation | done | Pairs : `_healing_loop` (Get_status) et `_on_neighbor` (HIA Actif) ; le nœud lui-même : `_maintenance_loop` le remet à 0x2000 (`DelegationState.handed_over`) une fois ses services délégués et sa charge sous le seuil 0x0004 ; pas de test |
| ARCH-5.6-7 | DEF | Tout état → 0x4xxx sur vérification d'endossement ou de NIT échouée | done | `handlers._check_sender` (0x4000), `Node.verify_endorsement_of` (0x4100, 0x4200), `_on_notify_end_of_service` (0x4300), `_on_request_revocation` (0x4400) |
| ARCH-5.6-8 | DEF | Exclusion temporaire 0x4200 : éligible à nouveau à l'expiration (10 min par défaut [NCP]) | done | `verify_endorsement_of` (`duration_ms=exclusion_ms`, 600 000), `Exclusions.is_excluded` lève l'exclusion échue |
| ARCH-5.6-9 | DEF | Les autres exclusions sont permanentes pour la clé concernée | done | `Exclusions.exclude` sans durée (`until=None`) |
| ARCH-5.6-10 | DEF | Seules les transitions du diagramme sont permises | done | `states.transition_allowed` + `Node.set_state` ; `transmute` refusée hors Actif/Inactif ; l'opérateur (`execute node state`) ne peut déclarer ni 0x0000 ni 0x1000, ni agir avant l'admission. |

#### 5.7 Retrait

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-5.7-1 | DEF | Un nœud retiré adresse Notify_end_of_service à chaque nœud de sa NEL | done | `Node.retire` ; `execute node retire` ; pas de test |
| ARCH-5.7-2 | DEF | Il adresse Request_revocation à son propre endosseur [NCP 7.5] | done | `Node.retire` |
| ARCH-5.7-3 | DEF | Il cède ses services par délégation (section 7), puis cesse d'émettre | done | `Node.retire` → `delegate_all(State.INACTIVE)` → `nndp.stop()` |
| ARCH-5.7-4 | DEF | Sa dernière fiche reste dans la table des pairs (suppression définitive non définie) | open | Voir ARCH-B-1 ; la fiche reste dans `NodeTable` |

### 6. Distance et nœuds de référence

#### 6.1 Charge de référence

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-6.1-1 | DEF | Mesure à intervalle régulier (paramètre 0x0007, 5 s par défaut) | done | `Node._load_loop` → `LoadMonitor.sample` |
| ARCH-6.1-2 | DEF | Quatre taux en ‰ : mémoire vive, processeur, espace disque des volumes utilisés par les services, carte réseau (débit observé / débit nominal) | done | `load.LoadMonitor.measure` : mémoire, CPU, réseau (débit observé / vitesse nominale), disque = taux maximal des `volumes` déclarés par l'administrateur (`config system service-host volumes`, `cli/views/system.py`), « / » par défaut |
| ARCH-6.1-3 | DEF | Chaque taux est lissé par la moyenne de ses trois dernières mesures | done | `LoadMonitor.smoothed` (`deque(maxlen=3)`) |
| ARCH-6.1-4 | DEF | Charge de référence = max des quatre taux lissés ; notée c lorsqu'elle est ramenée entre 0 et 1 | done | `LoadSample.reference` ; c = ‰ / 1000 dans `distance.distance` |

#### 6.2 Calcul de la distance

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-6.2-1 | DEF | Distance de A vers B calculée par A à partir de la réponse de B à Check_distance_to_node | done | `Node.measure` / `handlers._on_check_distance_to_node` |
| ARCH-6.2-2 | DEF | d = p + c + t/T + n ; p = 1 si B héberge le même service que A, 0 sinon ; c = charge de B ∈ [0,1] ; t = RTT mesuré par A (ms) ; T = tolérance 0x0002 (ms) ; n = 2 si B a déjà A pour nœud de référence, 0 sinon | done | `distance.distance` (p compare les mutations hébergées) ; pas de test unitaire |
| ARCH-6.2-3 | DEF | Un candidat dont t > T n'est pas éligible | done | `distance.distance` retourne None |
| ARCH-6.2-4 | DEF | Distance d'un candidat éligible ∈ [0, 5] ; plus faible = préféré | done | Découle de la formule ; `distance.choose/reselect` trient par d croissant |

#### 6.3 Choix des nœuds de référence

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-6.3-1 | DEF | Choisir les NNR (0x0001) candidats éligibles de distance minimale parmi les nœuds actifs de l'USD | done | `Node.measure_distances` (`active_nodes`, `parameter(usd, 0x0001)`, `distance.reselect`) |
| ARCH-6.3-2 | DEF | Informer chacun de la liste complète par Inform_reference_node | done | `Node.inform_references` |
| ARCH-6.3-3 | DEF | Relation orientée (B référence de A n'implique pas A référence de B) | done | `Node.references` vs `Node.referenced_by` |

#### 6.4 Mesure périodique

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-6.4-1 | DEF | Tous les 0x0006 (300 s), mesurer la distance des nœuds de référence et d'un échantillon d'au plus 32 autres nœuds actifs tirés au hasard | done | `Node._distance_loop`, `distance.sample` |
| ARCH-6.4-2 | DEF | Remplacer un nœud de référence si un candidat est plus proche d'au moins 0,2 (hystérésis) | done | `distance.reselect` (`HYSTERESIS = 0.2`) |
| ARCH-6.4-3 | DEF | Un nœud de référence qui quitte l'état Actif est remplacé sans attendre | done | `Node._on_neighbor_inactive` (retrait puis `measure_distances` immédiat) et `handlers._on_declare_state` (référence déclarée non active → `measure_distances`) |

### 7. Délégation et reprise

#### 7.1 Nœud affaibli

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-7.1-1 | DEF | Affaibli si la charge atteint le seuil 0x0004 (800 ‰) lors de trois mesures consécutives | done | `LoadMonitor.weakened`, `Node.check_weakness` |
| ARCH-7.1-2 | DEF | En urgence si la charge atteint 0x0005 (950 ‰) ou si le nœud entre dans 0x3301–0x3304 | done | `Node.check_weakness` (`LoadMonitor.emergency`), entrées en 0x330x suivies de `Node.emergency` |
| ARCH-7.1-3 | DEF | Service dynamique : Tm = Tmoy + V/D (Tmoy des propriétés de mutation, V octets de données, D débit mesuré vers les nœuds de référence en o/s) | done | `node.py:useful_transmutation_time` : Tm = Tmoy + V/D pour les services dynamiques ; V = taille des chemins de données déclarés (`system service-host data-paths`) ; D = débit mesuré sur les gros échanges Send_node_table (`send_table`, moyenne glissante), vitesse nominale du lien en attendant. |
| ARCH-7.1-4 | DEVRAIT | Se considérer affaibli dès que la tendance linéaire sur les trois dernières mesures atteint le seuil en moins de Tm | done | `LoadMonitor.weakened(transmutation_s=Tm)` : tendance linéaire sur les trois dernières mesures, appliquée seulement aux mutations dynamiques (`check_weakness`, Tm = None sinon) ; D approché (voir 7.1-3) |

#### 7.2 Demande d'aide

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-7.2-1 | DEF | Le nœud affaibli adresse Request_help à ses X (0x0003, 5) nœuds de référence les plus proches | done | `Node.request_help` / `_solicited` |
| ARCH-7.2-2 | DEF | X ne peut dépasser NNR | done | `signed.check_ranges`, `cli/views/domain.UsdConfig._coherent` ; test `test_cli.py::test_incoherent_usd_is_refused_inside_the_node` |
| ARCH-7.2-3 | DEF | Réponse favorable si : charge + charge estimée du service < seuil d'affaiblissement | done | `handlers._can_take` (estimation locale = moitié de la charge du demandeur, le draft ne la définit pas) |
| ARCH-7.2-4 | DEF | Réponse favorable si : nombre d'instances du service dans l'USD < borne maximale de la mutation | done | `handlers._can_take` (`instance_count`) |
| ARCH-7.2-5 | DEF | Réponse favorable si : dépendances du service accessibles (8.4) | done | `handlers._can_take` exige pour chaque dépendance une instance hébergée localement ou présente dans la table des services les plus proches (`nndp.services.best`) |
| ARCH-7.2-6 | DEF | Le nœud affaibli choisit la réponse favorable de distance minimale et adresse Confirm_delegation | done | `Node.request_help` |
| ARCH-7.2-7 | DEF | Le nœud de récupération transmute pour héberger une instance supplémentaire ; le nœud affaibli reste actif | done | `handlers._on_confirm_delegation` → `Node.transmute` ; `request_help` ne change pas l'état |

#### 7.3 Demande urgente

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-7.3-1 | DEF | Le nœud en urgence se déclare dans l'état 0x330x correspondant à son motif | done | `check_weakness`, `_health_loop`, `_dependency_loop`, `apply_mutation_update`, `execute node emergency` (état + `publish_record`) |
| ARCH-7.3-2 | DEF | Puis adresse Request_emergency à ses X nœuds de référence les plus proches en indiquant la liste des nœuds sollicités | done | `Node.emergency` → `_ask(Command.REQUEST_EMERGENCY, reason, solicited)` |
| ARCH-7.3-3 | PEUT | Chaque nœud sollicité peut relayer en Request_help vers ses propres nœuds de référence absents de la liste, et inclut dans sa réponse les nœuds qui ont accepté [NCP 6.4] | done | `handlers._help_or_emergency` (relais, réponses dans `extra`) |

#### 7.4 Bascule

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-7.4-1 | DEF | Le nœud défaillant adresse Confirm_delegation aux nœuds de récupération retenus, un par service | done | `Node.delegate_all` (premier nœud favorable qui accepte ; la délégation porte sur la mutation, seule unité que Confirm_delegation transporte) |
| ARCH-7.4-2 | DEF | Après confirmation, il déclare son inactivité par Declare_state à ses nœuds de référence | done | `Node.delegate_all` (Declare_state 0x3000) |
| ARCH-7.4-3 | DEF | Il exécute la séquence « emergency » de ses services, puis coupe les services de sa mutation | done | `Node.delegate_all` exécute « emergency » puis « unbuild » (sauf si « emergency » enchaîne déjà `action: unbuild`) et retire chaque service (`_withdraw`) |
| ARCH-7.4-4 | DEF | Les nœuds de récupération transmutent et reprennent ces services | done | `handlers._on_confirm_delegation` → `Node.transmute` |

#### 7.5 Expiration

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-7.5-1 | DEF | Sans confirmation dans le délai 0x0008 (30 s), les nœuds de référence attribuent 0x3200 au nœud défaillant | done | `handlers._delegation_deadline` : après 0x0008 s sans Confirm_delegation reçu ni Declare_state (délégation confirmée à un autre nœud, ARCH 7.4), le nœud de référence attribue 0x3200. |
| ARCH-7.5-2 | DEF | Les nœuds ayant répondu favorablement reprennent ses services comme si la délégation était confirmée, dans la limite de la borne maximale | partial | `_delegation_deadline` → `Node.transmute` si `_can_take` (borne max respectée) ; mais la reprise a aussi lieu après une délégation confirmée auprès d'un autre nœud (voir 7.5-1), d'où des instances en double jusqu'à la borne max ; départage = ARCH-B-7 |

#### 7.6 Cicatrisation

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-7.6-1 | DEF | Un nœud ayant attribué un état 0x3xxx à un pair lui adresse Get_status tous les 0x000B (60 s) | done | `Node._healing_loop` |
| ARCH-7.6-2 | DEF | Dès réponse « Actif » ou réception d'un HIA valide à l'état Actif, le pair est rétabli dans la table | done | `_healing_loop` et `Node._on_neighbor` suppriment l'état observé |
| ARCH-7.6-3 | DEF | Puis le nœud réévalue ses nœuds de référence | done | Après Get_status (`_healing_loop` → `measure_distances`) et après un HIA Actif (`_on_neighbor` → `measure_distances`) |

### 8. Mutations et services

#### 8.1 Transmutation

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-8.1-1 | DEF | Transmutation déclenchée par une délégation ou une décision de l'administrateur | done | `handlers._on_confirm_delegation`, `cli/actions/node_ops.execute_node_transmute` |
| ARCH-8.1-2 | DEF | Étape 1 : se déclarer dans l'état 0x3100 | done | `Node.transmute` (`INACTIVE_MUTATING` + `publish_record`) |
| ARCH-8.1-3 | DEF | Étape 2 : en entrant dans une aire nouvelle, obtenir du maître USD ses identifiants de gestion pour les services de cette aire | done | `Node.transmute` → `request_management_ids` ; test `test_node_integration.py` (0a1.0001) |
| ARCH-8.1-4 | DEF | Étape 3 : « unbuild » de chaque service de l'ancienne mutation puis « build » de chaque service de la nouvelle, dans l'ordre des dépendances | done | `Node.transmute`, `services.dependency_order` |
| ARCH-8.1-5 | DEF | Étape 4 : « check_health » de chaque nouveau service | done | `Node.transmute` |
| ARCH-8.1-6 | DEF | Étape 5 : déclarer 0x2000 si tous les contrôles réussissent, 0x3303 sinon | done | `Node.transmute` ; test `test_node_integration.py` (cas réussi) |
| ARCH-8.1-7 | DEF | Le nœud mesure la durée de chaque transmutation | done | `Node.transmutations`, `show mutation status` |
| ARCH-8.1-8 | PEUT | L'autorité peut s'en servir pour mettre à jour le Tmoy publié | done | Durées lisibles par `show mutation status` ; Tmoy modifiable sur le nœud autorité (`config mutation average-transmutation`, signé par `AuthorityBridge`) |

#### 8.2 Services statiques et dynamiques

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-8.2-1 | DEF | Statique : mêmes paramètres, commandes et données ; nouvelle instance opérationnelle dès la fin du build | done | `Node.transmute` : instance annoncée après build + check_health |
| ARCH-8.2-2 | DEF | Dynamique : mêmes paramètres et commandes, données propres ; acquisition des données (ex. diffusion SP) ; Tm dépend du volume | done | `ServiceSpec.type` « dynamic » active Tm = Tmoy + V/D (`Node.useful_transmutation_time`, D approché : voir 7.1-3) ; l'acquisition relève des commandes du service (diffusion SP disponible) |

#### 8.3 Fichier de service

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-8.3-1 | DEF | Flux YAML 1.2.2 encodé UTF-8, un document par service séparé par `---` | done | `services.parse_service_file` (UTF-8, `load_yaml_stream` avec `Yaml12Loader` : schéma core YAML 1.2, `yes`/`on` restent des chaînes, octal `0o`) ; tests `test_authority_services.py::test_service_file_is_yaml_1_2`, `test_yaml_1_2_scalars` |
| ARCH-8.3-2 | DOIT | Clé `name` (chaîne, obligatoire) ; DOIT figurer dans le catalogue des services de l'USD | done | `name` obligatoire (`parse_service_file`) ; présence au catalogue vérifiée par l'autorité (`bridge._check_mutation`) et par le nœud avant tout build (`Node.uncatalogued` dans `transmute`) ; test `test_authority_services.py::test_mutation_service_outside_catalogue_refused` (côté autorité) |
| ARCH-8.3-3 | DEF | Clé `type` : static ou dynamic, static par défaut | done | `parse_service_file` |
| ARCH-8.3-4 | DEF | Clé `dependencies` : liste de chaînes | done | `parse_service_file` |
| ARCH-8.3-5 | DEF | Clés séquences `build`, `unbuild`, `emergency` (sauvegarde avant arrêt), `check_health` (réussit si toutes les étapes réussissent), `update` | done | `services.SEQUENCES`, `ServiceRunner.run` |
| ARCH-8.3-6 | DEF | Identifiant, aire, VIP et adresse de groupe ne figurent pas dans le fichier de service mais dans le catalogue | done | `services.KNOWN_KEYS` (seule une clé `sp` héritée est tolérée et ignorée) ; catalogue dans `UsdProperties.catalog` |
| ARCH-8.3-7 | DOIT | NE DOIT PAS construire un service dont le nom est absent du catalogue | done | `Node.transmute` lève ValueError avant toute commande si `uncatalogued(mutation)` n'est pas vide ; pas de test côté nœud |
| ARCH-8.3-8 | DEF | Séquence = liste d'étapes exécutées dans l'ordre ; étape = `command` (commande OS) ou `action` (nom d'une autre séquence du même service : build ou unbuild) | done | `parse_service_file`, `ServiceRunner.run` |
| ARCH-8.3-9 | PEUT | Une étape peut contenir `timeout` en secondes (300 par défaut) | done | `services.Step.timeout`, `DEFAULT_TIMEOUT` (le champ CLI `step_timeout` n'est plus utilisé) |
| ARCH-8.3-10 | DEF | Une commande réussit si elle se termine dans le délai avec un code de sortie nul ; le premier échec interrompt et fait échouer la séquence | done | `ServiceRunner._command` / `run` ; pas de test d'échec ni de délai |
| ARCH-8.3-11 | DOIT | DOIT contrôler la signature de l'autorité sur les propriétés de mutation avant d'exécuter la moindre commande | done | `Node.mutation_specs` vérifie la signature de l'autorité à chaque appel, avant toute commande (utilisé par `transmute`, `_health_loop`, `apply_mutation_update`, `delegate_all`, `_can_take`) ; `transmute` la vérifie aussi en tête ; objets relus de `signed.json` donc revérifiés avant exécution |

#### 8.4 Dépendances

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-8.4-1 | DEF | Un service peut dépendre de services hébergés par d'autres nœuds | done | `ServiceSpec.dependencies`, `Node._dependency_loop` (table des services les plus proches) |
| ARCH-8.4-2 | DOIT | Un service et ses dépendances DOIVENT appartenir à la même aire | done | `cli/bridge.py:settle` contrôle chaque mutation (`_check_mutation`) contre le catalogue signé : ni une mutation ni un changement de catalogue ne peut placer une dépendance dans une autre aire ; `node._dependency_loop` contrôle l'accessibilité à l'exécution. |
| ARCH-8.4-3 | DOIT | L'autorité NE DOIT PAS publier de propriétés violant cette règle | done | Comme 8.4-2 : refus au moment de la signature (`AuthorityBridge.settle`). |
| ARCH-8.4-4 | DEF | Instances disponibles des dépendances connues par la table des services les plus proches (11.5) | done | `Node._dependency_loop` (`nndp.services.best`) |
| ARCH-8.4-5 | DEF | Tous les 0x0009 (30 s), vérifier qu'au moins une instance accessible de chaque dépendance existe | done | `Node._dependency_loop` (0x0009) parcourt toutes les dépendances à chaque tour, sans plus terminer la tâche |
| ARCH-8.4-6 | DEF | Sinon : se déclarer en 0x3302 et émettre une demande urgente | done | `Node._dependency_loop` (`INACTIVE_EMERGENCY_DEPENDENCIES`, `emergency`) |

#### 8.5 Mises à jour

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-8.5-1 | DEF | Mise à jour = nouvelle version des propriétés de mutation dont le fichier contient « update » | done | `handlers._on_send_mutation_properties` → `Node.apply_mutation_update` (séquence `update` présente) |
| ARCH-8.5-2 | DEF | Un nœud hébergeant le service exécute « update » puis « check_health » | done | `Node.offer_mutation` → `apply_mutation_update` (« update » puis « check_health ») dès qu'une version antérieure est connue, y compris après un redémarrage ; pas de test |
| ARCH-8.5-3 | DEF | En cas de succès, il adopte la version et la propage par Send_mutation_properties | done | `_on_send_mutation_properties` → `_relay_properties`, `_properties_loop` |
| ARCH-8.5-4 | DOIT | En cas d'échec, il NE DOIT PAS propager la nouvelle version | done | `node.py:offer_mutation` / `apply_mutation_update` : l'hôte exécute update puis check_health ; pendant ce temps `push_properties` diffuse la version précédente (`Node.updating`) et `inject` ne diffuse qu'après (`_push_after_updates`) ; en cas d'échec, la version précédente est rétablie, chaque service déjà mis à jour est reconstruit, rien n'est relayé. |
| ARCH-8.5-5 | DEF | En cas d'échec, il rétablit la version précédente par sa séquence « build » ; s'il réussit il reste actif, sinon 0x3304 et demande urgente | done | `apply_mutation_update` remet la version précédente dans `signed.mutations`, exécute son « build » ; échec → 0x3304, `publish_record`, `emergency` ; seul le service en échec est reconstruit (voir constats) ; pas de test |
| ARCH-8.5-6 | DEF | Un nœud n'hébergeant pas le service propage la nouvelle version sans l'exécuter | done | `_on_send_mutation_properties` (update seulement si `mutation.name == self.mutation`) |

#### 8.6 Bornes d'instances

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-8.6-1 | DEF | Les propriétés de mutation fixent le nombre minimal et maximal d'instances dans l'USD [NCP 6.10] | done | `codec.MutationProperties.min_instances/max_instances` (la CLI garde l'extension « 0 = illimité », hors draft) |
| ARCH-8.6-2 | DOIT | NE DOIT PAS accepter une délégation qui dépasserait la borne maximale | done | `handlers._can_take` (Request_help/emergency et Confirm_delegation) |
| ARCH-8.6-3 | DEF | Après cicatrisation, si le nombre d'instances dépasse la borne max, les nœuds en excédent d'identifiant lexicographiquement le plus grand déconstruisent leur instance | done | `Node.enforce_instance_bounds` (appelé par `_healing_loop`) |

#### 8.7 Environnement d'exécution des séquences (ARCH-03)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-8.7-1 | DEF | Chaque commande reçoit USMD_SERVICE, USMD_SERVICE_ID, USMD_MANAGEMENT_ID, USMD_SP_ADDRESS, USMD_DATA_ID_PREFIX, USMD_VIP, USMD_GROUP, USMD_AREA, USMD_USDN, USMD_NODE_ID, USMD_MUTATION, USMD_SEQUENCE, USMD_DATA_DIR | done | `Node.service_environment` → `ServiceRunner(environment=…)` ; tests `test_data_ids.py::test_sequences_get_the_usmd_variables`, `test_node_integration.py` ; `show service environment service=<nom>` |
| ARCH-8.7-2 | DOIT | NE DOIT PAS exécuter build, update ou check_health d'un service sans identifiant de gestion | done | `ServiceRunner.run` (`NEEDS_ADDRESS`) ; test `test_data_ids.py::test_no_sp_address_refuses_build_update_and_health` |
| ARCH-8.7-3 | DEF | unbuild et emergency restent exécutées, avec la dernière adresse SP connue | done | Même test ; `Node.management` n'est jamais effacé par une transmutation |
| ARCH-8.7-4 | DEF | Répertoire de données propre au service sur le nœud, créé avant build | done | `Node.service_data_dir` (`services/<nom>` de l'état, ou `service_data`) créé par `service_environment` |
| ARCH-8.7-5 | DOIT | NE DOIT PAS effacer le répertoire de données lors d'un unbuild, d'une transmutation ou d'une urgence | done | Aucun chemin du nœud ne le supprime |
| ARCH-8.7-6 | DEF | Le répertoire est réutilisé quand le nœud reconstruit le même service | done | Chemin stable par nom de service ; identifiant de gestion durable (ARCH-11.4-3) |
| ARCH-8.7-7 | DOIT | NE DOIT PAS exécuter deux séquences d'un même service en même temps ; une étape « action » s'exécute dans la séquence appelante | done | Verrou par service dans `ServiceRunner.run`, `_sequence` pour les actions ; test `test_data_ids.py::test_sequences_of_one_service_never_overlap` |
| ARCH-8.7-8 | DEF | Les variables USMD_* fixées par le nœud remplacent celles de son environnement | done | `{**os.environ, **variables}` |
| ARCH-8.7-9 | DEVRAIT | Un service dynamique DEVRAIT identifier ses données par les identifiants de la section 11.6 | n/a | Exigence sur l'auteur du fichier de service ; outillage : `show data-id postgresql` |

### 9. Configuration

#### 9.1 Propriétés de l'USC

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-9.1-1 | DEF | Propriétés USC : USCN, version, clé publique Ed25519 de l'USC, liste des USD | done | `codec.UscProperties` |
| ARCH-9.1-2 | DEF | Format défini par Send_usc_properties [NCP 6.8] | done | `UscProperties.encode/decode`, `handlers._on_send_usc_properties` |

#### 9.2 Propriétés de l'USD et paramètres

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-9.2-1 | DEF | Propriétés USD : USDN, version, clé publique Ed25519 de l'USD, liste des aires, catalogue des services, liste de paramètres | done | `codec.UsdProperties` |
| ARCH-9.2-2 | DEF | Paramètre = couple (code 16 bits, valeur 32 bits) [NCP 6.9] | done | `UsdProperties._unsigned/decode` (u16, u32) |
| ARCH-9.2-3 | DEF | Un paramètre absent prend sa valeur par défaut | done | `signed.parameter` |
| ARCH-9.2-4 | DEF | 0x0001 NNR, nœuds, défaut 5 | done | `Node.measure_distances` |
| ARCH-9.2-5 | DEF | 0x0002 tolérance de ping T, ms, défaut 1000 | done | `measure_distances`, `NndpHooks.ping_tolerance_ms` |
| ARCH-9.2-6 | DEF | 0x0003 nombre de nœuds sollicités X, défaut 5 | done | `Node._solicited` |
| ARCH-9.2-7 | DEF | 0x0004 seuil d'affaiblissement, ‰, défaut 800 | done | `Node.check_weakness`, `handlers._can_take` |
| ARCH-9.2-8 | DEF | 0x0005 seuil d'urgence, ‰, défaut 950 | done | `Node.check_weakness` |
| ARCH-9.2-9 | DEF | 0x0006 intervalle de mesure des distances, s, défaut 300 | done | `Node._distance_loop` |
| ARCH-9.2-10 | DEF | 0x0007 intervalle d'échantillonnage de la charge, s, défaut 5 | done | `Node._load_loop` |
| ARCH-9.2-11 | DEF | 0x0008 délai de délégation, s, défaut 30 | done | `handlers._delegation_deadline` (`parameter(usd, 0x0008)`, 30 s par défaut) |
| ARCH-9.2-12 | DEF | 0x0009 intervalle de vérification des dépendances, s, défaut 30 | done | `Node._dependency_loop` |
| ARCH-9.2-13 | DEF | 0x000A instances retenues par service K, défaut 3 | done | `NearestServices.k` (`Node._start_nndp`, `on_config_changed`) |
| ARCH-9.2-14 | DEF | 0x000B intervalle de cicatrisation, s, défaut 60 | done | `Node._healing_loop` |
| ARCH-9.2-15 | DEF | 0x000C intervalle de contrôle de santé, s, défaut 30 | done | `Node._health_loop` |
| ARCH-9.2-16 | DEF | 0x000D validité d'un paquet d'endossement, s, défaut 2 592 000 (30 j) | done | `handlers._on_request_approval` |
| ARCH-9.2-17 | DEF | 0x0010 port UDP de SP, aucun défaut | done | `Node.start_sp` (SP non démarré sans valeur) |
| ARCH-9.2-18 | DEF | 0x0011 et 0x0012 réservés (ancien préfixe des services) | done | Absents de `signed.USD_PARAMETERS`, donc ignorés ; test `test_cli.py::test_show_logging_and_usd_parameters` |
| ARCH-9.2-19 | DEF | 0x0013 MTU de l'interface SP, octets, défaut 1412 | done | `Node.start_sp`, `SpEngine.mtu` |
| ARCH-9.2-20 | DEF | 0x0014 nombre d'électeurs Nv, défaut 5 | done | `Node._maintenance_loop` |
| ARCH-9.2-21 | DEF | 0x0015 délai de retrait d'un électeur inactif, s, défaut 600 | done | `Node._maintenance_loop` |
| ARCH-9.2-22 | DEF | Un nœud qui reçoit un code inconnu l'ignore | done | `signed.check_ranges` (codes inconnus ignorés), `parameter` ne lit que les codes connus |
| ARCH-9.2-23 | DEVRAIT | Valeur hors plage : conserver les propriétés en vigueur et DEVRAIT le signaler à l'administrateur | done | `SignedConfig.offer_usd` lève avant d'appliquer ; `handlers._on_send_usd_properties` journalise « USD properties refused » (`show node events`) ; plages propres à l'implémentation (`USD_PARAMETERS`) |
| ARCH-9.2-24 | DEF | Contrôle de santé de chaque service tous les 0x000C ; après 3 échecs consécutifs, état 0x3303 et demande urgente | done | `Node._health_loop` |

#### 9.3 Versions et propagation

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-9.3-1 | DEF | Version d'un objet = date en ms depuis l'époque Unix de sa dernière modification par l'autorité | done | `AuthorityBridge.settle` (`max(now_ms(), dernière + 1)`) ; test `test_cli.py::test_authority_commit_signs_and_others_refuse` (pas de nouvelle version sans changement) |
| ARCH-9.3-2 | DEF | Chaque nœud transmet périodiquement ses objets à ses nœuds de référence [NCP 6.8] | done | `Node._properties_loop` |
| ARCH-9.3-3 | DEF | Un objet n'est appliqué que si la signature de l'autorité est valide et sa version strictement postérieure | done | `SignedConfig.offer_*` ; test `test_node_integration.py` |
| ARCH-9.3-4 | DEF | L'autorité injecte une modification en l'adressant à un nœud quelconque | done | Poste autorité = nœud USMD-RDSH : `Node.inject` puis `push_properties` vers ses références |
| ARCH-9.3-5 | DEF | Propagation à tout l'USD en un nombre de périodes borné par le diamètre du graphe des nœuds de référence | done | Relais immédiat sur changement (`handlers._relay_properties`) + envoi périodique ; pas de test multi-sauts |

#### 9.4 Partition

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-9.4-1 | DEF | Chaque partie continue de fonctionner : 0x3200/0x3400 aux nœuds de l'autre partie et reprise de leurs services | done | 0x3400 (`_on_neighbor_inactive`) et reprise des services du nœud muet par une de ses références (`take_over`) ; 0x3200 et reprise après une délégation non confirmée (`_delegation_deadline`) ; pas de test multi-nœuds |
| ARCH-9.4-2 | DEF | Aucune partie ne peut modifier la configuration (réservée à l'autorité) | done | Seuls les objets signés par la clé USC s'appliquent (`SignedConfig.offer_*`, `AuthorityBridge.settle`) |
| ARCH-9.4-3 | DEF | À la reconnexion, cicatrisation (7.6) puis règle 8.6 rétablissent les bornes ; réconciliation des données à la charge du service | done | `Node._healing_loop` → `enforce_instance_bounds` |

### 10. En-tête de trame commun et versions

#### 10.1 En-tête de trame

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-10.1-1 | DEF | Toute trame NNDP, NCP et SP commence par un en-tête de 9 octets : Magic(16) Version(8) Événement(16) Longueur(32) | done | `wire.HEADER` (`!HBHI`, 9 octets), `wire.frame` ; la datagramme NNDP encapsule la trame derrière clé et signature, comme le prévoit [NNDP-01 5.2] (`nndp.HereIAm.sign`) |
| ARCH-10.1-2 | DEF | Entiers codés en ordre réseau | done | `wire.HEADER`, `Writer/Reader` (big-endian) |
| ARCH-10.1-3 | DEF | Magic = 0xD5C1 ; une trame ne commençant pas par cette valeur est rejetée | done | `wire.FrameHeader.decode` |
| ARCH-10.1-4 | DEF | Version = version majeure du protocole, 1 pour tous les brouillons actuels | done | `wire.VERSION = 1`, version ≠ 1 rejetée par `FrameHeader.decode` |
| ARCH-10.1-5 | DEF | Événement = type de trame interprété dans le registre propre à chaque protocole | done | `nndp.EVENT_HIA`, `codec.Command`, `sp/handshake.EVENT_*` |
| ARCH-10.1-6 | DEF | Longueur = nombre d'**octets** qui suivent l'en-tête | done | `wire.frame`, `FrameHeader.decode(expect_exact=True)`, `transport.seal_message` ; test `test_nndp01.py::test_empty_hia_is_187_bytes_and_full_is_1155` |
| ARCH-10.1-7 | DEF | Le protocole d'une trame est déterminé par le port de réception, non par l'en-tête | done | Une socket par protocole (`NndpService.start`, `Node._start_ncp`, `Node.start_sp`) |

#### 10.2 Numérotation des versions

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-10.2-1 | DEF | Version notée en 4 composantes majeure.fonctionnelle.correctif-sécurité.correctif | done | `show version` à 4 composantes (`show_system._version`) ; `pyproject.toml` déclare `0.0.1.0` |
| ARCH-10.2-2 | DEF | Majeure : retrait/modification incompatible ou changement du format des trames ; les trois autres remises à 0 | n/a | Règle de processus de publication |
| ARCH-10.2-3 | DEF | Fonctionnelle : ajout compatible ; 3e : correction de vulnérabilité ; 4e : correction d'anomalie | n/a | Règle de processus de publication |
| ARCH-10.2-4 | DEF | Seule la composante majeure figure dans le champ Version de l'en-tête | done | `wire.VERSION` (8 bits) |
| ARCH-10.2-5 | DOIT | Les versions de même majeure DOIVENT interopérer : un événement inconnu est ignoré, ou en NCP provoque une réponse d'erreur | done | NNDP : `check_datagram` rejette sans réponse ; SP : `SpEngine.from_udp` ignore ; NCP : `handlers.handle_request` répond 0x0003 « unknown command » |

### 11. Services, aires et adresses SP

#### 11.1 Catalogue des services

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-11.1-1 | DEF | Le catalogue fait partie des propriétés de l'USD | done | `UsdProperties.catalog` |
| ARCH-11.1-2 | DEF | Identifiant : 12 bits, unique dans l'USD, noté en 3 chiffres hexadécimaux minuscules ; 0x000 et 0xFFF réservés ; services de 0x001 à 0xFFE | done | `UsdProperties.validate`, `ServiceConfig._service_id`, `ServiceView.apply` ; test `test_cli.py::test_service_id_reserved_values_are_refused` |
| ARCH-11.1-3 | DEF | Nom : chaîne UTF-8 unique dans l'USD, reprise par la clé `name` du fichier de service | done | Unicité dans `UsdProperties.validate` ; `bridge._service_file` choisit le document dont `name` correspond ; le nœud refuse un nom hors catalogue (`Node.uncatalogued`) |
| ARCH-11.1-4 | DEF | Aire : identifiant de l'aire à laquelle le service appartient | done | `CatalogEntry.area_id` (8 bits), existence vérifiée par `UsdProperties.validate` |
| ARCH-11.1-5 | DEF | VIP : adresse IPv4 du service dans le préfixe de son aire | done | `UsdProperties.validate` (VIP hors aire refusée) |
| ARCH-11.1-6 | DEF | Adresse de groupe : IPv4 facultative dans 239.0.0.0/8 | done | `UsdProperties.validate`, `ServiceConfig._coherent` |
| ARCH-11.1-7 | DEF | Catalogue signé par l'autorité avec les autres propriétés de l'USD | done | `UsdProperties.sign/verify` ; test `test_cli.py::test_authority_commit_signs_and_others_refuse` |
| ARCH-11.1-8 | DEF | Seuls les services du catalogue peuvent être hébergés | done | Refusé à la signature (`bridge._check_mutation`) et avant tout build (`Node.transmute` / `uncatalogued`) ; `Node._host` n'annonce qu'un service du catalogue ; test `test_authority_services.py::test_mutation_service_outside_catalogue_refused` |
| ARCH-11.1-9 | DEVRAIT | L'identifiant d'un service retiré NE DEVRAIT PAS être réattribué avant l'expiration de toutes les entrées qui le mentionnent (11.5) | done | `AuthorityBridge.settle` → `_check_service_ids` (pas de réattribution directe ni de réutilisation avant `SERVICE_ID_QUARANTINE_MS` = 1 h), retraits mémorisés dans `authority/retired.json` (`Authority.retire_service/reuse_allowed`) ; tests `test_authority_services.py::test_retired_service_id_waits_an_hour`, `test_retired_service_id_not_reused_at_once` |

#### 11.2 Aires de service

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-11.2-1 | DEF | Un USD contient une ou plusieurs aires | done | `UsdProperties.validate` exige au moins une aire ; test `test_authority_services.py::test_usd_needs_an_area_and_mask_8_to_32` |
| ARCH-11.2-2 | DEF | Chaque aire porte un WVNN | done | Plan d'adressage porté par SP : routes des aires du nœud sur l'interface SP (`Node.sp_routes`, `sp/tun.py`) |
| ARCH-11.2-3 | DEF | Identifiant 8 bits unique dans l'USD, et un nom | done | `codec.Area`, `UsdProperties.validate`, `ServiceAreaView.apply` |
| ARCH-11.2-4 | DEF | Préfixe IPv4 : adresse + longueur de masque | done | `codec.Area.prefix/length` (8 à 32 au décodage, à la validation et dans la CLI `ServiceAreaConfig`) ; tests `test_authority_services.py::test_usd_needs_an_area_and_mask_8_to_32`, `test_cli_prefix_length_matches_the_wire` |
| ARCH-11.2-5 | DEF | Toutes les adresses du préfixe sont utilisables, y compris hôte tout-0 et tout-1 | done | Aucune adresse exclue (`UsdProperties.validate`, `SpEngine`) |
| ARCH-11.2-6 | DOIT | Préfixes des aires d'un USD DOIVENT être disjoints entre eux | done | `UsdProperties.validate`, `ServiceAreaView.apply` ; test `test_cli.py::test_service_catalogue_checks_areas` |
| ARCH-11.2-7 | DOIT | Préfixes DOIVENT être disjoints des adresses que les nœuds utilisent pour communiquer [SP 4.1] | done | Refus de signer une aire contenant une adresse de nœud connue (`bridge._check_node_addresses`) ; le nœud n'installe pas la route d'une aire qui contient une adresse de la NIT ou chevauche une route système (`Node.sp_routes` / `prefix_conflict`) ; test `test_authority_services.py::test_area_containing_a_node_address_refused` |
| ARCH-11.2-8 | DEF | Chaque service appartient à une seule aire | done | `CatalogEntry.area_id` unique |
| ARCH-11.2-9 | DEF | Les services d'une aire ne peuvent joindre ceux d'une autre : SP ignore tout paquet dont source et destination sont dans des aires différentes [SP 5] | done | `SpEngine.from_tun`, `SpEngine._deliver` ; test `test_sp01_engine.py::test_area_isolation_and_unknown_destination_are_dropped` |
| ARCH-11.2-10 | DEF | Un nœud appartient aux aires des services de sa mutation ; sans mutation, à aucune aire | done | `SignedConfig.areas_of_mutation`, `Node.my_areas` |

#### 11.3 Adresse SP

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-11.3-1 | DEF | Adresse SP = identifiant de service (12 bits) + identifiant de gestion (16 bits), notée `sss.nnnn` en hexadécimal minuscule | done | `addresses.to_text/from_text` ; test `test_nndp01.py::test_sp_address_text_form` |
| ARCH-11.3-2 | DEF | Codage réseau sur 32 bits : 4 bits réservés à 0, identifiant 12 bits, gestion 16 bits ; 0a1.5d68 → 0x00A15D68 | done | `addresses.pack/unpack` ; même test |
| ARCH-11.3-3 | DEF | Gestion 0x0000 = instance quelconque la plus proche (VIP) ; 0x0001–0xFFFE = nœud attribué par le maître ; 0xFFFF = toutes les instances (adresse de groupe) | done | `addresses.ANY_INSTANCE/ALL_INSTANCES`, `raft.StateMachine.free_id` (1–0xFFFE), `SpEngine._broadcast` |
| ARCH-11.3-4 | DEF | Une adresse `sss.0000` ne circule jamais dans une trame ; l'émetteur la résout avant l'envoi [SP 6] | done | `SpEngine.from_tun` → `select` (adresse d'instance) ; test `test_sp01_engine.py::test_unicast_through_a_handshake_and_reply_affinity` |

#### 11.4 Identifiants de gestion

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-11.4-1 | DEF | Tout nœud appartenant à des aires obtient du maître un identifiant de gestion pour chaque service de chacune de ses aires, hébergé ou non, par Request_management_id [NCP 6.15] | done | `Node.request_management_ids` (`my_area_services`) ; test `test_node_integration.py` |
| ARCH-11.4-2 | DEF | Identifiant unique pour un service donné ; la même valeur peut servir pour des services différents | done | `raft.StateMachine.free_id` (par service) |
| ARCH-11.4-3 | DEF | Attribution durable : survit aux transmutations, libérée seulement par le maître au retrait du nœud | done | `Node.management` persistée, jamais effacée par `transmute` ; libération au retrait = ARCH-B-2 |
| ARCH-11.4-4 | DEF | Le nœud publie ses adresses SP dans sa fiche de nœud [NCP 7.8] | done | `Node.publish_record` (`sp_addresses`) |
| ARCH-11.4-5 | DEF | Le journal répliqué du maître tient la table qui fait foi : adresse SP → nœud + clé Ed25519 | done | `raft.StateMachine.assignments` (`Assignment.node_id`, `key`) |
| ARCH-11.4-6 | DOIT | Un nœud DOIT obtenir ses identifiants de gestion avant de construire un service d'une aire nouvelle pour lui | done | `Node.transmute` appelle `request_management_ids` et refuse tout build s'il manque un identifiant pour un service de ses aires (puis 0x3303 + urgence) |
| ARCH-11.4-7 | DEF | Un nœud peut reprendre une instance d'un autre service de son aire sans nouvelle attribution, même maître injoignable | done | Identifiants obtenus pour tous les services des aires ; `transmute` ne redemande que les manquants |

#### 11.5 Services hébergés et services les plus proches

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-11.5-1 | DEF | Les HIA portent la liste des services hébergés : adresses SP des instances exécutées dont le dernier contrôle de santé a réussi [NNDP 5.4] | done | `NndpHooks.hosted` ← `Node.hosted` (ajout après check_health réussi, retrait sur échec : `_host`/`_withdraw`) |
| ARCH-11.5-2 | DEF | Les HIA portent le vecteur de services : pour chaque service des aires de l'émetteur, adresse SP de l'instance la plus proche connue, distance, nombre de sauts | done | `nndp.NearestServices.vector`, `HereIAm.vector` |
| ARCH-11.5-3 | DEF | HIA émis en diffusion sur le segment et en unicast vers les nœuds de référence | done | `NndpService.emit` |
| ARCH-11.5-4 | DEF | Distance D en millièmes, 0 à 65 534 ; 65 535 = inaccessible | done | `nndp.UNREACHABLE`, `NearestServices.receive/withdraw_local` |
| ARCH-11.5-5 | DEF | À la source : D = charge de référence du nœud hôte en ‰ | done | `NearestServices.set_local(..., load.reference)` (`Node._load_loop`, `_host`) ; test `test_nndp01.py::test_local_instance_and_withdrawal` |
| ARCH-11.5-6 | DEF | À réception d'une entrée annoncée par X : D' = D + 1000 × t / T (plafonnée à 65 535), sauts' = sauts + 1 ; t = RTT vers X, ou T si inconnu ; T = paramètre 0x0002 | done | `NearestServices.receive` ; test `test_nndp01.py::test_vector_distance_hops_poisoning_and_expiry` |
| ARCH-11.5-7 | DOIT | Chaque nœud DOIT tenir, pour chaque service de ses aires, les K (0x000A, 3) instances de plus faible distance, et annoncer la meilleure dans ses HIA | done | `NearestServices._trim`, `best`, `vector` ; même test |
| ARCH-11.5-8 | DEF | Règles d'acceptation, d'expiration et de limitation des boucles selon [NNDP 6.5] | done | `NearestServices.receive/expire/forget` (15 sauts, 3 × I, retour empoisonné) ; même test |
| ARCH-11.5-9 | DEF | La table sert au choix de la destination SP [SP 6] et au contrôle des dépendances (8.4) | done | `_NodeSpContext.nearest` → `SpEngine.select` ; `Node._dependency_loop` |
| ARCH-11.5-10 | DEF | Distance de service distincte de la distance entre nœuds de la section 6 | done | `nndp.NearestServices` (D en ‰) vs `distance.distance` (d ∈ [0,5]) |

#### 11.6 Identifiants de données des services (ARCH-03)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-11.6-1 | DEF | UUID de version 8 [RFC 9562] : adresse SP (32 bits) \| horodatage ms 48 bits réparti autour de la version et de la variante \| séquence 16 bits \| aléa 26 bits ; le texte commence par l'adresse SP (00b20003-…) | done | `dataid.encode/decode` ; test `test_data_ids.py::test_identifier_starts_with_the_sp_address_and_is_a_version_8_uuid` |
| ARCH-11.6-2 | DEF | L'ordre des octets range par instance puis par date de création | done | test `test_data_ids.py::test_order_is_instance_then_time` |
| ARCH-11.6-3 | DOIT | Adresse SP attribuée à l'instance, identifiant de gestion 0x0001 à 0xFFFE ; sss.0000 et sss.ffff interdits | done | `dataid.check_address` ; test `test_only_instance_addresses_make_identifiers` |
| ARCH-11.6-4 | DOIT | L'horodatage d'un générateur NE DOIT PAS décroître, même si l'horloge recule | done | `DataIdGenerator.next` ; test `test_generator_never_goes_back_and_carries_over_the_sequence` |
| ARCH-11.6-5 | DEF | Séquence +1 dans la même milliseconde, repart d'une valeur aléatoire 0..0x7FFF à chaque nouvelle milliseconde, passage à la milliseconde suivante au-delà de 0xFFFF | done | Même test ; `test_generator_identifiers_are_unique_and_sorted` (50 000 identifiants) |
| ARCH-11.6-6 | DOIT | Aléa d'un générateur cryptographique ou à graine non partagée entre processus | done | `secrets.randbits` ; SQL : `random()` de chaque processus serveur PostgreSQL |
| ARCH-11.6-7 | DEVRAIT | Plusieurs processus d'une instance DEVRAIENT partager la séquence | done | SQL : séquence `usmd_id_seq` (0..65535, CYCLE) ; vérifié sur PostgreSQL 17 (20 000 identifiants uniques, décodage SQL = Python) |
| ARCH-11.6-8 | DEF | Tout nœud retrouve instance et date ; version ≠ 8, variante ≠ 0b10 ou 4 premiers bits non nuls → pas un identifiant USMD-RDSH | done | `dataid.decode`, `show data-id id=<uuid>` ; tests `test_other_uuids_are_not_data_identifiers`, `test_cli.py::test_data_id_commands` |
| ARCH-11.6-9 | DEVRAIT | Le maître DEVRAIT réattribuer en dernier les identifiants de gestion libérés | open | Aucune libération n'existe encore (ARCH-B-2) ; voir ARCH-B-10 |
| ARCH-11.6-10 | PEUT | Le nœud PEUT fournir le texte SQL et un générateur équivalent | done | `show data-id postgresql [service=…] [database=…]` (`usmd_id()`, `usmd_id_sp_address()`, `usmd_id_created()`), `execute data-id generate service=… count=…` |

### 12. Maître USD

#### 12.1 Rôle

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-12.1-1 | DEF | Le maître attribue les identifiants de gestion et tient la table des adresses SP | done | `Node.allocate_management_ids`, `show usd assignments` ; test `test_node_integration.py` |
| ARCH-12.1-2 | DEF | Le maître est le leader Raft élu parmi les électeurs ; la table des adresses SP est l'état du journal répliqué | done | `raft.Raft`, `raft.StateMachine` |
| ARCH-12.1-3 | DEF | Une attribution n'est confirmée au demandeur qu'une fois inscrite dans le journal d'une majorité d'électeurs | done | `Node.allocate_management_ids` propose les enregistrements (`assign_record`) et ne répond qu'après `Raft.propose` (commit), sinon statut 0x02 ; l'état n'est modifié qu'à l'application ; identifiants en attente réservés par `Raft.free_id_for` ; tests `test_ncp02_transport.py::test_raft_propose_commits_everywhere`, `test_reserved_ids_include_uncommitted_assignments` |
| ARCH-12.1-4 | DEF | L'indisponibilité du maître n'empêche que les nouvelles attributions (SP, découverte, délégation, transmutations continuent) | done | SP, NNDP, délégation et `transmute` ne dépendent pas de Raft |

#### 12.2 Électeurs et élection

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-12.2-1 | DEF | Au plus Nv électeurs (0x0014, défaut 5) | done | `Node._maintenance_loop` |
| ARCH-12.2-2 | DEF | L'ensemble des électeurs est inscrit dans le journal répliqué | done | `raft.voter_record` (ADD/REMOVE_VOTER), `Raft.voters` |
| ARCH-12.2-3 | DEF | Le premier nœud, créé avec un jeton « fondateur » [NCP 7.7], initialise le journal et en est l'unique électeur | done | `Node.found` → `Raft.found` ; test `test_node_integration.py` |
| ARCH-12.2-4 | DEF | Tant que l'ensemble compte moins de Nv électeurs, le maître ajoute un nœud actif de rôle Node_executor, le plus ancien (plus petit identifiant) | done | `Node._maintenance_loop` (`sorted(active_nodes())`, `Nal.allows(key, NODE_EXECUTOR)`, donc tout rôle qui inclut celui d'exécutant) |
| ARCH-12.2-5 | DEF | Le maître retire un électeur non « Actif » depuis plus de 0x0015 (600 s) | done | `Node._maintenance_loop` |
| ARCH-12.2-6 | DEF | Modifications de l'ensemble un électeur à la fois (changement d'un seul serveur, Raft) | done | `Raft.propose` / `_config_pending` |
| ARCH-12.2-7 | DEF | Élection, réplication, instantanés par Raft_request_vote, Raft_append_entries, Raft_install_snapshot [NCP 6.16–6.18] | done | `Raft.elect/_ballot/handle_vote`, `replicate/handle_append`, `_send_snapshot/handle_snapshot` (instantanés paginés) ; `handlers._on_raft_*` ; compaction automatique (`COMPACT_AFTER`) ; tests `test_ncp02_transport.py::test_raft_election_after_leader_loss`, `test_raft_snapshot_installed_in_several_pages`, `test_raft_automatic_compaction` |
| ARCH-12.2-8 | DOIT | Chaque électeur DOIT conserver sur support persistant son terme courant, son vote et son journal | done | `Raft._save/_load` (`raft.json`, remplacement atomique) |
| ARCH-12.2-9 | DEF | Un nœud apprend le maître et les électeurs par la réponse à Request_management_id ; un électeur non maître redirige vers le maître connu | done | `Node.allocate_management_ids` (statut 0x01 + maître), `Node.request_management_ids` (`known_voters`, suivi du maître) |

#### 12.3 Partition

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-12.3-1 | DEF | Seule une partie contenant une majorité des électeurs peut élire un maître et attribuer des identifiants | done | `Raft.quorum`, `_ballot`, `_advance_commit` |
| ARCH-12.3-2 | DEF | Deux maîtres ne peuvent attribuer la même adresse SP à deux nœuds | done | Confirmation seulement après commit majoritaire (`Raft.propose`) |
| ARCH-12.3-3 | DEF | Les autres parties fonctionnent avec les adresses déjà attribuées et ne peuvent intégrer un nœud dans une aire nouvelle avant la reconnexion | done | Pas d'attribution sans majorité (`Raft.propose`) et pas de build d'une aire nouvelle sans identifiant (`Node.transmute`, voir 11.4-6) |

### 13. Considérations opérationnelles

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-13-1 | DEF | Tâche admin : écrire les fichiers de service et les faire signer par l'autorité | done | `config service set service-file` → `bridge._service_file` → `MutationProperties` signé |
| ARCH-13-2 | DEF | Tâche admin : créer les nœuds, faire signer leur jeton, fournir rôle, ancres, nœud de contact et EDB facultatifs | done | `execute authority token create`, `config system bootstrap`, `config system trust-anchor` |
| ARCH-13-3 | DEF | Tâche admin : modifier les propriétés de l'USC et des USD | done | `config usc` / `config usd` sur le nœud autorité (`AuthorityBridge.settle`) |
| ARCH-13-4 | DOIT | L'exploitant DOIT synchroniser les horloges des nœuds | n/a | Exploitation (aucun indicateur de synchronisation dans `show clock`) |
| ARCH-13-5 | DOIT | L'exploitant DOIT déclarer les services au catalogue et choisir pour chaque aire un préfixe disjoint des autres aires et des adresses des nœuds | n/a | Exploitation ; l'outil contrôle la disjonction entre aires et avec les adresses des nœuds connues (voir 11.2-7) |
| ARCH-13-6 | DOIT | L'exploitant DOIT autoriser les flux UDP NNDP (diffusion, 5221 → 5222), NCP (9992) et SP (port de l'USD) | n/a | Exploitation ; ports affichés par `show nndp`, `show ncp statistics`, `show sp` |
| ARCH-13-7 | DOIT | L'exploitant DOIT maintenir l'EDB à jour lorsqu'elle est utilisée | n/a | Exploitation ; voir ARCH-B-9 |

### 14. Considérations de sécurité

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-14-1 | DOIT | La clé privée de l'USC DOIT être conservée hors ligne ou en HSM et n'être utilisée que pour signer | done | Signature possible sur une machine hors ligne puis transport des objets signés (`authority.export_signed/import_signed`, `execute properties export/import`) ; la clé n'est utilisée que pour signer et n'est jamais transmise ; pas de HSM (fichier `authority/usc.key`, protection laissée à l'exploitant) ; test `test_authority_services.py::test_export_import_round_trip` |
| ARCH-14-2 | DEF | Le remplacement de la clé de l'USC exige de recréer les ancres de tous les nœuds | done | Ancre par nœud (`config system trust-anchor usc-public-key`), `Node.usc_key` |
| ARCH-14-3 | DOIT | Un nœud NE DOIT exécuter que des fichiers dont la signature d'autorité est valide | done | Voir 8.3-11 (`Node.mutation_specs` vérifie la signature avant chaque exécution) |
| ARCH-14-4 | DEVRAIT | Exécuter les commandes avec les privilèges minimaux nécessaires | done | `ServiceRunner.run_as` (paramètre `user` de `create_subprocess_shell`, POSIX), réglé par `config system service-host run-as` (`cli/views/system.py`) ; sans réglage, ou sous Windows, les commandes gardent les privilèges du nœud |
| ARCH-14-5 | DOIT | La clé privée de l'USD DOIT être protégée comme celle de l'USC | done | Comme 14-1 : jetons signés sur le poste qui détient `authority/usd.key`, éventuellement hors ligne, puis remis en base64url ; pas de HSM |
| ARCH-14-6 | DEVRAIT | Les paquets d'endossement DEVRAIENT avoir une validité limitée (0x000D) | done | `handlers._on_request_approval` (expiration), `Node.verify_endorsement_of` (refus d'un paquet expiré) |
| ARCH-14-7 | DEF | Chaque entrée de la table des nœuds est signée par le nœud décrit et rattachée à la clé de l'USD ; un relais ne peut falsifier identité ou adresse | done | `TableEntry.verify`, `Node.accept_entry` |
| ARCH-14-8 | DEVRAIT | L'état réel d'un nœud DEVRAIT être confirmé (Get_status ou HIA récent) avant toute délégation [NCP 7.9] | done | Délégation seulement à un nœud dont la réponse NCP signée est favorable (`_ask`), ce qui suppose son état Actif (`handlers._can_take`) |
| ARCH-14-9 | DEVRAIT | Limiter le nombre de demandes d'aide et d'urgence acceptées d'un même pair par unité de temps | done | `handlers._request_rate_ok` : au plus 3 Request_help/Request_emergency par pair et par 10 s, au-delà erreur 0x0004 (`BUSY`) ; pas de test |
| ARCH-14-10 | DEF | L'administrateur peut retirer la clé d'un nœud compromis des NAL | done | `execute nal revoke` (`cli/actions/security.py`) : retrait de l'ancre et des rôles (`Nal.revoke`), exclusion permanente (les rôles ne sont plus réaccordés par `_learn_entry`), retrait de `config trust nal` ; `bridge._apply_nal` révoque aussi une entrée supprimée de la table ; pas de test |
| ARCH-14-11 | DEF | Seuils, hystérésis (6.4) et bornes d'instances limitent l'instabilité | done | `Node.check_weakness`, `distance.reselect`, `handlers._can_take` / `enforce_instance_bounds` |
| ARCH-14-12 | DEVRAIT | Un nœud constatant que deux fiches revendiquent la même adresse SP DEVRAIT interroger un autre électeur avant de retenir l'une d'elles | partial | `_NodeSpContext.owner` détecte deux fiches revendiquant la même adresse ; un électeur tranche avec la table répliquée, un autre nœud n'utilise pas l'adresse (avertissement) au lieu d'interroger un électeur : commande non définie (ARCH-B-3) |
| ARCH-14-13 | DEF | SP n'établit de session qu'avec le nœud auquel l'adresse SP est attribuée dans sa fiche signée, et ce nœud doit annoncer le service dans sa liste des services hébergés [SP 6.1] | done | `SpEngine._eligible` (`owner` d'après les fiches, `hia_hosted`) ; test `test_sp01_engine.py::test_abandoned_handshake_makes_peer_ineligible` |
| ARCH-14-14 | DEF | Isolation des aires appliquée par SP à l'émission et à la réception | done | `SpEngine.from_tun`, `_deliver` ; test `test_sp01_engine.py::test_area_isolation_and_unknown_destination_are_dropped` |
| ARCH-14-15 | DEF | Une partition provoquée ne permet pas de modifier la configuration | done | Voir ARCH-9.4-2 |
| ARCH-14-16 | DEVRAIT | La source de temps DEVRAIT être authentifiée (ex. NTS, RFC 8915) | n/a | Exploitation |

### 15. Considérations IANA

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-15-1 | DEF | Registre « États de nœud USMD » (16 bits) initialisé par la table 5.5 ; familles 0x5 à 0xF réservées | done | `states.State` ; un code non enregistré est refusé (`State(...)` → ValueError dans `Node.accept_entry`, `handlers._on_declare_state`) |
| ARCH-15-2 | DEF | Registre « Paramètres d'USD » (16 bits) initialisé par 9.2 ; 0x0000 réservé ; 0x0016–0x7FFF spécification requise ; 0x8000–0xFFFF expérimental | done | `signed.USD_PARAMETERS` (0x0001–0x0015) ; les autres codes sont ignorés (`check_ranges`) |
| ARCH-15-3 | DEF | Registre « Clés du fichier de service USMD » initialisé par 8.3 | done | `services.KNOWN_KEYS` / `SEQUENCES` |
| ARCH-15-4 | DEF | Identifiants de service, d'aire et de gestion propres à chaque USD, sans registre | done | Portés par `UsdProperties` et le journal Raft de l'USD |
| ARCH-15-5 | DEF | Magic 0xD5C1 fixé par ce document | done | `wire.MAGIC` |

### Annexe A. Exemple de fichier de service (cas de recette)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-A-1 | DEF | Aire « prod », identifiant 0x01, préfixe 192.168.1.0/24 configurable | done | `config service-area` → `codec.Area(1, "prod", "192.168.1.0", 24)` |
| ARCH-A-2 | DEF | Catalogue : 0a1 web 192.168.1.10 sans groupe ; 0a2 backend 192.168.1.11 ; 0b2 db 192.168.1.20 groupe 239.1.0.20 ; `show service catalog` sans anomalie | done | Représentable et validé (`UsdProperties.validate`, `catalog_rows`) ; test analogue `test_cli.py::test_authority_commit_signs_and_others_refuse` |
| ARCH-A-3 | DEF | Nœud d'identifiant de gestion 0x5d68 pour web → adresse SP 0a1.5d68 | done | `addresses.to_text(0x00A15D68)` ; test `test_nndp01.py::test_sp_address_text_form` |
| ARCH-A-4 | DEF | Requête vers la VIP 192.168.1.20 → 0b2.0000, résolue vers l'instance de db la plus proche | done | `SpEngine.from_tun` / `select` ; test `test_sp01_engine.py::test_unicast_through_a_handshake_and_reply_affinity` |
| ARCH-A-5 | DEF | Requête vers 239.1.0.20 → 0b2.ffff, toutes les instances de db | done | `SpEngine._broadcast` ; test `test_sp01_engine.py::test_broadcast_reaches_mutation_members_once` |
| ARCH-A-6 | DEF | Le fichier de la mutation « frontal » (name, type, dependencies, build, unbuild, emergency avec `action: unbuild`, check_health avec `timeout: 5`, update) est analysé et accepté | done | `services.parse_service_file` ; test `test_node_integration.py` (`SERVICE_FILE` avec `action: unbuild`, `timeout: 5`) |
| ARCH-A-7 | DEF | Exécution : `emergency` copie puis enchaîne `unbuild` ; `check_health` échoue si `curl` dépasse 5 s ou sort ≠ 0 | done | `ServiceRunner.run` (action), `_command` (délai, code de sortie) ; pas de test de l'échec |

### Annexe B. Points ouverts (suivi)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| ARCH-B-1 | DEF | Retrait définitif d'un nœud de la table (fiche de retrait signée ou révocation par l'opérateur de l'USD) | open | À définir dans NCP ; `NodeTable` ne supprime jamais une entrée |
| ARCH-B-2 | DEF | Libération des identifiants de gestion d'un nœud retiré par le maître | open | Dépend de B-1 ; `raft.release_record` existe mais n'est jamais utilisé |
| ARCH-B-3 | DEF | Conflit d'adresses SP : commande d'interrogation d'un électeur ou attestation signée d'attribution | open | Voir ARCH-14-12 |
| ARCH-B-4 | DEF | Taille du vecteur de services : HIA ≤ 1200 octets ; plus de 120 services → plusieurs HIA par intervalle [NNDP 5.4] | open | Implémenté par `NndpService.build` (découpage par 120) ; tests `test_nndp01.py::test_empty_hia_is_187_bytes_and_full_is_1155`, `test_more_than_120_entries_are_split_and_lists_bounded` |
| ARCH-B-5 | DEF | Révocation d'un jeton de création avant expiration (liste de révocation dans les propriétés de l'USD envisagée) | open | — |
| ARCH-B-6 | DEF | Transmutation sur décision de l'administrateur : aucune commande NCP | open | Commande locale `execute node transmute` seulement |
| ARCH-B-7 | DEF | Reprise sans confirmation (7.5) : règle de départage entre nœuds de récupération concurrents | open | `_delegation_deadline` fait reprendre chaque nœud favorable, sans départage (borne max seule limite) |
| ARCH-B-8 | DEF | Borne minimale : qui déclenche la création d'instances sous la borne min | open | `min_instances` utilisé seulement par `Node.take_over` (reprise d'un nœud muet tant que le nombre d'instances est sous max(min, 1)) ; aucune création d'instance hors de ce cas |
| ARCH-B-9 | DEF | Maintien de l'EDB (par l'administrateur ou par les nœuds) | open | — |
| ARCH-B-10 | DEF | Réattribution d'un identifiant de gestion libéré : délai minimal ou horodatage minimal imposé au nouveau titulaire, pour que ses identifiants de données ne rencontrent pas ceux de l'ancien (ARCH-03) | open | Dépend de ARCH-B-2 |

---

# Partie 2 — NCP

## Cahier de recette NCP — draft-usmd-ncp-02

Source : `draft-usmd-ncp-02.txt` (22 octobre 2026). Code examiné : `src/usmd_rdsh/node/**` (nouvelle implémentation : `ncp/codec.py`, `ncp/transport.py`, `handlers.py`, `node.py`, `raft.py`, `tables.py`, `signed.py`, `authority.py`, `identity.py`, `wire.py`, `crypto.py`, `states.py`, `addresses.py`), `src/usmd_rdsh/cli/**` et `src/usmd_rdsh/web/**` (branche `feature/cli-web-interface`, fichiers non suivis inclus). L'ancien prototype (`proto/`, `self/`, `sys/`, `security/`) est remplacé et n'est plus utilisé par l'application ; il n'est plus audité.

Légende des niveaux : **DOIT** (DOIT, NE DOIT PAS, OBLIGATOIRE), **DEVRAIT** (DEVRAIT, NE DEVRAIT PAS, RECOMMANDÉ), **PEUT** (PEUT, FACULTATIF), **DEF** (définition normative qui implique un comportement ou un format, sans mot-clé BCP 14).

Légende des états : **done** (implémenté et conforme, code lu), **partial** (une partie existe, le manque est précisé), **missing** (rien dans le code), **config-only** (paramètre ou registre visible/configurable dans la CLI ou le web, sans comportement protocolaire derrière), **open** (ambiguïté ou point ouvert du draft), **n/a** (IANA ou hypothèse opérationnelle).

Tests (80 passent, `pdm run pytest -q tests`) :

- `tests/test_node_integration.py::test_founder_admission_sync_and_master` (deux nœuds sur 127.0.0.2/127.0.0.3, liés à leur adresse, NNDP désactivé) : fondation, Request_approval, paquet d'endossement, synchronisation (Send_node_table complet puis USC/USD/mutations), Inform_reference_node, Check_distance_to_node, relais en incrément, Get_status, transmutation avec Request_management_id et Raft (un seul électeur), refus d'un objet USD mal signé. Désigné ci-dessous par « test intégration ».
- `tests/test_ncp02_transport.py` : `test_permille_bounds`, `test_rate_limiter_window_and_bound`, `test_single_fragment_request_response`, `test_multi_fragment_request_is_acknowledged` (5 fragments, accusés), `test_duplicate_request_answered_from_cache` (réponse perdue, retransmission, aucune réexécution), `test_stale_response_is_dropped`, `test_unknown_address_refused_except_request_approval`, `test_reply_x25519_hook_answers_unknown_requester`, `test_timeout_schedule_without_extra_doubled_wait` ; Raft à trois électeurs : `test_raft_election_after_leader_loss`, `test_raft_propose_commits_everywhere`, `test_raft_snapshot_installed_in_several_pages`, `test_raft_snapshot_pages_wait_for_all`, `test_raft_automatic_compaction`, `test_raft_on_voter_change`, `test_reserved_ids_include_uncommitted_assignments`. Désignés ci-dessous par leur nom.
- `tests/test_authority_services.py::test_only_one_founder_token_per_usd`.

Restent sans test : les exclusions (7.4, 7.5, 7.6), la vérification d'endossement, le contrôle USDN du jeton, la confrontation des adresses SP au journal, Request_help/emergency, Declare_state, Node.rekey, l'écoute IPv6, les bornes globales de réassemblage et les vecteurs de taille de l'annexe A.

### 0. Constat général sur le code

- **Transport** (`node/ncp/transport.py`, `NcpTransport`, `asyncio.DatagramProtocol`) : UDP, port 9992 (`LocalSettings.ncp_port`), lié à `bind_address` (défaut 0.0.0.0) ; quand `bind_address` vaut 0.0.0.0, `Node._start_ncp` ouvre en plus `[::]:9992` sur **le même objet protocole** (voir 4-2/4-3 : défaut constaté). Enveloppe X25519 éphémère + HKDF-SHA-256 + ChaCha20-Poly1305 (`seal_message`, `parse_fragment`, `_on_fragment`), fragments de 1111 octets au plus, 1024 fragments au plus, réassemblage par (IP source, clé éphémère, sel) en 10 s, bornes de réassemblage (16 par adresse, 256 messages et 16 Mio en tout), accusés de fragments (type 0x03, champ de bits MSB d'abord), retransmission (3 émissions, attentes 2/4/8 s), cache de réponses 60 s indexé par (clé de l'émetteur, identifiant de requête) complété d'un cache de groupes réassemblés (`_completed`, 4096) qui renvoie la réponse à une retransmission sans recalcul X25519. Avant tout calcul : limiteur de débit par adresse (`RateLimiter`, 200 datagrammes/s) ; avant X25519 : refus d'un nouveau groupe venant d'une adresse inconnue (`address_known`), sauf Request_approval limitée à 5/s par adresse. Réponses, erreurs et accusés hors fenêtre de fraîcheur sont abandonnés. Les valeurs de la section 8 propres au transport sont des **constantes** (`MAX_UDP`, `MAX_PLAIN`, `MAX_FRAGMENTS`, `REASSEMBLY_S`, `ACK_DELAY_S`, `RESPONSE_CACHE_S`, `PER_SOURCE`) ; seuls le délai/nombre de retransmissions et la fenêtre de fraîcheur sont pilotés par la configuration.
- **Primitives** (`node/crypto.py`) : uniquement Ed25519 (signature détachée), X25519 (refus du secret nul), HKDF-SHA-256, ChaCha20-Poly1305, via `cryptography`.
- **En-tête** (`node/wire.py`, `FrameHeader`) : magic 0xD5C1, version 1, événement, longueur en **octets** ; `Writer`/`Reader` grand-boutistes avec Booléen strict, Chaîne, Liste, Identifiant ULID vérifié.
- **Codec** (`node/ncp/codec.py`) : `Message` (signature sur la concaténation de 5.6), `CreationToken`, `NodeRecord`, `TableEntry`, `EndorsementPacket`, `UscProperties`, `UsdProperties` (+ `validate`), `MutationProperties`, `LogRecord`, corps génériques (erreur, accusé, accusé de fragments), énumérations `Command` (20), `MessageType`, `ErrorCode` (11), `Role` (4), `RecordType` (5).
- **Serveur** (`node/handlers.py`, `NcpHandlers.handle_request`) : fraîcheur (0x0002), commande inconnue (0x0003), contrôles de 6.1 (`_check_sender` : NIT, couple adresse/clé avec exclusion 0x4000, NAL Node_executor, électeurs, nœuds de référence, exception de l'endosseur), puis les 20 commandes `_on_*`.
- **Client** (`node/node.py`, `Node`) : admission (`request_approval`, `found`), synchronisation (`_synchronise`, `finish_synchronisation`), distances, propagation des propriétés (`push_properties`, `_properties_loop`), table des nœuds (`accept_entry`, `check_token`, `schedule_relay`, `send_table`, `_reconcile_loop`), vérification d'endossement (`verify_endorsement_of`), retrait (`retire`), identifiants de gestion (`request_management_ids`, `allocate_management_ids`), délégation (`request_help`, `emergency`, `delegate_all`).
- **Raft** (`node/raft.py`) : pré-vote, vote, réplication, battement de cœur, enregistrements 0x01..0x05, configuration effective dès l'inscription, une seule modification à la fois, minuteur d'élection retiré après chaque tentative, compaction automatique (`compact_after` = 1000 enregistrements appliqués), instantané paginé (`snapshot_pages`, ≤ 1000 × 1111 octets par page) et accumulé jusqu'à la dernière page (`handle_snapshot`), rappel `on_voter_change`, identifiants réservés non encore validés (`reserved_ids`, `free_id_for`).
- **Tables** (`node/tables.py`) : NIT (clé → adresses avec TTL, X25519), NAL, NEL, table des nœuds (jeton + fiche), exclusions (famille 0x4000, temporaires ou permanentes), endossements vérifiés.
- **Gestion** : `cli/bridge.py` applique `config protocol ncp` (port, retransmission, fraîcheur, intervalles, exclusion, relais, réconciliation, Raft) au nœud ; `max_udp_payload`, `max_fragments`, `reassembly_timeout`, `fragment_ack_delay`, `response_cache` et `reassembly_per_address` restent **sans effet** (constantes du transport) et acceptent des valeurs hors norme. `cli/actions/node_ops.py` : `execute node admission | token install | transmute | retire | help | emergency`, `execute table reconcile`, `execute properties push`, `execute management-id request`, `execute authority keygen | token create` ; `execute node state` émet Declare_state ; `cli/actions/security.py` : `execute node rekey` (`Node.rekey`), `execute nal revoke`, `execute properties export | import` ; `Authority.mint_token` tient le registre des jetons fondateurs (`founders.json`) ; `show ncp [commands|errors|statistics]`, `show nel`, `show node-table`. Une modification d'autorité (USC, USD, aires, catalogue, mutations) est signée et injectée uniquement sur un nœud qui détient la clé USC (`AuthorityBridge.settle`).
- **Ré-audit (après corrections)** : toutes les lignes partial/missing de l'audit précédent ont été relues dans le code. Restent deux défauts introduits ou non couverts par les corrections :
  1. *Écoute IPv6* (`Node._start_ncp`) : le même `NcpTransport` est passé aux deux `create_datagram_endpoint` ; le second `connection_made` remplace `self._transport` par la socket IPv6, par laquelle passent ensuite **tous** les envois. Reproduit sous Windows (Python du projet, script hors projet) : liaison `[::]` réussie (IPV6_V6ONLY vaut 1 par défaut), puis `sendto` vers une adresse IPv4 échoue (`OSError` 10014, remonté à `error_received`) ; NCP n'émet plus rien dès que `bind_address` vaut 0.0.0.0, la valeur par défaut. Sous Linux (double pile), la liaison `[::]:9992` après `0.0.0.0:9992` échoue normalement (EADDRINUSE), l'erreur est avalée et IPv4 reste fonctionnel, sans IPv6. `close()` ne ferme que la dernière socket. Le test intégration lie chaque nœud à 127.0.0.x et ne voit pas le défaut.
  2. *Renouvellement des clés* (`Node.rekey`) : `identity.json` reçoit de nouvelles paires, mais `NcpTransport` (`_signing`, `_static`), `NndpService` et `SpEngine` gardent les objets clés passés à leur construction, et `restart_nndp` ne les remplace pas ; jusqu'au redémarrage du processus, NCP signe avec l'ancienne clé Ed25519 et déchiffre avec l'ancienne X25519 (une Request_approval avec le nouveau jeton serait refusée en 0x0007, clé de l'émetteur ≠ clé du jeton).

---

### 3. Vue d'ensemble du protocole

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-3-1 | DEF | NCP est requête-réponse : le destinataire répond par un message de **même commande** (même champ événement). | done | `NcpTransport._reply` reprend `request.event` ; `request` attend la réponse par (clé destinataire, identifiant). Test intégration. |
| NCP-3-2 | DEF | Tous les messages (requête, réponse, erreur, accusé) sont chiffrés pour le destinataire et signés par l'émetteur. | done | `NcpTransport._build` → `Message.encode` (signature) → `seal_message` (chiffrement) pour les quatre types, accusés de fragments compris (`_send_ack`). |
| NCP-3-3 | DEF | Pour une requête de n > 1 fragments, le destinataire envoie des accusés de fragments avant la réponse. | done | `_on_fragment` → `_schedule_ack` si `assembly.count > 1`, avant `_on_message`. Non testé. |
| NCP-3-4 | DEF | Le destinataire est identifié par sa clé publique Ed25519 (signature) et sa clé publique X25519 (chiffrement), connues par la NIT ou par un HIA [NNDP]. | done | `Node.x25519_of` : NIT, puis X25519 en attente d'admission, puis voisins NNDP ; `Node.call` passe (Ed25519, X25519) à `NcpTransport.request`. |

### 4. Transport

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-4-1 | DEF | NCP s'exécute directement sur UDP [RFC768] ; il n'utilise **ni QUIC ni TCP**. Confidentialité, authentification, fragmentation et retransmission sont assurées par NCP. | done | `Node._start_ncp` : `create_datagram_endpoint` ; tout le reste dans `ncp/transport.py`. Test intégration. |
| NCP-4-2 | DOIT | Un nœud DOIT écouter sur le port **UDP 9992** en IPv4. | done | `node.py:_start_ncp` : une seule extrémité UDP (adresse de liaison, port 9992 par défaut) ; l'écoute IPv6 facultative a été retirée, elle remplaçait le socket d'émission IPv4. Couvert par `tests/test_node_integration.py`. |
| NCP-4-3 | PEUT | Un nœud PEUT écouter en IPv6. | n/a | PEUT non retenu : la série est IPv4 seulement [ARCH 3.5] ; une écoute IPv6 demanderait un second transport distinct. |
| NCP-4-4 | DOIT | La charge UDP d'un fragment NE DOIT PAS dépasser **1200 octets**. | done | Émission : `seal_message` découpe à `MAX_PLAIN = 1111` (9 + 64 + 1111 + 16 = 1200) ; réception : `parse_fragment` rejette > `MAX_UDP`. Le champ CLI `max_udp_payload` (576..65507) est sans effet. |
| NCP-4-5 | DEF | Le port source d'une requête est libre ; les réponses (et accusés) sont renvoyées à l'adresse **et au port source** de la requête. | done | `datagram_received` conserve `(addr[0], addr[1])` ; `_reply`, `_send_ack` et le renvoi du cache utilisent cette adresse. |

### 5. Format des messages

#### 5.1 Ordre des octets

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-5.1-1 | DEF | Tous les entiers sont grand-boutistes (ordre réseau). | done | `wire.Writer`/`Reader` (`struct "!"`), `FrameHeader` (`"!HBHI"`), `struct.pack("!HH")` pour index/nombre. |
| NCP-5.1-2 | DEF | Tous les champs sont alignés sur l'octet. | done | Codec entièrement à l'octet (`Writer`, `Reader`). |

#### 5.2 Structure d'un fragment

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-5.2-1 | DEF | Un fragment = en-tête de trame (9 o) ‖ partie en clair de l'enveloppe (64 o : clé éphémère 32, sel 16, nonce 12, index 2, nombre 2, dans cet ordre) ‖ texte chiffré (≤ 1111 o) ‖ étiquette AEAD (16 o). | done | `seal_message` (construction) et `parse_fragment` (offsets 9/41/57/69/73) conformes à F1. |
| NCP-5.2-2 | DEF | Taille maximale : 9 + 64 + 1111 + 16 = 1200 octets. | done | `parse_fragment` : `len(data) > MAX_UDP` et texte > 1111 rejetés. |
| NCP-5.2-3 | DEF | Taille minimale d'un fragment valide : 9 + 64 + 0 + 16 = 89 octets (en pratique ≥ 9+64+113+16 = 202 pour un message réel, annexe A). Un datagramme plus court est ignoré. | done | `parse_fragment` : `< HEADER_SIZE + ENVELOPE + 16` ⇒ `WireError`, ignoré par `datagram_received` (compteur `dropped`). Non testé. |

#### 5.3 En-tête de trame

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-5.3-1 | DEF | En-tête identique à [NNDP] 5.3 : magic **0xD5C1** (16 bits), version (8 bits) = **1**, événement (16 bits), longueur (32 bits). | done | `wire.FrameHeader.encode/decode`, `MAGIC = 0xD5C1`, `VERSION = 1`. |
| NCP-5.3-2 | DEF | L'événement porte le code de commande (0x0001..0x0014). | done | `seal_message(event, …)` ; `codec.Command`. |
| NCP-5.3-3 | DEF | La longueur = nombre d'**octets** qui suivent l'en-tête : 64 + longueur du texte chiffré + 16. | done | `FrameHeader(event, ENVELOPE + len(chunk) + 16)` dans `seal_message`. |
| NCP-5.3-4 | DEF | Un fragment dont le magic ≠ 0xD5C1, la version ≠ 1 ou la longueur ≠ taille réelle − 9 est ignoré sans réponse (conséquence de 5.5 et 10). | done | `FrameHeader.decode(expect_exact=True)` lève `WireError` ; `datagram_received` l'ignore. Non testé. |

#### 5.4 Enveloppe

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-5.4-1 | DEF | Clé éphémère : clé publique X25519 (32 o) générée par l'émetteur **pour ce message**. | done | `seal_message` : `AgreementKey.generate()` à chaque appel. |
| NCP-5.4-2 | DOIT | La clé éphémère DOIT être nouvelle pour chaque message et NE DOIT PAS être réutilisée. | done | Une génération par `seal_message` ; les retransmissions et le renvoi du cache réémettent les mêmes datagrammes du même message (ambiguïté F7-3 tranchée). Non testé. |
| NCP-5.4-3 | DEF | Sel : 16 octets aléatoires **propres au message** (identiques dans tous les fragments du message), passés à HKDF. | done | `seal_message` : `secrets.token_bytes(16)` une fois par message ; `_key(…, salt, …)`. |
| NCP-5.4-4 | DEF | Nonce : 12 octets aléatoires **propres à chaque fragment**. | done | `seal_message` : `secrets.token_bytes(12)` dans la boucle des fragments. |
| NCP-5.4-5 | DEF | Index : entier 16 bits, rang du fragment à partir de 0 ; doit être < nombre. | done | `parse_fragment` : `index >= count` ⇒ ignoré. |
| NCP-5.4-6 | DEF | Nombre : entier 16 bits, nombre total de fragments, de **1 à 1024** ; 0 ou > 1024 ⇒ fragment ignoré. | done | `parse_fragment` : `1 <= count <= MAX_FRAGMENTS`. Le champ CLI `max_fragments` (1..65535) est sans effet. |
| NCP-5.4-7 | DEF | Texte chiffré : fragment du texte en clair chiffré, suivi de l'étiquette de 16 octets. | done | `crypto.seal` (ChaCha20Poly1305.encrypt renvoie chiffré ‖ étiquette). |

#### 5.5 Chiffrement

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-5.5-1 | DEF | Secret partagé = X25519(clé éphémère privée de l'émetteur, clé publique X25519 statique du destinataire) [RFC7748]. Côté récepteur : X25519(sa clé privée X25519, clé éphémère reçue). | done | `seal_message` : `ephemeral.agree(dest_x25519)` ; `_on_fragment` : `self._static.agree(fragment.ephemeral)` ; paire statique dans `identity.json` (`Identity.agreement`). `AgreementKey.agree` refuse le secret nul. |
| NCP-5.5-2 | DEF | clé = HKDF-SHA-256(sel = Sel(16), ikm = secret_partagé(32), info = ASCII `"USMD-NCP-v1"` (11 o, sans terminateur) ‖ clé_éphémère (32) ‖ X25519_destinataire (32), L = 32). info fait 75 octets. | done | `transport._key` → `crypto.hkdf`. |
| NCP-5.5-3 | DEF | Chaque fragment est chiffré par ChaCha20-Poly1305 IETF [RFC8439] (nonce 96 bits) avec cette clé et le nonce du fragment. | done | `crypto.seal` / `open_sealed`. |
| NCP-5.5-4 | DEF | AAD = en-tête de trame (9 o, longueur comprise) ‖ clé éphémère (32) ‖ sel (16) ‖ index (2) ‖ nombre (2) — **sans le nonce** ; 61 octets. | done | `seal_message` (`aad = header + eph + salt + index/count`) et `parse_fragment` (`data[:9] + eph + salt + data[69:73]`). Pas de test de falsification. |
| NCP-5.5-5 | DEF | Le nonce est tiré au hasard pour chaque fragment (pas de compteur). | done | `secrets.token_bytes(12)`. |
| NCP-5.5-6 | DEF | Un destinataire qui ne parvient pas à authentifier un fragment l'**ignore sans répondre** (ni erreur, ni accusé). | done | `open_sealed` lève `CryptoError` avant toute création d'état de réassemblage ; `datagram_received` l'ignore. |
| NCP-5.5-7 | DEF | Primitives figées pour la version 1 (Ed25519, X25519, HKDF-SHA-256, ChaCha20-Poly1305) ; tout changement exige une nouvelle version (sec. 10). | done | `node/crypto.py` n'expose que ces quatre primitives, sans négociation. |

#### 5.6 Message

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-5.6-1 | DEF | Le texte en clair est obtenu par réassemblage des fragments **dans l'ordre de leur index**. | done | `_on_fragment` : `b"".join(assembly.pieces[i] for i in range(count))`. |
| NCP-5.6-2 | DEF | Type (8 bits) : 0x00 Requête, 0x01 Réponse, 0x02 Erreur, 0x03 Accusé de fragments ; toute autre valeur ⇒ message malformé. | done | `codec.MessageType` ; `Message.decode` : `plaintext[0] > 0x03` ⇒ `WireError` (message ignoré). |
| NCP-5.6-3 | DEF | Identifiant de requête (64 bits) aléatoire choisi par l'émetteur de la requête et **répété dans la réponse** (et dans l'erreur). | done | `NcpTransport.request` : `secrets.randbits(64) or 1` ; `_reply` reprend `request.request_id`. |
| NCP-5.6-4 | DEF | Horodatage (64 bits) : date d'émission en ms depuis l'époque Unix. | done | `_build` : `now_ms()`. |
| NCP-5.6-5 | DEF | Clé de l'émetteur : clé publique Ed25519 (32 o). | done | `Message.sender = self._signing.public`. |
| NCP-5.6-6 | DEF | Corps : variable, défini par commande et type (section 6). | done | `Message.body` = `plaintext[49:-64]`. |
| NCP-5.6-7 | DEF | Signature : Ed25519 (64 o) [RFC8032] sur `"USMD-NCP-v1"` (11 o ASCII) ‖ événement (2 o) ‖ Ed25519_destinataire (32) ‖ type (1) ‖ identifiant de requête (8) ‖ horodatage (8) ‖ clé de l'émetteur (32) ‖ corps. | done | `Message.signed_bytes` (signature détachée, `SigningKey.sign`). |
| NCP-5.6-8 | DEF | La signature est vérifiée avec la clé de l'émetteur ; échec ⇒ message ignoré sans réponse (sec. 10 : NE DOIT PAS répondre à un message non authentifié). | done | `NcpTransport._on_message` : `message.verify(self._signing.public)`, `CryptoError` ⇒ `return`. |
| NCP-5.6-9 | DEF | La signature lie le message à un seul destinataire (clé du destinataire) et une seule commande (événement) : un message reçu, rechiffré vers un tiers, est rejeté par ce tiers (clé destinataire différente) ; un message dont l'événement de l'en-tête a été changé est rejeté. | done | Vérification avec la clé locale comme destinataire et l'événement de l'en-tête (`Message.decode(event, …)`). Pas de test de non-réutilisation. |
| NCP-5.6-10 | DEF | Message minimal (corps vide) = 1 + 8 + 8 + 32 + 64 = 113 octets ; un texte en clair plus court est malformé. | done | `Message.decode` : `len < 49 + 64` ⇒ `WireError`. |

#### 5.7 Fragmentation et fiabilité

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-5.7-1 | DEF | Un texte en clair > 1111 octets est réparti en fragments de **1111 octets**, le dernier pouvant être plus court ; ≤ 1111 ⇒ un seul fragment. | done | `seal_message` : tranches `[i:i + MAX_PLAIN]`. `test_multi_fragment_request_is_acknowledged` (5 fragments). |
| NCP-5.7-2 | DEF | Taille maximale d'un message : 1024 × 1111 = 1 137 664 octets de texte en clair ; au-delà, l'émetteur refuse d'envoyer (ou pagine, cf. 6.14/6.18). | done | `seal_message` lève `WireError` au-delà ; pagination de Send_node_table dans `Node.send_table` (voir 6.18-3 pour l'instantané). |
| NCP-5.7-3 | DEF | Les fragments d'un même message ont la même clé éphémère et le même sel, et des nonces distincts. | done | `seal_message`. |
| NCP-5.7-4 | DEF | Le destinataire regroupe les fragments par (adresse source, clé éphémère, sel). | done | `_on_fragment` : `group = (address[0], ephemeral, salt)` ; un fragment d'événement ou de nombre différent est ignoré. |
| NCP-5.7-5 | DEF | Chaque fragment est authentifié indépendamment ; les doublons (même index) sont ignorés. | done | `open_sealed` par fragment, puis `if fragment.index in assembly.pieces: return`. |
| NCP-5.7-6 | DEF | Message abandonné si tous les fragments ne sont pas reçus dans le délai de réassemblage (**10 s**). | done | `REASSEMBLY_S = 10.0` ; `_expire` et la tâche d'accusé suppriment l'assemblage. Le champ CLI `reassembly_timeout` est sans effet. |
| NCP-5.7-7 | DOIT | Le destinataire DOIT limiter le nombre de messages en cours de réassemblage (**16 par adresse source** par défaut) et la mémoire qu'ils occupent. | done | `NcpTransport._new_assembly` : `PER_SOURCE = 16` par adresse et `MAX_ASSEMBLIES = 256` en tout, contrôlés avant X25519 ; `_on_fragment` : `MAX_BUFFERED` (16 Mio de texte en clair cumulé, `_buffered` décrémenté par `_drop_assembly`). Groupes terminés bornés (`MAX_COMPLETED = 4096`). Le champ CLI `reassembly_per_address` reste sans effet. Bornes globales non testées. |
| NCP-5.7-8 | DEF | Message multi-fragments : accusé (type 0x03) envoyé dès le **premier fragment reçu**, puis à chaque période de **100 ms** sans nouveau fragment, et à la **fin du réassemblage**. | done | `_schedule_ack` (premier, fin) et la tâche `ticker` (100 ms de silence, `ACK_DELAY_S`). Ambiguïté F7-2 tranchée : l'accusé n'est émis qu'une fois le fragment 0 reçu (clé de l'émetteur lue en `piece[17:49]`) ; si le premier fragment reçu n'est pas le 0, le premier accusé est différé. `test_multi_fragment_request_is_acknowledged`. |
| NCP-5.7-9 | DEF | Corps de l'accusé : sel du message (16 o) ‖ nombre de fragments (16 bits) ‖ champ de bits de ⌈nombre/8⌉ octets, bit de rang i = 1 si fragment i reçu. | done | `codec.fragment_ack_body` / `parse_fragment_ack`, MSB d'abord (ambiguïté F7-1 tranchée). |
| NCP-5.7-10 | DEF | L'identifiant de requête d'un accusé vaut **0**. | done | `_send_ack` : `self._build(…, MessageType.FRAGMENT_ACK, 0, …)`. |
| NCP-5.7-11 | DEF | L'émetteur retransmet les fragments non acquittés après **2 s**, délai doublé à chaque tentative (2, 4, 8 s), jusqu'à **3 tentatives**, puis abandonne et considère la requête échouée. | done | `NcpTransport.request` (requêtes) et `_retransmit_reply` (réponses multi-fragments, même calendrier) ; `NcpTimeout` à l'abandon. Interprétation : 3 tentatives = 3 émissions (première comprise), attentes 2, 4 puis 8 s, soit 2 retransmissions et 14 s au total, sans attente doublée supplémentaire. Réglable par `config protocol ncp retransmit-*`. `test_timeout_schedule_without_extra_doubled_wait`. |
| NCP-5.7-12 | DEF | Message d'un seul fragment : pas d'accusé, la réponse en tient lieu ; sans réponse dans le délai de retransmission, l'émetteur retransmet la requête avec le **même identifiant de requête**. | done | Pas d'accusé si `count == 1` ; `request` renvoie le même datagramme (même clé éphémère, même identifiant) : ambiguïté F7-3 tranchée. |
| NCP-5.7-13 | DOIT | Le destinataire DOIT conserver **60 s** les réponses envoyées, indexées par (clé de l'émetteur, identifiant de requête). | done | `_on_request` : `self._responses[key] = (loop_now + RESPONSE_CACHE_S, datagrams)`. Le champ CLI `response_cache` est sans effet. |
| NCP-5.7-14 | DOIT | Il DOIT renvoyer la réponse conservée, **sans réexécuter la commande**, à toute requête reçue en double. | done | `_on_fragment` : un fragment d'un groupe déjà réassemblé (`_completed`) est authentifié par l'AEAD puis reçoit la réponse en cache ; `_on_request` : renvoi du cache, requête en cours d'exécution (`_executing`) ignorée. `test_duplicate_request_answered_from_cache` (une seule exécution). |
| NCP-5.7-15 | DEF | Les accusés et réponses voyagent eux-mêmes dans l'enveloppe chiffrée (vers la clé X25519 de l'émetteur de la requête). | done | `x25519_of` (NIT, `_approval_x25519`, voisins NNDP), puis repli `reply_x25519` → `Node._reply_x25519` (X25519 de la fiche d'une Request_approval, retenue par `_remember_requester`). `test_reply_x25519_hook_answers_unknown_requester`. |

### 6. Commandes

#### 6.1 Règles communes

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.1-1 | DEF | Types : Entier non signé BE 8/16/32/64 ; Booléen 8 bits (0x00 faux, 0x01 vrai, autre ⇒ malformé) ; Date 64 bits ms Unix ; Pour mille 16 bits 0..1000 (> 1000 ⇒ malformé) ; Identifiant 26 o ASCII ULID canonique ; Chaîne = longueur 16 bits + UTF-8 ; Liste = nombre 16 bits + éléments. | done | `wire.Reader.permille` (0..1000) utilisé pour Request_help/emergency (`handlers._help_or_emergency`), la réponse Check_distance (`node.measure`) et la réponse Get_status (`node._healing_loop`) ; une réponse mal formée est ignorée sans arrêter les boucles. Test : `tests/test_ncp02_transport.py`. |
| NCP-6.1-2 | DEF | Registre des 20 commandes 0x0001..0x0014 (voir tableau « Formats binaires »). | done | `codec.Command` ; `show ncp commands`. |
| NCP-6.1-3 | DOIT | Les commandes 0x0003, 0x0004, 0x0006, 0x0007, 0x0008, 0x0009 et 0x0010 NE DOIVENT être adressées qu'à des nœuds de référence de l'émetteur. | done | Côté client, seules cibles : `self.references` (`_solicited`, `push_properties`, `_relay_properties`, `inform_references`, `_relay_once`, `_reconcile_loop`, `verify_endorsement_of`, relais d'urgence) ; exception de l'endosseur dans `_synchronise`. |
| NCP-6.1-4 | DEF | Un destinataire qui reçoit l'une de ces commandes d'un nœud dont il n'est pas nœud de référence répond par l'erreur **0x0001**. | done | `handlers._am_reference_of` : relation de référence (Inform_reference_node ou fiche), plus la seule exception du draft (l'endosseur vers le nœud endossé en 0x0000/0x1000) ; Inform_reference_node qui ne nous nomme pas reçoit 0x0001. |
| NCP-6.1-5 | PEUT | Exception : un endosseur PEUT adresser 0x0006, 0x0007, 0x0008 et 0x0010 à un nœud qu'il a endossé tant que celui-ci est à l'état 0x0000 ou 0x1000. | done | Émetteur : `_synchronise` ; récepteur : `ENDORSER_EXCEPTION` dans `_check_sender` et `_am_reference_of`. Test intégration. |
| NCP-6.1-6 | DEF | Les commandes 0x0012..0x0014 ne circulent qu'entre électeurs ; reçues d'un nœud absent de la configuration Raft ⇒ erreur **0x000A**. | done | `_check_sender` : `command in RAFT` et identifiant hors `raft.voters` ⇒ `VOTERS_ONLY`. |
| NCP-6.1-7 | DEF | 0x0011 peut être adressée à tout nœud ; seul un électeur la traite (les autres répondent statut 0x01/0x03, cf. 6.15). | done | `allocate_management_ids` : non-électeur ⇒ 0x01 (maître connu) ou 0x03. |
| NCP-6.1-8 | DOIT | Avant d'exécuter une commande, le destinataire DOIT vérifier que la clé de l'émetteur figure dans sa NIT **avec l'adresse IP source**. | done | `_check_sender` : `nit.knows` puis `nit.accepts(key, ip)` (TTL compris) avant tout `_on_*`. |
| NCP-6.1-9 | DOIT | … et que son rôle dans la NAL autorise la commande (rôle minimal Node_executor pour toutes, voir matrice). | done | `_check_sender` : `nal.allows(key, Role.NODE_EXECUTOR)` (un rôle de code inférieur inclut les suivants). |
| NCP-6.1-10 | DEF | Seule Request_approval peut provenir d'une clé inconnue. | done | `handle_request` : `_check_sender` sauté pour 0x0005 seulement. |
| NCP-6.1-11 | DEF | Matrice : 0x0001, 0x0002, 0x0003, 0x0004, 0x000E, 0x000F, 0x0009, 0x000A..0x000D, 0x0011 ⇒ Node_executor ; 0x0006..0x0008 ⇒ Node_executor + signature d'autorité valide sur l'objet ; 0x0010 ⇒ Node_executor + signatures valides sur chaque entrée ; 0x0012..0x0014 ⇒ Node_executor + appartenance à la configuration Raft ; 0x0005 ⇒ aucun rôle mais jeton de création valide. | done | `_check_sender` + `SignedConfig.offer_*` (signature d'autorité) + `accept_entry` (entrée invalide ignorée) + contrôle Raft + `check_token` pour 0x0005. |
| NCP-6.1-12 | DEF | Réponse : même commande (événement), type 0x01. | done | `handlers._ok`, `_reply`. |
| NCP-6.1-13 | DEF | Erreur : type 0x02, corps = code d'erreur 16 bits + Chaîne descriptive **facultative**. | done | `codec.error_body` / `parse_error` (chaîne présente ssi des octets restent). |
| NCP-6.1-14 | DEF | Quand le rôle est insuffisant ⇒ erreur 0x0001 ; clé ou couple (adresse, clé) inconnu ⇒ 0x0005 (sauf cas de 7.6 où le message est ignoré). | done | `_check_sender` : clé inconnue ⇒ 0x0005 ; clé connue et couple inconnu ⇒ cas 7.6 (ignoré) ; rôle ⇒ 0x0001. Ambiguïté F7-9 tranchée. |

#### 6.2 Get_status (0x0001)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.2-1 | DEF | Requête : corps vide. | done | `Node._healing_loop`, test intégration (`b.call(a.node_id, Command.GET_STATUS)`). |
| NCP-6.2-2 | DEF | Réponse : RAM (‰), CPU (‰), disque (‰), carte réseau (‰), service en cours (Chaîne, longueur 0 si aucun), état du nœud (16 bits, registre ARCH). | done | `_on_get_status` (charges lissées bornées à 1000, mutation en cours, état d'origine D sinon 0x3000). Test intégration. |

#### 6.3 Check_distance_to_node (0x0002)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.3-1 | DEF | Requête : date d'envoi (Date). | done | `Node.measure`. |
| NCP-6.3-2 | DEF | Réponse : date reçue répétée (Date), charge de référence du répondant (‰), service hébergé (Chaîne), booléen « le répondant a l'émetteur comme nœud de référence ». | done | `_on_check_distance_to_node`. Test intégration (via `finish_synchronisation`). |
| NCP-6.3-3 | DEF | L'émetteur calcule lui-même le RTT t avec sa propre horloge et la distance d selon [ARCH] 6 ; le répondant ne mesure pas t. | done | `Node.measure` (horloge monotone locale), `distance.distance`. |

#### 6.4 Request_emergency (0x0003) et Request_help (0x0004)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.4-1 | DEF | Request_help = délégation préventive d'un nœud affaibli fonctionnel ; Request_emergency = reprise immédiate demandée par un nœud défaillant. | done | `Node.request_help` (`check_weakness`), `Node.emergency` ; `execute node help | emergency`. Non testé. |
| NCP-6.4-2 | DEF | Corps commun : motif (16 bits ; Emergency : 0x3301..0x3304 ; Help : 0x0000), nœuds sollicités (Liste d'Identifiants, tous les destinataires de la demande), charge de référence (‰). | done | Émission `Node._ask` ; réception `_help_or_emergency` (décodage strict : Pour mille contrôlé, octets en trop refusés). Limite de 3 demandes par pair et par 10 s (`_request_rate_ok`, 0x0004 au-delà). Non testé. |
| NCP-6.4-3 | DEF | Motif hors plage (Emergency hors 0x3301..0x3304, Help ≠ 0x0000) ⇒ erreur 0x0003. | done | `_help_or_emergency` lève `WireError` ⇒ 0x0003. |
| NCP-6.4-4 | DEF | Réponse : booléen (peut prendre le relais) + Liste d'Identifiants de nœuds de récupération supplémentaires. | done | `_help_or_emergency` ; lu par `_ask`. |
| NCP-6.4-5 | PEUT | Sur Request_emergency, un nœud de référence PEUT envoyer Request_help à ses propres nœuds de référence absents de la liste des sollicités, puis inclure dans sa réponse ceux qui ont répondu positivement. | done | `_help_or_emergency` (`relay`, `ask`). |
| NCP-6.4-6 | DOIT | Il DOIT répondre à la Request_emergency en **2 s au plus**. | done | Relais borné par `asyncio.wait_for(…, 1.5)` en parallèle. |
| NCP-6.4-7 | DEF | Commandes réservées aux nœuds de référence de l'émetteur (6.1-3). | done | `REFERENCE_ONLY`. |

#### 6.5 Confirm_delegation (0x000E)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.5-1 | DEF | Adressée par le nœud affaibli/défaillant à un nœud de récupération retenu parmi ceux ayant répondu à Request_help/Request_emergency ; elle accorde la délégation. | done | `Node.request_help`, `Node.delegate_all`. |
| NCP-6.5-2 | DEF | Requête : identifiant du service délégué (Chaîne) + motif (16 bits). | done | La Chaîne porte le **nom de la mutation** (interprétation de « service délégué », cohérente avec la transmutation de 6.5-3). |
| NCP-6.5-3 | DEF | Réponse : booléen, vrai si le destinataire prend le service en charge ; dans ce cas il déclenche la transmutation correspondante. | done | `_on_confirm_delegation` → `Node.transmute`. |

#### 6.6 Declare_state (0x000F)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.6-1 | DEF | Informe un nœud de référence d'un changement d'état de l'émetteur. Requête : état (16 bits) + date de validité **facultative** (Date). | done | Émission par `delegate_all` et `execute node state` (état seul, la date étant facultative) ; `handlers._on_declare_state` lit la date ssi 8 octets restent, refuse les octets en trop (`reader.end()` ⇒ 0x0003) et la retient dans `state_validity_of` (non exploitée ailleurs : le draft n'en fixe pas l'usage). Non testé. |
| NCP-6.6-2 | DEF | Réponse : accusé (6.12). | done | `ack_body(True)`. |
| NCP-6.6-3 | DEF | Un nœud affaibli envoie Declare_state avec 0x3000 (Inactif) **après** avoir confirmé sa délégation et **avant** de couper les services de sa dernière transmutation. | done | `Node.delegate_all` : Confirm_delegation, Declare_state 0x3000, puis séquences `emergency`/retrait. |
| NCP-6.6-4 | DEF | Un état d'origine O déclaré ⇒ rejet (erreur 0x0003) (cohérence avec 7.8 : on ne publie jamais d'état d'origine O). | done | `_on_declare_state` : `not state.declarable` ⇒ 0x0003 ; état non enregistré ⇒ `ValueError` ⇒ 0x0003. CLI : `DeclaredState` (test `test_observed_state_cannot_be_declared`). |

#### 6.7 Request_approval (0x0005)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.7-1 | DEF | Envoyée à un nœud admis par un nœud qui veut rejoindre l'USD ; la clé de l'émetteur est sa propre clé, absente de la NIT du destinataire. | done | `Node.request_approval` ; réception sans `_check_sender`. Test intégration. |
| NCP-6.7-2 | DEF | Corps : jeton de création (7.7) ‖ fiche de nœud (7.8) à l'état **0x0000**, sans mutation ni nœud de référence ‖ nonce (16 o aléatoires) ‖ rôles demandés (Liste d'entiers 8 bits). | done | `Node.request_approval` : jeton ‖ `initial_record()` (0x0000, sans mutation ni référence) ‖ `secrets.token_bytes(16)` ‖ rôles du jeton ; lecture `_on_request_approval` (nonce sauté, rôles par `_read_roles`, `reader.end()`). Test intégration. |
| NCP-6.7-3 | DEF | Fiche non conforme (état ≠ 0x0000, mutation non vide, nœuds de référence non vides) ⇒ erreur 0x0009. | done | `_on_request_approval` (signature de la fiche comprise). |
| NCP-6.7-4 | DEF | Acceptation : réponse = booléen vrai ‖ paquet d'endossement (7.1). | done | `_on_request_approval`. Test intégration. |
| NCP-6.7-5 | DEF | Refus : erreur (section 9), notamment **0x0007** si jeton refusé, **0x0008** si l'identifiant est déjà utilisé dans l'USD (par une autre clé), 0x0009 fiche invalide / adresse ≠ source. | done | Codes produits par `_on_request_approval` (0x0007 jeton/rôles, 0x0008, 0x0009, 0x0004 si non actif). `handle_request` appelle `_remember_requester` avant tout contrôle : la X25519 de la fiche est retenue et `NcpTransport._on_request` l'obtient par `reply_x25519` (`Node._reply_x25519`), donc le refus parvient aussi à un demandeur non voisin. `test_reply_x25519_hook_answers_unknown_requester` (crochet du transport ; pas de test de bout en bout d'un refus). Restes mineurs : un jeton à indicateurs réservés donne 0x0003 (choix F7-8) et, illisible, empêche `_remember_requester` de retenir la clé, donc ce refus-là n'est pas délivré à un non-voisin ; `_approval_x25519` n'est jamais purgé (croît d'une entrée par clé demandeuse, débit borné à 5/s par adresse). |
| NCP-6.7-6 | DEF | Après 0x0008, le demandeur génère un nouvel identifiant (ULID) et une nouvelle fiche et renouvelle sa demande avec le **même jeton**. | done | `request_approval` : `identity.regenerate_id()`, `save_identity` ; le tour suivant de `_bootstrap_loop` reprend avec `self.token` (erreur désormais remise, 6.7-5). Non testé. |
| NCP-6.7-7 | PEUT | Après toute autre erreur, le demandeur PEUT s'adresser à un autre nœud. | done | `_bootstrap_loop` passe au candidat suivant (`candidates()` : nœud de contact, EDB, voisins NNDP actifs). |

#### 6.8 Send_usc_properties (0x0006)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.8-1 | DEF | Envoi périodique des propriétés de l'USC : **60 s ± 25 %** de gigue aléatoire (45..75 s). | done | `Node._properties_loop` avec `_jitter` (0,75..1,25) ; intervalle `config protocol ncp properties-interval`. |
| NCP-6.8-2 | DEF | Corps : USCN (Identifiant 26 o) ‖ version (Date) ‖ clé Ed25519 de l'USC (32 o) ‖ liste des USD (Liste d'Identifiants USDN) ‖ signature de l'autorité (64 o) sur les champs précédents. | done | `codec.UscProperties` (signature sans chaîne de contexte, ambiguïté F7-5). Test intégration. |
| NCP-6.8-3 | DEF | Réponse : booléen (appliquées) + version détenue par le répondant (Date). | done | `ack_body(applied, held)`. |
| NCP-6.8-4 | DEF | Le destinataire n'applique que si la signature est valide pour la clé d'autorité qu'il connaît **et** si la version est **strictement postérieure** à la sienne. | done | `SignedConfig.offer_usc` ; clé d'autorité = ancre USC ou clé USC détenue (`Node.usc_key`). Signature invalide ⇒ erreur 0x0006, version non postérieure ⇒ booléen faux (ambiguïté F7-6 tranchée). |
| NCP-6.8-5 | DEF | Réservée aux nœuds de référence, sauf exception endosseur (6.1-3/6.1-5). | done | `REFERENCE_ONLY` + `ENDORSER_EXCEPTION`. |

#### 6.9 Send_usd_properties (0x0007)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.9-1 | DEF | Corps : USDN (26 o) ‖ version (Date) ‖ clé Ed25519 de l'USD (32) ‖ aires (Liste d'aires) ‖ catalogue (Liste de services) ‖ paramètres (Liste de (code 16, valeur 32)) ‖ signature d'autorité (64) sur les champs précédents. | done | `codec.UsdProperties` ; construit depuis la configuration par `AuthorityBridge.build`. Test intégration. |
| NCP-6.9-2 | DEF | Aire : identifiant (8 bits), nom (Chaîne), préfixe (32 bits), longueur de masque (8 bits, **8..32**). | done | `UsdProperties._unsigned/decode` (masque hors 8..32 ⇒ 0x0003). |
| NCP-6.9-3 | DEF | Service : identifiant (16 bits, 4 bits de poids fort à 0), nom (Chaîne), identifiant d'aire (8), VIP (32), adresse de groupe (32, 0 si aucune). | done | `CatalogEntry` ; `validate` impose 0x001..0xFFE. |
| NCP-6.9-4 | DEF | Rejet (erreur **0x0003**) si deux aires ont des préfixes qui se recouvrent. | done | `UsdProperties.validate` (appelé par `offer_usd`) ⇒ `WireError` ⇒ 0x0003. |
| NCP-6.9-5 | DEF | Rejet 0x0003 si deux services ont le même identifiant ou le même nom. | done | `validate`. |
| NCP-6.9-6 | DEF | Rejet 0x0003 si un identifiant de service vaut 0x000 ou 0xFFF (et, par le format, s'il dépasse 0xFFF). | done | `validate` (`0x001 <= id <= 0xFFE`). |
| NCP-6.9-7 | DEF | Rejet 0x0003 si une VIP n'appartient pas au préfixe de l'aire du service. | done | `validate`. |
| NCP-6.9-8 | DEF | Rejet 0x0003 si une adresse de groupe non nulle n'appartient pas à 239.0.0.0/8. | done | `validate`. |
| NCP-6.9-9 | DEF | Rejet 0x0003 si un service référence une aire inconnue (implicite). | done | `validate` (`entry.area_id not in by_id`). |
| NCP-6.9-10 | DEF | Réponse et règle d'application identiques à Send_usc_properties (signature valide + version strictement postérieure). | done | `SignedConfig.offer_usd` (+ `check_ranges`). Test intégration (refus d'un objet signé par la mauvaise clé). |

#### 6.10 Send_mutation_properties (0x0008)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.10-1 | DEF | Corps : Liste de mutations ; chaque mutation = identifiant (Chaîne) ‖ version (Date) ‖ temps de transmutation moyen (32 bits, ms) ‖ nombre min de services (16) ‖ nombre max (16) ‖ longueur du fichier de service (32) ‖ fichier YAML (UTF-8) ‖ signature d'autorité (64) propre à chaque mutation. | done | `codec.MutationProperties`, `encode_mutations`/`decode_mutations` ; la CLI saisit des secondes converties en ms (`AuthorityBridge.build`). Test intégration. |
| NCP-6.10-2 | DEF | Réponse identique à Send_usc_properties ; application par mutation si signature valide et version strictement postérieure. | done | `_on_send_mutation_properties`, `SignedConfig.offer_mutation` ; booléen = au moins une appliquée, version = plus récente détenue. |

#### 6.11 Inform_reference_node (0x0009)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.11-1 | DEF | Le nœud informe un de ses nœuds de référence de la liste de ses propres nœuds de référence : corps = Liste d'Identifiants. | done | `Node.inform_references` ; réception `_on_inform_reference_node` (`referenced_by`). Test intégration. |
| NCP-6.11-2 | DEF | Réponse : accusé (6.12). | done | `ack_body(True)` quand la liste nous nomme ; sinon erreur 0x0001 (`_on_inform_reference_node`). |

#### 6.12 Accusé

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.12-1 | DEF | Accusé (réponse type 0x01) : corps = booléen ‖ version détenue (Date) **facultative**. | done | `codec.ack_body` / `parse_ack` (Date présente ssi 8 octets restent). |

#### 6.13 Commandes d'endossement (0x000A..0x000D)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.13-1 | DEF | Endorsement_check_required : requête vide ; réponse = paquet d'endossement du répondant. | done | `_on_endorsement_check_required`. Le fondateur, sans endosseur, renvoie un paquet auto-signé : point ouvert du draft (voir F7-12). |
| NCP-6.13-2 | DEF | Verify_endorsement : requête = paquet d'endossement ; réponse = booléen (l'endosseur confirme). | done | `_on_verify_endorsement` (paquet présent dans la NEL, ou auto-endossement du fondateur). |
| NCP-6.13-3 | DEF | Notify_end_of_service : requête = Identifiant de l'endosseur qui disparaît ; réponse = accusé. | done | Émission `Node.retire` ; réception `_on_notify_end_of_service`. |
| NCP-6.13-4 | DEF | Request_revocation : requête = Identifiant du nœud qui disparaît ; réponse = accusé. | done | Émission `Node.retire` ; réception `_on_request_revocation`. |

#### 6.14 Send_node_table (0x0010)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.14-1 | DEF | Usages : synchronisation d'un nœud nouvellement admis, propagation des changements, réconciliation périodique entre nœuds de référence. | done | `_synchronise`, `_relay_once`, `_reconcile_loop` (et `execute table reconcile`). Test intégration (synchronisation, relais). |
| NCP-6.14-2 | DEF | Requête : mode (8 bits : 0x00 complète, 0x01 incrément ; autre ⇒ 0x0003) ‖ page (16, à partir de 0) ‖ nombre de pages (16, ≥ 1 ; = 1 en incrément) ‖ entrées (Liste d'entrées). | done | `Node.send_table` : en incrément chaque tranche part comme un échange distinct `(page 0, 1 page)` ; en complet `(i, n)`. `handlers._on_send_node_table` refuse (0x0003) un mode inconnu, `page >= pages` et `pages != 1` en incrément, puis `reader.end()`. Test intégration (complet et incrément) ; le refus n'est pas testé. |
| NCP-6.14-3 | DEF | Entrée = jeton de création (7.7) ‖ fiche de nœud la plus récente (7.8). | done | `codec.TableEntry`, `tables.Entry.encode`. |
| NCP-6.14-4 | DEF | Mode complet : table triée **par identifiant**, répartie sur autant de pages que nécessaire, chaque page étant un message distinct. | done | `tables.NodeTable.sorted()` + `send_table` (un `call` par page). |
| NCP-6.14-5 | DOIT | Le texte en clair de chaque page NE DOIT PAS dépasser la taille maximale d'un message (1024 fragments, 1 137 664 o). | done | `send_table` coupe à 1000 × 1111 octets d'entrées (marge pour les en-têtes) ; `seal_message` refuse au-delà. |
| NCP-6.14-6 | DEF | Réponse (Liste d'entrées) en incrément : entrées que le répondant détient dans une version **plus récente** que celles reçues. | done | `_on_send_node_table` (`newer`). |
| NCP-6.14-7 | DEF | Réponse en complet : mêmes entrées pour la page reçue et, en réponse à la **dernière page**, les entrées détenues absentes de **toutes** les pages. | done | `_on_send_node_table` : `_table_pages[sender]` cumule les clés vues sur les pages. |
| NCP-6.14-8 | DEF | L'émetteur traite les entrées de la réponse comme celles d'une requête (7.9) ; un échange complet réconcilie les deux tables en un passage. | done | `send_table` : `accept_entry` sur chaque entrée de la réponse, relayées avec `schedule_relay(peer, …)` (attribuées au répondant). |
| NCP-6.14-9 | DEF | Signatures valides exigées sur chaque entrée (matrice 6.1). | done | `accept_entry` → `TableEntry.verify` + `check_token`. |

#### 6.15 Request_management_id (0x0011)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.15-1 | DEF | Requête : Liste d'identifiants de service (Entiers 16 bits). | done | `request_management_ids` ; `_on_request_management_id`. Test intégration. |
| NCP-6.15-2 | DEF | Réponse : statut (8 : 0x00 attribué, 0x01 pas le maître, 0x02 maître sans quorum, 0x03 maître inconnu) ‖ terme (64) ‖ maître (Identifiant, 26 octets nuls si inconnu) ‖ électeurs (Liste d'Identifiants) ‖ attributions (Liste de (service 16, gestion 16), vide si statut ≠ 0x00). | done | `allocate_management_ids.answer`. |
| NCP-6.15-3 | DEF | Non-électeur : statut 0x01 s'il connaît le maître, 0x03 sinon. | done | `allocate_management_ids`. |
| NCP-6.15-4 | DEF | Électeur non maître : statut 0x01 ; le demandeur réitère auprès du maître indiqué. | done | `allocate_management_ids` ; `request_management_ids` ajoute le maître indiqué aux cibles. |
| NCP-6.15-5 | DEF | Le maître vérifie que chaque service demandé est au catalogue et appartient à une aire du demandeur (déduite de la mutation de sa fiche) ; sinon erreur **0x000B**. | done | `allocate_management_ids` (`areas_of_mutation` de la fiche) ⇒ `NcpRemoteError(0x000B)`. |
| NCP-6.15-6 | DEF | Si le demandeur a déjà un identifiant pour le service, le maître renvoie le même (idempotence). | done | `StateMachine.management_of`. |
| NCP-6.15-7 | DEF | Sinon il choisit le **plus petit identifiant libre de 0x0001 à 0xFFFE** pour ce service et inscrit un enregistrement Attribution (0x01) dans le journal. | done | `Node.allocate_management_ids` → `Raft.free_id_for` (`range(1, 0xFFFF)` hors `reserved_ids` : état appliqué **et** attributions inscrites non encore appliquées, plus celles du même lot), `assign_record`. Test intégration (identifiant 1), `test_reserved_ids_include_uncommitted_assignments`. |
| NCP-6.15-8 | DEF | Statut 0x00 seulement après validation (inscription dans le journal d'une majorité d'électeurs) ; sinon, au terme du délai de retransmission (2 s), statut 0x02. | done | `Raft.propose(records, settings.ncp_retransmit)` ⇒ 0x02 à l'expiration. |
| NCP-6.15-9 | DEF | Le demandeur inscrit les adresses SP obtenues (service 12 bits ‖ gestion 16 bits, codage ARCH 11.3) dans une nouvelle fiche et la propage. | done | `request_management_ids` → `publish_record` (`addresses.pack`). |
| NCP-6.15-10 | DEF | Un nœud apprend les électeurs par la réponse et par l'indicateur E des fiches ; s'il n'en connaît aucun, il s'adresse à ses nœuds de référence. | done | `Node.request_management_ids` : cibles = maître connu, électeurs Raft locaux, `known_voters` (dernière réponse), fiches de la table portant l'indicateur E (`record.voter`), puis nœuds de référence en dernier recours ; un statut 0x01 ajoute le maître indiqué. Test intégration (un seul électeur ; la sélection par indicateur E n'est pas testée). |

#### 6.16 Raft_request_vote (0x0012)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.16-1 | DEF | Met en œuvre RequestVote de [RAFT] avec **pré-vote** (thèse Ongaro 9.6). | done | `Raft.elect`, `_ballot`, `handle_vote`. `test_raft_election_after_leader_loss` (trois électeurs). |
| NCP-6.16-2 | DEF | Requête : pré-vote (Booléen) ‖ terme (64 ; terme suivant en pré-vote, sans incrémenter le terme courant) ‖ candidat (Identifiant) ‖ index du dernier enregistrement (64) ‖ terme du dernier enregistrement (64). | done | `Raft._ballot` (51 octets) ; `handle_vote`. |
| NCP-6.16-3 | DEF | Réponse : terme courant du répondant (64) ‖ vote accordé (Booléen). | done | `handle_vote`. |
| NCP-6.16-4 | DEF | Un pré-vote n'incrémente aucun terme (ni chez le candidat, ni chez le votant). | done | `elect` n'incrémente qu'après le pré-vote ; `handle_vote(pre_vote=True)` ne modifie aucun état. |
| NCP-6.16-5 | DEF | Un électeur refuse vote et pré-vote s'il a reçu un Raft_append_entries valide du maître actuel depuis moins que le délai d'élection minimal (5 s). | done | `handle_vote` : `recent_leader` (`election_s[0]`). |
| NCP-6.16-6 | DEF | Règles RAFT standard : vote unique par terme, journal du candidat au moins aussi à jour. | done | `handle_vote` (`voted_for`, `up_to_date`), état persistant `raft.json`. |

#### 6.17 Raft_append_entries (0x0013)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.17-1 | DEF | Réplique le journal et sert de battement de cœur (intervalle **1 s**). | done | `Raft._run` : `replicate()` toutes les `heartbeat_s` (`config protocol ncp raft-heartbeat`). |
| NCP-6.17-2 | DEF | Requête : terme (64) ‖ maître (Identifiant) ‖ index précédent (64) ‖ terme précédent (64) ‖ index de validation (64) ‖ enregistrements (Liste, vide pour un battement). | done | `_replicate_to`, `handle_append`. |
| NCP-6.17-3 | DEF | Enregistrement : terme (64) ‖ type (8) ‖ longueur des données (16) ‖ données. | done | `codec.LogRecord.encode/read` (longueur contrôlée par type). |
| NCP-6.17-4 | DEF | Type 0x01 Attribution : service (16), gestion (16), Identifiant du nœud (26), clé Ed25519 du nœud (32). | done | `raft.assign_record`, `StateMachine.apply`. |
| NCP-6.17-5 | DEF | Type 0x02 Libération : service (16), gestion (16). | done | `raft.release_record`, `StateMachine.apply` (jamais émis par le nœud aujourd'hui). |
| NCP-6.17-6 | DEF | Type 0x03 Ajout d'un électeur : Identifiant (26), clé Ed25519 (32). | done | `raft.voter_record` ; `Node._maintenance_loop`. |
| NCP-6.17-7 | DEF | Type 0x04 Retrait d'un électeur : Identifiant (26). | done | `voter_record(…, None)` ; `_maintenance_loop` (délai USD 0x0015). |
| NCP-6.17-8 | DEF | Type 0x05 Aucune opération : données vides ; inscrit par un nouveau maître au début de son terme. | done | `Raft._become_leader`. |
| NCP-6.17-9 | DEF | Réponse : terme courant (64) ‖ succès (Booléen) ‖ index du dernier enregistrement concordant (64). | done | `handle_append`. |
| NCP-6.17-10 | DEF | Cohérence, validation et application selon [RAFT]. | done | `handle_append` (contrôle prev, troncature), `_advance_commit` (entrées du terme courant), `_apply_committed`. `test_raft_propose_commits_everywhere`, `test_raft_election_after_leader_loss`. |
| NCP-6.17-11 | DEF | Une configuration prend effet **dès son inscription** dans le journal, sans attendre sa validation. | done | `Raft.voters` lit tout le journal, validé ou non. |
| NCP-6.17-12 | DEF | Une seule modification de configuration en cours à la fois. | done | `Raft.propose` + `_config_pending`. |
| NCP-6.17-13 | DEF | Délai d'élection tiré au hasard entre **5 et 10 s**. | done | `Raft._run` : `random.uniform(*election_s)`, nouveau tirage après chaque tentative (évite les élections partagées répétées) ; `config protocol ncp raft-election-min/max`. |

#### 6.18 Raft_install_snapshot (0x0014)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-6.18-1 | DEF | Envoyée par le maître à un électeur trop en retard pour Raft_append_entries. | done | `Raft._apply_committed` appelle `compact()` dès que `applied - snapshot_index >= compact_after` (1000) ; `compact` fige la configuration validée (`_voters_upto(applied)`). `_replicate_to` → `_send_snapshot` si `next_index <= snapshot_index`. `test_raft_automatic_compaction`, `test_raft_snapshot_installed_in_several_pages`. |
| NCP-6.18-2 | DEF | Requête : terme (64) ‖ maître (Identifiant) ‖ dernier index inclus (64) ‖ dernier terme inclus (64) ‖ page (16) ‖ nombre de pages (16) ‖ électeurs (Liste de (Identifiant, clé Ed25519)) **seulement en page 0** ‖ attributions (Liste de (service 16, gestion 16, Identifiant 26, clé 32)). | done | `Raft.snapshot_pages` (électeurs écrits en page 0 seulement), `handle_snapshot` (lus en page 0 seulement : ambiguïté F7-7 tranchée « absent »). `test_raft_snapshot_installed_in_several_pages`. |
| NCP-6.18-3 | DEF | Instantané réparti sur des pages, chacune un message distinct (≤ taille max). | done | `Raft.snapshot_pages` : corps bornés à `snapshot_page_bytes` (1000 × 1111 octets, sous la taille max d'un message), page 0 réduite de la liste des électeurs, refus au-delà de 65 535 pages ; `_send_snapshot` envoie une requête par page dans l'ordre et s'arrête si le répondant a un terme supérieur. `test_raft_snapshot_installed_in_several_pages` (pages réduites). |
| NCP-6.18-4 | DEF | Réponse : terme courant du répondant (64). | done | `handle_snapshot`. |
| NCP-6.18-5 | DEF | L'électeur n'applique l'instantané qu'après réception de **toutes** les pages. | done | `Raft.handle_snapshot` accumule les pages par (maître, dernier index inclus) dans `_PendingSnapshot` (un seul instantané en cours) et n'installe qu'une fois les pages 0..n−1 et les électeurs reçus ; le journal postérieur concordant est conservé. `test_raft_snapshot_pages_wait_for_all`. |

### 7. Endossement, admission et révocation

#### 7.1 Paquet d'endossement

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-7.1-1 | DEF | Format : clé Ed25519 de l'endosseur (32) ‖ Identifiant du nouveau nœud (26) ‖ clé Ed25519 du nouveau nœud (32) ‖ clé X25519 du nouveau nœud (32) ‖ rôles accordés (Liste d'entiers 8) ‖ serial (16 o) ‖ expiration (Date) ‖ signature (64). | done | `codec.EndorsementPacket` (202 + k octets) ; `show nel`. Test intégration. |
| NCP-7.1-2 | DEF | Signature Ed25519 de l'endosseur sur `"USMD-NCP-v1-endorsement"` (23 o ASCII) ‖ tous les champs précédents. | done | `EndorsementPacket.sign/verify`. |
| NCP-7.1-3 | DEF | Le serial (16 o) identifie de façon unique le paquet (aléatoire). | done | `secrets.token_bytes(16)` par défaut. |
| NCP-7.1-4 | DEF | Durée de validité du paquet = paramètre USD 0x000D (endorsement_validity) [ARCH]. | done | `_on_request_approval` : `parameter(usd, 0x000D)` (défaut 2 592 000 s). |

#### 7.2 Admission

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-7.2-1 | DEF | Le nœud génère ses clés Ed25519 et X25519 et son identifiant ULID, puis obtient un jeton de création lié à sa clé Ed25519. | done | `identity.load_identity` ; `Node.install_token` (décodage, lien à la clé, signature) ; `execute node token install`, `config system bootstrap creation-token`. |
| NCP-7.2-2 | DEF | Il envoie Request_approval à un nœud admis avec son jeton et sa fiche initiale. | done | `_bootstrap_loop` → `request_approval` (`initial_record`). Test intégration. |
| NCP-7.2-3 | DEF | L'endosseur vérifie le jeton (7.7) et la fiche (7.8). | done | `_on_request_approval` : `check_token(for_admission=True)`, `record.verify`. |
| NCP-7.2-4 | DEF | Il vérifie que l'adresse de la fiche = adresse source de la requête (sinon 0x0009). | done | `record.address != ip` ⇒ 0x0009. |
| NCP-7.2-5 | DEF | Il vérifie qu'aucune entrée de sa table ne porte le même identifiant avec une autre clé (sinon 0x0008). | done | `tables.nodes.by_id` ⇒ 0x0008. |
| NCP-7.2-6 | DOIT | Il NE DOIT PAS endosser un nœud dont le jeton est refusé (erreur 0x0007). | done | Retour 0x0007 avant toute signature de paquet. |
| NCP-7.2-7 | DEF | Il répond par un paquet d'endossement dont les rôles = rôles demandés. | done | `EndorsementPacket(…, requested or token.roles, …)` (rôles lus par `_read_roles` ; liste vide ⇒ rôles du jeton ; le client demande toujours les rôles du jeton). |
| NCP-7.2-8 | DEF | Il enregistre le nœud dans sa NEL, sa NIT et sa NAL, ajoute (jeton, fiche) à sa table des nœuds et la propage en mode incrément à ses nœuds de référence. | done | `_on_request_approval` : `nel.append`, `nodes.merge`, `_learn_entry` (NIT + NAL), `schedule_relay`. Test intégration (NEL). |
| NCP-7.2-9 | DEF | Il envoie ensuite au nouveau nœud (exception 6.1) : Send_node_table complet, puis Send_usc_properties, Send_usd_properties, Send_mutation_properties (dans cet ordre). | done | `NcpHandlers._synchronise`. Test intégration. |
| NCP-7.2-10 | DEF | Le nouveau nœud passe à 0x1000 dès réception du paquet d'endossement, choisit ses nœuds de référence [ARCH 6.3], puis émet une nouvelle fiche à 0x2000 et la propage à ses nœuds de référence. | done | `request_approval` (0x1000) ; `finish_synchronisation` : `measure_distances`, `inform_references`, `publish_record`. Test intégration. |

#### 7.3 Rôles

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-7.3-1 | DEF | Codes de rôle : 0x01 Usc_operator, 0x02 Usd_operator, 0x03 Node_operator, 0x04 Node_executor. | done | `codec.Role` ; correspondance texte dans `cli/bridge._ROLE`. |
| NCP-7.3-2 | DEF | La NAL associe à chaque clé publique un ou plusieurs rôles. | done | `tables.Nal` (ancres, rôles du jeton, `config trust nal`) ; contrôle dans `_check_sender`. |
| NCP-7.3-3 | DEF | Un code de rôle inconnu dans une liste de rôles ⇒ corps malformé (0x0003). | done | `codec._read_roles` (`WireError` hors 0x01..0x04) pour le jeton, le paquet d'endossement et désormais les rôles demandés de Request_approval (`handlers._on_request_approval` ⇒ 0x0003, avant le contrôle du jeton). Non testé. |

#### 7.4 Vérification d'endossement

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-7.4-1 | DEF | Quand V reçoit une communication de E (clé dans la NIT) sans paquet d'endossement associé, V envoie Endorsement_check_required à E ; E répond avec son paquet. | done | `_check_sender` lance `verify_endorsement_of` (sauf soi, son endosseur, ses endossés, ou déjà vérifié). Non testé. |
| NCP-7.4-2 | DEF | V vérifie la signature, l'expiration et le contenu du paquet (id/clés de E = émetteur). | done | `Node.verify_endorsement_of` : signature, expiration, `packet.node_key == key`, `packet.node_id` et `packet.node_x25519` égaux à ceux de la fiche de E dans la table ; tout écart ⇒ exclusion 0x4100. Non testé. |
| NCP-7.4-3 | DEF | Si l'endosseur n'est pas dans la NIT de V, V réconcilie sa table avec un nœud de référence (Send_node_table complet) puis reprend. | done | `verify_endorsement_of` (`send_table(…, mode=0x00)`). |
| NCP-7.4-4 | DEF | Si l'endosseur est joignable, V lui envoie Verify_endorsement avec le paquet ; réponse vrai = approuvé, faux sinon. | done | `verify_endorsement_of`. |
| NCP-7.4-5 | DEF | Paquet invalide ou désapprouvé ⇒ E exclu de façon permanente (état **0x4100**). | done | `exclusions.exclude(key, EXCLUDED_INVALID_ENDORSEMENT)`. |
| NCP-7.4-6 | DEF | Endosseur introuvable ou injoignable ⇒ E exclu temporairement (**10 min** par défaut), état **0x4200** qui précise la date d'exclusion. | done | `exclude(…, EXCLUDED_UNVERIFIABLE_ENDORSEMENT, duration_ms=settings.exclusion_ms)` ; `Exclusion.since/until`. |
| NCP-7.4-7 | DEVRAIT | Un vérificateur DEVRAIT confronter les rôles du paquet aux rôles autorisés du jeton présent dans la table des nœuds (sec. 10). | done | `Node.verify_endorsement_of` : `set(packet.roles) <= set(entry.token.roles)`, sinon exclusion 0x4100. Non testé. |

#### 7.5 Fin de service et révocation

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-7.5-1 | DEF | Un endosseur qui disparaît par volonté de l'administrateur et dont la NEL contient des paquets envoie Notify_end_of_service à chaque nœud endossé. | done | `Node.retire` (`execute node retire`). Non testé. |
| NCP-7.5-2 | DEF | Les nœuds prévenus suppriment le paquet détenu et recommencent l'admission (avec le même jeton s'il n'a pas expiré). | done | `_on_notify_end_of_service` : paquet et endosseur effacés, état 0x0000 ; `_bootstrap_loop` reprend avec `self.token`. |
| NCP-7.5-3 | DEF | Un nœud qui disparaît et a été endossé par un pair envoie Request_revocation à ce pair. | done | `Node.retire`. |
| NCP-7.5-4 | DEF | Destinataire d'une Notify_end_of_service jamais endossé par l'émetteur ⇒ ignore et exclut l'émetteur définitivement (**0x4300**). | done | `_on_notify_end_of_service` (`self.endorser != sender`). |
| NCP-7.5-5 | DEF | Destinataire d'une Request_revocation n'ayant jamais endossé l'émetteur ⇒ ignore et exclut l'émetteur définitivement (**0x4400**). | done | `_on_request_revocation` (aucun paquet de la NEL pour cette clé). |

#### 7.6 Association adresse et clé

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-7.6-1 | DEF | Une clé peut être associée à plusieurs IP et une IP à plusieurs clés dans la NIT. | done | `tables.Nit` (adresses par clé, avec TTL ; recherche par adresse). |
| NCP-7.6-2 | DEF | Message authentifié venant d'une paire (IP, clé) absente de la NIT alors que la clé y figure ⇒ message ignoré. | done | `_check_sender` renvoie `None` (aucune réponse). |
| NCP-7.6-3 | DEF | Exclusion (état **0x4000**) seulement après vérification de la signature et si le message n'est pas un rejeu. | done | La signature est vérifiée par le transport avant `handle_request` ; rejeu < 60 s servi par le cache, rejeu > 30 s refusé en 0x0002 avant le contrôle NIT. Non testé. |
| NCP-7.6-4 | DEVRAIT | Avant d'exclure, le nœud DEVRAIT vérifier si sa table des nœuds contient une fiche plus récente de ce nœud portant l'adresse source ; si oui il met la NIT à jour et traite le message. | done | `_check_sender` : `entry.record.address == ip` ⇒ `nit.associate` puis traitement. |

#### 7.7 Jeton de création

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-7.7-1 | DEF | Format : version (8, =1) ‖ indicateurs (8 : bit 0x80 F fondateur, autres bits à 0) ‖ USDN (26) ‖ clé du nœud (32) ‖ rôles autorisés (Liste d'entiers 8) ‖ émission (Date) ‖ expiration (Date) ‖ serial (16) ‖ clé de l'émetteur (32, clé publique de l'USD) ‖ signature (64). | done | `codec.CreationToken` ; `Authority.mint_token`, `execute authority token create`. Test intégration. |
| NCP-7.7-2 | DEF | Signature sur `"USMD-NCP-v1-creation-token"` (26 o ASCII) ‖ tous les champs précédents. | done | `CreationToken.sign/verify`. |
| NCP-7.7-3 | DEF | Avec un seul rôle autorisé, le jeton fait **191 octets**. | done | Par construction (1+1+26+32+3+8+8+16+32+64). Pas de vecteur de test. |
| NCP-7.7-4 | DEF | Bits réservés des indicateurs à 0 (à l'émission) ; à la réception, rejet ou ignorance ? Non précisé. | done | Émission à 0 ; réception : `CreationToken.read` rejette (`WireError` ⇒ 0x0003 en admission, entrée ignorée en table). Ambiguïté F7-8 tranchée : rejet. |
| NCP-7.7-5 | DEF | Un jeton F permet de fonder l'USD : si le nœud ne trouve aucun nœud admis à la fin de l'amorçage [ARCH 5.2], il s'admet lui-même : table des nœuds avec sa propre entrée, journal Raft avec lui seul électeur, passage à « Actif ». | done | `_bootstrap_loop` (3 tours sans candidat) → `Node.found` (`Raft.found`). Test intégration (appel direct de `found`). |
| NCP-7.7-6 | DEVRAIT | L'opérateur NE DEVRAIT délivrer qu'un seul jeton fondateur par USD. | done | `Authority.mint_token` inscrit chaque jeton fondateur par USDN dans `<state>/authority/founders.json` et refuse un second fondateur pour le même USD sauf `allow_second_founder` explicite (jeton perdu). `tests/test_authority_services.py::test_only_one_founder_token_per_usd`. Registre local au poste opérateur. |
| NCP-7.7-7 | DEF | Un nœud qui trouve des nœuds admis ignore l'indicateur F et suit l'admission ordinaire. | done | `_bootstrap_loop` tente les candidats avant toute fondation. |
| NCP-7.7-8 | DEF | Le nœud génère ses clés avant le jeton ; la clé privée de l'USD n'est jamais présente sur les nœuds. | done | `load_identity` au premier démarrage ; clé USD seulement sur un poste opérateur (`Authority`, `<state>/authority/usd.key`, 0600, jamais affichée). |
| NCP-7.7-9 | DEF | Acceptation : version = 1 et USDN = USD du vérificateur. | done | Version contrôlée (`CreationToken.read`) ; `Node.check_token` compare `token.usdn` à `signed.usd.usdn` (contrôle sauté tant qu'aucune propriété USD n'est détenue, cas d'un nœud non synchronisé ; un endosseur actif en détient toujours). Non testé. |
| NCP-7.7-10 | DEF | Clé de l'émetteur = clé publique de l'USD (propriétés USD en vigueur, ou ancre de confiance dans la NAL). | done | `check_token` : `token.issuer` ∈ {`Node.usd_key`} (ancre, puis USD en vigueur, puis clé détenue). |
| NCP-7.7-11 | DEF | Signature valide. | done | `token.verify()`. |
| NCP-7.7-12 | DEF | Clé du nœud = clé de l'émetteur de la Request_approval. | done | `check_token(requester=message.sender)`. |
| NCP-7.7-13 | DEF | Heure locale ∈ [émission − fenêtre de fraîcheur (30 s), expiration]. | done | `check_token(for_admission=True)`. |
| NCP-7.7-14 | DEF | expiration − émission ≤ durée maximale de validité (**7 jours**). | done | `check_token` (constante 7 j) ; `Authority.mint_token` refuse au-delà. |
| NCP-7.7-15 | DEF | Rôles demandés ⊆ rôles autorisés. | done | `_on_request_approval` ⇒ 0x0007. |
| NCP-7.7-16 | DEF | Jeton non à usage unique : réutilisable pour la même clé jusqu'à expiration (après 0x0008, après fin de service de l'endosseur). | done | Aucun suivi d'usage du serial ; le jeton reste dans `admission.json`. |
| NCP-7.7-17 | DEF | Jeton accompagnant une entrée de table : mêmes règles **sauf** expiration (et sa fenêtre) et lien avec l'émetteur de la requête. | done | `accept_entry` → `check_token(for_admission=False)` : émetteur, signature, USDN, ≤ 7 jours (lecture retenue du texte), sans expiration ni lien à l'émetteur de la requête. |

#### 7.8 Fiche de nœud

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-7.8-1 | DEF | Format : Identifiant (26) ‖ IPv4 (32 bits) ‖ clé X25519 (32) ‖ état (16) ‖ indicateurs (8 : bit 0x80 E électeur, autres à 0) ‖ date (Date) ‖ mutation (Chaîne, longueur 0 si aucune) ‖ nœuds de référence (Liste d'Identifiants) ‖ adresses SP (Liste d'Entiers 32 bits) ‖ signature (64). | done | `codec.NodeRecord` (bits réservés rejetés à la lecture). `show node-table`. |
| NCP-7.8-2 | DEF | Signature sur `"USMD-NCP-v1-node-record"` (23 o ASCII) ‖ clé Ed25519 du nœud (32) ‖ tous les champs précédents ; la clé Ed25519 n'est pas dans la fiche (fournie par le jeton). | done | `NodeRecord.signed_bytes`, `TableEntry.verify`. |
| NCP-7.8-3 | DEF | L'adresse IPv4 est celle où le nœud reçoit NCP, NNDP et SP. | done | `settings.address` (adresse locale détectée ou configurée) dans `initial_record`/`publish_record`. |
| NCP-7.8-4 | DEF | Date d'émission **strictement croissante** pour un même nœud. | done | `record_date = max(record_date + 1, now_ms())` (persistée) ; réception : `NodeTable.merge` exige `>`. |
| NCP-7.8-5 | DEF | Nouvelle fiche à chaque changement d'adresse, d'état déclaré, d'indicateurs, de mutation, de nœuds de référence ou d'adresses SP. | done | `publish_record` appelé sur changement d'état, de mutation, de références, d'adresses SP ; d'indicateur E via `Raft.on_voter_change` → `Node._on_voter_change` ; d'adresse via `_maintenance_loop` (toutes les 30 s, `local_ipv4()` comparé à `settings.address`, seulement si `bind_address` vaut 0.0.0.0, nœud actif ou inactif). `test_raft_on_voter_change` (rappel Raft) ; le changement d'adresse n'est pas testé. |
| NCP-7.8-6 | DOIT | Un nœud NE DOIT inscrire dans sa fiche que des adresses SP attribuées par le maître. | done | `publish_record` dérive les adresses de `self.management`, rempli seulement par une réponse 0x00 du maître. |
| NCP-7.8-7 | DEF | Un nœud ne publie jamais d'état d'origine O (0x3200, 0x3400, famille 0x4000), qui restent locaux. | done | `publish_record` (et `_on_get_status`, NNDP) remplacent un état non `declarable` par 0x3000. |
| NCP-7.8-8 | DEF | Fiche valide ssi signature vérifiée avec la clé du jeton associé, état d'origine D, et date ≤ heure locale + fenêtre de fraîcheur (30 s). | done | `accept_entry`. |
| NCP-7.8-9 | DEF | Taille : 143 o (fiche initiale vide) ; 273 o avec 5 nœuds de référence, sans mutation ni SP ; +4 o par adresse SP. | done | Par construction (`NodeRecord._unsigned`). Pas de vecteur de test. |
| NCP-7.8-10 | DEF | Indicateur E positionné ssi le nœud est électeur (membre de la configuration Raft). | done | `publish_record` : `voter = raft.is_voter` ; `Raft._check_voter` (appelé après inscription, application, instantané, fondation) déclenche `on_voter_change` à chaque bascule, et `Node._on_voter_change` republie la fiche. `test_raft_on_voter_change`. |

#### 7.9 Propagation de la table des nœuds

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-7.9-1 | DEF | À la réception d'une entrée (requête ou réponse Send_node_table) : vérifier jeton (7.7) et fiche (7.8), ignorer en cas d'échec. | done | `Node.accept_entry` (après le filtre de date de 7.9-9). |
| NCP-7.9-2 | DEF | Ignorer l'entrée si la clé du nœud est exclue localement (famille 0x4000). | done | `accept_entry` (`exclusions.is_excluded`). |
| NCP-7.9-3 | DEF | Même identifiant avec une autre clé : garder l'entrée dont le jeton a la date d'**émission la plus ancienne**, ignorer l'autre. | done | `NodeTable.merge`. |
| NCP-7.9-4 | DEF | Date de fiche strictement postérieure à celle détenue pour cette clé, ou clé inconnue ⇒ remplacer/ajouter, mettre à jour la NIT (association adresse/clé, clé X25519), marquer modifiée. | done | `NodeTable.merge` + `_learn_entry`. |
| NCP-7.9-5 | DEF | Sinon ignorer. | done | `merge` renvoie `False`. |
| NCP-7.9-6 | DEF | Entrées modifiées relayées en incrément aux nœuds de référence **sauf l'émetteur**, après un regroupement d'au plus **1 s**. | done | `schedule_relay` / `_relay_once` (délai `relay_delay`, `_relay_from` mémorise la provenance de la dernière modification de chaque entrée) ; requêtes : `schedule_relay(message.sender, accepted)` ; réponses : `Node.send_table` appelle `schedule_relay(peer, accepted)`, donc le répondant n'est plus resservi. Test intégration (relais) ; l'exclusion de l'émetteur n'est pas testée. |
| NCP-7.9-7 | DEF | Réconciliation périodique (**600 s ± 25 %**) avec un nœud de référence tiré au hasard, en mode complet. | done | `_reconcile_loop` (`_jitter`, `random.choice`). |
| NCP-7.9-8 | DEVRAIT | Les décisions dépendant de l'état réel (choix du nœud de récupération, destination SP) DEVRAIENT être confirmées par Get_status ou un HIA récent. | done | Récupération : réponses fraîches à Request_help/emergency ; SP : `_NodeSpContext.peer` (HIA des voisins, état observé) ; guérison par Get_status (`_healing_loop`). |
| NCP-7.9-9 | DEVRAIT | Un récepteur DEVRAIT ignorer **sans vérification** les entrées dont la date de fiche n'est pas plus récente que celle détenue (sec. 10). | done | `Node.accept_entry` : `entry.record.date <= held.record.date` pour la même clé ⇒ retour immédiat, avant toute vérification de signature. Non testé. |

### 8. Paramètres

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-8-1 | DEF | Port UDP 9992. | done | `LocalSettings.ncp_port`, `transport.PORT`. |
| NCP-8-2 | DEF | Charge UDP max 1200 o. | done | `transport.MAX_UDP` ; champ CLI `max_udp_payload` sans effet. |
| NCP-8-3 | DEF | Texte en clair max par fragment 1111 o. | done | `transport.MAX_PLAIN`. |
| NCP-8-4 | DEF | Fragments max par message 1024. | done | `transport.MAX_FRAGMENTS` ; champ CLI `max_fragments` sans effet. |
| NCP-8-5 | DEF | Délai de réassemblage 10 s. | done | `REASSEMBLY_S` ; champ CLI sans effet. |
| NCP-8-6 | DEF | Délai de retransmission 2 s, doublé à chaque tentative. | done | `RETRANSMIT_S`, `settings.ncp_retransmit` (appliqué à chaud par `apply_local`). `test_timeout_schedule_without_extra_doubled_wait`. |
| NCP-8-7 | DEF | Tentatives de retransmission 3. | done | `ATTEMPTS`, `settings.ncp_attempts` (3 émissions, voir 5.7-11). |
| NCP-8-8 | DEF | Délai d'accusé de fragments 100 ms. | done | `ACK_DELAY_S` ; champ CLI `fragment_ack_delay` sans effet. |
| NCP-8-9 | DEF | Fenêtre de fraîcheur de l'horodatage 30 s. | done | `settings.freshness_s` (partagé avec NNDP : `config protocol nndp` et `config protocol ncp` écrivent la même valeur). |
| NCP-8-10 | DEF | Conservation des réponses 60 s. | done | `RESPONSE_CACHE_S` ; champ CLI `response_cache` sans effet. |
| NCP-8-11 | DEF | Messages en réassemblage par adresse 16. | done | `PER_SOURCE` ; champ CLI sans effet. |
| NCP-8-12 | DEF | Intervalle de diffusion des propriétés 60 s, gigue 25 %. | done | `settings.properties_interval` + `_jitter`. |
| NCP-8-13 | DEF | Durée d'exclusion temporaire 10 min. | done | `settings.exclusion_ms` (600 000). |
| NCP-8-14 | DEF | Durée maximale de validité d'un jeton 7 jours. | done | Constante dans `check_token` et `authority.MAX_TOKEN_VALIDITY_MS` (non configurable, absent de `NcpConfig`). |
| NCP-8-15 | DEF | Délai de regroupement des relais 1 s. | done | `settings.relay_delay`. |
| NCP-8-16 | DEF | Intervalle de réconciliation 600 s, gigue 25 %. | done | `settings.reconcile_interval` + `_jitter`. |
| NCP-8-17 | DEF | Battement de cœur Raft 1 s. | done | `settings.raft_heartbeat` (lu à la création de `Raft`). |
| NCP-8-18 | DEF | Délai d'élection Raft aléatoire 5..10 s. | done | `settings.raft_election` ; validateur `NcpConfig._raft`. |
| NCP-8-19 | DEF | Message dont l'horodatage s'écarte de plus de la fenêtre de fraîcheur (abs(ts − now) > 30 s) ⇒ rejet avec erreur **0x0002**. | done | Requêtes : `handle_request` ⇒ 0x0002. Réponses, erreurs et accusés de fragments : `NcpTransport._on_message` les abandonne sans suite (on ne répond pas à une réponse). `test_stale_response_is_dropped`. |

### 9. Codes d'erreur

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-9-1 | DEF | 0x0001 Commande non autorisée (rôle insuffisant, ou pas de relation de référence). | done | `ErrorCode.NOT_AUTHORISED`, `_check_sender`. `show ncp errors`. |
| NCP-9-2 | DEF | 0x0002 Horodatage hors fenêtre de fraîcheur. | done | `handle_request`. |
| NCP-9-3 | DEF | 0x0003 Corps malformé ou paramètre invalide. | done | `handle_request` (WireError/ValueError, commande inconnue). |
| NCP-9-4 | DEF | 0x0004 Destinataire occupé, réessayer plus tard. | done | Exception d'un traitement (`_on_request`) ; Request_approval reçue par un nœud non actif. La limite de réassemblage ignore sans répondre. |
| NCP-9-5 | DEF | 0x0005 Clé ou association (adresse, clé) inconnue. | done | `_check_sender`, `_on_request_management_id`. |
| NCP-9-6 | DEF | 0x0006 Version de l'objet obsolète ou signature d'autorité invalide. | done | `_on_send_*_properties` (signature) ; version obsolète ⇒ booléen faux (F7-6). |
| NCP-9-7 | DEF | 0x0007 Jeton absent, invalide, expiré ou non lié à la clé de l'émetteur. | done | `_on_request_approval`. |
| NCP-9-8 | DEF | 0x0008 Identifiant de nœud déjà utilisé dans l'USD par une autre clé. | done | `_on_request_approval`. |
| NCP-9-9 | DEF | 0x0009 Fiche invalide, ou adresse de la fiche ≠ adresse source. | done | `_on_request_approval`. |
| NCP-9-10 | DEF | 0x000A Commande réservée aux électeurs. | done | `_check_sender`. |
| NCP-9-11 | DEF | 0x000B Identifiant de service inconnu ou hors des aires du demandeur. | done | `allocate_management_ids`. |

### 10. Considérations de sécurité

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-10-1 | DEVRAIT | Il est RECOMMANDÉ de renouveler la clé X25519 statique en réadmettant le nœud. | done | `node.py:rekey` (commande `execute node rekey`) : nouvelles paires Ed25519/X25519 enregistrées, NCP, NNDP et SP rouverts aussitôt avec les nouvelles clés, retour à 0x0000 pour une nouvelle admission. |
| NCP-10-2 | DEF | La signature est vérifiée **avant toute action** ; les actions coûteuses (exécution, réponse volumineuse) n'ont lieu qu'après. | done | `_on_message` vérifie avant `_on_request`/handler (seuls le limiteur de débit, le contrôle d'adresse, l'AEAD et les accusés de fragments précèdent). |
| NCP-10-3 | DOIT | Les caches (identifiants de requête / réponses) DOIVENT être conservés au moins fenêtre de fraîcheur + temps cumulé des retransmissions (30 + 2 + 4 + 8 = 44 s ; 60 s par défaut). | done | `RESPONSE_CACHE_S = 60` (le champ CLI `response_cache`, qui accepterait < 44 s, est sans effet). |
| NCP-10-4 | DEVRAIT | Rejeter sans calcul (avant X25519) les datagrammes d'une adresse absente de la NIT, sauf Request_approval (événement 0x0005 lisible dans l'en-tête en clair). | done | `NcpTransport._new_assembly` : pour un événement ≠ 0x0005, `address_known(source)` faux ⇒ `WireError` avant `self._static.agree` ; `Node._address_known` = adresse de la NIT, nœud de contact configuré, ou adresse d'une fiche de la table (léger élargissement de « NIT »). Un groupe déjà réassemblé (`_completed`) est traité sans X25519. `test_unknown_address_refused_except_request_approval`. |
| NCP-10-5 | DEVRAIT | Limiter le débit de traitement par adresse. | done | `NcpTransport.datagram_received` : `datagram_limit` (`RateLimiter`, 200 datagrammes/s par adresse, table de 4096 sources avec éviction) avant tout traitement ; en plus, 3 Request_help/emergency par pair et par 10 s (`handlers._request_rate_ok`). `test_rate_limiter_window_and_bound`. |
| NCP-10-6 | DEVRAIT | Borner les états de réassemblage. | done | 16 par adresse, 256 en tout, 16 Mio de texte en clair, 4096 groupes terminés (voir 5.7-7). Non testé. |
| NCP-10-7 | DEVRAIT | Limiter par adresse source le débit des Request_approval. | done | `NcpTransport._new_assembly` : `approval_limit` (`RateLimiter`, 5 nouveaux messages 0x0005/s par adresse), avant X25519. `test_rate_limiter_window_and_bound` (limiteur) ; la limite propre à 0x0005 n'est pas testée. |
| NCP-10-8 | DEVRAIT | Ignorer sans vérification les entrées de table non plus récentes (= 7.9-9). | done | Voir 7.9-9 (`Node.accept_entry`). |
| NCP-10-9 | DOIT | Un destinataire NE DOIT PAS répondre à un message non authentifié (échec AEAD ou signature). | done | `datagram_received` (AEAD) et `_on_message` (signature) abandonnent sans réponse. |
| NCP-10-10 | DEF | Les réponses ne sont jamais plus volumineuses que nécessaire (pas d'amplification). | done | Réponse seulement à un émetteur authentifié dont la X25519 est connue ; clé inconnue ⇒ petite erreur, ou rien. |
| NCP-10-11 | DEF | Exclusions prononcées uniquement après vérification de signature ; un message rejoué n'entraîne jamais l'exclusion de son émetteur légitime. | done | Exclusions dans les handlers seulement (après `_on_message`) ; rejeux absorbés par le cache ou la fraîcheur (voir 7.6-3). |
| NCP-10-12 | DEVRAIT | La clé privée de l'USD DEVRAIT être conservée hors ligne. | done | `Authority` : clé facultative, propre au poste opérateur, avertissement à la création (`execute authority keygen`). |
| NCP-10-13 | DEVRAIT | Confronter les rôles d'un paquet d'endossement aux rôles autorisés du jeton (= 7.4-7). | done | Voir 7.4-7 (`Node.verify_endorsement_of`). |
| NCP-10-14 | DEVRAIT | Il est RECOMMANDÉ de limiter la durée de validité des paquets d'endossement. | done | Expiration = paramètre USD 0x000D ; vérifiée dans `verify_endorsement_of`. |
| NCP-10-15 | DEF | Un nœud admis peut revendiquer une adresse SP non attribuée ; seul un électeur peut le vérifier (vérification par les électeurs contre le journal). | done | `Node.accept_entry` : sur un électeur (`raft.is_voter` et `commit_index > 0`), chaque adresse SP de la fiche doit correspondre à une attribution de `raft.state.assignments` au même nœud (clé), sinon la fiche est ignorée et un événement journalisé. Les non-électeurs font confiance à la fiche (`_NodeSpContext.owner`), ce que le draft admet. Limite : l'électeur compare à l'état **appliqué** ; un suiveur qui n'a pas encore appris la validation (battement suivant) peut ignorer une fiche légitime, rattrapée par une republication ou la réconciliation (600 s). Non testé. |
| NCP-10-16 | DEF | Hypothèse : horloges à moins de 30 s de l'heure réelle. | n/a | Hypothèse opérationnelle ; `show clock` la rappelle. |

### 11. Considérations IANA (registres à refléter dans le code)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-11-1 | DEF | Port UDP 9992 « usmd-ncp ». | n/a | IANA. Reflété : `transport.PORT`. |
| NCP-11-2 | DEF | Commandes : 0x0000 réservé ; 0x0001..0x0014 attribués ; 0x0015..0x7FFF spécification requise ; 0x8000..0xFFFF expérimental. Un événement inconnu ⇒ comportement non spécifié (proposer erreur 0x0003 après authentification). | n/a | IANA. Reflété : `codec.Command` ; événement inconnu ⇒ 0x0003 après authentification (`handle_request`). |
| NCP-11-3 | DEF | Types de message 0x00..0x03. | n/a | IANA. Reflété : `codec.MessageType`. |
| NCP-11-4 | DEF | Types d'enregistrement Raft 0x01..0x05. | n/a | IANA. Reflété : `codec.RecordType`. |
| NCP-11-5 | DEF | Indicateurs du jeton : 0x80 Fondateur. | n/a | IANA. Reflété : `CreationToken` (0x80). |
| NCP-11-6 | DEF | Codes d'erreur 0x0001..0x000B. | n/a | IANA. Reflété : `codec.ErrorCode`, `show ncp errors`. |
| NCP-11-7 | DEF | Modes de Send_node_table 0x00/0x01. | n/a | IANA. Reflété : littéraux 0x00/0x01 de `send_table`/`_on_send_node_table`. |
| NCP-11-8 | DEF | Versions du jeton : 0x01. | n/a | IANA. Reflété : `CreationToken.version`. |
| NCP-11-9 | DEF | Rôles NAL 0x01..0x04. | n/a | IANA. Reflété : `codec.Role`. |
| NCP-11-10 | DEF | Registre des états de nœud et magic de [ARCH]. | n/a | IANA. Reflété : `node/states.State`, `wire.MAGIC`. |

### Annexe A. Tailles (vecteurs de test)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NCP-A-1 | DEF | Get_status requête : texte en clair 113 o ; fragment 9 + 64 + 113 + 16 = **202 o** de charge UDP. | done | Par construction (`Message.encode`, `seal_message`). Pas de vecteur de test. |
| NCP-A-2 | DEF | Fiche sans mutation, 5 nœuds de référence, sans SP : **273 o** ; +4 o par adresse SP. Entrée (jeton 1 rôle + fiche) : **464 o** + len(mutation) + 4×SP. | done | Par construction (`NodeRecord`, `TableEntry`). Pas de vecteur de test. |
| NCP-A-3 | DEF | Message de 1024 fragments = 1 137 664 o, ≈ 2 400 entrées par page. | done | `seal_message` (borne) ; `send_table` pagine à 1000 × 1111 o. |
| NCP-A-4 | DEF | Request_approval à 1 rôle : 49 (en-tête message) + 191 + 143 + 16 + 3 + 64 = **466 o**, un seul fragment. | done | `request_approval` (jeton ‖ fiche initiale ‖ nonce ‖ rôles). Pas de vecteur de test. |

---

## Formats binaires

Conventions : entiers non signés **grand-boutistes**, alignés sur l'octet ; `u8/u16/u32/u64` ; `Bool` = u8 (0x00/0x01) ; `Date` = u64 ms Unix ; `PM` (pour mille) = u16 0..1000 ; `Id` = 26 octets ASCII ULID canonique (Crockford base32, majuscules) ; `Str` = u16 longueur en octets + UTF-8 ; `List<T>` = u16 nombre d'éléments + éléments ; `‖` = concaténation. Les chaînes de contexte sont en ASCII **sans** octet de longueur ni terminateur NUL.

Conformité du code : tous les formats ci-dessous ont été comparés à `node/wire.py`, `node/ncp/codec.py`, `node/ncp/transport.py`, `node/raft.py`, `node/handlers.py` et `node/node.py` ; ils sont conformes. Le nonce de Request_approval est désormais aléatoire (6.7-2) ; la plage `PM` est contrôlée partout sauf dans la réponse Get_status lue par `_healing_loop` (6.1-1).

### F1. Fragment (datagramme UDP, ≤ 1200 o)

| Offset | Champ | Taille | Codage | Notes |
|---|---|---|---|---|
| 0 | Magic | 2 | u16 = 0xD5C1 | En-tête de trame |
| 2 | Version | 1 | u8 = 0x01 | |
| 3 | Événement | 2 | u16 | Code de commande 0x0001..0x0014 |
| 5 | Longueur | 4 | u32 | Octets après l'en-tête = 64 + len(C) + 16 |
| 9 | Clé éphémère | 32 | X25519 pub | Identique sur tous les fragments du message ; nouvelle par message |
| 41 | Sel | 16 | octets aléatoires | Identique sur tous les fragments |
| 57 | Nonce | 12 | octets aléatoires | Différent par fragment |
| 69 | Index | 2 | u16 | 0..Nombre−1 |
| 71 | Nombre | 2 | u16 | 1..1024 |
| 73 | Texte chiffré C | n | ChaCha20 | n ≤ 1111 ; n = 1111 sauf dernier fragment |
| 73+n | Étiquette | 16 | Poly1305 | |

Taille totale = 89 + n. AAD (61 o) = octets [0..9) ‖ [9..41) ‖ [41..57) ‖ [69..73) (en-tête complet, clé éph., sel, index, nombre ; nonce exclu).

Dérivation : `ss = X25519(eph_priv, X25519_dest_pub)` ; `K = HKDF-SHA256(salt=Sel, ikm=ss, info=b"USMD-NCP-v1" ‖ eph_pub ‖ X25519_dest_pub, L=32)` ; `C‖tag = ChaCha20-Poly1305-IETF-Encrypt(K, nonce, plaintext_slice, AAD)`. Le fragment d'index i chiffre `plaintext[i*1111 : (i+1)*1111]`.

Code : `transport.seal_message`, `parse_fragment`, `_key` — conforme.

### F2. Enveloppe (partie en clair, 64 o)

| Champ | Taille | Codage |
|---|---|---|
| Clé éphémère | 32 o | X25519 |
| Sel | 16 o | aléatoire |
| Nonce | 12 o | aléatoire |
| Index | 2 o | u16 |
| Nombre | 2 o | u16 |

Code : `transport.ENVELOPE = 64` — conforme.

### F3. Message (texte en clair réassemblé)

| Offset | Champ | Taille | Codage |
|---|---|---|---|
| 0 | Type | 1 | u8 : 0x00 Requête, 0x01 Réponse, 0x02 Erreur, 0x03 Accusé de fragments |
| 1 | Identifiant de requête | 8 | u64 (0 pour un accusé de fragments) |
| 9 | Horodatage | 8 | Date |
| 17 | Clé de l'émetteur | 32 | Ed25519 pub |
| 49 | Corps | variable | selon commande et type |
| fin−64 | Signature | 64 | Ed25519 |

Le corps se délimite par la fin du texte en clair moins 64. Signature : `Ed25519.sign(b"USMD-NCP-v1" ‖ u16 événement ‖ Ed25519_dest(32) ‖ type(1) ‖ reqid(8) ‖ ts(8) ‖ clé_émetteur(32) ‖ corps)`.

Code : `codec.Message.encode/decode/signed_bytes` — conforme.

### F4. Corps génériques

**Erreur (type 0x02)**

| Champ | Taille | Codage |
|---|---|---|
| Code | 2 | u16 (0x0001..0x000B) |
| Description | 0 ou 2+n | `Str` facultative — présente ssi des octets restent dans le corps |

Code : `codec.error_body` / `parse_error` — conforme (chaîne omise si vide).

**Accusé (réponse type 0x01, section 6.12)**

| Champ | Taille | Codage |
|---|---|---|
| Résultat | 1 | Bool |
| Version détenue | 0 ou 8 | Date facultative — présente ssi 8 octets restent |

Code : `codec.ack_body` / `parse_ack` — conforme.

**Accusé de fragments (type 0x03)**

| Champ | Taille | Codage |
|---|---|---|
| Sel | 16 | sel du message acquitté |
| Nombre | 2 | u16 |
| Bits reçus | ⌈Nombre/8⌉ | bit i ⇒ fragment i reçu. Ordre non spécifié ; hypothèse : octet i//8, masque `0x80 >> (i % 8)` (MSB en premier, cohérent avec l'ordre réseau) ; bits de remplissage à 0 |

Code : `codec.fragment_ack_body` / `parse_fragment_ack` — hypothèse MSB d'abord retenue, bits de remplissage à 0 (non vérifiés à la lecture).

Ambiguïtés de l'accusé de fragments à trancher : événement de l'en-tête = commande du message acquitté (hypothèse) ; l'accusé est chiffré vers la clé X25519 de l'émetteur (NIT/table, ou fiche de Request_approval) — un accusé « dès le premier fragment » suppose de connaître l'émetteur, ce qui n'est possible qu'à partir du fragment 0 (en-tête du message) ou de l'adresse source via la NIT. **Tranché par le code** (`NcpTransport._send_ack`) : événement = celui du message acquitté ; clé de l'émetteur lue dans le fragment 0, X25519 via `Node.x25519_of` ; aucun accusé tant que le fragment 0 n'est pas reçu.

### F5. Types composés

**Aire** (Send_usd_properties)

| Champ | Taille | Codage |
|---|---|---|
| Identifiant | 1 | u8 |
| Nom | 2+n | Str |
| Préfixe | 4 | u32 (IPv4) |
| Longueur de masque | 1 | u8, 8..32 |

**Service**

| Champ | Taille | Codage |
|---|---|---|
| Identifiant | 2 | u16, 4 bits forts = 0, ∉ {0x000, 0xFFF} |
| Nom | 2+n | Str |
| Aire | 1 | u8 (identifiant d'aire) |
| VIP | 4 | u32 IPv4, dans le préfixe de l'aire |
| Groupe | 4 | u32 IPv4, 0 ou dans 239.0.0.0/8 |

**Paramètre USD** : code u16 ‖ valeur u32 (6 o). Le code les émet triés par code (`UsdProperties._unsigned`).

**Mutation** (Send_mutation_properties)

| Champ | Taille | Codage |
|---|---|---|
| Identifiant | 2+n | Str |
| Version | 8 | Date |
| Temps de transmutation moyen | 4 | u32 ms |
| Nombre minimal de services | 2 | u16 |
| Nombre maximal de services | 2 | u16 |
| Longueur du fichier | 4 | u32 |
| Fichier de service | L | YAML UTF-8 |
| Signature d'autorité | 64 | Ed25519 (clé USC) sur les champs précédents **de cette mutation** (hypothèse ; pas de chaîne de contexte spécifiée) |

Code : `codec.MutationProperties` — hypothèse retenue (clé USC, sans contexte, par mutation).

**Paquet d'endossement** (7.1)

| Champ | Taille | Codage |
|---|---|---|
| Clé Ed25519 de l'endosseur | 32 | |
| Identifiant du nouveau nœud | 26 | Id |
| Clé Ed25519 du nouveau nœud | 32 | |
| Clé X25519 du nouveau nœud | 32 | |
| Rôles accordés | 2+k | List<u8> |
| Serial | 16 | aléatoire |
| Expiration | 8 | Date |
| Signature | 64 | Ed25519(endosseur) sur `b"USMD-NCP-v1-endorsement"` ‖ champs précédents |

Taille = 202 + k. Code : `codec.EndorsementPacket` — conforme.

**Jeton de création** (7.7)

| Offset | Champ | Taille | Codage |
|---|---|---|---|
| 0 | Version | 1 | u8 = 1 |
| 1 | Indicateurs | 1 | u8 ; 0x80 = F (fondateur) ; autres bits 0 |
| 2 | USDN | 26 | Id |
| 28 | Clé du nœud | 32 | Ed25519 |
| 60 | Rôles autorisés | 2+k | List<u8> |
| 62+k | Émission | 8 | Date |
| 70+k | Expiration | 8 | Date |
| 78+k | Serial | 16 | aléatoire |
| 94+k | Clé de l'émetteur | 32 | Ed25519 de l'USD |
| 126+k | Signature | 64 | sur `b"USMD-NCP-v1-creation-token"` ‖ octets [0 .. 126+k) |

Taille = 190 + k (191 pour k = 1). Code : `codec.CreationToken` — conforme ; texte base64url sans remplissage côté CLI.

**Fiche de nœud** (7.8)

| Champ | Taille | Codage |
|---|---|---|
| Identifiant | 26 | Id |
| Adresse IPv4 | 4 | u32 |
| Clé X25519 | 32 | statique |
| État | 2 | u16, origine D |
| Indicateurs | 1 | u8 ; 0x80 = E (électeur) ; autres 0 |
| Date | 8 | Date, strictement croissante |
| Mutation | 2+m | Str (m = 0 si aucune) |
| Nœuds de référence | 2+26r | List<Id> |
| Adresses SP | 2+4s | List<u32> (service 12 bits ‖ gestion 16 bits selon ARCH 11.3) |
| Signature | 64 | sur `b"USMD-NCP-v1-node-record"` ‖ clé Ed25519 du nœud (32, issue du jeton) ‖ champs précédents |

Taille = 143 + m + 26r + 4s. Code : `codec.NodeRecord`, `addresses.pack` — conforme.

**Entrée de table** = Jeton ‖ Fiche (auto-délimités). Code : `codec.TableEntry`, `tables.Entry.encode`.

### F6. Corps par commande

| Code | Commande | Requête (type 0x00) | Réponse (type 0x01) |
|---|---|---|---|
| 0x0001 | Get_status | vide | RAM PM(2) ‖ CPU PM(2) ‖ disque PM(2) ‖ réseau PM(2) ‖ service en cours Str ‖ état u16 |
| 0x0002 | Check_distance_to_node | date d'envoi Date(8) | date reçue Date(8) ‖ charge de référence PM(2) ‖ service hébergé Str ‖ émetteur est mon nœud de référence Bool(1) |
| 0x0003 | Request_emergency | motif u16 (0x3301..0x3304) ‖ sollicités List<Id> ‖ charge de référence PM(2) | peut relayer Bool ‖ nœuds de récupération List<Id> |
| 0x0004 | Request_help | motif u16 (=0x0000) ‖ sollicités List<Id> ‖ charge de référence PM | peut relayer Bool ‖ nœuds de récupération List<Id> |
| 0x0005 | Request_approval | Jeton ‖ Fiche (état 0x0000, mutation vide, sans nœud de référence) ‖ nonce 16 o ‖ rôles demandés List<u8> | Bool (=0x01) ‖ Paquet d'endossement ; refus = Erreur 0x0007/0x0008/0x0009/… |
| 0x0006 | Send_usc_properties | USCN Id ‖ version Date ‖ clé USC 32 ‖ USD List<Id> ‖ signature d'autorité 64 (sur les champs précédents) | appliqué Bool ‖ version détenue Date |
| 0x0007 | Send_usd_properties | USDN Id ‖ version Date ‖ clé USD 32 ‖ aires List<Aire> ‖ catalogue List<Service> ‖ paramètres List<(u16,u32)> ‖ signature d'autorité 64 | appliqué Bool ‖ version détenue Date (rejet de validité : Erreur 0x0003) |
| 0x0008 | Send_mutation_properties | List<Mutation> (signature dans chaque mutation) | appliqué Bool ‖ version détenue Date |
| 0x0009 | Inform_reference_node | List<Id> | Accusé (Bool ‖ [Date]) |
| 0x000A | Endorsement_check_required | vide | Paquet d'endossement |
| 0x000B | Verify_endorsement | Paquet d'endossement | Bool |
| 0x000C | Notify_end_of_service | Id de l'endosseur (26) | Accusé |
| 0x000D | Request_revocation | Id du nœud qui disparaît (26) | Accusé |
| 0x000E | Confirm_delegation | service Str ‖ motif u16 | Bool |
| 0x000F | Declare_state | état u16 ‖ [validité Date] (facultatif, présent ssi 8 octets restent) | Accusé |
| 0x0010 | Send_node_table | mode u8 (0x00/0x01) ‖ page u16 ‖ nombre de pages u16 ‖ entrées List<Entrée> | entrées List<Entrée> |
| 0x0011 | Request_management_id | services List<u16> | statut u8 ‖ terme u64 ‖ maître Id (26 × 0x00 si inconnu) ‖ électeurs List<Id> ‖ attributions List<(u16 service, u16 gestion)> |
| 0x0012 | Raft_request_vote | pré-vote Bool ‖ terme u64 ‖ candidat Id ‖ dernier index u64 ‖ dernier terme u64 | terme u64 ‖ accordé Bool |
| 0x0013 | Raft_append_entries | terme u64 ‖ maître Id ‖ index précédent u64 ‖ terme précédent u64 ‖ index de validation u64 ‖ List<Enregistrement> | terme u64 ‖ succès Bool ‖ dernier index concordant u64 |
| 0x0014 | Raft_install_snapshot | terme u64 ‖ maître Id ‖ dernier index inclus u64 ‖ dernier terme inclus u64 ‖ page u16 ‖ nombre de pages u16 ‖ [électeurs List<(Id, clé 32)> — page 0 seulement] ‖ attributions List<(u16, u16, Id, clé 32)> | terme u64 |

Tailles fixes utiles : Get_status réponse = 8 + 2 + len(service) + 2 ; Check_distance requête = 8 ; Raft_request_vote requête = 1 + 8 + 26 + 8 + 8 = 51, réponse = 9 ; Raft_append_entries réponse = 17 ; Raft_install_snapshot réponse = 8 ; élément d'attribution de snapshot = 76 o ; électeur de snapshot = 58 o.

Code (émetteur / récepteur) : 0x0001 `_on_get_status` / `_healing_loop` ; 0x0002 `measure` / `_on_check_distance_to_node` ; 0x0003-0x0004 `_ask` / `_help_or_emergency` ; 0x0005 `request_approval` / `_on_request_approval` (nonce aléatoire) ; 0x0006-0x0008 `push_properties`, `_synchronise` / `_on_send_*` ; 0x0009 `inform_references` / `_on_inform_reference_node` ; 0x000A-0x000B `verify_endorsement_of` / `_on_endorsement_check_required`, `_on_verify_endorsement` ; 0x000C-0x000D `retire` / `_on_notify_end_of_service`, `_on_request_revocation` ; 0x000E `request_help`, `delegate_all` / `_on_confirm_delegation` (Str = nom de mutation) ; 0x000F `delegate_all`, `execute node state` / `_on_declare_state` (Date facultative lue, jamais émise) ; 0x0010 `send_table` / `_on_send_node_table` ; 0x0011 `request_management_ids` / `allocate_management_ids` ; 0x0012-0x0014 `Raft._ballot`, `_replicate_to`, `snapshot_pages` + `_send_snapshot` / `handle_vote`, `handle_append`, `handle_snapshot`. Toutes les dispositions sont conformes au tableau.

**Enregistrement Raft**

| Champ | Taille | Codage |
|---|---|---|
| Terme | 8 | u64 |
| Type | 1 | u8 |
| Longueur des données | 2 | u16 |
| Données | L | selon type |

| Type | Nom | Données | L |
|---|---|---|---|
| 0x01 | Attribution | service u16 ‖ gestion u16 ‖ Id nœud 26 ‖ clé Ed25519 32 | 62 |
| 0x02 | Libération | service u16 ‖ gestion u16 | 4 |
| 0x03 | Ajout d'électeur | Id 26 ‖ clé Ed25519 32 | 58 |
| 0x04 | Retrait d'électeur | Id 26 | 26 |
| 0x05 | Aucune opération | vide | 0 |

Code : `codec.LogRecord` (longueur imposée par type), `raft.assign_record/release_record/voter_record` — conforme.

**Statuts de Request_management_id** : 0x00 attribué ; 0x01 pas le maître ; 0x02 maître sans quorum ; 0x03 maître inconnu.

**Rôles** : 0x01 Usc_operator ; 0x02 Usd_operator ; 0x03 Node_operator ; 0x04 Node_executor.

**Modes Send_node_table** : 0x00 complète ; 0x01 incrément.

### F7. Ambiguïtés relevées (état de résolution dans le code)

1. Ordre des bits du champ de bits de l'accusé de fragments (hypothèse MSB-first). — **Résolu** : MSB d'abord (`codec.fragment_ack_body`).
2. Événement porté par un accusé de fragments et moyen de le chiffrer avant d'avoir reçu le fragment 0. — **Résolu** : événement du message acquitté ; aucun accusé avant le fragment 0 (`transport._send_ack`). Reste à faire valider par le draft.
3. Retransmission d'une requête mono-fragment : renvoi du même datagramme ou nouvelle enveloppe (nouvelle clé éphémère imposée par 5.4) ? Le cache de réponses doit fonctionner dans les deux cas. — **Résolu** : même datagramme (`NcpTransport.request`) ; le destinataire reconnaît le groupe déjà réassemblé (`_completed`, AEAD seul, sans X25519) et renvoie les datagrammes de la réponse d'origine (`test_duplicate_request_answered_from_cache`). Lié : « jusqu'à 3 tentatives » est lu comme 3 émissions avec attentes 2/4/8 s (`test_timeout_schedule_without_extra_doubled_wait`) ; à confirmer par le draft.
4. Champs facultatifs (chaîne d'erreur, Date de l'accusé, Date de Declare_state) : présence déduite de la longueur restante (hypothèse). — **Résolu** pour les trois (`parse_error`, `parse_ack`, `_on_declare_state` : Date ssi 8 octets restent, autre reste ⇒ 0x0003). La Date de Declare_state n'est jamais émise et son usage reste à préciser par le draft (le code la retient sans l'exploiter).
5. Signatures d'autorité (USC, USD, mutation) : pas de chaîne de contexte ni de précision sur la couverture exacte pour la mutation ; clé d'autorité = clé USC (hypothèse). — **Résolu** selon l'hypothèse : pas de contexte, signature des champs précédents de l'objet (de chaque mutation), clé = ancre USC ou clé USC détenue (`Node.usc_key`).
6. Refus d'application des propriétés : réponse booléen faux ou erreur 0x0006 ? — **Résolu** : signature invalide ou clé d'autorité inconnue ⇒ erreur 0x0006 ; version non postérieure ⇒ réponse booléen faux + version détenue ; objet USD invalide ⇒ erreur 0x0003.
7. Champ électeurs de Raft_install_snapshot en page > 0 : absent (hypothèse) ou liste vide. — **Résolu** : absent, à l'émission (`Raft.snapshot_pages`) comme à la lecture (`handle_snapshot`) ; désormais exercé, l'instantané étant paginé (`test_raft_snapshot_installed_in_several_pages`).
8. Bits réservés à 1 dans les indicateurs du jeton/de la fiche : rejet ou ignorance. — **Résolu** : rejet (`WireError` ; 0x0003 en admission, entrée ignorée dans la table).
9. Règle 6.1 « clé dans la NIT avec l'IP source » vs 7.6 (ignorer) vs erreur 0x0005 : quand répondre 0x0005 plutôt qu'ignorer. — **Résolu** : clé inconnue ⇒ 0x0005 ; clé connue, couple inconnu ⇒ mise à jour depuis la table si la fiche porte l'adresse, sinon exclusion 0x4000 sans réponse (`_check_sender`).
10. Événement inconnu (0x0015+) : pas de comportement spécifié. — **Résolu** : erreur 0x0003 après authentification (`handle_request`).
11. Comment le destinataire connaît-il les nœuds de référence de l'émetteur (pour 6.1-4) : via Inform_reference_node et/ou la fiche. — **Résolu** : union des deux (`_am_reference_of`) ; Inform_reference_node est accepté de tous et refusé en 0x0001 s'il ne nomme pas le destinataire. Écart restant : Send_node_table accepté d'un nœud endossé pendant sa synchronisation (6.1-4).
12. (Nouveau) Le fondateur n'a pas d'endosseur : que répond-il à Endorsement_check_required, et qui confirme son paquet ? — **Ouvert** ; le code renvoie un paquet auto-signé et se confirme lui-même (`_on_endorsement_check_required`, `_on_verify_endorsement`).
13. (Nouveau) Un nœud de contact hors du segment n'est jamais entendu par NNDP : d'où le demandeur tient-il sa X25519 (et l'endosseur celle du demandeur pour lui renvoyer une erreur) ? — **Ouvert** pour le demandeur : le code prend les clés du contact dans `config system bootstrap contact-node-ed25519/-x25519`. **Résolu** côté endosseur : la X25519 du demandeur est lue dans la fiche portée par la Request_approval (`_remember_requester`, `reply_x25519`), ce qui permet de lui renvoyer un refus (6.7-5) ; le draft pourrait l'écrire explicitement. Le nœud de contact est aussi admis par le filtre d'adresse de 10-4 (`Node._address_known`).
15. (Nouveau) « Tentatives de retransmission : 3 » : trois émissions en tout (lecture du code) ou trois retransmissions après la première émission ? Le calendrier « 2, 4, 8 s » suggère la première lecture.
16. (Nouveau) Filtre de 10-4 « adresse absente de la NIT » : le code l'élargit au nœud de contact et aux adresses des fiches de la table (une entrée de la NIT expire avec son TTL alors que la fiche reste valable). Le draft pourrait préciser la source de vérité.
14. (Nouveau) « Identifiant du service délégué (Chaîne) » de Confirm_delegation : nom de service du catalogue ou nom de mutation ? — Le code envoie le nom de la mutation.

---

---

# Partie 3 — NNDP

## Cahier de recette NNDP — draft-usmd-nndp-01

Source : `readme/drafts/draft-usmd-nndp-01` (22 octobre 2026). Code analysé : branche `feature/cli-web-interface`,
implémentation `src/usmd_rdsh/node/` (`nndp.py`, `wire.py`, `crypto.py`, `addresses.py`, `identity.py`, `states.py`,
`tables.py`, crochets NNDP de `node.py`), côté gestion `cli/actions/nndp.py`, `cli/views/protocol.py`, `cli/bridge.py`,
`web/server.py`, `web/static/index.html` ; tests `tests/test_nndp01.py`. L'ancien prototype (`proto/**`, `self/**`,
`sys/**`) est remplacé et n'est plus utilisé par l'application : il n'est plus évalué ici.

Légende des états :

| État | Sens |
|---|---|
| done | Implémenté et conforme au texte ; fonction et test (ou vérification) indiqués en « Remarque » |
| partial | Implémenté en partie ; ce qui manque est dans « Remarque » |
| missing | Absent du code |
| config-only | Le paramètre existe (CLI/config) mais aucun comportement protocolaire ne l'utilise |
| open | Point ouvert ou incohérence du draft |
| n/a | Exigence administrative, informative ou d'exploitation, non vérifiable dans le code (IANA, déploiement) |

Niveaux : DOIT / NE DOIT PAS / DEVRAIT / NE DEVRAIT PAS / PEUT ; « DEF » = définition normative (format, valeur, algorithme) testable sans mot-clé BCP 14.

Constat global : `node/nndp.py` implémente le **format -01 complet** : en-tête commun de 9 octets (`wire.FrameHeader`,
magic 0xD5C1, version 1, longueur en octets contrôlée exactement), charge HIA avec L = 26, ULID ASCII, prochaine
émission, état, horodatage, clé X25519, services hébergés (H ≤ 32) et vecteur (V ≤ 120, entrées de 7 octets).
L'exemple de l'annexe A est reproduit à l'octet près (trame de 109 octets, datagramme de 205 octets), désormais
couvert par `test_annex_a_example_bytes`. La réception applique tous les contrôles de 6.2 (port, taille, en-tête
avant la signature, signature, ULID/état, fraîcheur, rejeu et monotonie, intervalle, listes), puis la confrontation à
la NIT, après une limitation de débit par adresse source (`_rate_ok`, 20 datagrammes/s). `NndpService` émet en
diffusion et en unicast vers les nœuds de référence (retour empoisonné), émet des HIA anticipés espacés d'au moins 1 s
(seulement quand l'hébergement ou une meilleure instance change), détecte l'inactivité à 2 × I **par clé** quelle que
soit l'adresse (0x3400 via `Node._on_neighbor_inactive`, effacé par tout HIA valide), et `NearestServices` tient la
table des K instances les plus proches (métrique D' avec un RTT issu du seul Check_distance réussi, sauts, expiration
3 × I purgée avant chaque annonce, retrait en 65 535 pendant 3 intervalles avec une seule entrée par service, instance
locale jamais évincée, plafond `MAX_PER_SENDER` par émetteur, propres adresses SP issues des identifiants de gestion).
F NNDP est indépendant de F NCP (`nndp_freshness_s`) et les ports ne sont plus configurables.

Re-vérification (après corrections) : tous les écarts relevés au premier audit sont levés sauf un. Reste **partial**
la limitation de débit (NNDP-8-8), faite par adresse source mais pas par clé. Reste **open** NNDP-4-10 (incohérence
du draft sur la copie unicast). Réserve d'affichage hors exigence : `cli/actions/nndp.py` (`show nndp`, page web)
affiche `settings.freshness_s` (F NCP) au lieu de `nndp_freshness_s`.

Bilan de la partie : 130 exigences ; 124 done, 1 partial, 0 missing, 1 open, 4 n/a.

---

### 1. Introduction et portée (sections 1, 2, 3)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-1-1 | DEF | NNDP permet à un nœud d'annoncer sa présence, de prouver la détention d'une clé Ed25519 et de signaler la cadence de ses annonces. | done | `nndp.HereIAm` (prochaine émission + horodatage → `interval_ms`), `HereIAm.sign` ; test `test_freshness_interval_and_excluded_state`. |
| NNDP-1-2 | DEF | NNDP transporte dans le même message les services hébergés et les instances de service les plus proches, propagés de proche en proche (vecteur de distances). | done | `HereIAm.hosted`/`vector`, `NearestServices.receive`/`vector` ; test `test_vector_distance_hops_poisoning_and_expiry`. |
| NNDP-1-3 | DEF | NNDP ne gère ni l'admission (NCP Request_approval), ni la hiérarchie nœud/USD/USC, ni le transport des services (SP). | done | `nndp.py` ne fait qu'appeler des crochets (`NndpHooks`) ; admission, tables et SP restent dans `node.py`/`node/sp`. |
| NNDP-2-1 | DEF | Adresse SP = (identifiant de service 12 bits, identifiant de gestion 16 bits) codée sur 32 bits, notée `sss.mmmm` (ex. `0a1.5d68`) ; les 4 bits de poids fort valent donc 0. | done | `addresses.pack/unpack/to_text/from_text` ; test `test_sp_address_text_form`. |
| NNDP-2-2 | DEF | L'identifiant de nœud est un ULID. | done | `identity.py` (`ulid.new().str`, contrôle `is_ulid` au chargement) ; réception `wire.Reader.ident` → `is_ulid`. |
| NNDP-3-1 | DEF | NNDP est sans connexion et sans réponse : aucun message de réponse n'est défini. | done | `NndpService.handle_datagram` ne répond jamais (compteur `rejected` + journal debug). |
| NNDP-3-2 | DEF | Un nœud émet un HIA toutes les I secondes (15 s par défaut), en diffusion et en unicast vers chacun de ses nœuds de référence. | done | `NndpService._emit_loop` → `emit` (diffusion puis `reference_addresses`). Pas de test d'émission socket. |
| NNDP-3-3 | DEF | Le récepteur vérifie signature et fraîcheur puis met à jour sa connaissance de l'émetteur, de ses services hébergés et de sa table des services les plus proches. | done | `check_datagram` + `NndpService.accept` ; test `test_replay_ordering_nit_and_inactivity`. |

### 2. Transport (section 4)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-4-1 | DEF | NNDP fonctionne sur UDP et IPv4 uniquement ; IPv6 hors périmètre. | done | `NndpService.start` : `AF_INET, SOCK_DGRAM`. |
| NNDP-4-2 | DOIT | Un HIA DOIT être émis en diffusion limitée vers 255.255.255.255. | done | `NndpService.emit` → `sendto(..., (BROADCAST, destination_port))`, `SO_BROADCAST` dans `start`. |
| NNDP-4-3 | DOIT | Un nœud admis DOIT en outre envoyer chaque HIA en unicast à l'adresse IPv4 de chacun de ses nœuds de référence, telle que donnée par sa NIT. | done | `NndpService.emit` (sauf état 0x0000) sur `Node.reference_addresses` ; l'adresse vient de l'enregistrement de la table des nœuds, qui est aussi celle inscrite dans la NIT par `_learn_entry`. Pas de test. |
| NNDP-4-4 | DEF | Port UDP de destination 5222 ; port UDP source 5221. | done | `SOURCE_PORT`/`DESTINATION_PORT` ; socket d'émission liée à 5221 (`start`). Plus configurables depuis la CLI ni le web (`NndpConfig` sans port) ; voir NNDP-7-4/7-5. |
| NNDP-4-5 | DOIT | Un nœud DOIT écouter sur le port 5222. | done | `start` : `recv_sock.bind(("0.0.0.0", destination_port))`. |
| NNDP-4-6 | DOIT | Un nœud DOIT ignorer tout datagramme dont le port source n'est pas 5221. | done | `check_datagram` (premier contrôle) ; test `test_reception_checks[source port]`. |
| NNDP-4-7 | NE DOIT PAS | Un datagramme NNDP NE DOIT PAS être fragmenté. | done | Taille bornée par construction à 1155 o (`encode_payload` refuse H > 32 / V > 120, `build` découpe le vecteur) ; aucun bit DF positionné, le plafond 1200 o du draft fait office de garantie. |
| NNDP-4-8 | DEF | Taille d'un datagramme ≥ 187 octets. | done | HIA vide = 187 o ; test `test_empty_hia_is_187_bytes_and_full_is_1155`. |
| NNDP-4-9 | NE DOIT PAS | La taille NE DOIT PAS dépasser 1200 octets. | done | Émission ≤ 1155 o par construction ; réception : `check_datagram` refuse > `MAX_DATAGRAM`. |
| NNDP-4-10 | DEF | Un nœud de référence situé sur le même segment reçoit deux copies (diffusion + unicast) ; la seconde est rejetée comme rejeu, sans effet. | open | Incohérence du draft : le HIA unicast porte le vecteur empoisonné (6.1), il n'est donc pas une copie du HIA diffusé. Le code (`emit` → `build(towards=key)`) le construit et l'horodate à part : s'il tombe dans la même milliseconde il est rejeté comme rejeu (et le retour empoisonné est perdu), sinon il est accepté. À trancher dans le draft (même horodatage imposé, ou deux HIA distincts assumés). |

### 3. Format des messages — ordre des octets et datagramme (sections 5.1, 5.2)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-5.1-1 | DEF | Entiers en ordre réseau (grand-boutiste), bit de poids fort en premier. | done | `wire.Writer`/`Reader` et `HEADER` en `struct` `"!"` ; annexe A reproduite. |
| NNDP-5.1-2 | DEF | Tous les champs sont alignés sur l'octet. | done | Aucun champ binaire non multiple de 8 bits dans `HereIAm.encode_payload`. |
| NNDP-5.2-1 | DEF | Datagramme = clé publique Ed25519 de l'émetteur (32 o) ‖ signature Ed25519 (64 o) ‖ trame signée (en-tête 9 o + charge 82 à 1050 o). | done | `HereIAm.sign` : `key.public + key.sign(signed) + signed` ; `check_datagram` découpe 32/64/reste ; tests de taille 187/1155. |
| NNDP-5.2-2 | DEF | La signature porte sur l'intégralité de la trame (en-tête + charge). | done | `HereIAm.sign` signe `frame(EVENT_HIA, payload)` ; test `test_reception_checks[signature]` (dernier octet de charge altéré). |
| NNDP-5.2-3 | DEF | Signature calculée selon RFC 8032 avec la clé privée correspondant à la clé publique placée en tête. | done | `crypto.SigningKey.sign` / `crypto.verify` (Ed25519 de `cryptography`). |

### 4. En-tête de trame (section 5.3)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-5.3-1 | DEF | En-tête de 9 octets commun NNDP/NCP/SP : Magic (16) ‖ Version (8) ‖ Événement (16) ‖ Longueur (32). | done | `wire.HEADER = Struct("!HBHI")`, `FrameHeader.encode` ; annexe A vérifiée (`d5c1 01 0001 00000064`). |
| NNDP-5.3-2 | DEF | Magic = 0xD5C1 placé aux octets 0-1 de la trame. | done | `wire.MAGIC`, `FrameHeader.encode`. |
| NNDP-5.3-3 | DOIT | Un récepteur DOIT rejeter toute trame qui ne commence pas par 0xD5C1. | done | `FrameHeader.decode` (« bad magic »), appelé par `check_datagram` avant la signature. Test `test_bad_header_fields_are_refused[magic]`. |
| NNDP-5.3-4 | DEF | Version = 1 dans ce document (8 bits). | done | `wire.VERSION = 1`. |
| NNDP-5.3-5 | DOIT | Un récepteur DOIT rejeter toute version non prise en charge. | done | `FrameHeader.decode` (« unsupported version »). Test `test_bad_header_fields_are_refused[version]`. |
| NNDP-5.3-6 | DEF | Événement 16 bits ; 0x0001 = Here I am ; autres valeurs réservées. | done | `EVENT_HIA = 0x0001` ; `check_datagram` rejette tout autre événement. |
| NNDP-5.3-7 | DEF | Longueur 32 bits = taille de la charge **en octets**, en-tête exclu. | done | `wire.frame` : `len(payload)`. |
| NNDP-5.3-8 | DOIT | Un récepteur DOIT rejeter la trame si la longueur ne correspond pas à la taille réelle de la charge. | done | `FrameHeader.decode(expect_exact=True)`. Test `test_bad_header_fields_are_refused[length]`. |

### 5. Charge Here I am (section 5.4)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-5.4-1 | DEF | Octets 0-1 : longueur de l'identifiant L, 16 bits. | done | `encode_payload` : `u16(26)` en tête de charge. |
| NNDP-5.4-2 | DOIT | En version 1, L DOIT valoir 26. | done | Émission : constante 26 + `Writer.ident` exige 26 caractères ; réception : `decode_payload` rejette L ≠ 26. |
| NNDP-5.4-3 | DEF | Octets 2-27 : identifiant = ULID textuel canonique 26 caractères (Crockford base 32), codé ASCII. | done | `Writer.ident` (ASCII), `Reader.ident` → `wire.is_ulid` (alphabet Crockford, 1er caractère ≤ 7). |
| NNDP-5.4-4 | DEF | Octets 28-35 : prochaine émission, 64 bits, ms depuis l'époque Unix. | done | `u64(next_emission)` ; annexe A vérifiée. |
| NNDP-5.4-5 | DEF | Octets 36-37 : état du nœud, 16 bits, code du registre USMD-ARCH. | done | `u16(state)`, `states.State`. |
| NNDP-5.4-6 | NE DOIT PAS | Un nœud NE DOIT PAS émettre de code de la famille 0x4000 (Exclu). | done | `encode_payload` lève `WireError` ; crochet `Node._start_nndp.state` remplace un état exclu par 0x3000 ; test `test_freshness_interval_and_excluded_state`. |
| NNDP-5.4-7 | DEF | Octets 38-45 : horodatage d'émission, 64 bits, ms Unix, horloge de l'émetteur. | done | `u64(timestamp)`, `NndpService.build` (`now_ms()`). |
| NNDP-5.4-8 | DEF | Octets 46-77 : clé publique X25519 statique de l'émetteur, 32 octets, utilisée pour chiffrer les messages NCP qui lui sont destinés. | done | `raw(x25519)` = `identity.x25519_public` ; utilisée par `Node.x25519_of` et `candidates`. |
| NNDP-5.4-9 | DEF | Octets 78-79 : nombre H de services hébergés, 16 bits. | done | `u16(len(hosted))`. |
| NNDP-5.4-10 | DEF | Octets 80-… : H adresses SP de 4 octets ; instances exécutées par l'émetteur dont le dernier contrôle de santé a réussi. | done | Crochet `hosted` = `Node.hosted` (alimenté par `_host`/`_withdraw` selon `check_health`). |
| NNDP-5.4-11 | DEF | H ≤ 32 ; liste vide pour un nœud non admis. | done | `build` : `hosted[:MAX_HOSTED]`, listes vidées en état 0x0000 ; test `test_unadmitted_node_announces_empty_lists`. |
| NNDP-5.4-12 | DEF | Puis nombre V d'entrées du vecteur, 16 bits. | done | `u16(len(vector))`. |
| NNDP-5.4-13 | DEF | Puis V entrées de 7 octets : adresse SP (32 bits) ‖ distance D (16 bits, millièmes, 65 535 = inaccessible) ‖ nombre de sauts (8 bits). | done | `u32 ‖ u16 ‖ u8` ; annexe A vérifiée. |
| NNDP-5.4-14 | DEF | Vecteur : au plus une entrée par service et 120 entrées par HIA ; vide pour un nœud non admis. | done | `NearestServices.vector` : une entrée par service (meilleure instance) ; l'instance en retrait n'est annoncée en 65 535 que si aucune autre instance du service n'est connue. Découpage à 120 et listes vides si non admis dans `build`. Tests `test_withdrawal_keeps_one_entry_per_service_and_local_is_never_evicted`, `test_more_than_120_entries_are_split_and_lists_bounded`, `test_unadmitted_node_announces_empty_lists`. |
| NNDP-5.4-15 | DEF | Taille max avec 32 services et 120 entrées : 187 + 128 + 840 = 1155 octets. | done | Test `test_empty_hia_is_187_bytes_and_full_is_1155`. |
| NNDP-5.4-16 | DEF | Plus de 120 entrées : réparties sur plusieurs HIA dans le même intervalle, chacun avec son propre horodatage et la même prochaine émission, chacun répétant la liste complète des services hébergés. | done | `NndpService.build` : découpage par 120, `timestamp = stamp + index`, même `_next_emission`, `hosted` répété. Test `test_more_than_120_entries_are_split_and_lists_bounded` (300 services → 3 datagrammes ≤ 1200 o ; horodatages distincts non vérifiés par le test). |

### 6. Émission (section 6.1)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-6.1-1 | DEF | Un nœud actif émet un HIA à intervalle régulier. | done | `NndpService._emit_loop` (émet dans tout état non exclu, y compris 0x0000 comme l'exige 6.4). |
| NNDP-6.1-2 | DEF | L'horodatage d'émission est l'heure courante de l'horloge de l'émetteur. | done | `build` : `stamp = now_ms()`. |
| NNDP-6.1-3 | DEF | Prochaine émission = horodatage d'émission + I. | done | `build` : `stamp + interval_s * 1000` (remis à zéro à chaque cycle régulier). Dérive de quelques ms par cycle (sommeil après l'envoi), sans effet sur 2 × I. |
| NNDP-6.1-4 | DEF | Liste des services hébergés et vecteur renseignés selon 6.5. | done | `build` : crochet `hosted` + `services.vector(towards=..., now=stamp)`. |
| NNDP-6.1-5 | DEF | L'émetteur signe la trame avec sa clé Ed25519 et place sa clé publique en tête du datagramme. | done | `HereIAm.sign`. |
| NNDP-6.1-6 | DEF | I = 15 s par défaut. | done | `LocalSettings.hia_interval = 15`, `NndpService(interval_s=15)`, `NndpConfig.hia_interval`. |
| NNDP-6.1-7 | DOIT | I DOIT être compris entre 1 s et 3600 s. | done | `NndpConfig.hia_interval` `Field(ge=1, le=3600)`, seule voie de modification (`bridge.apply_local`). Pas de garde dans `NndpService` lui-même. |
| NNDP-6.1-8 | PEUT | Un nœud PEUT émettre un HIA anticipé quand un service hébergé apparaît/disparaît ou que la meilleure instance d'un service change. | done | `Node._host`/`_withdraw` → `nndp.trigger()` ; `on_vector_change` quand `receive`/`expire`/`forget` changent une meilleure instance. `_host` ne déclenche plus que si le service n'était pas déjà hébergé (`new`). Pas de test. |
| NNDP-6.1-9 | DEF | Deux HIA anticipés sont séparés d'au moins 1 s. | done | `NndpService.trigger` (`TRIGGERED_SPACING = 1.0`, déclenchement abandonné sinon). Pas de test. |
| NNDP-6.1-10 | DEF | Un HIA anticipé annonce la prochaine émission du cycle régulier (inchangée). | done | `build` conserve `_next_emission` s'il est postérieur à l'horodatage. |
| NNDP-6.1-11 | DEF | Horizon partagé avec retour empoisonné : dans un HIA unicast vers un nœud de référence R, les entrées dont la meilleure instance a été apprise de R sont annoncées avec D = 65 535. | done | `NearestServices.vector(towards=R)`, appelé par `emit` pour chaque référence ; test `test_vector_distance_hops_poisoning_and_expiry`. |
| NNDP-6.1-12 | DEF | Cette règle ne s'applique pas aux HIA diffusés. | done | Diffusion : `build()` sans `towards` ; même test (`vector()` = 800). |

### 7. Réception (section 6.2)

Contrôles effectués **dans l'ordre**, abandon silencieux au premier échec.

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-6.2-1 | DEF | Au premier échec d'un contrôle, le datagramme est ignoré sans réponse. | done | `handle_datagram` : `WireError` → compteur + `last_rejection`, aucune réponse. Limitation de débit par adresse (`_rate_ok`) en amont. Ordre effectif : (1), magic/version/longueur de (3) avant (2) (recommandation 8), (2), événement, puis décodage de la charge qui contrôle L, ULID et (8) H/V/longueur/bits de poids fort, puis état (4), fraîcheur (5), intervalle (7), rejeu (6), NIT. Interversions sans effet observable (rejet silencieux dans tous les cas). |
| NNDP-6.2-2 | DEF | (1) Port source = 5221 **et** taille du datagramme entre 105 et 1200 octets. | done | `check_datagram` ; tests `test_reception_checks[source port]`, `[size]`. |
| NNDP-6.2-3 | DEF | (2) Signature valide pour la clé publique en tête. | done | `crypto.is_valid` ; test `test_reception_checks[signature]`. |
| NNDP-6.2-4 | DEF | (3) Magic, version et événement attendus, longueur déclarée = charge reçue. | done | `FrameHeader.decode` + contrôle d'événement dans `check_datagram`. Test `test_bad_header_fields_are_refused` (magic, version, événement, longueur). |
| NNDP-6.2-5 | DEF | (4) Identifiant = ULID valide de 26 caractères et état hors famille 0x4000. | done | `Reader.ident` (`is_ulid`), `check_datagram` (`state >> 12 == 0x4`). Pas de test de rejet dédié. |
| NNDP-6.2-6 | DEF | (5) \|horodatage d'émission − heure locale\| ≤ F. | done | `check_datagram` (`freshness_ms`) ; test `test_freshness_interval_and_excluded_state`. |
| NNDP-6.2-7 | DEF | (6) Le couple (clé publique, horodatage) n'a pas déjà été reçu dans la fenêtre F (anti-rejeu). | done | `NndpService.accept` (`_seen`, purgé par `check_inactivity`) ; test `test_replay_ordering_nit_and_inactivity`. |
| NNDP-6.2-8 | DEVRAIT | Rejeter tout HIA dont l'horodatage ≤ celui du dernier HIA valide de la même clé. | done | `accept` (`_last_timestamp`) ; même test (« older »). |
| NNDP-6.2-9 | DEF | (7) Intervalle annoncé (prochaine émission − horodatage) entre 1 s et 3600 s. | done | `check_datagram` ; test `test_freshness_interval_and_excluded_state`. |
| NNDP-6.2-10 | DEF | (8) H ≤ 32, V ≤ 120, longueur déclarée = exactement la taille des listes, 4 bits de poids fort de chaque adresse SP = 0. | done | `HereIAm.decode_payload` (bornes, `reader.end()`, `address >> 28`). Pas de test de rejet dédié. |
| NNDP-6.2-11 | DEF | Si tout réussit : enregistrer/mettre à jour, pour la clé publique **et** l'IP source, l'identifiant, l'état, la clé X25519, les services hébergés, l'horodatage d'émission et la date de réception. | done | `accept` : `neighbors[(key, address)] = Neighbor(...)` avec tous ces champs. |
| NNDP-6.2-12 | DEF | Si l'émetteur est un nœud admis de l'USD, traiter ensuite son vecteur selon 6.5. | done | `accept` : `hooks.is_admitted(key)` (`Node.is_admitted_key` : dans la table des nœuds et non exclu) avant `services.receive`. |
| NNDP-6.2-13 | DEF | L'adresse IP n'est pas transportée : elle est déduite de l'en-tête IP. | done | `_Protocol.datagram_received` → `addr[0]`. |
| NNDP-6.2-14 | DOIT | Le récepteur DOIT confronter le couple (IP, clé) à sa NIT lorsque la clé y figure déjà. | done | `accept` → `hooks.nit_accepts` = `tables.NIT.accepts` (clé connue à une autre adresse → rejet) ; test `test_replay_ordering_nit_and_inactivity` (« NIT »). |
| NNDP-6.2-15 | DEF | Un HIA valide n'établit pas l'appartenance à l'USD (NNDP ne prouve que la détention de la clé). | done | Un HIA n'écrit ni la NIT ni la table des nœuds (`Node._on_neighbor` ne fait que journaliser/cicatriser). |

### 8. Détection d'inactivité (section 6.3)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-6.3-1 | DEF | I d'un nœud = prochaine émission − horodatage d'émission de son dernier HIA valide. | done | `Neighbor.interval_ms` = `HereIAm.interval_ms` de l'émetteur. |
| NNDP-6.3-2 | DEF | Inactif si aucun HIA valide reçu dans les 2 × I qui suivent la réception du dernier. | done | `check_inactivity` : échéance par **clé** = max des `Neighbor.deadline` (`received_at + 2 × I`) de toutes ses adresses, contrôlée chaque seconde ; `on_inactive` une seule fois par clé. Tests `test_replay_ordering_nit_and_inactivity` (30 001 ms), `test_inactivity_is_per_key_across_addresses`. |
| NNDP-6.3-3 | DEF | Le nœud inactif reçoit l'état 0x3400 « Inactif : NNDP : aucun HIA reçu dans le délai ». | done | `Neighbor.inactive = True` ; `Node._on_neighbor_inactive` → `observed[key] = INACTIVE_NNDP_TIMEOUT` (nœuds admis) ; affiché par `show nndp neighbors` et le web. |
| NNDP-6.3-4 | DEF | Le nœud redevient actif dès qu'un HIA valide est reçu. | done | `accept` remplace le `Neighbor` (`inactive = False`) ; `Node._on_neighbor` efface `observed[key]` dès que l'état observé est 0x3400, quel que soit l'état annoncé (autres états 0x3xxx : seulement sur HIA Actif, cicatrisation ARCH 7.6). Pas de test unitaire de `_on_neighbor`. |
| NNDP-6.3-5 | DEF | Les nœuds qui ont déclaré un nœud inactif tentent régulièrement de le rejoindre (cicatrisation). | done | `Node._healing_loop` : Get_status vers chaque clé observée en famille 0x3 (dont 0x3400), période USD 0x000B. |
| NNDP-6.3-6 | DEF | Délai d'inactivité 2 × I, non configurable. | done | Aucun paramètre ; `Neighbor.deadline`. `clear nndp neighbors` (outil d'administration) n'en change pas la règle. |

### 9. Suites de la découverte (section 6.4)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-6.4-1 | PEUT | Sur HIA valide d'une clé inconnue, le récepteur PEUT ouvrir un échange NCP vers l'IP source en utilisant la clé X25519 du HIA. | done | Option utilisée : `Node.x25519_of` et `Node.candidates` reprennent la X25519 et l'adresse du HIA (`Request_approval` vers un voisin entendu) ; aucun échange spontané depuis `_on_neighbor` (facultatif). |
| NNDP-6.4-2 | DEF | Un nœud nouvellement créé émet des HIA avec l'état « En attente d'approbation » (0x0000). | done | `Node.__init__` : `state = State.APPROVAL_REQUIRED` ; `_emit_loop` émet dans cet état ; test `test_unadmitted_node_announces_empty_lists`. |
| NNDP-6.4-3 | DEF | Un nœud nouvellement créé utilise les HIA reçus pour choisir les nœuds auprès desquels demander son admission (Request_approval). | done | `Node.candidates` (voisins NNDP actifs, `_heard_at` pour le nœud de contact et l'EDB) utilisé par `_bootstrap_loop`. |

### 10. Services hébergés et table des services les plus proches (section 6.5)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-6.5-1 | DEF | Chaque nœud admis tient, pour chaque service de ses aires, une table d'au plus K instances (paramètre USD 0x000A, défaut 3). | done | `NearestServices(k)` ; K = paramètre 0x000A (`_start_nndp`, mis à jour à chaque configuration signée) ; filtre `my_services` = `Node.my_area_services`. |
| NNDP-6.5-2 | DEF | Entrée de table = adresse SP, distance D, nombre de sauts, nœud d'apprentissage, date d'expiration. | done | `ServiceEntry`. |
| NNDP-6.5-3 | DEF | Instance locale : pour chaque service hébergé au dernier contrôle de santé réussi, inscrire sa propre instance avec D = charge de référence en ‰ et 0 saut. | done | `NearestServices.set_local` appelé par `Node._host` (contrôle de santé réussi) et `_load_loop` (charge `load.reference`) ; `_trim` ne l'évince jamais. Tests `test_local_instance_and_withdrawal`, `test_withdrawal_keeps_one_entry_per_service_and_local_is_never_evicted` (K = 1). |
| NNDP-6.5-4 | DEF | L'instance locale est aussi inscrite dans la liste des services hébergés. | done | `Node.hosted` (crochet `hosted`), alimenté par `_host`. |
| NNDP-6.5-5 | DEF | Quand un nœud cesse d'héberger un service : annoncer son instance avec D = 65 535 pendant 3 intervalles, puis la retirer. | done | `withdraw_local` + `tick_withdrawals` (par cycle régulier) ; tests `test_local_instance_and_withdrawal`, `test_withdrawal_keeps_one_entry_per_service_and_local_is_never_evicted`. |
| NNDP-6.5-6 | DEF | Réception (A, D, S) de X : ignorer si le service de A n'appartient à aucune aire du récepteur. | done | `receive` (`service not in my_services`) ; test (0b2 ignoré). |
| NNDP-6.5-7 | DEF | Ignorer si A est l'une des propres adresses SP du récepteur. | done | `accept` passe à `receive` `my_addresses = local_addresses() ∪ hooks.my_addresses()`, ce crochet donnant toutes les adresses SP issues des identifiants de gestion du nœud (`Node._start_nndp` : `pack(s, m)` pour `self.management`), y compris un service en retrait ou non hébergé ; l'instance locale n'est plus évincée par `_trim`. Pas de test dédié (les tests passent `my_addresses=set()`). |
| NNDP-6.5-8 | DEF | Métrique : D' = D + 1000 × t / T, plafonné à 65 535, t = dernier RTT mesuré vers X par Check_distance_to_node (t = T si inconnu), T = tolérance de ping de l'USD. | done | Formule dans `receive` (T = paramètre 0x0002, t = T si `rtt_ms` absent) ; test `test_vector_distance_hops_poisoning_and_expiry` (300 + 500 = 800). `Node.call` n'enregistre `rtt[key]` qu'après une réponse à `CHECK_DISTANCE_TO_NODE` (plus de `finally`) : un délai dépassé lève avant l'affectation. Pas de test de `Node.call`. |
| NNDP-6.5-9 | DEF | S' = S + 1. | done | `receive` ; test (2 → 3). |
| NNDP-6.5-10 | DEF | Instance inaccessible par X si D = 65 535 ou S' > 15 (limite de 15 sauts). | done | `receive` (`unreachable`) ; test (14 sauts accepté, 15 → 16 rejeté). |
| NNDP-6.5-11 | DEF | Si A appris de X est déjà en table : mettre à jour distance, sauts et expiration **même si la distance augmente** ; supprimer l'entrée si inaccessible. | done | `receive` (branche `same`) ; test (800 → 900, puis suppression). |
| NNDP-6.5-12 | DEF | Sinon, si accessible : ajouter A, ou remplacer l'entrée apprise d'un autre nœud si D' est strictement inférieure ; ne conserver que les K instances de plus faible distance. | done | `receive` + `_trim` ; test (remplacement par y). |
| NNDP-6.5-13 | DEF | Expiration d'une entrée apprise de X = 3 × intervalle annoncé par X. | done | `expires = now + 3 × sender_interval_ms` ; test (44 999 / 45 000 ms). |
| NNDP-6.5-14 | DEF | Une entrée expirée est supprimée. | done | `NearestServices.expire`, appelé chaque seconde par `check_inactivity` ; même test. |
| NNDP-6.5-15 | DEF | Toutes les entrées apprises d'un nœud déclaré inactif (6.3) sont supprimées. | done | `check_inactivity` → `services.forget(key)` une fois par clé déclarée inactive. Pas de test dédié de `forget`. |
| NNDP-6.5-16 | DEF | Annonce : pour chaque service de ses aires, annoncer l'instance de plus faible distance de la table avec sa distance et ses sauts. | done | `NearestServices.vector` / `best` (une entrée par service). Test `test_vector_distance_hops_poisoning_and_expiry`. |
| NNDP-6.5-17 | DEF | N'annoncer que des entrées non expirées. | done | `NndpService.build` appelle `services.vector(towards=..., now=stamp)`, qui exécute `expire(now)` avant de composer le vecteur ; purge périodique conservée dans `check_inactivity`. Pas de test dédié de `vector(now=)`. |
| NNDP-6.5-18 | DEF | Limitation des boucles par : 15 sauts, horizon partagé avec retour empoisonné (unicast), expiration, mise à jour obligatoire des entrées du même nœud. | done | Les quatre mécanismes sont présents (`MAX_HOPS`, `vector(towards)`, `expire`, branche `same`). Pas de test de convergence (triangle, retrait d'instance). |
| NNDP-6.5-19 | DEF | La table sert à SP pour choisir l'instance de destination et au contrôle des dépendances. | done | `node.py` : adaptateur SP lisant `nndp.services.entries` ; `_dependency_loop` utilise `nndp.services.best`. |
| NNDP-6.5-20 | DEF | La liste des services hébergés reçue de chaque pair permet de connaître les services réellement exécutés par chaque voisin. | done | `Neighbor.hosted` → `hia_hosted` du moteur SP (`sp/engine.py`), affiché par `show nndp neighbors`. |

### 11. Paramètres (section 7)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-7-1 | DEF | Intervalle d'émission I : défaut 15 s, plage 1-3600 s. | done | `NndpConfig.hia_interval` `Field(15, ge=1, le=3600)` → `bridge.apply_local` → `restart_nndp`. |
| NNDP-7-2 | DEF | Fenêtre de fraîcheur F : défaut 30 s, plage 1-600 s, paramètre local du récepteur. | done | `LocalSettings.nndp_freshness_s` (défaut 30), distinct de `freshness_s` (NCP) ; `NndpConfig.freshness_window` `Field(30, ge=1, le=600)` → `bridge.apply_local("protocol nndp")` → `restart_nndp` → `NndpService.freshness_s` (contrôle de fraîcheur et cache de rejeu). Test `test_freshness_interval_and_excluded_state`. Réserve d'affichage : `cli/actions/nndp.py` (`show nndp`, page web) affiche `settings.freshness_s` (F NCP) et non `nndp_freshness_s`. |
| NNDP-7-3 | DEF | Délai d'inactivité 2 × I, non configurable. | done | `Neighbor.deadline`, agrégé par clé dans `check_inactivity` ; aucun paramètre. |
| NNDP-7-4 | DEF | Port source 5221, fixe. | done | `SOURCE_PORT = 5221` ; `NndpConfig` n'expose plus de port (docstring « ports are fixed »), aucune voie CLI/web ne modifie `LocalSettings.nndp_source_port`, champ conservé pour les tests (plusieurs nœuds sur un hôte). |
| NNDP-7-5 | DEF | Port destination 5222, fixe. | done | `DESTINATION_PORT = 5222` ; même situation que NNDP-7-4 (`nndp_destination_port` non exposé par `NndpConfig`). |
| NNDP-7-6 | DEF | Services hébergés par HIA : 32 au plus, fixe. | done | `MAX_HOSTED = 32` (émission et réception). |
| NNDP-7-7 | DEF | Entrées du vecteur par HIA : 120 au plus, fixe. | done | `MAX_VECTOR = 120` (émission découpée, réception bornée). |
| NNDP-7-8 | DEF | Instances retenues par service K : 3, paramètre USD 0x000A. | done | `parameter(signed.usd, 0x000A) or 3` → `NearestServices.k`. |
| NNDP-7-9 | DEF | Nombre maximal de sauts : 15, fixe. | done | `MAX_HOPS = 15`. |
| NNDP-7-10 | DEF | Expiration d'une entrée : 3 × intervalle de l'annonceur, fixe. | done | `NearestServices.receive`. |
| NNDP-7-11 | DEF | Espacement des HIA anticipés : au moins 1 s, fixe. | done | `TRIGGERED_SPACING = 1.0`. |
| NNDP-7-12 | DOIT | Les nœuds DOIVENT avoir une horloge dont l'écart avec l'heure réelle reste < F, y compris avant leur première admission. | n/a | Exigence d'exploitation (NTP) ; aucun contrôle ni avertissement dans le code (les rejets « freshness » sont visibles dans `show nndp`, « Last rejection »). |

### 12. Considérations de sécurité (section 8)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-8-1 | DEF | La signature prouve uniquement la détention de la clé privée, pas l'appartenance au domaine ; l'admission relève de NCP/endossement. | done | Voir NNDP-6.2-15 : NNDP n'inscrit rien dans la NIT ni la table des nœuds. |
| NNDP-8-2 | DEF | Les récepteurs doivent conserver les couples (clé, horodatage) au moins F (minuscule « doivent », mais requis par 6.2). | done | `accept` : `_seen[(key, ts)] = now + F`, purgé seulement après échéance. |
| NNDP-8-3 | NE DEVRAIT PAS | Un récepteur NE DEVRAIT PAS exclure un nœud sur la seule base d'un HIA reçu d'une adresse inattendue. | done | Contradiction NIT → simple rejet du HIA (`accept`), aucune exclusion. |
| NNDP-8-4 | NE DOIT PAS | NNDP NE DOIT PAS être utilisé sur un réseau non maîtrisé sans filtrage. | n/a | Exigence de déploiement. |
| NNDP-8-5 | DEVRAIT | Un USD réparti entre plusieurs sites DEVRAIT relier ces sites par des liens protégés. | n/a | Exigence de déploiement. |
| NNDP-8-6 | DEF | Seuls les vecteurs émis par des nœuds admis sont pris en compte. | done | `accept` : `hooks.is_admitted(key)`. |
| NNDP-8-7 | DEVRAIT | Un récepteur DEVRAIT limiter le nombre d'entrées acceptées d'un même nœud. | done | `NearestServices.receive` : au-delà de `MAX_PER_SENDER` (480 = 4 × 120) entrées apprises d'un même émetteur (`_count_from`), une nouvelle entrée accessible est ignorée (mises à jour et suppressions restent permises). Pas de test dédié. |
| NNDP-8-8 | DEVRAIT | Un récepteur DEVRAIT limiter le débit de HIA traités par adresse source et par clé. | done | `nndp.NndpService.handle_datagram` / `_rate_ok` : au plus 20 datagrammes par seconde et par adresse source, et autant par clé annoncée, avant toute vérification de signature. Test : `tests/test_hardening.py`. |
| NNDP-8-9 | DEVRAIT | Un récepteur DEVRAIT effectuer les contrôles peu coûteux (port source, taille, magic) avant la vérification de signature. | done | `check_datagram` : port, taille, puis `FrameHeader.decode(signed)` (magic, version, longueur) **avant** `is_valid`. Test `test_bad_header_fields_are_refused` (magic, version, longueur rejetés sans passer par la signature). |
| NNDP-8-10 | NE DOIT PAS | L'exigence de fraîcheur NE DOIT PAS être contournée en élargissant F au-delà de 1-600 s. | done | `NndpConfig.freshness_window` `ge=1, le=600`, seule voie vers `nndp_freshness_s` (le F NCP, `NcpConfig` `le=300`, est désormais distinct). |

### 13. Considérations IANA (section 9)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-9-1 | DEF | Ports UDP 5221 (« usmd-nndp-src ») et 5222 (« usmd-nndp ») — proposés, à confirmer. | n/a | Valeurs par défaut du code. |
| NNDP-9-2 | DEF | Registre « Événements NNDP USMD » (16 bits, Spécification requise) : 0x0000 réservé ; 0x0001 Here I am ; 0x0002-0xFFFF non attribués. | done | Seul `EVENT_HIA` émis/accepté (`check_datagram`). |
| NNDP-9-3 | DEF | Utilisation du registre « États de nœud USMD » de USMD-ARCH. | done | `node/states.py` (0x0000 … 0x4xxx, libellés dont 0x3400). |
| NNDP-9-4 | DEF | Utilisation du magic 0xD5C1 enregistré par USMD-ARCH. | done | `wire.MAGIC`, aux octets 0-1 de la trame. |

### 14. Vecteur de test (annexe A)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| NNDP-A-1 | DEF | Le codage de l'exemple (ID `01ARZ3NDEKTSV4RRFFQ69G5FAV`, Actif, 21/10/2026 10:00:00 UTC, I = 15 s, X25519 = 00..1F, service 0a1.5d68 à 312 ‰, db 0b2.0007 à 540 / 1 saut) DOIT produire exactement l'en-tête `d5c1 01 0001 00000064` et la charge de 100 octets de l'annexe ; datagramme = 205 octets. | done | Test `test_annex_a_example_bytes` : `frame(1, HereIAm(...).encode_payload())` = la trame hexadécimale ci-dessous à l'octet près (109 o), `sign` → 205 o, `check_datagram` relit un `HereIAm` identique. |

### 15. Remarques transverses sur les tests existants

- `tests/test_nndp01.py` (14 fonctions, 19 cas avec les paramétrages ; suite complète `pdm run pytest -q tests` : 80 tests verts lors de cette re-vérification) couvre : tailles 187/1155, rejets port/signature/taille, rejets magic/version/événement/longueur, fraîcheur, intervalle, état exclu à l'émission, rejeu, monotonie, NIT, inactivité à 2 × I et par clé sur deux adresses, métrique/sauts/retour empoisonné/expiration, retrait local, une entrée par service pendant un retrait, instance locale jamais évincée (K = 1), découpage > 120 entrées, listes vides en 0x0000, vecteur de l'annexe A, échange `build` → `handle_datagram`/`accept` entre deux `NndpService`, adresses SP.
- Non couverts : ULID invalide, état 0x4xxx à la réception, H > 32 / V > 120 / bits de poids fort à la réception ; horodatages distincts des HIA découpés ; HIA anticipés et espacement ; unicast aux références ; `forget` à l'inactivité ; `MAX_PER_SENDER` ; `_rate_ok` ; crochet `my_addresses` ; `Node._on_neighbor` (fin de 0x3400) ; RTT de `Node.call` ; convergence multi-nœuds.
- Le test « de bout en bout » relie deux `NndpService` en mémoire, sans socket ; `tests/test_node_integration.py` désactive toujours NNDP (`nndp_enabled = False`) : aucun HIA ne circule entre deux `Node` réels.
- L'ancien prototype (`proto/nndp/**`, `self/**`, `sys/**`) et ses tests ne sont plus utilisés par l'application.

---

### Format binaire

Tous les entiers en grand-boutiste, champs alignés à l'octet. Décalages absolus dans le datagramme UDP (L = 26, version 1).

#### Datagramme

| Décalage | Taille | Champ | Codage | Signé ? |
|---|---|---|---|---|
| 0 | 32 | Clé publique Ed25519 de l'émetteur | octets bruts (RFC 8032) | non |
| 32 | 64 | Signature Ed25519 | R ‖ S (RFC 8032), sur la trame entière (octets 96 → fin) | — |
| 96 | 9 + N | Trame signée = en-tête de trame + charge HIA | voir ci-dessous | **oui, intégralement** |

Tailles : minimum 187 o (H = 0, V = 0), maximum théorique 1155 o (H = 32, V = 120), plafond absolu 1200 o, non fragmenté. Contrôle de taille à la réception : 105 ≤ taille ≤ 1200 (105 = 32 + 64 + 9).

#### En-tête de trame (9 octets, commun NNDP/NCP/SP)

| Décalage trame | Décalage datagramme | Taille | Champ | Valeur / codage |
|---|---|---|---|---|
| 0 | 96 | 2 | Magic | 0xD5C1 |
| 2 | 98 | 1 | Version | 0x01 |
| 3 | 99 | 2 | Événement | 0x0001 (Here I am) ; 0x0000 réservé ; autres non attribués |
| 5 | 101 | 4 | Longueur | taille de la charge **en octets**, en-tête exclu (= 82 + 4H + 7V) |

#### Charge Here I am (82 à 1050 octets)

| Décalage charge | Décalage datagramme | Taille | Champ | Codage / contraintes |
|---|---|---|---|---|
| 0 | 105 | 2 | Longueur de l'identifiant L | uint16, DOIT = 26 |
| 2 | 107 | 26 | Identifiant de nœud | ULID canonique, Crockford base 32, ASCII |
| 28 | 133 | 8 | Prochaine émission | uint64, ms depuis l'époque Unix |
| 36 | 141 | 2 | État du nœud | uint16, registre « États de nœud USMD » ; famille 0x4000 interdite |
| 38 | 143 | 8 | Horodatage d'émission | uint64, ms depuis l'époque Unix ; \|Δ heure locale\| ≤ F ; (prochaine − horodatage) ∈ [1 000 ; 3 600 000] ms |
| 46 | 151 | 32 | Clé publique X25519 | octets bruts |
| 78 | 183 | 2 | H | uint16, ≤ 32 (0 si non admis) |
| 80 | 185 | 4 × H | Services hébergés | H adresses SP uint32 (4 bits de poids fort = 0 ; 12 bits service ‖ 16 bits gestion) |
| 80 + 4H | 185 + 4H | 2 | V | uint16, ≤ 120 (0 si non admis) |
| 82 + 4H | 187 + 4H | 7 × V | Vecteur de services | V entrées de 7 octets (ci-dessous) |

Entrée du vecteur (7 octets) :

| Décalage | Taille | Champ | Codage |
|---|---|---|---|
| 0 | 4 | Adresse SP de l'instance | uint32, 4 bits de poids fort = 0 |
| 4 | 2 | Distance D | uint16, millièmes (‰) ; 65 535 = inaccessible |
| 6 | 1 | Nombre de sauts | uint8 ; inaccessible si S + 1 > 15 |

Contrôle de cohérence à la réception : Longueur = 82 + 4H + 7V = taille du datagramme − 105.

#### Exemple (annexe A), trame complète en hexadécimal

```
d5c1 01 0001 00000064                          en-tête (Longueur = 100)
001a                                           L = 26
303141525a334e44454b545356345252
46465136394735464156                           "01ARZ3NDEKTSV4RRFFQ69G5FAV"
000001a15de77f98                               prochaine émission 2026-10-21T10:00:15Z
2000                                           état Actif
000001a15de74500                               horodatage 2026-10-21T10:00:00Z
000102030405060708090a0b0c0d0e0f
101112131415161718191a1b1c1d1e1f               X25519
0001  00a15d68                                 H = 1 : 0a1.5d68
0002  00a15d68 0138 00                         V = 2 : 0a1.5d68, D = 312, 0 saut
      00b20007 021c 01                                 0b2.0007, D = 540, 1 saut
```

Datagramme : 32 (clé) + 64 (signature) + 9 + 100 = 205 octets.

#### Conformité du code au format

`node/wire.py` (`FrameHeader`, `frame`, `Writer`, `Reader`) et `node/nndp.py` (`HereIAm.encode_payload`/`decode_payload`, `sign`, `check_datagram`) produisent et relisent exactement ce format : l'exemple ci-dessus est reproduit à l'octet près (`test_annex_a_example_bytes`). Les écarts du format draft-00 de l'ancien prototype (magic dans la charge, version en double, longueur en bits, champs -01 absents) ont disparu avec lui.

---

---

# Partie 4 — SP

## Cahier de recette SP : draft-usmd-sp-01 (Service Protocol)

Source : `draft-usmd-sp-01.txt` (22 octobre 2026), complété par `draft-usmd-rdsh-architecture-02` sections 10 et 11 (en-tête commun, codage des adresses SP), auxquelles SP renvoie.
Code examiné : `src/usmd_rdsh/node/**` (nouvelle implémentation, non suivie dans git), `src/usmd_rdsh/cli/**`, `src/usmd_rdsh/web/**`, branche `feature/cli-web-interface`. L'ancien prototype (`src/usmd_rdsh/proto`, `self`, `sys`) est remplacé et n'est plus utilisé ; il n'est plus cité ci-dessous.
Tests : `tests/test_sp01.py` (poignée de main, calendrier des clés, trames de données, anti-rejeu, durées de vie), `tests/test_sp01_engine.py` (deux moteurs reliés en mémoire : SAT, affinité, isolation, ICMP, diffusion, doublon de diffusion, maintiens sans ping-pong, abandon de poignée de main, ECN, fragmentation), `tests/test_nndp01.py` (codec des adresses SP), `tests/test_node_integration.py` (identifiant de gestion obtenu du maître Raft).

### Constat général

**SP est implémenté de bout en bout.** Le plan de données tient dans `node/sp/` ; le nœud (`node/node.py`) le démarre, le configure et lui fournit ses tables :

| Élément | Fichier | Contenu |
|---|---|---|
| En-tête commun | `node/wire.py` (`FrameHeader`) | `!HBHI` : magic 0xD5C1, version 1, événement, longueur en octets ; refus du magic, de la version et d'une longueur inexacte |
| Adresses SP | `node/addresses.py` | `pack`/`unpack`/`to_text`/`from_text`, 4 bits réservés à 0, `sss.0000` et `sss.ffff` |
| Primitives | `node/crypto.py` | Ed25519, X25519 (refus du secret nul), HKDF-SHA-256, ChaCha20-Poly1305 via `cryptography` (déclarée dans `pyproject.toml`) |
| Poignée de main et clés | `node/sp/handshake.py` | initiation 165 o, réponse 161 o, k_init, k_resp, sig_I, sig_R, h, h2, k_IR/k_RI : conformes à la section « Formats binaires » (relu octet par octet) |
| Sessions | `node/sp/session.py` | trame de données, nonce, AAD, compteur, fenêtre anti-rejeu 2048, maintien, 120/180/240/180 s |
| Paquets internes | `node/sp/packets.py` | analyse IPv4 (somme de contrôle), quintuplet, ICMP type 3 codes 1 et 4, fragmentation RFC 791, ECN RFC 6040 |
| Flux | `node/sp/flows.py` | table des flux, 300 s, 10 s après FIN/RST dans les deux sens |
| Moteur | `node/sp/engine.py` (`SpEngine`) | SAT (§5.2), réception (§5.3), éligibilité et sélection (§6), poignées de main, attente, réémissions, inéligibilité, renouvellement (§7.6), contrôles §7.7, diffusion et cache (§8) |
| Interface | `node/sp/tun.py` | Linux `/dev/net/tun` (`IFF_TUN \| IFF_NO_PI`, `ip`, `arp_ignore`/`arp_announce`), Windows Wintun (ctypes, `netsh`), repli en mémoire (`MemoryTun`) avec avertissement |
| Intégration | `node/node.py` | `start_sp`/`stop_sp`/`restart_sp`, `_set_dont_fragment`, `sp_vips`/`sp_routes`/`sp_groups`, `_NodeSpContext` (catalogue, adresses SP depuis les fiches signées, services les plus proches NNDP, NIT, NAL, états), identifiants de gestion (`request_management_ids`, `allocate_management_ids`, Raft) |
| Propriétés de l'USD | `node/ncp/codec.py` (`UsdProperties`, `Area`, `CatalogEntry`, `validate`), `node/signed.py` | aires et catalogue signés, versionnés, propagés par NCP ; refus des aires qui se recouvrent, des VIP hors de leur aire, des groupes hors 239/8, des identifiants de service hors 001..ffe ou en double |
| Gestion | `cli/bridge.py`, `cli/actions/domain.py`, `cli/actions/node_ops.py`, `web/server.py`, `web/static/index.html` | `show sp`, `show sp sessions`, `show sp flows`, `clear sp flows`, `show sp addresses`, `show sp statistics`, `execute management-id request` ; la page web affiche l'état SP et les sessions |

Re-vérification après corrections : sont désormais faits le maintien sans ping-pong (`Session.last_data_received`, test `test_keepalives_do_not_answer_keepalives`), la perte d'éligibilité et des sessions d'un pair exclu (`_NodeSpContext.peer`), la reconfiguration de l'interface au retrait et à la transmutation (`Node.refresh_interface`), la route 239/8 dès qu'un service des aires du nœud a un groupe, le contrôle des préfixes d'aires contre les adresses des nœuds et les routes du système (`Node.prefix_conflict`), le TOS externe à l'émission (`IP_TOS` par envoi), la lecture de l'ECN externe sous Linux (`recvmsg` + `IP_RECVTOS`), la jonction IGMP réelle (`tun.Memberships`, `IP_ADD_MEMBERSHIP`), l'unicité des VIP et groupes dans `UsdProperties.validate`, les six réglages locaux SP conservés dans `LocalSettings` et passés au moteur, l'unicité des index de session (`_free_index`), l'effacement des éphémères (`InitiatorState.forget`), le contrôle MTU contre le lien local (`_check_mtu`) et la limitation de débit de diffusion.

Restent **partial** : (1) sous Windows, l'ECN externe reçu est toujours lu Not-ECT (asyncio Proactor sans `recvmsg`, limitation documentée dans `start_sp`), donc RFC 6040 n'est pas appliqué en réception (SP-9.2-1, 9.2-3, 9.2-4) ; (2) sous Windows, `system_routes` (`route print -4`) ne filtre pas l'interface SP : la route d'aire posée sur `usmd-sp` est vue comme un conflit au `refresh_interface` suivant et retirée, puis remise au suivant (SP-4.1-6, SP-5.1-3) ; (3) MTU des chemins non mesurée, seul le lien local est comparé, avec un simple événement d'erreur (SP-9.1-2). Les nouveaux comportements (exclusion, réglages locaux, index uniques, `forget`, limiteur de diffusion, `prefix_conflict`, unicité VIP/groupe dans `validate`, TOS/ECN socket, jonction de groupe) n'ont pas de test dédié. Aucun test ne touche une vraie interface TUN : les vérifications sur interface réelle sont indiquées en remarque.

Légende des états : voir l'en-tête du cahier (**done** = implémenté, conforme et couvert par un test ou une vérification indiquée ; **partial** ; **missing** ; **config-only** ; **open** / **n/a**).

Niveaux : DOIT / NE DOIT PAS / DEVRAIT / PEUT = mots-clés BCP 14 ; **Norme** = règle normative rédigée à l'indicatif (« le nœud ignore… », « est… ») ; **Déf.** = définition normative (format, valeur, table).

---

### 2. Terminologie (définitions normatives)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-2-1 | Déf. | Une **aire de service** est un plan d'adressage IPv4 d'un USD portant un WVNN ; les services d'une aire ne peuvent pas joindre ceux d'une autre. | done | Aires dans `UsdProperties.areas` (`ncp/codec.py`) ; isolation par `SpEngine.from_tun` et `SpEngine._deliver`. Test : `test_area_isolation_and_unknown_destination_are_dropped`. |
| SP-2-2 | Déf. | La **VIP** est l'adresse IPv4 virtuelle attribuée à un service par le catalogue, dans le préfixe de son aire. | done | `CatalogEntry.vip` ; `UsdProperties.validate` refuse une VIP hors de son aire (« service VIP outside its area »). |
| SP-2-3 | Déf. | L'**adresse de groupe** est une adresse IPv4 de diffusion attribuée par le catalogue, prise dans 239.0.0.0/8. | done | `CatalogEntry.group` (0.0.0.0 = aucune) ; `UsdProperties.validate` vérifie l'appartenance à 239.0.0.0/8 ; `ServiceConfig._coherent` côté CLI. Unicité : voir SP-4.2-10. |
| SP-2-4 | Déf. | L'**adresse SP** est le couple (identifiant de service, identifiant de gestion), notée `sss.nnnn`. | done | `node/addresses.py` (`pack`, `to_text`, `from_text`). Test : `test_nndp01.py` (0a1.5d68 = 0x00A15D68). |
| SP-2-5 | Déf. | Un **flux** est une suite de paquets internes de même protocole, mêmes adresses et, le cas échéant, mêmes ports. | done | `IPv4.flow` (`sp/packets.py`), `FlowTable` (`sp/flows.py`). |
| SP-2-6 | Déf. | Une **session** est une association de sécurité bidirectionnelle entre deux nœuds établie par une poignée de main. | done | `Session` (`sp/session.py`), créée par `SpEngine._on_initiation` / `_on_response`. |
| SP-2-7 | Déf. | Le **paquet interne** est le paquet IPv4 lu ou écrit sur l'interface SP. | done | `SpEngine.from_tun` / `write_tun`. |

### 4.1 Aires de service

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-4.1-1 | Norme | SP fonctionne uniquement en IPv4 (paquets internes et transport). | done | `packets.parse` refuse version != 4 ; socket `AF_INET` dans `Node.start_sp`. |
| SP-4.1-2 | Norme | Un USD contient une ou plusieurs aires, définies dans ses propriétés avec le catalogue ; chaque aire a un préfixe IPv4 et porte son propre WVNN. | done | `UsdProperties.areas`/`catalog`, signés, versionnés, propagés par NCP (`SignedConfig.offer_usd`). Pas de refus d'un USD sans aire, mais `validate` exige que chaque service du catalogue nomme une aire existante. |
| SP-4.1-3 | Norme | Toutes les adresses du préfixe d'une aire sont utilisables, y compris celles dont la partie hôte est tout à 0 ou tout à 1. | done | `validate` teste `vip in network` (adresses réseau et diffusion comprises) ; la TUN porte les VIP en /32. Vérification : VIP x.x.x.0 et x.x.x.255 acceptées par `validate`. |
| SP-4.1-4 | NE DOIT PAS | Les préfixes des aires ne se recouvrent pas entre eux. | done | `UsdProperties.validate` (« overlapping area prefixes ») et `ServiceAreaView.apply` côté CLI. Test : `test_cli.py` (« overlap »). |
| SP-4.1-5 | NE DOIT PAS | Les préfixes des aires ne recouvrent pas les adresses que les nœuds utilisent pour communiquer (adresses NIT, adresse locale). | done | `Node.prefix_conflict` : refuse une aire contenant `settings.address` ou une adresse de la NIT ; `Node.sp_routes` n'installe pas la route de cette aire et émet un événement ERROR. Pas de test. |
| SP-4.1-6 | NE DOIT PAS | Les préfixes des aires ne recouvrent aucun réseau joignable par les nœuds en dehors du WVNN (table de routage locale). | done | `node.py:prefix_conflict` + `system_routes()` (Linux `ip -4 route`, Windows `route print -4`) : un préfixe d'aire qui recouvre une route du système n'est pas routé ; la route posée par le nœud sur l'interface SP (`tun.routes`) est exclue du contrôle. Test : `tests/test_hardening.py` (adresses de nœuds). |
| SP-4.1-7 | RECOMMANDÉ | Prendre les plages dans des blocs privés distincts RFC 1918 (ex. 10/8 pour les nœuds, 192.168.x.0/24 pour les aires). | n/a | Conseil d'exploitation ; un avertissement dans `show service-area summary` serait un plus. |
| SP-4.1-8 | Norme | Isolation : à l'émission comme à la réception, un nœud ignore tout paquet interne dont la source et la destination appartiennent à des aires différentes. | done | `SpEngine.from_tun` (`source.area != destination.area`) et `SpEngine._deliver` (« services in different areas »). Test : `test_area_isolation_and_unknown_destination_are_dropped` (émission). |

### 4.2 VIP, adresses de groupe et adresses SP

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-4.2-1 | Norme | VIP, adresse de groupe éventuelle et identifiant d'un service sont fixés par le catalogue, transportés et versionnés avec les propriétés de l'USD (NCP §6.9), identiques sur tous les nœuds. | done | `CatalogEntry` dans `UsdProperties` (signé, versionné, `SignedConfig.offer_usd`) ; `cli/bridge.py` construit et signe ; `Node.push_properties` propage. |
| SP-4.2-2 | Norme | L'adresse de groupe appartient à 239.0.0.0/8 (portée administrative, RFC 2365). | done | `UsdProperties.validate` (test d'appartenance réseau) et `ServiceConfig._coherent`. |
| SP-4.2-3 | Norme | Les applications n'utilisent que les VIP et adresses de groupe ; les adresses SP sont internes à SP. | done | Par construction : la TUN n'échange que des paquets IPv4 ; les adresses SP n'apparaissent que dans le texte chiffré (`sp/session.py`). |
| SP-4.2-4 | Déf. | Destination = VIP du service sss : adresse SP `sss.0000`, résolue en `sss.nnnn` avant l'envoi, traitement unicast vers une instance (§6). | done | `SpEngine.from_tun` → `flows.lookup`/`select` ; `encode_payload` refuse `sss.0000`. Test : `test_unicast_through_a_handshake_and_reply_affinity`. |
| SP-4.2-5 | Déf. | Destination = adresse de groupe du service sss : adresse SP `sss.ffff`, diffusion vers toutes les instances (§8). | done | `SpEngine._broadcast`. Test : `test_broadcast_reaches_mutation_members_once`. |
| SP-4.2-6 | Norme | L'adresse SP source d'un paquet est celle du nœud émetteur pour le service dont la VIP est la source du paquet. | done | `SpEngine.from_tun` : `addresses.pack(source.service_id, management_id(...))`. |
| SP-4.2-7 | Norme | Un nœud obtient ses identifiants de gestion du maître USD (NCP §6.15, Request_management_id) avant de pouvoir émettre. | done | `Node.request_management_ids` / `allocate_management_ids` (Raft) ; `from_tun` ignore le paquet tant que l'identifiant manque. Test : `test_node_integration.py` (`b.management[0x0A1] == 1`). |
| SP-4.2-8 | Déf. (ARCH §11.3) | Codage réseau d'une adresse SP sur 32 bits : 4 bits à 0, identifiant de service 12 bits, identifiant de gestion 16 bits (0a1.5d68 = 0x00A15D68). Notation hexadécimale minuscule. | done | `addresses.pack`/`unpack` (refus des 4 bits hauts), `to_text`. Test : `test_nndp01.py`. |
| SP-4.2-9 | Déf. (ARCH §11.1/11.3) | Identifiants de service 0x001..0xFFE (0x000 et 0xFFF réservés) ; identifiants de gestion 0x0001..0xFFFE attribués, 0x0000 = instance la plus proche, 0xFFFF = toutes les instances. | done | `UsdProperties.validate`, `ServiceConfig._service_id` ; `RaftState.free_id` attribue dans `range(1, 0xFFFF)` ; `addresses.ANY_INSTANCE`/`ALL_INSTANCES`. |
| SP-4.2-10 | Norme | Unicité dans l'USD : identifiant de service, VIP (et, implicitement, adresse de groupe). | done | `UsdProperties.validate` (`ncp/codec.py`) : identifiant et nom uniques, VIP unique, groupe (≠ 0.0.0.0) unique (« a VIP or group address is used by two services ») ; donc aussi pour un USD reçu par NCP. CLI : `ServiceView` vérifie `id`, `vip`, `group` sur toutes les lignes. Pas de test de doublon VIP/groupe. |

### 4.3 Tables

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-4.3-1 | Déf. | **Table SP/VIP** : clé = VIP ou adresse de groupe ; contenu = identifiant du service et de son aire ; source = catalogue (NCP). | done | `_NodeSpContext.catalog` → `CatalogService` ; recherche par adresse `SpEngine._by_ip` (parcours linéaire). |
| SP-4.3-2 | Déf. | **Table des adresses SP** : clé = adresse SP ; contenu = nœud auquel elle est attribuée ; source = fiches de nœud (NCP, Send_node_table), fiche signée. | done | `_NodeSpContext.owner` (parcourt `record.sp_addresses` des fiches signées) ; `show sp addresses`. |
| SP-4.3-3 | Déf. | **Table des services les plus proches** : clé = identifiant de service ; au plus K instances (adresses SP) avec leur distance ; source = HIA (NNDP §6.5). | done | `NearestServices` (`node/nndp.py`), lue par `_NodeSpContext.nearest`. |
| SP-4.3-4 | Déf. | **Table des sessions** : clé = index local de session ; contenu = pair, clés, compteurs, fenêtre anti-rejeu, dates ; source = poignées de main SP. | done | `SpEngine.sessions` (`dict[int, Session]`) ; `show sp sessions`. |
| SP-4.3-5 | Déf. | **Table des flux** : clé = quintuplet ; contenu = adresse SP du correspondant, sens (direct/inverse), date de dernière activité ; source = trafic SP. | done | `FlowTable.flows` / `Flow` ; `show sp flows`. |
| SP-4.3-6 | Déf. | **Cache de diffusion** : clé = (clé du pair, identifiant de diffusion) ; contenu = date de réception ; source = trames de diffusion reçues. | done | `SpEngine._broadcast_seen` (stocke la date d'expiration). |

### 5.1 Configuration de l'interface

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-5.1-1 | Norme | Chaque nœud crée une interface SP de type TUN, échangeant des paquets IPv4 sans en-tête de liaison (pas d'en-tête PI/Ethernet). | done | `sp/tun.py` : `LinuxTun` (`IFF_TUN \| IFF_NO_PI`), `WintunTun` ; repli `MemoryTun` (avertissement « simulated in memory »). Vérification manuelle : `ip -d link show usmd-sp` (tun, pi off) ; aucun test sur interface réelle. |
| SP-5.1-2 | Norme | L'interface porte comme adresses locales les VIP de tous les services hébergés par le nœud, et seulement celles-ci (ajout/retrait à chaque transmutation). | done | `Node.sp_vips` (services de `self.hosted`) appliqué par `Node.refresh_interface`, appelé par `start_sp`, `_host`, `_withdraw` et `transmute` ; `LinuxTun`/`WintunTun.configure` retirent les VIP absentes. Vérification : `ip -4 addr show usmd-sp` après retrait d'un service. Pas de test. |
| SP-5.1-3 | DOIT | Pour chaque aire à laquelle le nœud appartient, une route vers le préfixe de l'aire désigne l'interface SP. | done | `node.py:sp_routes` + `refresh_interface` : une route par aire du nœud vers l'interface SP, aucune pour les autres ; la route posée par le nœud n'est plus vue comme un conflit (Windows et Linux). |
| SP-5.1-4 | NE DOIT PAS | Pas de route vers le préfixe d'une aire à laquelle le nœud n'appartient pas. | done | `Node.transmute` appelle `refresh_interface` dès que `self.mutation` change (et `_withdraw` à chaque service retiré) ; `sp_routes` ne contient que les aires de `my_areas()` ; `configure` supprime les routes absentes (`ip route del`, `netsh ... delete route`). Pas de test. |
| SP-5.1-5 | DOIT | Le nœud rejoint, sur l'interface SP, les adresses de groupe des services qu'il héberge. | done | `tun.Memberships.update` : `IP_ADD_MEMBERSHIP` / `IP_DROP_MEMBERSHIP` sur un socket dédié, pour `Node.sp_groups` (groupes des services hébergés). Linux : `ip_mreqn` avec l'index de `usmd-sp` (`_ifindex_request`) ; Windows : `ip_mreq` avec la première VIP de l'interface comme adresse locale. Échec journalisé en ERROR. Vérification : `ip maddr show dev usmd-sp` / `netsh interface ipv4 show joins`. Pas de test. |
| SP-5.1-6 | DOIT | Le nœud installe une route vers 239.0.0.0/8 désignant l'interface SP pour les adresses de groupe connues. | done | `Node.sp_routes` ajoute 239.0.0.0/8 dès qu'un service des aires du nœud (`my_area_services`) a une adresse de groupe, qu'il soit hébergé ou non (seuls groupes joignables, vu l'isolation des aires). Choix /8 (ambiguïté /8 ou /32 : voir points ambigus). Pas de test. |
| SP-5.1-7 | Norme | La MTU de l'interface est fixée selon §9.1 (paramètre 0x0013). | done | `open_tun(mtu=parameter(usd, 0x0013))` ; Linux `ip link set mtu`, Windows `netsh ... mtu=`. |
| SP-5.1-8 | NE DOIT PAS | Ne pas répondre aux requêtes ARP portant sur une VIP sur les interfaces physiques. | done | `LinuxTun.__init__` : `net.ipv4.conf.all.arp_ignore=1`, `arp_announce=2` (réglage système global) ; Windows : modèle d'hôte fort. Vérification : `arping` d'une VIP depuis le segment, sans réponse. |
| SP-5.1-9 | NE DOIT PAS | Ne pas annoncer le préfixe d'une aire à un routeur. | done | Par construction : aucun protocole de routage dans le code. |
| SP-5.1-10 | Norme | Un paquet destiné à un service hébergé localement est remis directement par l'OS sans passer par SP (l'instance locale est toujours la moins coûteuse). | done | VIP locale = adresse de la TUN ; `_NodeSpContext.nearest` exclut les instances locales (`learned_from is None`). |
| SP-5.1-11 | Norme | Seuls les services communiquent via le WVNN : l'adresse source d'un paquet interne est la VIP d'un service hébergé par l'émetteur. | done | `SpEngine._local_vip`. Test : `test_area_isolation_and_unknown_destination_are_dropped` (source 192.168.1.99). |
| SP-5.1-12 | Norme | Un nœud qui n'héberge aucun service n'émet aucun trafic SP. | done | Sans VIP locale, `from_tun` ignore tout ; maintiens et poignées de main ne naissent que d'un trafic. |

### 5.2 Émission (SAT)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-5.2-1 | Norme | Pour chaque paquet lu sur l'interface : vérifier que c'est un datagramme IPv4 bien formé, que la source est une VIP locale et que la destination est dans la table SP/VIP ; sinon l'ignorer. | done | `packets.parse` (version, IHL, longueurs, somme de contrôle), `_local_vip`, `_by_ip` dans `SpEngine.from_tun`. Test : `test_area_isolation_and_unknown_destination_are_dropped`. |
| SP-5.2-2 | Norme | Vérifier que service source et service destination appartiennent à la même aire ; sinon ignorer. | done | `from_tun`. Même test. |
| SP-5.2-3 | Norme | Adresse SP source = (service source, propre identifiant de gestion du nœud pour ce service). | done | `from_tun` ; paquet ignoré sans identifiant. |
| SP-5.2-4 | Norme | Si la destination est une adresse de groupe, appliquer §8. | done | `from_tun` → `_broadcast`. Test : `test_broadcast_reaches_mutation_members_once`. |
| SP-5.2-5 | Norme | Sinon, adresse SP destination = table des flux, à défaut choix §6.2, puis mise à jour de la table des flux. | done | `flows.lookup` → `select` → `flows.record_outbound`. Test : `test_unicast_through_a_handshake_and_reply_affinity`. |
| SP-5.2-6 | Norme | Pair = nœud auquel l'adresse SP destination est attribuée selon la table des adresses SP. | done | `context.owner(target)`. |
| SP-5.2-7 | Norme | Encapsuler dans une trame de données de la session courante avec ce pair (§7.5) ; si aucune session, mettre en attente et engager une poignée de main (§7.6). | done | `SpEngine._send_payload` / `_initiate`. Test : `test_unicast_through_a_handshake_and_reply_affinity`. |
| SP-5.2-8 | Norme | Si aucun nœud ne peut être choisi, écrire sur l'interface SP un ICMP Destination inaccessible type 3 code 1 (hôte inaccessible, RFC 792) adressé à la source du paquet. | done | `SpEngine._icmp` → `packets.icmp_unreachable` (en-tête d'origine + 8 octets, source = VIP destination). Test : `test_no_instance_answers_icmp_host_unreachable`. |
| SP-5.2-9 | Norme | Ordre des étapes : validation, aire, adresse source, groupe, flux/sélection, pair, encapsulation/attente. | done | Ordre de `from_tun` (contrôle MTU §9.1 inséré après l'adresse source). |

### 5.3 Réception

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-5.3-1 | Norme | Pour chaque trame authentifiée : l'adresse SP destination est l'une des adresses du nœud, ou `sss.ffff`, pour un service qu'il héberge. | done | `SpEngine._deliver` (service hébergé, identifiant de gestion égal au nôtre sauf `ffff`). |
| SP-5.3-2 | Norme | L'adresse SP source est attribuée au pair dans la table des adresses SP. | done | `_deliver` : `owner(payload.source) != peer_key` → ignoré. |
| SP-5.3-3 | Norme | Les deux services appartiennent à la même aire. | done | `_deliver`. |
| SP-5.3-4 | Norme | Source du paquet interne = VIP du service source ; destination = VIP (ou adresse de groupe) du service destination. | done | `_deliver` (« inner addresses do not match »). |
| SP-5.3-5 | Norme | Appliquer le traitement ECN §9.2. | done | `SpEngine._deliver` appelle `packets.decapsulate_ecn(payload, outer_ecn)` avec l'ECN externe transmis par `from_udp` → `_on_data`. Test `test_ecn_decapsulation`. Source de l'ECN externe selon l'OS : voir SP-9.2-3. |
| SP-5.3-6 | Norme | Enregistrer le flux inverse dans la table des flux (§6.3), sauf trame de diffusion (§8). | done | `_deliver` → `flows.record_inbound` sauf diffusion. Test : `test_unicast_through_a_handshake_and_reply_affinity`. |
| SP-5.3-7 | Norme | Écrire le paquet sur l'interface SP sans modifier son TTL. | done | `_deliver` → `write_tun(raw)` ; `with_ecn` ne touche que TOS et somme de contrôle. |
| SP-5.3-8 | Norme | Un paquet qui échoue à une vérification est ignoré. | done | `WireError`/`CryptoError`/`PacketError` capturées dans `SpEngine.from_udp` (compteur `dropped`). |
| SP-5.3-9 | Norme | SP n'émet jamais de message d'erreur vers un pair. | done | `from_udp` n'émet rien sur erreur (journal DEBUG seulement). |

### 6.1 Éligibilité

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-6.1-1 | Norme | Les candidats pour S sont les instances de la table des services les plus proches pour S (NNDP §6.5). | done | `SpEngine.select` ← `_NodeSpContext.nearest` (`nndp.services`). |
| SP-6.1-2 | Norme | Éligible seulement si la table des adresses SP attribue A à N d'après la fiche signée de N. | done | `SpEngine._eligible` → `owner` (fiches signées). |
| SP-6.1-3 | Norme | Éligible seulement si le dernier HIA reçu de N, s'il y en a un, annonce A parmi ses services hébergés. | done | `_eligible` (`peer.hia_hosted`) ; `_NodeSpContext.peer` lit `Neighbor.hosted`. |
| SP-6.1-4 | Norme | Éligible seulement si l'état de N est « Actif » (0x2000). | done | `Peer.active` = `Node.peer_state(key) == State.ACTIVE`. |
| SP-6.1-5 | Norme | Éligible seulement si N figure dans la NIT de l'émetteur. | done | `_NodeSpContext.peer` renvoie `None` sans adresse NIT. |
| SP-6.1-6 | Norme | Éligible seulement si aucune poignée de main vers N n'a échoué au cours des 30 dernières secondes. | done | `SpEngine._ineligible` (`INELIGIBLE_S` = 30). Test : `test_abandoned_handshake_makes_peer_ineligible`. Durée = `SpEngine.ineligible_s` (réglage local, SP-10-9). |

### 6.2 Coût et sélection

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-6.2-1 | Déf. | Coût k = D / 1000, D = distance (en ‰) de l'instance dans la table des services les plus proches (ARCH §11.5 : charge de référence + 1000·t/T cumulés, plafond 65 535 = inaccessible). | done | `SpEngine.select` (`d / 1000`, exclusion de D = 65 535). |
| SP-6.2-2 | Norme | Déterminer k_min parmi les instances éligibles. | done | `select`. |
| SP-6.2-3 | Norme | Choisir uniformément au hasard une instance éligible de coût <= k_min + Δ. | done | `random.choice(pool)`. Pas de test statistique ; vérification : 1000 tirages avec 3 instances à égalité. |
| SP-6.2-4 | Déf. | Δ = 0,1 par défaut (local). | done | `selection_margin` → `LocalSettings.sp_margin` → `SpEngine.margin` (`cli/bridge.py`, `Node.start_sp`). |

### 6.3 Affinité des flux

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-6.3-1 | Norme | Une fois choisie, l'instance de destination d'un flux ne change pas tant que le flux est actif. | done | `FlowTable.lookup` avant toute sélection. |
| SP-6.3-2 | Déf. | Quintuplet TCP/UDP = (protocole, adr. source, port source, adr. destination, port destination) ; autres protocoles : ports = 0. | done | `IPv4.flow`/`ports` ; fragments non premiers : ports 0 (donc autre quintuplet, voir points ambigus). |
| SP-6.3-3 | Norme | À l'émission, enregistrer le flux direct avec l'adresse SP de l'instance choisie. | done | `FlowTable.record_outbound`. |
| SP-6.3-4 | Norme | À la réception, enregistrer le flux inverse (source/destination échangées) avec l'adresse SP source de la trame. | done | `FlowTable.record_inbound` (`reverse`). |
| SP-6.3-5 | Norme | Une réponse est adressée à l'instance exacte qui a émis la requête. | done | Test : `test_unicast_through_a_handshake_and_reply_affinity` (B héberge aussi 0x0A1 ; la réponse revient à A). |
| SP-6.3-6 | Norme | Expiration d'une entrée après 300 s d'inactivité. | done | `FlowTable.idle_s` (défaut 300, `flow_idle_s` du moteur), `_expired`, `expire` appelé par `SpEngine.tick`. Réglage local : SP-10-6. |
| SP-6.3-7 | Norme | Expiration 10 s après l'observation d'un segment TCP FIN ou RST dans chaque sens. | done | `Flow.fin_out`/`fin_in`, `closing_since`, `CLOSING_S` = 10 (lecture littérale : FIN ou RST requis dans les deux sens). |
| SP-6.3-8 | Norme | Si l'instance d'une entrée directe cesse d'être éligible, l'entrée est supprimée et le flux suivant est réorienté. | done | `from_tun` : `_eligible` sur la cible du flux, sinon `flows.drop_address` et nouvelle sélection ; aussi `_redirect`. |
| SP-6.3-9 | Norme | La recherche dans la table des flux précède toujours la sélection §6.2. | done | `from_tun`. |

### 7.1 Transport

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-7.1-1 | Norme | SP s'exécute au-dessus d'UDP et d'IPv4. | done | `Node.start_sp` (socket `AF_INET`/`SOCK_DGRAM`). |
| SP-7.1-2 | Norme | Le port UDP est le paramètre USD 0x0010, sans valeur par défaut (exemples : 9993). | done | `USD_PARAMETERS[0x0010]` sans défaut ; `start_sp` ne démarre pas sans port ; `show sp` l'indique. |
| SP-7.1-3 | Norme | Toutes les trames SP sont émises depuis ce port et vers ce port. | done | `bind(("0.0.0.0", port))`, `sendto((ip, port))` ; `from_udp` ignore un port source différent. |
| SP-7.1-4 | Norme | L'adresse IPv4 d'un pair est celle que la NIT associe à sa clé publique. | done | `Peer.address` = `nit.address_of(key)`. |
| SP-7.1-5 | Norme | Ignorer toute trame provenant d'une adresse que la NIT n'associe pas à la clé du pair de la session concernée. | done | `_on_data` et `_on_response` (`peer.address != source`), `_on_initiation` (`initiator_allowed`). |
| SP-7.1-6 | Norme | Datagrammes SP émis avec DF positionné. | done | `_set_dont_fragment` (Linux `IP_MTU_DISCOVER=IP_PMTUDISC_DO`, Windows `IP_DONTFRAGMENT` = 14 ; erreur ignorée). Vérification : capture, bit DF des datagrammes SP. |

### 7.2 Format commun

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-7.2-1 | Déf. | En-tête commun ARCH §10 de 9 octets : magic 0xD5C1 (16), version (8, = 1), événement (16), longueur (32, en octets, de tout ce qui suit l'en-tête). | done | `wire.FrameHeader` (`!HBHI`). Tests : tailles 165/161/38 dans `test_sp01.py`. |
| SP-7.2-2 | Norme | Tous les entiers en ordre réseau (big-endian). | done | `struct` `!` partout dans `sp/`. |
| SP-7.2-3 | Déf. | Événements : 0x0001 Initiation, 0x0002 Réponse, 0x0003 Données. | done | `handshake.EVENT_*`. |
| SP-7.2-4 | Norme (ARCH §10) | Une trame qui ne commence pas par 0xD5C1 est rejetée ; le protocole est déterminé par le port de réception. | done | `FrameHeader.decode` (« bad magic ») ; socket SP dédiée. |
| SP-7.2-5 | DOIT (ARCH §10.2) | Événement inconnu (même version majeure) : ignoré. | done | `from_udp` : aucune branche pour un autre événement. |

### 7.3 Poignée de main

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-7.3-1 | Norme | Établissement en un aller-retour entre initiateur I et répondeur R. | done | `build_initiation` / `build_response` / `open_response`. Test : `_handshake` dans `test_sp01.py`. |
| SP-7.3-2 | Norme | Chaque nœud connaît la clé Ed25519 et la clé X25519 **statique** de l'autre par la NIT et les HIA. | done | `Peer.x25519` = `record.x25519` de la fiche ; clé locale `identity.agreement`. |
| SP-7.3-3 | Norme | Les identités sont prouvées par des signatures Ed25519 placées dans des parties chiffrées (identité de l'initiateur cachée à l'observateur). | done | Ed_I ‖ sig_I et Ed_R ‖ sig_R scellés (`seal`). |
| SP-7.3-4 | Déf. | Initiation (0x0001) : Index de I (32 bits, aléatoire) ; e_I (32 octets, X25519 public, nouvelle pour **chaque** initiation) ; Horodatage (64 bits, ms depuis l'époque Unix) ; Partie chiffrée (112 octets = AEAD sous k_init de Ed_I(32) ‖ sig_I(64), plus étiquette 16). | done | `build_initiation` (longueur 156, total 165) ; `_initiate` génère une éphémère à chaque appel. Test : `len(initiation) == 165`. |
| SP-7.3-5 | Déf. | k_init = HKDF-SHA-256(sel = "USMD-SP-v1", ikm = DH(e_I, S_R), info = "init" ‖ e_I ‖ S_R, L = 32). | done | `build_initiation`, `open_initiation`. Test : `test_initiation_for_another_responder_does_not_open`. |
| SP-7.3-6 | Déf. | sig_I = Ed25519(I, "USMD-SP-v1-init" ‖ index_I ‖ e_I ‖ horodatage ‖ Ed_R ‖ S_R). | done | 123 octets ; signature détachée (`SigningKey.sign`, `verify`). |
| SP-7.3-7 | Déf. | Réponse (0x0002) : Index de R (32, aléatoire) ; Index de I (32, recopié) ; e_R (32 octets, nouvelle pour chaque réponse) ; Partie chiffrée (112 octets = AEAD sous k_resp de Ed_R ‖ sig_R + étiquette). | done | `build_response` (longueur 152, total 161). Test : `len(response) == 161`. |
| SP-7.3-8 | Déf. | h = SHA-256(trame d'initiation complète, en-tête compris). | done | `_sha256(initiation.raw)` / `_sha256(state.initiation)`. |
| SP-7.3-9 | Déf. | k_resp = HKDF-SHA-256(sel = h, ikm = DH(e_R, e_I) ‖ DH(s_R, e_I), info = "resp" ‖ e_R, L = 32). | done | `build_response` (dh2 ‖ dh3) ; `open_response` (DH(e_I, e_R) ‖ dh1). |
| SP-7.3-10 | Déf. | sig_R = Ed25519(R, "USMD-SP-v1-resp" ‖ h ‖ index_R ‖ index_I ‖ e_R ‖ Ed_I). | done | 119 octets. |
| SP-7.3-11 | Déf. | Parties chiffrées : ChaCha20-Poly1305 (RFC 8439), nonce nul de 12 octets (clé à usage unique). | done | `_ZERO_NONCE`, `crypto.seal`. |
| SP-7.3-12 | Déf. | AAD des parties chiffrées = en-tête de trame + tous les champs en clair qui précèdent la partie chiffrée (init : 9+4+32+8 = 53 o ; réponse : 9+4+4+32 = 49 o). | done | `data[:53]`, `data[:49]`. |
| SP-7.3-13 | Norme | Les index de session sont choisis au hasard (aléa cryptographique recommandé, unicité locale à garantir). | done | `SpEngine._free_index` : tire `hs.new_index()` (`secrets.randbits(32)`) jusqu'à un index absent de `sessions` et des `_pending` ; utilisé par `_initiate` et `_on_initiation` (réponse). Pas de test de collision. |
| SP-7.3-14 | Norme | L'initiateur vérifie la réponse (index_I connu, AEAD sous k_resp, Ed_R = clé attendue, sig_R valide). | done | `_on_response` (index en attente, adresse) + `open_response`. Test : `test_response_from_unexpected_key_is_refused`. |

### 7.4 Clés de session

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-7.4-1 | Déf. | h2 = SHA-256(trame d'initiation ‖ trame de réponse), trames complètes. | done | `build_response`, `open_response`. |
| SP-7.4-2 | Déf. | k_IR ‖ k_RI = HKDF-SHA-256(sel = h2, ikm = DH(e_I, e_R) ‖ DH(e_I, S_R), info = "USMD-SP-v1-session", L = 64) ; k_IR = octets 0..31, k_RI = octets 32..63. | done | I : `send=okm[:32]`, `receive=okm[32:]` ; R : l'inverse. Test : `test_both_sides_derive_mirrored_keys` (pas de vecteur de test indépendant). |
| SP-7.4-3 | Norme | k_IR chiffre I vers R ; k_RI chiffre R vers I. | done | `SessionKeys.send_key`/`receive_key`. |
| SP-7.4-4 | DOIT | Effacer les clés éphémères privées dès le calcul des clés de session. | done | `InitiatorState.forget` (remplace `dh1` par des zéros, abandonne la clé éphémère) appelé par `open_response` dès les clés de session calculées et par `SpEngine._initiate` pour l'initiation remplacée ; côté R, l'éphémère reste une variable locale de `build_response`. Limite du langage : les `bytes` immuables ne sont pas écrasés, seules les références sont abandonnées ; sur abandon (`tick`) et `drop_peer`, `_pending` est supprimé sans `forget` (même effet). Pas de test. |

### 7.5 Trame de données

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-7.5-1 | Déf. | Trame de données (0x0003) : Index du destinataire (32 bits, choisi par le destinataire) ; Compteur (64 bits, à partir de 0 dans chaque sens) ; Partie chiffrée (variable, texte clair + étiquette 16). | done | `Session.seal` (index = `remote_index`). Test : `test_data_frames_keepalive_broadcast_and_replay`. |
| SP-7.5-2 | Déf. | Texte clair : Indicateurs (8 bits) ; Adresse SP source (32) ; Adresse SP destination (32) ; Identifiant de diffusion (64, seulement si identifiant de gestion destination = 0xFFFF) ; Paquet interne (IPv4 complet). | done | `encode_payload`/`decode_payload`. Même test. |
| SP-7.5-3 | Déf. | Indicateur 0x80 (M) = trame de maintien ; autres bits réservés : 0 à l'émission, ignorés à la réception. | done | `FLAG_KEEPALIVE` ; seul 0x80 est testé à la réception. |
| SP-7.5-4 | Norme | Adresse SP destination = instance précise ou `sss.ffff`, **jamais** `sss.0000`. | done | `encode_payload` et `decode_payload` refusent `sss.0000`. Test : `match="0000"`. |
| SP-7.5-5 | Déf. | Nonce = 4 octets nuls ‖ compteur (64 bits big-endian). | done | `Session.seal`/`open`. |
| SP-7.5-6 | Déf. | AAD = en-tête de trame (9) ‖ index du destinataire (4) ‖ compteur (8) = 21 octets. | done | `data[:21]`. |
| SP-7.5-7 | Norme | L'émetteur incrémente le compteur à chaque trame. | done | `send_counter += 1`. |
| SP-7.5-8 | NE DOIT JAMAIS | Réutiliser une valeur de compteur sous la même clé. | done | Compteur monotone par session ; `can_send` refuse à 2^64-1. |
| SP-7.5-9 | Norme | Le destinataire retrouve la session par l'index, authentifie, puis applique une fenêtre anti-rejeu d'au moins 2048 valeurs (RFC 6479). | done | `_on_data` (index), `Session.open`, `ReplayWindow` (bitmap glissant de 2048). Test : `test_replay_window_accepts_out_of_order_inside_2048`. Taille = `SpEngine.replay_window` (réglage local, SP-10-13). |
| SP-7.5-10 | Norme | Ignorer toute trame non authentifiée, rejouée ou trop ancienne. | done | `window.check` avant, `window.record` après authentification. Test : `match="replayed"`. |
| SP-7.5-11 | Norme | Trame de maintien : texte clair = octet d'indicateurs seul (M = 1). | done | Test : `len(keepalive) == 38`. |
| SP-7.5-12 | Norme | Un nœud qui a reçu des données et n'en a émis aucune pendant 10 s envoie une trame de maintien. | done | `SpEngine.tick` envoie un maintien si rien émis depuis 10 s et des **données** reçues depuis moins de 10 s (`Session.last_data_received`, mis à jour par `_on_data` seulement hors maintien) : un maintien n'appelle plus de maintien. Test `test_keepalives_do_not_answer_keepalives`. |

### 7.6 Établissement, renouvellement et fermeture

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-7.6-1 | Norme | Engager une poignée de main lorsqu'il faut émettre vers un pair sans session valide. | done | `_send_payload` → `_initiate`. |
| SP-7.6-2 | Norme | Au plus 32 paquets en attente par pair ; au-delà, ignorer les plus anciens. | done | `_initiate` : `deque(maxlen=self.pending_per_peer)` (défaut 32, réglage local SP-10-7). Pas de test du débordement. |
| SP-7.6-3 | Norme | Sans réponse : réémission avec **nouvelle** clé éphémère après 2 s puis 4 s, puis abandon. | done | `SpEngine.tick` (`RETRANSMIT_S`, `_initiate` régénère e_I et l'index ; abandon 4 s après la 2e réémission). Test : `test_abandoned_handshake_makes_peer_ineligible` (3 initiations). |
| SP-7.6-4 | Norme | Après abandon : pair inéligible 30 s ; paquets en attente réorientés ou ignorés. | done | `tick` → `_ineligible`, `_redirect` (nouvelle sélection ; copies de diffusion ignorées). Même test (inéligibilité) ; réorientation non testée. |
| SP-7.6-5 | Norme | Le répondeur n'émet aucune trame de données sur une nouvelle session avant d'avoir reçu et authentifié une première trame de l'initiateur. | done | `Session.can_send` (`confirmed`). Test : `assert not r.can_send(1.0)`. |
| SP-7.6-6 | Norme | L'initiateur envoie une trame de maintien dès la réception de la réponse s'il n'a aucun paquet en attente. | done | `_on_response`. Pas de test dédié. |
| SP-7.6-7 | Norme | Renouvellement par nouvelle poignée de main après 120 s ou 2^60 trames émises (premier terme). | done | `Session.needs_rekey` ; `tick` (initiateur) et `_send_payload`. Test : `test_session_lifetimes`. |
| SP-7.6-8 | NE DOIT | Ne plus émettre sur une session au-delà de 180 s. | done | `can_send`. Même test. |
| SP-7.6-9 | NE DOIT | Ne plus recevoir sur une session au-delà de 240 s. | done | `can_receive`, suppression dans `tick`. Même test. |
| SP-7.6-10 | Norme | Renouvellements simultanés : émettre sur la session la plus récemment établie ; accepter en réception toute session valide. | done | `session_for` (max `established` parmi `can_send`) ; réception par index. |
| SP-7.6-11 | Norme | Supprimer une session sans trafic depuis 180 s. | done | `Session.idle` (180 s depuis le dernier envoi/réception), suppression dans `tick` ; effectif depuis la correction du maintien (SP-7.5-12). Pas de test d'inactivité. |
| SP-7.6-12 | Norme | Supprimer toutes les sessions d'un pair qui perd l'état Actif, est exclu ou disparaît de la NIT. | done | `_NodeSpContext.peer` renvoie `None` pour un pair exclu (`tables.exclusions.is_excluded`), absent de la NIT ou de la table des nœuds ; `SpEngine.tick` supprime alors ses sessions (comme pour un pair non Actif) et `_eligible` le refuse ; `drop_peer` sur silence NNDP. Pas de test d'exclusion. |

### 7.7 Traitement d'une initiation

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-7.7-1 | Norme | Contrôles dans l'ordre (du moins au plus coûteux), trame ignorée sans réponse au premier échec. | done | `SpEngine._on_initiation` dans l'ordre (1)…(7). Pas de test d'ordre ; vérification : initiation depuis une IP hors NIT, aucun appel X25519 (mock de `open_initiation`). |
| SP-7.7-2 | Norme | (1) magic, version, événement et longueur corrects (longueur = 156 pour une initiation). | done | `parse_initiation_header` (165 o, `FrameHeader.decode` exact). |
| SP-7.7-3 | Norme | (2) adresse source dans la NIT et débit d'initiations de cette adresse <= 10/s. | done | `address_known`, fenêtre glissante `_rate` (`INITIATION_RATE`). |
| SP-7.7-4 | Norme | (3) horodatage à moins de 30 s de l'heure locale. | done | `FRESHNESS_MS`. |
| SP-7.7-5 | Norme | (4) e_I non reçue au cours des 60 dernières secondes (cache des clés éphémères). | done | `_seen_ephemeral` (enregistrée après authentification, purgée par `tick`). |
| SP-7.7-6 | Norme | (5) la partie chiffrée s'authentifie sous k_init. | done | `open_initiation`. |
| SP-7.7-7 | Norme | (6) Ed_I est associée à l'adresse source dans la NIT et la NAL lui accorde au moins Node_executor. | done | `_NodeSpContext.initiator_allowed` (`nit.associated`, `nal.allows(Role.NODE_EXECUTOR)`). |
| SP-7.7-8 | Norme | (7) sig_I valide. | done | `verify_initiation` (signature détachée). |

### 8. Diffusion vers un service

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-8-1 | Norme | Un paquet interne destiné à l'adresse de groupe de S est adressé à `sss.ffff` et répliqué par l'émetteur. | done | `SpEngine._broadcast`. Test : `test_broadcast_reaches_mutation_members_once`. |
| SP-8-2 | Norme | Une copie chiffrée par session vers chaque nœud Actif dont la fiche indique une mutation comprenant S (NCP §7.8), sauf l'émetteur. | done | `_broadcast` sur `context.peers()` (`active`, `mutation_services` depuis la fiche, clé != la nôtre). |
| SP-8-3 | Norme | Toutes les copies portent `sss.ffff` et le même identifiant de diffusion 64 bits tiré au hasard. | done | `secrets.randbits(64)` une fois par paquet (par fragment). |
| SP-8-4 | Norme | Le destinataire ignore une trame dont (clé du pair, identifiant de diffusion) est dans le cache, puis enregistre le couple pour 60 s, puis écrit le paquet sur l'interface SP. | done | `_deliver` (`_broadcast_seen`, `BROADCAST_CACHE_S`). Test `test_duplicate_broadcast_is_written_once`. |
| SP-8-5 | Norme | Trames de diffusion jamais relayées et n'alimentant pas la table des flux. | done | `_deliver` n'écrit que sur la TUN ; `record_inbound` sauté. |
| SP-8-6 | Norme | Aucune clé de groupe : sécurité = celle des sessions bilatérales. | done | Copies scellées par `Session.seal`. |
| SP-8-7 | Norme | Diffusion non fiable (pas d'accusé, pas de réémission). | done | Aucun accusé ni réémission dans `_broadcast`. |
| SP-8-8 | DEVRAIT (§11) | Limiter le débit de diffusion par service. | done | `SpEngine._broadcast` : fenêtre glissante d'1 s par service (`_broadcast_sent`), paquet ignoré au-delà de `broadcast_rate` (réglage local `SpConfig.broadcast_rate`, défaut 1000/s). Pas de test. |

### 9.1 MTU

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-9.1-1 | Déf. | Surcoût maximal 82 octets : IPv4 20 + UDP 8 + en-tête 9 + index/compteur 12 + indicateurs 1 + adresses SP 8 + id diffusion 8 + étiquette 16. | done | Format de `Session.seal`. Tests : 46 + n (unicast), 54 + n (diffusion). |
| SP-9.1-2 | DOIT | MTU de l'interface SP <= plus petite MTU des chemins entre nœuds de l'USD - 82. | done | `node.py:_check_mtu` : SP n'est pas démarré si MTU SP + 82 dépasse la MTU du lien local, borne supérieure de la MTU de chemin ; événement d'erreur. La MTU de chemin elle-même relève de l'exploitant (0x0013). |
| SP-9.1-3 | Norme | Défaut 1412 (paramètre 0x0013), adapté à un chemin de MTU 1500 (marge 6 octets). | done | `USD_PARAMETERS[0x0013]` = 1412 (576..9000). |
| SP-9.1-4 | Norme | Paquet interne > MTU avec DF : l'ignorer et écrire sur l'interface un ICMP type 3 code 4 (fragmentation nécessaire) indiquant la MTU de l'interface (RFC 1191, champ Next-Hop MTU). | done | `from_tun` → `_icmp(packet, 4, ...)`. Test : `test_df_packet_above_mtu_gets_frag_needed`. |
| SP-9.1-5 | Norme | Sinon (sans DF), fragmenter le paquet interne (RFC 791) avant encapsulation. | done | `packets.fragment`. Test : `test_fragmentation_respects_mtu_and_offsets`. Options recopiées sur le seul premier fragment. |

### 9.2 ECN et DSCP

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-9.2-1 | Norme | Mode normal RFC 6040. | partial | Linux : complet (TOS externe à l'émission, ECN externe lu par `recvmsg`, `decapsulate_ecn`). Windows : émission faite (SP-9.2-2), mais l'ECN externe reçu vaut toujours Not-ECT (SP-9.2-3), donc une marque CE du réseau est perdue. |
| SP-9.2-2 | Norme | Encapsulation : champ ECN du paquet interne recopié dans l'en-tête IPv4 externe. | done | `from_tun`/`_broadcast` transmettent `piece.tos` ; `Node.start_sp.send_udp` fait `setsockopt(IP_TOS, tos)` avant chaque `sendto` (erreur ignorée) ; trames de poignée de main et maintiens à 0. Vérification : capture, champ ECN externe = interne. Sous Windows, l'effet de `IP_TOS` dépend de la pile (non vérifié). Pas de test socket. |
| SP-9.2-3 | Norme | Décapsulation : externe CE et interne ECT(0)/ECT(1) : interne marqué CE (recalcul de la somme de contrôle IPv4). | partial | `decapsulate_ecn`/`with_ecn` corrects (test `test_ecn_decapsulation`). Linux : `start_sp` active `IP_RECVTOS`, lit chaque datagramme par `sock.recvmsg` (lecteur `add_reader`) et passe `tos & 3` à `from_udp` : fait. Windows : branche `create_datagram_endpoint` sans `recvmsg`, `outer_ecn` toujours 0 (limitation documentée dans le code) : non fait. Pas de test socket. |
| SP-9.2-4 | Norme | Décapsulation : externe CE et interne Not-ECT : paquet ignoré. | partial | `decapsulate_ecn` renvoie `None` et `_deliver` ignore le paquet (test `test_ecn_decapsulation`) ; effectif sous Linux seulement, jamais déclenché sous Windows (ECN externe lu Not-ECT), voir SP-9.2-3. |
| SP-9.2-5 | Norme | Autres cas : ECN interne conservé. | done | `decapsulate_ecn` renvoie le paquet inchangé. Test : `test_ecn_decapsulation` (ECT(1), externe Not-ECT). |
| SP-9.2-6 | DEVRAIT | Recopier le DSCP interne dans l'en-tête externe. | done | Le TOS complet (DSCP + ECN) du paquet interne est posé par `IP_TOS` dans `send_udp` (voir SP-9.2-2 ; sous Windows, DSCP soumis à la stratégie QoS, non vérifié). |
| SP-9.2-7 | Norme | TTL interne non modifié ; TTL externe fixé par l'OS. | done | Aucune écriture du TTL ; socket sans `IP_TTL`. |

### 10. Paramètres

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-10-1 | Déf. | Port UDP : aucun défaut (9993 en exemple), USD 0x0010. | done | `USD_PARAMETERS[0x0010]`, `start_sp`. |
| SP-10-2 | Déf. | Aires de service et catalogue : aucun défaut, propriétés de l'USD. | done | `UsdProperties.areas`/`catalog`, `cli/bridge.py`. |
| SP-10-3 | Déf. | MTU interface SP : 1412, USD 0x0013. | done | `parameter(usd, 0x0013)` → TUN et `SpEngine.mtu`. |
| SP-10-4 | Déf. | K instances retenues par service : 3, USD 0x000A. | done | `nndp.services.k` (`Node.on_config_changed`). |
| SP-10-5 | Déf. | Marge Δ : 0,1, local. | done | `SpConfig.selection_margin` → `LocalSettings.sp_margin` → `SpEngine.margin`. |
| SP-10-6 | Déf. | Inactivité d'un flux : 300 s, local. | done | `SpConfig.flow_idle_timeout` → `bridge.apply_local` → `LocalSettings.sp_flow_idle` (conservé) et `node.sp.flows.idle_s` ; `start_sp` recrée le moteur avec `flow_idle_s=s.sp_flow_idle`. Pas de test. |
| SP-10-7 | Déf. | Paquets en attente par pair : 32, local. | done | `SpConfig.pending_per_peer` → `LocalSettings.sp_pending` → `SpEngine(pending_per_peer=)` (et `node.sp.pending_per_peer` à chaud) → `deque(maxlen=self.pending_per_peer)` dans `_initiate`. Défaut 32. Pas de test. |
| SP-10-8 | Déf. | Réémission de l'initiation : 2 s puis 4 s, fixe. | done | `RETRANSMIT_S`. |
| SP-10-9 | Déf. | Inéligibilité après échec : 30 s, local. | done | `SpConfig.ineligible_after_failure` → `LocalSettings.sp_ineligible` → `SpEngine.ineligible_s`, utilisé par `tick` à l'abandon. Défaut 30. Test `test_abandoned_handshake_makes_peer_ineligible` (valeur par défaut). |
| SP-10-10 | Déf. | Renouvellement : 120 s ou 2^60 trames, fixe. | done | `REKEY_AFTER_S`, `REKEY_AFTER_FRAMES`. |
| SP-10-11 | Déf. | Fin d'émission / réception : 180 s / 240 s, fixe. | done | `SEND_LIMIT_S`, `RECEIVE_LIMIT_S`. |
| SP-10-12 | Déf. | Maintien : 10 s, fixe. | done | `KEEPALIVE_S` = 10 (comportement corrigé : SP-7.5-12). |
| SP-10-13 | Déf. | Fenêtre anti-rejeu : >= 2048 trames, local. | done | `SpConfig.replay_window` (`ge=2048`) → `LocalSettings.sp_replay_window` → `SpEngine.replay_window` → `ReplayWindow(self.replay_window)` pour chaque nouvelle session (`_on_initiation`, `_on_response`) ; `ReplayWindow` impose au moins 2048. Test `test_replay_window_accepts_out_of_order_inside_2048` (taille par défaut). |
| SP-10-14 | Déf. | Fenêtre de fraîcheur des initiations : 30 s, fixe. | done | `FRESHNESS_MS`. |
| SP-10-15 | Déf. | Durée du cache de diffusion : 60 s, fixe. | done | `BROADCAST_CACHE_S`. |
| SP-10-16 | Norme (§7.7) | Débit max d'initiations par adresse source : 10/s ; cache des e_I : 60 s. | done | `INITIATION_RATE`, `EPHEMERAL_MEMORY_S`. |
| SP-10-17 | Norme (§6.3) | Délai après FIN/RST : 10 s. | done | `flows.CLOSING_S`. |

### 11. Considérations de sécurité (exigences testables)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-11-1 | Norme | Confidentialité persistante : clés de session issues des éphémères ; compromission de la clé X25519 statique n'expose pas les sessions passées. | done | Par construction : l'ikm de session contient DH(e_I, e_R) (`handshake.py`). Effacement des éphémères : `InitiatorState.forget`, voir SP-7.4-4. |
| SP-11-2 | Norme | Seule une clé admise, liée à son adresse par la NIT et dotée d'un rôle suffisant est acceptée. | done | Répondeur : `_NodeSpContext.initiator_allowed` (non exclu, NIT, NAL ≥ Node_executor) ; initiateur et sessions établies : `_NodeSpContext.peer` → `None` pour un pair exclu ou hors NIT (inéligible, sessions supprimées par `tick`) ; réception de données : `_on_data` exige l'adresse NIT du pair. Pas de test d'exclusion. |
| SP-11-3 | Norme | Une adresse SP n'est acceptée que si elle figure dans la fiche signée du nœud ; identifiants de gestion attribués seulement par le maître USD. | done | `owner` (fiches signées) en émission et en réception ; `allocate_management_ids` refuse hors meneur Raft. Test : `test_node_integration.py`. |
| SP-11-4 | Norme | Relais ouvert interdit : un nœud n'écrit sur l'interface SP que des paquets destinés à des services qu'il héberge. | done | `_deliver` (service hébergé et adresses internes contrôlées). |
| SP-11-5 | Norme | Primitives figées pour la version 1 : X25519, Ed25519, HKDF-SHA-256, ChaCha20-Poly1305 ; tout changement impose un nouveau numéro de version. | done | `node/crypto.py` (aucune négociation) ; `wire.VERSION` = 1. |
| SP-11-6 | DEVRAIT | Limiter le débit de diffusion par service (doublon de SP-8-8). | done | `SpEngine._broadcast` (`broadcast_rate`), voir SP-8-8. |

### 12. IANA

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-12-1 | Déf. | Registre des événements SP : 0x0000 réservé ; 0x0001 Initiation ; 0x0002 Réponse ; 0x0003 Données ; 0x0004..0x7FFF Spécification requise ; 0x8000..0xFFFF expérimental. | done | `from_udp` ne traite que 0x0001..0x0003 ; 0x0000 et les autres sont ignorés. |
| SP-12-2 | Déf. | Registre des indicateurs de données : 0x80 Maintien ; autres bits Spécification requise. | done | `FLAG_KEEPALIVE`. |
| SP-12-3 | Norme | Aucun port assigné par l'IANA : port choisi par l'administrateur. | done | 0x0010 sans défaut ; `config usd` → `sp_port`. |

### Annexe A (contrôles chiffrés)

| ID | Niveau | Exigence | État | Remarque |
|---|---|---|---|---|
| SP-A-1 | Déf. | Unicast d'un paquet interne de 1412 o : charge UDP 9+12+1+8+1412+16 = 1458 o ; datagramme IPv4 1486 o. | done | Test : `len(frame) == 46 + 20` (même formule). |
| SP-A-2 | Déf. | Diffusion : +8 o, datagramme 1494 o. | done | Test : `len(bcast) == 54 + 20`. |
| SP-A-3 | Déf. | Maintien : 38 o de charge UDP. | done | Test : `len(keepalive) == 38`. |
| SP-A-4 | Déf. | Initiation : 165 o ; réponse : 161 o. | done | Tests : `len(initiation) == 165`, `len(response) == 161`. |

Bilan de la partie (re-vérification) : 191 exigences (le tableau d'en-tête en annonce 192) ; 184 done, 6 partial, 0 missing, 1 n/a. Partial restants : SP-4.1-6 et SP-5.1-3 (filtrage des routes sous Windows), SP-9.1-2 (MTU des chemins), SP-9.2-1, SP-9.2-3, SP-9.2-4 (ECN externe reçu sous Windows).

---

### Formats binaires

Tous les entiers sont big-endian. `‖` = concaténation. Les chaînes ASCII sont sans terminateur.

Relecture du code : `wire.FrameHeader`, `addresses`, `sp/handshake.py` et `sp/session.py` suivent ces formats octet par octet (offsets, longueurs, constantes ASCII, nonces, AAD, ordre des DH et découpage de `okm`).

#### En-tête commun (ARCH-02 §10.1), 9 octets

```
off  taille  champ
0    2       Magic      = 0xD5C1
2    1       Version    = 0x01
3    2       Événement  (0x0001 | 0x0002 | 0x0003)
5    4       Longueur   = nombre d'octets qui suivent l'en-tête
```

#### Adresse SP (ARCH-02 §11.3), 4 octets

```
bits 31..28 : 0000 (réservé)
bits 27..16 : identifiant de service (12 bits, 0x001..0xFFE)
bits 15..0  : identifiant de gestion (0x0000 = la plus proche, jamais sur le fil ;
              0x0001..0xFFFE = nœud ; 0xFFFF = toutes les instances)
ex. 0a1.5d68 -> 0x00A15D68
```

#### Initiation (événement 0x0001), 165 octets, Longueur = 156

```
off  taille  champ
0    9       en-tête (événement 0x0001, longueur 156)
9    4       index_I         (aléatoire, choisi par I)
13   32      e_I             (clé publique X25519 éphémère)
45   8       horodatage      (ms depuis l'époque Unix, uint64)
53   112     AEAD_k_init( Ed_I[32] ‖ sig_I[64] )  = 96 o chiffrés + étiquette 16 o
             nonce = 00×12 ; AAD = octets 0..52 (53 o)
```

#### Réponse (événement 0x0002), 161 octets, Longueur = 152

```
off  taille  champ
0    9       en-tête (événement 0x0002, longueur 152)
9    4       index_R         (aléatoire, choisi par R)
13   4       index_I         (recopié)
17   32      e_R             (clé publique X25519 éphémère)
49   112     AEAD_k_resp( Ed_R[32] ‖ sig_R[64] ) = 96 o chiffrés + étiquette 16 o
             nonce = 00×12 ; AAD = octets 0..48 (49 o)
```

#### Trame de données (événement 0x0003)

```
off  taille  champ
0    9       en-tête (événement 0x0003, longueur = 12 + len(texte clair) + 16)
9    4       index du destinataire (choisi par le destinataire lors de la poignée de main)
13   8       compteur (uint64, part de 0 dans chaque sens)
21   n+16    ChaCha20-Poly1305( k_dir, nonce, texte clair, AAD )
             nonce = 00 00 00 00 ‖ compteur[8]   (12 o)
             AAD   = octets 0..20 (en-tête ‖ index ‖ compteur, 21 o)
             k_dir = k_IR si émis par l'initiateur, k_RI si émis par le répondeur
```

Texte clair :

```
off  taille  champ
0    1       indicateurs : 0x80 = M (maintien) ; bits 0x7F réservés (0 à l'émission, ignorés)
-- si M = 1 : fin du texte clair (1 octet) --
1    4       adresse SP source
5    4       adresse SP destination (jamais sss.0000)
9    8       identifiant de diffusion (uint64 aléatoire) -- seulement si (dest & 0xFFFF) == 0xFFFF
9|17 var     paquet interne IPv4 complet
```

Tailles : maintien = 9+12+1+16 = 38 o ; unicast = 46 + len(paquet) ; diffusion = 54 + len(paquet).

#### Calendrier des clés

Notations : X25519(priv, pub) = DH ; SHA-256 = H ; HKDF-SHA-256 au sens de RFC 5869 (Extract avec sel, puis Expand avec info, longueur L).

```
Constantes ASCII :
  "USMD-SP-v1"          (10 o)   sel de k_init
  "init"                ( 4 o)
  "resp"                ( 4 o)
  "USMD-SP-v1-init"     (15 o)   préfixe de sig_I
  "USMD-SP-v1-resp"     (15 o)   préfixe de sig_R
  "USMD-SP-v1-session"  (18 o)   info des clés de session

Initiation (I, puis R pour vérifier)
  dh1    = X25519(e_I_priv, S_R)                    = X25519(s_R, e_I_pub)
  k_init = HKDF(salt="USMD-SP-v1", ikm=dh1,
                info="init" ‖ e_I_pub[32] ‖ S_R[32], L=32)
  msg_I  = "USMD-SP-v1-init" ‖ index_I[4] ‖ e_I_pub[32] ‖ ts[8] ‖ Ed_R[32] ‖ S_R[32]   (123 o)
  sig_I  = Ed25519_sign(clé Ed25519 privée de I, msg_I)        (64 o, signature détachée)

Réponse (R, puis I pour vérifier)
  h      = H(initiation complète, 165 o)
  dh2    = X25519(e_R_priv, e_I_pub)                = X25519(e_I_priv, e_R_pub)
  dh3    = X25519(s_R, e_I_pub)                     = X25519(e_I_priv, S_R)   (= dh1)
  k_resp = HKDF(salt=h, ikm=dh2 ‖ dh3, info="resp" ‖ e_R_pub[32], L=32)
  msg_R  = "USMD-SP-v1-resp" ‖ h[32] ‖ index_R[4] ‖ index_I[4] ‖ e_R_pub[32] ‖ Ed_I[32]  (119 o)
  sig_R  = Ed25519_sign(clé Ed25519 privée de R, msg_R)

Session
  h2          = H(initiation[165] ‖ réponse[161])
  okm         = HKDF(salt=h2, ikm=dh2 ‖ dh1, info="USMD-SP-v1-session", L=64)
                (ikm écrit côté I : DH(e_I, e_R) ‖ DH(e_I, S_R))
  k_IR        = okm[0:32]   (I -> R)
  k_RI        = okm[32:64]  (R -> I)
  puis effacement de e_I_priv et e_R_priv (DOIT)
```

Remarques sur le calendrier :
- dh1 sert deux fois (k_init, puis session) ; dh3 = dh1 dans k_resp. C'est voulu (preuve de détention de s_R par R), mais ce point est à confirmer par l'auteur.
- AEAD des poignées de main : nonce nul autorisé car k_init et k_resp sont à usage unique (e_I et e_R neufs à chaque tentative, y compris lors des réémissions de §7.6) ; c'est le cas dans `SpEngine._initiate` et `build_response`.
- Contrôle recommandé : rejeter un résultat X25519 tout à zéro (point d'ordre faible), non exigé par le draft ; fait dans `AgreementKey.agree`.
- Il manque un vecteur de test figé (clés et aléas fixés, trames attendues) pour vérifier le calendrier indépendamment du code ; `build_initiation`/`build_response` acceptent déjà `index` et `ephemeral` en paramètres.

---

### Interface TUN par OS

| OS | Facilité | Détails | Implémentation |
|---|---|---|---|
| Linux | `/dev/net/tun` (module noyau `tun`) | `open("/dev/net/tun")` puis `ioctl(TUNSETIFF)` avec `IFF_TUN \| IFF_NO_PI` (paquets IP bruts, sans en-tête PI, conforme à SP-5.1-1). Requiert `CAP_NET_ADMIN` (root ou capacité). Adresses, MTU, routes (préfixes d'aires, 239.0.0.0/8) via netlink ou `ip`. Jonction de groupe par socket `IP_ADD_MEMBERSHIP` lié à l'interface. ARP sur VIP : `net.ipv4.conf.*.arp_ignore=1`, `arp_announce=2` (SP-5.1-8). | `LinuxTun` (stdlib `fcntl`/`ioctl`, commandes `ip` et `sysctl`, lecture par `add_reader`). Jonction de groupe par `tun.Memberships` (`IP_ADD_MEMBERSHIP` avec `ip_mreqn` sur l'index de `usmd-sp`, SP-5.1-5). Les erreurs des commandes `ip`/`sysctl` sont ignorées. |
| Windows | **Wintun** (`wintun.dll`, pilote L3 signé de WireGuard) | DLL à livrer avec l'application (amd64/arm64) ; `WintunCreateAdapter`, `WintunStartSession` (anneau), `WintunReceivePacket`/`WintunAllocateSendPacket`/`WintunSendPacket`, événement de lecture `WintunGetReadWaitEvent`. Paquets IP bruts sans en-tête de liaison. Requiert les droits administrateur. Adresses/routes/MTU via IP Helper API ou `netsh`. Modèle d'hôte fort par défaut (pas d'ARP pour la VIP sur les cartes physiques). | `WintunTun` (ctypes, fil de lecture dédié, `netsh`). Jonction de groupe par `tun.Memberships` (`ip_mreq` avec la première VIP). Routes ajoutées/retirées par différence. `system_routes` (`route print -4`) ne filtre pas l'interface SP : routes d'aires en alternance (SP-4.1-6). `wintun.dll` doit être trouvable (non livrée dans le dépôt). |
| macOS (pour mémoire) | `utun` (socket `PF_SYSTEM`/`SYSPROTO_CONTROL`) | Préfixe de famille AF de 4 octets sur chaque paquet. | Non implémenté : repli `MemoryTun`. |
| Autre / sans droits | — | — | `MemoryTun` : paquets écrits conservés en mémoire, rien n'est remis au système ; avertissement au démarrage ; `show sp` affiche le type d'interface. |

Primitives cryptographiques : `cryptography` (déclarée dans `pyproject.toml`) fournit `X25519PrivateKey`, `ChaCha20Poly1305`, `HKDF(SHA256)`, Ed25519 ; c'est la seule bibliothèque utilisée par `node/crypto.py`.

Options socket côté UDP : DF fait (`_set_dont_fragment`) ; TOS externe fait par `setsockopt(IP_TOS)` avant chaque envoi (`send_udp`) ; ECN reçu lu sous Linux (`IP_RECVTOS` + `recvmsg`, lecteur `add_reader`). Reste à faire sous Windows : lecture de l'ECN reçu (`IP_RECVECN` + `WSARecvMsg` ; `asyncio` ProactorEventLoop n'exposant pas `recvmsg`, un fil dédié est à prévoir) et, pour l'émission, `IP_ECN` en cmsg via `WSASendMsg` si `IP_TOS` est ignoré par la pile.

---

### Points ambigus relevés (à lever avant recette)

1. §5.1 : « route vers 239.0.0.0/8 … pour les adresses de groupe connues » : route /8 unique ou routes /32 par groupe ? Le code installe un /8 dès qu'un service des aires du nœud a une adresse de groupe.
2. §5.2 : adresse source de l'ICMP « hôte inaccessible » non précisée ; le code utilise la VIP destination (aussi pour l'ICMP code 4).
3. §6.2 : traitement d'une distance D = 65 535 (inaccessible) non précisé ; le code l'exclut.
4. §6.3 : « FIN ou RST dans chaque sens » : un RST unilatéral suffit-il ? Le code exige les deux sens. Fragments non premiers (pas de ports) non traités : le code leur donne des ports 0, donc un autre quintuplet, et peut les envoyer à une autre instance que le premier fragment.
5. §7.3 : contrôles de la réponse côté initiateur non listés (index_I, Ed_R attendu, sig_R, fenêtre de temps) ; le code fait les trois premiers et contrôle l'adresse source.
6. §7.6 : l'expression « 2^60 trames émises » fixe une limite très en dessous de 2^64 ; cohérente ; le code refuse aussi d'émettre à 2^64-1.
7. §8 : destinataires de diffusion = fiches de nœud (mutation comprenant S), pas les services hébergés réellement annoncés (HIA) ; une instance en échec de santé reçoit donc la diffusion, puis l'ignore (`_deliver` exige un service hébergé).
8. §7.5 : « a reçu des données » : une trame de maintien compte-t-elle comme donnée reçue ? Si oui, deux pairs se renvoient des maintiens indéfiniment. Le code a tranché « non » (`last_data_received`, SP-7.5-12) ; le draft devrait le dire.
9. §7.6 : délai d'abandon après la dernière réémission non précisé ; le code attend 4 s (abandon à t = 10 s).
