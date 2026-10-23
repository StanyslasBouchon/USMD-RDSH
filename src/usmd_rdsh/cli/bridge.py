"""Between the configuration tree and the running node.

Two kinds of configuration meet in the tree:

* **local settings** - protocol timers, bootstrap, trust anchors, static NAL:
  this node's own, applied directly to :class:`~usmd_rdsh.node.node.Node`;
* **authority objects** - USC, USD (parameters, service areas, catalogue) and
  mutations [ARCH-02 3.3, 9]: no node decides them. On a node holding the USC
  key a commit builds the objects, signs a new version (the date in ms) and
  injects it; anywhere else the tree mirrors what is in force, and a change is
  refused with the reason.

The node calls :func:`reflect` whenever it applies newer signed objects, so
``show configuration`` and the web forms always show what is in force.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
from pathlib import Path
from typing import Any

import yaml

from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.node.crypto import b64u, unb64u
from usmd_rdsh.node.ncp.codec import (
    Area,
    CatalogEntry,
    MutationProperties,
    Role,
    UscProperties,
    UsdProperties,
)
from usmd_rdsh.node.services import (
    check_file_name,
    load_yaml_stream,
    parse_service_file,
)
from usmd_rdsh.node.signed import USD_PARAMETERS
from usmd_rdsh.node.wire import WireError, now_ms

log = logging.getLogger("usmd_rdsh.cli")

AUTHORITY_PATHS = ("usc", "usd", "service-area", "service", "mutation")
_CODES = {name: code for code, (name, *_rest) in USD_PARAMETERS.items()}
_ROLE = {"usc-operator": Role.USC_OPERATOR, "usd-operator": Role.USD_OPERATOR,
         "node-operator": Role.NODE_OPERATOR, "node-executor": Role.NODE_EXECUTOR}


# ---------------------------------------------------------------------------
# Local settings
# ---------------------------------------------------------------------------


async def apply_local(path: str, config: Any) -> None:
    """Push one local node of the tree into the running node."""
    node = RUNTIME.node
    if node is None:
        return
    s = node.settings
    if path == "protocol nndp":
        changed = (s.nndp_enabled, s.hia_interval, s.nndp_freshness_s) != (
            config.status, config.hia_interval, config.freshness_window)
        s.nndp_enabled, s.hia_interval, s.nndp_freshness_s = (
            config.status, config.hia_interval, config.freshness_window)
        if changed and node.nndp is not None:
            await node.restart_nndp()
    elif path == "protocol ncp":
        s.ncp_port = config.port
        s.ncp_retransmit, s.ncp_attempts = config.retransmit_timeout, config.retransmit_attempts
        s.freshness_s = config.freshness_window
        s.properties_interval = config.properties_interval
        s.exclusion_ms = config.exclusion_duration * 1000
        s.relay_delay = config.node_table_relay_delay
        s.reconcile_interval = config.node_table_reconcile
        s.raft_heartbeat = config.raft_heartbeat
        s.raft_election = (config.raft_election_min, config.raft_election_max)
        if node.ncp is not None:
            node.ncp.freshness_ms = s.freshness_s * 1000
            node.ncp.retransmit_s, node.ncp.attempts = s.ncp_retransmit, s.ncp_attempts
    elif path == "protocol sp":
        s.sp_margin, s.sp_flow_idle = config.selection_margin, config.flow_idle_timeout
        s.sp_pending, s.sp_ineligible = config.pending_per_peer, config.ineligible_after_failure
        s.sp_replay_window, s.sp_broadcast_rate = config.replay_window, config.broadcast_rate
        if node.sp is not None:
            node.sp.margin = config.selection_margin
            node.sp.flows.idle_s = config.flow_idle_timeout
            node.sp.pending_per_peer = config.pending_per_peer
            node.sp.ineligible_s = config.ineligible_after_failure
            node.sp.replay_window = config.replay_window
            node.sp.broadcast_rate = config.broadcast_rate
    elif path == "system bootstrap":
        anchors = RUNTIME.config("system trust-anchor")
        roles = roles_of(config.roles)
        _check_anchors(node, roles, config.creation_token,
                       anchors.usc_public_key, anchors.usd_public_key)
        s.roles = roles
        s.contact_node = config.contact_node
        s.contact_ed25519, s.contact_x25519 = config.contact_node_ed25519, config.contact_node_x25519
        s.edb_domain = config.edb_domain
        if config.creation_token and (node.token is None or
                                      b64u(node.token.encode()) != config.creation_token):
            node.install_token(config.creation_token)
        s.creation_token = config.creation_token
        node.apply_anchors()
    elif path == "system trust-anchor":
        for key in (config.usc_public_key, config.usd_public_key):
            if key and len(unb64u(key)) != 32:
                raise ValueError("an Ed25519 public key is 32 bytes (base64url)")
        bootstrap = RUNTIME.config("system bootstrap")
        _check_anchors(node, roles_of(bootstrap.roles), bootstrap.creation_token,
                       config.usc_public_key, config.usd_public_key)
        s.usc_anchor, s.usd_anchor = config.usc_public_key, config.usd_public_key
        node.apply_anchors()
    elif path == "trust nal":
        _apply_nal(node, config)


def roles_of(names) -> list[Role]:
    """Configured role names, deduplicated, in code order; executor when none."""
    return sorted({_ROLE[str(n)] for n in names or []} or {Role.NODE_EXECUTOR})


def _check_anchors(node, roles: list[Role], token: str, usc_anchor: str,
                   usd_anchor: str) -> None:
    """Refuse trust anchors that cannot support the configured roles [ARCH 4.4].

    A USD operator verifies objects signed by the USC: it needs the USC key.
    A node operator or executor verifies both the USC's objects and the USD's
    creation tokens: it needs both keys. A key the node holds itself, or (for
    the USD) the one carried by USD properties in force, counts as an anchor.
    Checked only once a creation token is set, so that a fresh node can be
    configured step by step.
    """
    if not token:
        return
    has_usc = bool(usc_anchor) or node.authority.usc is not None
    has_usd = bool(usd_anchor) or node.authority.usd is not None or node.signed.usd is not None
    for role in roles:  # each role brings its own needs
        if role == Role.USD_OPERATOR and not has_usc:
            raise ValueError("a usd-operator needs the USC trust anchor "
                             "('config system trust-anchor' / 'set usc-public-key') [ARCH 4.4]")
        if role in (Role.NODE_OPERATOR, Role.NODE_EXECUTOR) and not (has_usc and has_usd):
            missing = " and ".join(name for name, ok in (("USC", has_usc), ("USD", has_usd))
                                   if not ok)
            raise ValueError(f"a {role.name.lower().replace('_', '-')} needs the {missing} "
                             "trust anchor(s) ('config system trust-anchor') [ARCH 4.4]")


#: Keys granted by ``config trust nal`` at the previous apply, to revoke the
#: ones an administrator removes from the table.
_NAL_APPLIED: set[bytes] = set()


def _apply_nal(node, config: dict) -> None:
    """Grant the static NAL; revoke the entries removed since last time [ARCH 4.3]."""
    keys = {unb64u(key_text): entry for key_text, entry in config.items()}
    for key in _NAL_APPLIED - set(keys):
        node.tables.nal.anchors.discard(key)
        node.tables.nal.revoke(key)
    for key, entry in keys.items():
        node.tables.nal.grant(key, [_ROLE[str(r)] for r in entry.roles], anchor=True)
    _NAL_APPLIED.clear()
    _NAL_APPLIED.update(keys)
    node.apply_anchors()  # the node's own key and the USC/USD keys stay granted


# ---------------------------------------------------------------------------
# Authority objects
# ---------------------------------------------------------------------------


class AuthorityBridge:
    """Collects one commit's authority nodes, then signs or refuses them once."""

    def __init__(self) -> None:
        self.pending: dict[str, Any] = {}
        #: USCN / USDN generated by this commit, written into the tree once it
        #: is committed (see :func:`after_commit`) [ARCH-03 9.1].
        self.generated: dict[str, str] = {}

    def record(self, path: str, config: Any) -> None:
        self.pending[path] = config

    def _generate(self, path: str, wanted: bool) -> str:
        """A new ULID for an unnamed USC or USD that is being configured; only
        the authority names them, so only a node holding the USC key does."""
        node = RUNTIME.node
        if not wanted or node is None:
            return ""
        if node.authority.usc is None:
            raise ValueError(
                f"this node does not hold the USC key: only the authority creates the "
                f"{path.upper()} and generates its identifier [ARCH 3.3]")
        if path not in self.generated:
            import ulid  # pylint: disable=import-outside-toplevel

            self.generated[path] = ulid.new().str
        return self.generated[path]

    def _current(self, path: str) -> Any:
        return self.pending[path] if path in self.pending else RUNTIME.config(path)

    async def settle(self) -> None:
        if not self.pending:
            return
        pending, self.pending = self.pending, {}
        node = RUNTIME.node
        if node is None:
            return
        self.pending = pending  # _current reads it while building
        self.generated = {}
        try:
            usc, usd, mutations = self.build()
            catalogue = self._catalogue(usd)
        finally:
            self.pending = {}
        if node.authority.usc is None:
            if self._differs(node, usc, usd, mutations):
                raise ValueError(
                    "this node does not hold the USC key: USC, USD, areas, catalogue and "
                    "mutations come signed from the authority [ARCH 3.3]"
                )
            return
        key = node.authority.usc
        version = max(now_ms(), self._latest_version(node) + 1)
        out_usc = out_usd = None
        out_mut = []
        if usc is not None and _changed(node.signed.usc, usc):
            usc.version = version
            out_usc = usc.sign(key)
        retired: set[int] = set()
        if usd is not None and _changed(node.signed.usd, usd):
            usd.version = version
            try:
                usd.validate()
            except WireError as exc:
                raise ValueError(str(exc)) from exc
            _check_node_addresses(node, usd)
            retired = _check_service_ids(node, usd)
            out_usd = usd.sign(key)
        for mutation in mutations:
            # Every mutation is checked against the catalogue being signed, so a
            # catalogue change cannot move a dependency to another area [ARCH 8.4].
            _check_mutation(mutation, catalogue)
            if _changed(node.signed.mutations.get(mutation.name), mutation):
                mutation.version = version
                out_mut.append(mutation.sign(key))
        if out_usc or out_usd or out_mut:
            applied = node.inject(out_usc, out_usd, out_mut)
            if "usd" in applied:
                for service_id in retired:
                    node.authority.retire_service(service_id)
            log.warning("[AUTHORITY] Signed and injected %s (version %d)",
                        ", ".join(applied), version)

    def _catalogue(self, usd: UsdProperties | None) -> dict[str, int | str]:
        """Service name -> area, from the USD being signed or else the tree."""
        if usd is not None:
            return {e.name: e.area_id for e in usd.catalog}
        return {name: svc.area for name, svc in self._current("service").items()}

    @staticmethod
    def _latest_version(node) -> int:
        versions = [o.version for o in (node.signed.usc, node.signed.usd) if o]
        versions += [m.version for m in node.signed.mutations.values()]
        return max(versions or [0])

    def _differs(self, node, usc, usd, mutations) -> bool:
        if usc is not None and node.signed.usc is not None and _changed(node.signed.usc, usc):
            return True
        if usd is not None and (node.signed.usd is None and _non_default_usd(usd)
                                or node.signed.usd is not None and _changed(node.signed.usd, usd)):
            return True
        held = node.signed.mutations
        if {m.name for m in mutations} != set(held):
            return bool(mutations) or bool(held)
        return any(_changed(held[m.name], m) for m in mutations)

    # -- tree -> signed objects ------------------------------------------------

    def build(self):
        node = RUNTIME.node
        usc_cfg, usd_cfg = self._current("usc"), self._current("usd")
        areas_cfg, services_cfg = self._current("service-area"), self._current("service")
        mutations_cfg = self._current("mutation")
        usc = None
        usc_name = usc_cfg.name or self._generate("usc", bool(usc_cfg.label or usc_cfg.usd))
        if usc_name:
            authority = node.authority.usc.public if node.authority.usc else node.usc_key
            usc = UscProperties(usc_name, 0, authority or bytes(32), list(usc_cfg.usd),
                                label=usc_cfg.label)
        usd = None
        usd_name = usd_cfg.name or self._generate("usd", bool(usd_cfg.label))
        if usd_name:
            usd_key = unb64u(usd_cfg.public_key) if usd_cfg.public_key else (
                node.authority.usd.public if node.authority.usd else bytes(32))
            area_ids = {name: a.id for name, a in areas_cfg.items()}
            areas = [Area(a.id, name, a.prefix, a.prefix_length)
                     for name, a in sorted(areas_cfg.items(), key=lambda kv: kv[1].id)]
            catalog = []
            for name, svc in sorted(services_cfg.items(), key=lambda kv: kv[1].id):
                if svc.area not in area_ids:
                    raise ValueError(f"service '{name}' names unknown area '{svc.area}'")
                catalog.append(CatalogEntry(int(svc.id, 16), name, area_ids[svc.area],
                                            svc.vip or "0.0.0.0", svc.group or "0.0.0.0"))
            parameters = {}
            for field_name, code in _CODES.items():
                value = getattr(usd_cfg, field_name, None)
                if value is not None:
                    parameters[code] = int(value)
            usd = UsdProperties(usd_name, 0, usd_key, areas, catalog, parameters,
                                label=usd_cfg.label)
        mutations = [
            MutationProperties(name, 0, m.average_transmutation * 1000, m.min_instances,
                               m.max_instances, _service_file(m.services, services_cfg))
            for name, m in sorted(mutations_cfg.items())
        ]
        return usc, usd, mutations


def _check_node_addresses(node, usd: UsdProperties) -> None:
    """Area prefixes are disjoint from the nodes' own addresses [ARCH 11.2]."""
    addresses = {node.settings.address} if node.settings.address else set()
    addresses |= {e.record.address for e in node.tables.nodes.entries.values()
                  if e.record.address}
    for area in usd.areas:
        net = ipaddress.IPv4Network(f"{area.prefix}/{area.length}", strict=False)
        inside = sorted(a for a in addresses if _in(a, net))
        if inside:
            raise ValueError(
                f"area '{area.name}' ({net}) contains the node address(es) {', '.join(inside)}; "
                "area prefixes must be disjoint from the addresses nodes use [ARCH 11.2]"
            )


def _in(address: str, net: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.IPv4Address(address) in net
    except ValueError:
        return False


def _check_service_ids(node, usd: UsdProperties) -> set[int]:
    """Refuse reusing a recently retired identifier; return those now retired [ARCH 11.1]."""
    held = {e.service_id: e.name for e in node.signed.usd.catalog} if node.signed.usd else {}
    new = {e.service_id: e.name for e in usd.catalog}
    for service_id, name in new.items():
        if held.get(service_id) == name:
            continue
        if service_id in held:
            raise ValueError(
                f"service id {service_id:03x} designates '{held[service_id]}': retire it first, "
                "an id is not given to another service at once [ARCH 11.1]"
            )
        if not node.authority.reuse_allowed(service_id):
            raise ValueError(
                f"service id {service_id:03x} was retired from the catalogue less than an hour "
                "ago: NNDP entries may still announce it; choose another id [ARCH 11.1]"
            )
    return set(held) - set(new)


def _check_mutation(mutation: MutationProperties, catalogue: dict[str, int | str]) -> None:
    """Only catalogue services, with dependencies in their own area [ARCH 8.3, 8.4, 11.1]."""
    for spec in parse_service_file(mutation.service_file):
        if spec.name not in catalogue:
            raise ValueError(f"mutation '{mutation.name}': service '{spec.name}' is not in the "
                             "catalogue; only catalogue services can be hosted [ARCH 11.1]")
        for dependency in spec.dependencies:
            if dependency not in catalogue:
                raise ValueError(f"service '{spec.name}' depends on '{dependency}', which is "
                                 "not in the catalogue [ARCH 8.4]")
            if catalogue[dependency] != catalogue[spec.name]:
                raise ValueError(f"service '{spec.name}' depends on '{dependency}' of another "
                                 "area; a service and its dependencies share one area [ARCH 8.4]")


def _service_file(names: list[str], services_cfg: dict) -> bytes:
    """One YAML stream for a mutation, from each service's file [ARCH 8.3]."""
    documents = []
    for name in names:
        svc = services_cfg.get(name)
        if svc is None:
            raise ValueError(f"mutation names unknown service '{name}'")
        document = None
        if svc.service_file:
            try:
                text = Path(svc.service_file).expanduser().read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise ValueError(f"service '{name}': cannot read {svc.service_file}: {exc}") from exc
            for candidate in load_yaml_stream(text):
                if isinstance(candidate, dict) and candidate.get("name") == name:
                    document = candidate
        if svc.service_file and document is None:
            raise ValueError(f"service '{name}': {svc.service_file} has no document with "
                             f"'name: {name}' [ARCH 8.3]")
        if document is None:
            document = {"name": name, "type": str(svc.type),
                        "dependencies": list(svc.dependencies)}
        if svc.files:
            document["files"] = {**(document.get("files") or {}),
                                 **_attached_files(name, svc.files)}
        documents.append(document)
    text = yaml.safe_dump_all(documents, sort_keys=False, allow_unicode=True)
    parse_service_file(text)  # refuse what a node would refuse
    return text.encode("utf-8")


def _attached_files(service: str, paths: list[str]) -> dict[str, str]:
    """The ``files`` of a service document: base name -> base64 content."""
    files: dict[str, str] = {}
    for item in paths:
        path = Path(item).expanduser()
        name = check_file_name(path.name)
        if name in files:
            raise ValueError(f"service '{service}': two files are named '{name}'")
        try:
            files[name] = base64.b64encode(path.read_bytes()).decode("ascii")
        except OSError as exc:
            raise ValueError(f"service '{service}': cannot read {path}: {exc.strerror}") from exc
    return files


def _content(obj) -> bytes:
    """What a signed object says, version and signature aside."""
    version, signature = obj.version, obj.signature
    obj.version, obj.signature = 0, b""
    try:
        return obj.encode()
    finally:
        obj.version, obj.signature = version, signature


def _changed(held, new) -> bool:
    return held is None or _content(held) != _content(new)


def _non_default_usd(usd: UsdProperties) -> bool:
    return bool(usd.usdn)


AUTHORITY = AuthorityBridge()


async def after_commit(document) -> None:
    """The ``on_commit`` hook of every view session: the identifiers this
    commit generated join the tree, then the configuration is saved. Done
    here because the session adopts its working copy only after ``settle``."""
    for path, name in AUTHORITY.generated.items():
        document.set_field((path,), "name", name)
        log.warning("[AUTHORITY] %s named %s", path.upper(), name)
    AUTHORITY.generated = {}
    await RUNTIME.config_store.save(document)


# ---------------------------------------------------------------------------
# Signed objects -> tree
# ---------------------------------------------------------------------------


def reflect() -> None:
    """Rewrite the authority part of the tree from what is in force."""
    node = RUNTIME.node
    if node is None:
        return
    doc = RUNTIME.document
    signed = node.signed
    if signed.usc is not None:
        doc.set_field(("usc",), "name", signed.usc.uscn)
        doc.set_field(("usc",), "label", signed.usc.label)
        doc.set_field(("usc",), "public_key", b64u(signed.usc.public_key))
        doc.set_field(("usc",), "usd", list(signed.usc.usd))
    if signed.usd is not None:
        usd = signed.usd
        doc.set_field(("usd",), "name", usd.usdn)
        doc.set_field(("usd",), "label", usd.label)
        doc.set_field(("usd",), "public_key", b64u(usd.public_key))
        for code, value in usd.parameters.items():
            if code in USD_PARAMETERS:
                doc.set_field(("usd",), USD_PARAMETERS[code][0], value)
        doc.purge(("service-area",))
        names = {}
        for area in usd.areas:
            names[area.area_id] = area.name
            for field_name, value in (("name", area.name), ("id", area.area_id),
                                      ("prefix", area.prefix), ("prefix_length", area.length)):
                doc.set_field(("service-area",), field_name, value, key=area.name)
        kept = doc.rows(("service",))
        doc.purge(("service",))
        for entry in usd.catalog:
            local = kept.get(entry.name, {})
            values = {**local, "name": entry.name, "id": f"{entry.service_id:03x}",
                      "area": names.get(entry.area_id, str(entry.area_id)), "vip": entry.vip,
                      "group": "" if entry.group == "0.0.0.0" else entry.group}
            for field_name, value in values.items():
                doc.set_field(("service",), field_name, value, key=entry.name)
    if signed.mutations:
        doc.purge(("mutation",))
        for name, props in signed.mutations.items():
            values = {"name": name, "services": signed.mutation_services(name),
                      "min_instances": props.min_instances, "max_instances": props.max_instances,
                      "average_transmutation": props.average_transmutation_ms // 1000}
            for field_name, value in values.items():
                doc.set_field(("mutation",), field_name, value, key=name)
    RUNTIME.config_store.save_now(doc)
