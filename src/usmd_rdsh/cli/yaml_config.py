"""``usmd.yaml``: the node's configuration file, in the layout of ``usmd.example.yaml``.

The sections of the example are kept as they are::

    node:      address, roles (or role)
    usd:      name, cluster_name, edb_address, max_reference_nodes,
               load_threshold, ping_tolerance_ms, load_check_interval,
               emergency_threshold
    bootstrap, keys_file, nndp_ttl, ctl_socket
    ports:     ncp, nndp_listen, nndp_send, broadcast
    web:       enabled, host, port, username, password, ssl_cert, ssl_key

and the rest of the configuration tree joins them under its own path
(``usd: {voters: 3}``, ``system: {logging: {...}}``, ``protocol: {ncp: {...}}``,
``service: {web: {...}}``...), with the CLI's field names (``hia-interval``).

Values are those of the drafts:

* roles are the NAL roles [NCP-02 7.3]: ``usc-operator``, ``usd-operator``,
  ``node-operator``, ``node-executor``. The daemon's ``ucd_operator``,
  ``usd_operator``, ``operator`` and ``executor`` are read, reported, and
  written back under their spec name;
* thresholds given as fractions (``0.8``) become per mille (800) [ARCH 9.2];
* ports the drafts fix (NNDP 5221 -> 5222, limited broadcast) are reported
  when the file says otherwise and the spec value is kept; the NCP port may
  differ from 9992 (reported) [NCP-02 4].
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

from nan_actions.views import ConfigDocument, views

from usmd_rdsh.node.services import load_yaml_stream
from usmd_rdsh.node.wire import is_ulid

#: The daemon's role names and the spec's [NCP-02 7.3].
LEGACY_ROLES = {"ucd_operator": "usc-operator", "usd_operator": "usd-operator",
                "operator": "node-operator", "executor": "node-executor"}
SPEC_ROLES = ("usc-operator", "usd-operator", "node-operator", "node-executor")

#: Example key -> (tree path, field, conversion to the tree, conversion back).
_PER_MILLE = (lambda v: round(float(v) * 1000) if float(v) <= 1 else int(v),
              lambda v: round(int(v) / 1000, 3))
_SAME = (lambda v: v, lambda v: v)
USD_KEYS = {
    "name": (("usd",), "name", *_SAME),
    "cluster_name": (("usc",), "name", *_SAME),
    "edb_address": (("system", "bootstrap"), "edb_domain",
                    lambda v: v or "", lambda v: v or None),
    "max_reference_nodes": (("usd",), "reference_nodes", *_SAME),
    "load_threshold": (("usd",), "weakened_threshold", *_PER_MILLE),
    "ping_tolerance_ms": (("usd",), "ping_tolerance", *_SAME),
    "load_check_interval": (("usd",), "load_sample_interval", *_SAME),
    "emergency_threshold": (("usd",), "emergency_threshold", *_PER_MILLE),
}
WEB_KEYS = {"enabled": "status", "host": "listen_address", "port": "port",
            "username": "username", "password": "password", "tls": "tls_mode",
            "ssl_cert": "tls_certificate", "ssl_key": "tls_private_key"}
SPEC_PORTS = {"nndp_listen": 5222, "nndp_send": 5221}


@dataclass
class YamlConfig:
    """What a file holds beyond the tree, and what reading it reported."""

    document: ConfigDocument
    bootstrap: bool = False
    keys_file: str = ""
    warnings: list[str] = field(default_factory=list)


def _cli(name: str) -> str:
    return name.replace("-", "_")


def _set(doc: ConfigDocument, path: tuple[str, ...], name: str, value: Any,
         key: str | None = None) -> None:
    node = views.get(path)
    if node is None:
        raise ValueError(f"no configuration node '{' '.join(path)}'")
    spec = node.fields.by_cli_name(name.replace("_", "-"))
    if spec is None:
        raise ValueError(f"'{' '.join(path)}' has no field '{name}'")
    if spec.is_list and not isinstance(value, list):
        value = [value]
    doc.set_field(path, spec.name, value, key=key)


def _role(value: str, warnings: list[str]) -> str:
    text = str(value).strip().lower()
    if text in SPEC_ROLES:
        return text
    if text in LEGACY_ROLES:
        warnings.append(f"node.role '{value}' is the daemon's name: read as "
                        f"'{LEGACY_ROLES[text]}' [NCP-02 7.3]")
        return LEGACY_ROLES[text]
    raise ValueError(f"node.roles '{value}': among {', '.join(SPEC_ROLES)}")


def _tree(doc: ConfigDocument, prefix: tuple[str, ...], data: dict, warnings: list[str]) -> None:
    """A nested section whose keys are tree paths and fields."""
    for name, value in data.items():
        path = prefix + (str(name),)
        node = views.get(path)
        if node is not None and node.table:
            for key, row in (value or {}).items():
                for field_name, field_value in (row or {}).items():
                    _set(doc, path, field_name, field_value, key=str(key))
                doc.set_field(path, node.fields.by_cli_name(node.key or "").name, str(key),
                              key=str(key))
        elif node is not None and isinstance(value, dict):
            for field_name, field_value in value.items():
                _set(doc, path, field_name, field_value)
        elif views.is_container(path) and isinstance(value, dict):
            _tree(doc, path, value, warnings)
        else:
            warnings.append(f"'{'.'.join(path)}' is not part of the configuration: ignored")


def _tree_loaded() -> None:
    from usmd_rdsh.cli import views as _registered  # noqa: F401  # pylint: disable=import-outside-toplevel,unused-import


def parse(text: str) -> YamlConfig:
    """Read a ``usmd.yaml`` into the configuration tree."""
    _tree_loaded()
    documents = [d for d in load_yaml_stream(text) if d is not None]
    data: dict = documents[0] if documents else {}
    if not isinstance(data, dict):
        raise ValueError("usmd.yaml holds one mapping")
    out = YamlConfig(ConfigDocument())
    doc, warnings = out.document, out.warnings

    node = dict(data.pop("node", None) or {})
    if "address" in node:
        _set(doc, ("system", "global"), "address", str(node.pop("address")))
    if "role" in node or "roles" in node:
        given = node.pop("roles", None) or node.pop("role", None) or []
        node.pop("role", None)
        given = given if isinstance(given, list) else [given]
        roles = list(dict.fromkeys(_role(r, warnings) for r in given))
        _set(doc, ("system", "bootstrap"), "roles", roles)
    _tree(doc, ("system",), {"bootstrap": node} if node else {}, warnings)

    usd = dict(data.pop("usd", None) or {})
    for name, (path, field_name, to_tree, _back) in USD_KEYS.items():
        if name in usd:
            value = usd.pop(name)
            if value in (None, ""):
                continue  # absent: the default applies
            if field_name == "name" and not is_ulid(str(value).upper()):
                # usmd.example.yaml's "human-readable USDN": the label; the
                # identifier is generated when the USD is founded [NCP-03 6.8, 6.9].
                _set(doc, path, "label", str(value))
                continue
            _set(doc, path, field_name, to_tree(value))
    usd.pop("reference_hold_seconds", None)  # the daemon's own; ARCH 6.4 uses hysteresis
    for field_name, value in usd.items():  # the tree's own usd fields
        _set(doc, ("usd",), field_name, value)

    out.bootstrap = bool(data.pop("bootstrap", False))
    out.keys_file = str(data.pop("keys_file", "") or "")
    if "nndp_ttl" in data:
        _set(doc, ("protocol", "nndp"), "hia_interval", int(data.pop("nndp_ttl")))
    if data.pop("ctl_socket", None):
        warnings.append("ctl_socket: not used, the node's console and web interface replace it")

    ports = dict(data.pop("ports", None) or {})
    if "ncp" in ports:
        port = int(ports.pop("ncp"))
        if port != 9992:
            warnings.append(f"ports.ncp {port}: NCP-02 section 4 listens on UDP 9992")
        _set(doc, ("protocol", "ncp"), "port", port)
    for name, spec_port in SPEC_PORTS.items():
        if name in ports and int(ports.pop(name)) != spec_port:
            warnings.append(f"ports.{name}: fixed at {spec_port} by NNDP-01 section 4; kept")
    broadcast = ports.pop("broadcast", "auto")
    if str(broadcast) not in ("auto", "255.255.255.255"):
        warnings.append("ports.broadcast: NNDP-01 section 4 uses 255.255.255.255; kept")
    for name in ports:
        warnings.append(f"ports.{name}: unknown, ignored")

    web = dict(data.pop("web", None) or {})
    if web and "tls" not in web:
        # usmd.example.yaml: an empty certificate means a self-signed one.
        web["tls"] = "files" if web.get("ssl_cert") else "self-signed"
    for name, field_name in WEB_KEYS.items():
        if name in web:
            _set(doc, ("system", "web-interface"), field_name, web.pop(name))
    _tree(doc, ("system",), {"web-interface": web} if web else {}, warnings)

    _tree(doc, (), data, warnings)
    return out


def dump(document: ConfigDocument, *, bootstrap: bool = False, keys_file: str = "") -> str:
    """The tree as a ``usmd.yaml``: the example's layout first, then the rest."""
    _tree_loaded()
    used: set[tuple[tuple[str, ...], str]] = set()

    def take(path: tuple[str, ...], field_name: str) -> Any:
        values = document.fields(path)
        if field_name in values:
            used.add((path, field_name))
            return values[field_name]
        return None

    out: dict[str, Any] = {}
    node: dict[str, Any] = {}
    address = take(("system", "global"), "address")
    if address is not None:
        node["address"] = address
    roles = take(("system", "bootstrap"), "roles")
    if roles is not None:
        node["roles"] = [str(r) for r in roles]
    if node:
        out["node"] = node

    usd: dict[str, Any] = {}
    for name, (path, field_name, _to, back) in USD_KEYS.items():
        value = take(path, field_name)
        if value is not None and value != "":
            usd[name] = back(value)
    for field_name, value in document.fields(("usd",)).items():
        if (("usd",), field_name) not in used:
            usd[field_name.replace("_", "-")] = value
            used.add((("usd",), field_name))
    if usd:
        out["usd"] = usd

    out["bootstrap"] = bool(bootstrap)
    if keys_file:
        out["keys_file"] = keys_file
    hia = take(("protocol", "nndp"), "hia_interval")
    if hia is not None:
        out["nndp_ttl"] = hia
    ncp = take(("protocol", "ncp"), "port")
    out["ports"] = {"ncp": ncp if ncp is not None else 9992, "nndp_listen": 5222,
                    "nndp_send": 5221, "broadcast": "auto"}

    web: dict[str, Any] = {}
    for name, field_name in WEB_KEYS.items():
        value = take(("system", "web-interface"), field_name)
        if value is not None:
            web[name] = value
    if web:
        # parse() reads a missing tls as self-signed: write the default too.
        web.setdefault("tls", "off")
        out["web"] = web

    rest: dict[str, Any] = {}
    for node_def in views.nodes():
        path = node_def.path
        target = rest
        for segment in path[:-1]:
            target = target.setdefault(segment, {})
        if node_def.table:
            rows = document.rows(path)
            if rows:
                key_field = node_def.fields.by_cli_name(node_def.key or "").name
                target[path[-1]] = {
                    key: {f.replace("_", "-"): v for f, v in row.items() if f != key_field}
                    for key, row in rows.items()
                }
            continue
        values = {f.replace("_", "-"): v for f, v in document.fields(path).items()
                  if (path, f) not in used}
        if values and path != ("usd",):
            target[path[-1]] = values
    for section, values in rest.items():
        if not _non_empty(values):
            continue
        if section in out and isinstance(out[section], dict):
            out[section].update(values)
        else:
            out[section] = values

    header = ("# usmd.yaml — USMD-RDSH node configuration (layout of usmd.example.yaml)\n"
              "# Roles (several allowed): usc-operator | usd-operator | node-operator | "
              "node-executor [NCP-02 7.3]\n"
              "# Every node is an executor; operators are elected by the USD master "
              "[ARCH 12.4]\n")
    return header + yaml.safe_dump(_plain(out), sort_keys=False, allow_unicode=True)


def _non_empty(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_non_empty(v) for v in value.values())
    return True


def _plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if hasattr(value, "value") and not isinstance(value, (int, str)):
        return value.value
    if isinstance(value, str) and type(value) is not str:  # StrEnum
        return str(value)
    return value
