"""What happens before the node starts: founding a USD, development mode.

``bootstrap: true`` in ``usmd.yaml`` [usmd.example.yaml] means "create a new
USD": this node becomes the USD's authority and operator (it generates the USC
and USD key pairs, names the USD and USC with ULIDs when the file gives
non-ULID names) and mints itself a founder creation token [NCP-02 7.7]. It
then founds the USD when no admitted node answers [ARCH 5.2].

``--dev N`` runs virtual node N of a development cluster on this machine:

    state       .usmd-dev/nodeN/            (identity, configuration)
    authority   .usmd-dev/authority/        shared: any dev node can mint tokens
    address     127.0.0.(N+1)               NCP, NNDP and SP bind to it
    NNDP        sent to every other dev node instead of 255.255.255.255
    web         http://127.0.0.(N+1):8080/  login admin / admin

Node 1 founds the USD; the others mint themselves an ordinary token from the
shared authority and are admitted by whoever they hear. Never use it outside
development: the shared authority keys defeat the admission's security.
"""

from __future__ import annotations

import time
from pathlib import Path

from nan_runtime.state import StateDirectory

from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.node.crypto import b64u
from usmd_rdsh.node.ncp.codec import Role
from usmd_rdsh.node.wire import is_ulid

DEV_ROOT = Path(".usmd-dev")
_ROLES = {"usc-operator": Role.USC_OPERATOR, "usd-operator": Role.USD_OPERATOR,
          "node-operator": Role.NODE_OPERATOR, "node-executor": Role.NODE_EXECUTOR}
WEEK_MS = 7 * 24 * 3600 * 1000


def dev_address(index: int) -> str:
    return f"127.0.0.{index + 1}"


def dev_state(index: int) -> StateDirectory:
    return StateDirectory(DEV_ROOT / f"node{index}")


def _set(path: tuple[str, ...], name: str, value, *, only_if_unset: bool = False) -> None:
    doc = RUNTIME.document
    if only_if_unset and name in doc.fields(path):
        return
    doc.set_field(path, name, value)


def _roles(*extra: Role) -> list[Role]:
    """The configured roles, plus *extra*; a node is always an executor [ARCH 12.4]."""
    names = RUNTIME.document.fields(("system", "bootstrap")).get("roles") or []
    return sorted({_ROLES[str(n)] for n in names if str(n) in _ROLES}
                  | {Role.NODE_EXECUTOR, *extra})


def _usdn(messages: list[str]) -> str:
    import ulid  # pylint: disable=import-outside-toplevel

    usd = RUNTIME.document.fields(("usd",))
    name = str(usd.get("name") or "")
    if is_ulid(name.upper()):
        return name.upper()
    new = ulid.new().str
    if name:
        # A readable name is the USD's label; its identifier is a ULID [NCP-03 6.9].
        messages.append(f"USD '{name}' is identified by {new} [NCP-03 6.9]")
        _set(("usd",), "label", name, only_if_unset=True)
    _set(("usd",), "name", new)
    usc = str(RUNTIME.document.fields(("usc",)).get("name") or "")
    if usc and not is_ulid(usc.upper()):
        uscn = ulid.new().str
        messages.append(f"USC '{usc}' is identified by {uscn} [NCP-03 6.8]")
        _set(("usc",), "label", usc, only_if_unset=True)
        _set(("usc",), "name", uscn)
        _set(("usc",), "usd", [new])
    return new


def found(messages: list[str], *, usdn: str | None = None) -> None:
    """``bootstrap: true``: authority keys, names, founder token."""
    node = RUNTIME.node
    assert node is not None
    for which in ("usc", "usd"):
        if getattr(node.authority, which) is None:
            node.authority.generate(which)
            messages.append(f"Generated the {which.upper()} key pair (this node is the "
                            f"{'authority' if which == 'usc' else 'USD operator'})")
    _set(("system", "trust-anchor"), "usc_public_key", b64u(node.authority.usc.public))
    _set(("system", "trust-anchor"), "usd_public_key", b64u(node.authority.usd.public))
    _set(("usd",), "public_key", b64u(node.authority.usd.public), only_if_unset=True)
    name = usdn or _usdn(messages)
    if usdn:
        _set(("usd",), "name", usdn)
    if not RUNTIME.document.rows(("service-area",)):
        # A USD holds one or more service areas [ARCH-02 11.2].
        for field_name, value in (("name", "default"), ("id", 1), ("prefix", "10.255.0.0"),
                                  ("prefix_length", 16)):
            RUNTIME.document.set_field(("service-area",), field_name, value, key="default")
        messages.append("Created service area 'default' (10.255.0.0/16): a USD needs one")
    if node.token is None or node.token.usdn != name:
        # The founder holds both authority keys: it may be elected to either
        # role, so the USD starts with a USC and a USD operator [ARCH 12.4].
        token = node.authority.mint_token(
            name, node.key, _roles(Role.USC_OPERATOR, Role.USD_OPERATOR), validity_ms=WEEK_MS,
            founder=True, allow_second_founder=True)
        _set(("system", "bootstrap"), "creation_token", b64u(token.encode()))
        messages.append(f"Founder token minted for this node in USD {name}")


def join_with_shared_authority(messages: list[str], usdn: str) -> None:
    """A development node: an ordinary token from the shared authority."""
    node = RUNTIME.node
    assert node is not None
    _set(("system", "trust-anchor"), "usc_public_key", b64u(node.authority.usc.public))
    _set(("system", "trust-anchor"), "usd_public_key", b64u(node.authority.usd.public))
    if node.token is None or node.token.usdn != usdn:
        token = node.authority.mint_token(usdn, node.key, _roles(), validity_ms=WEEK_MS)
        _set(("system", "bootstrap"), "creation_token", b64u(token.encode()))
        messages.append(f"Development token minted for USD {usdn}")


def prepare_dev(index: int, count: int, messages: list[str]) -> None:
    """Settings of virtual node *index* among *count*."""
    node = RUNTIME.node
    assert node is not None
    address = dev_address(index)
    node.settings.address = node.settings.bind_address = address
    node.settings.dev_peers = [dev_address(i) for i in range(1, count + 1) if i != index]
    _set(("system", "global"), "address", address)
    _set(("system", "global"), "hostname", f"dev-node{index}", only_if_unset=True)
    _set(("protocol", "nndp"), "hia_interval", 5, only_if_unset=True)
    # Every dev node may be elected to any role, so a failover can be watched.
    _set(("system", "bootstrap"), "roles", list(_ROLES), only_if_unset=True)
    web = ("system", "web-interface")
    _set(web, "status", True, only_if_unset=True)
    _set(web, "listen_address", address)
    _set(web, "port", 8080, only_if_unset=True)
    _set(web, "username", "admin", only_if_unset=True)
    _set(web, "password", "admin", only_if_unset=True)
    usdn_file = DEV_ROOT / "usdn.txt"
    if index == 1:
        found(messages, usdn=usdn_file.read_text().strip() if usdn_file.exists() else None)
        _set(("usd",), "sp_port", 9993, only_if_unset=True)
        usdn_file.write_text(RUNTIME.document.fields(("usd",))["name"])
    else:
        deadline = time.time() + 30
        while not usdn_file.exists() or node.authority.usd is None:
            if time.time() > deadline:
                raise SystemExit("dev node 1 has not founded the USD yet: start it first")
            time.sleep(0.5)
            node.authority.usc = node.authority._load("usc.key")  # pylint: disable=protected-access
            node.authority.usd = node.authority._load("usd.key")  # pylint: disable=protected-access
        join_with_shared_authority(messages, usdn_file.read_text().strip())
    messages.append(f"Development node {index}/{count} at {address}, "
                    f"web http://{address}:8080/ (admin / admin)")
