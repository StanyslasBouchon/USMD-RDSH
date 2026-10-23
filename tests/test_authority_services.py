"""Authority safeguards and service files [ARCH-02 3.3, 8.3, 8.4, 11.1, 11.2; NCP-02 7.7]."""

import asyncio

import pytest
from nan_actions.views import ConfigDocument
from nan_runtime.state import StateDirectory

from usmd_rdsh.cli import bridge
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.views.domain import ServiceAreaConfig, UscConfig, UsdConfig
from usmd_rdsh.cli.views.node import TrustAnchorConfig
from usmd_rdsh.cli.views.services import MutationConfig, ServiceConfig
from usmd_rdsh.node.authority import (
    SERVICE_ID_QUARANTINE_MS,
    Authority,
    export_signed,
    import_signed,
)
from usmd_rdsh.node.crypto import SigningKey, b64u
from usmd_rdsh.node.ncp.codec import Area, CatalogEntry, MutationProperties, Role, UsdProperties
from usmd_rdsh.node.node import Node
from usmd_rdsh.node.services import load_yaml_stream, parse_service_file
from usmd_rdsh.node.wire import WireError

USDN = "01JAB7R9F2W5H1N3S8D0Q4K6ME"


# -- YAML 1.2 core schema [ARCH 8.3] -----------------------------------------------


def test_service_file_is_yaml_1_2():
    text = """
name: web
type: static
dependencies: [on, off]
build:
  - command: yes
  - command: no
    timeout: 0o17
"""
    (spec,) = parse_service_file(text)
    assert spec.type == "static"
    assert spec.dependencies == ["on", "off"]  # not booleans as in YAML 1.1
    assert [s.command for s in spec.sequences["build"]] == ["yes", "no"]
    assert spec.sequences["build"][1].timeout == 15  # 0o octal


def test_yaml_1_2_scalars():
    (doc,) = load_yaml_stream("a: TRUE\nb: False\nc: 1:30\nd: 010\ne: 2024-01-01\nf: 0x1f\n"
                              "g: 1.5e3\nh: ~\ni: On\n")
    assert doc == {"a": True, "b": False, "c": "1:30", "d": 10, "e": "2024-01-01", "f": 31,
                   "g": 1500.0, "h": None, "i": "On"}


# -- USD validity [ARCH 11.2] -----------------------------------------------------------


def _usd(areas, catalog=()):
    return UsdProperties(USDN, 1, bytes(32), list(areas), list(catalog), {})


def test_usd_needs_an_area_and_mask_8_to_32():
    with pytest.raises(WireError, match="at least one"):
        _usd([]).validate()
    with pytest.raises(WireError, match="8..32"):
        _usd([Area(1, "wide", "10.0.0.0", 7)]).validate()
    _usd([Area(1, "front", "10.80.0.0", 16)],
         [CatalogEntry(0x0A1, "web", 1, "10.80.0.10", "0.0.0.0")]).validate()


def test_cli_prefix_length_matches_the_wire():
    with pytest.raises(ValueError):
        ServiceAreaConfig(name="wide", id=1, prefix="10.0.0.0", prefix_length=7)
    assert ServiceAreaConfig(name="ok", id=1, prefix="10.0.0.0", prefix_length=8)


# -- founder tokens [NCP 7.7] -------------------------------------------------------------


def test_only_one_founder_token_per_usd(tmp_path):
    authority = Authority(StateDirectory(tmp_path))
    authority.generate("usd")
    first, second = SigningKey.generate().public, SigningKey.generate().public
    token = authority.mint_token(USDN, first, [Role.NODE_OPERATOR], validity_ms=60_000,
                                 founder=True)
    assert token.founder
    with pytest.raises(ValueError, match="founder token was already issued"):
        authority.mint_token(USDN, second, [Role.NODE_OPERATOR], validity_ms=60_000,
                             founder=True)
    # Survives a restart; ordinary tokens are unaffected; the override works.
    again = Authority(StateDirectory(tmp_path))
    with pytest.raises(ValueError):
        again.mint_token(USDN, second, [Role.NODE_OPERATOR], validity_ms=60_000, founder=True)
    again.mint_token(USDN, second, [Role.NODE_EXECUTOR], validity_ms=60_000)
    assert again.mint_token(USDN, second, [Role.NODE_OPERATOR], validity_ms=60_000,
                            founder=True, allow_second_founder=True).founder
    assert (tmp_path / "authority" / "founders.json").exists()


# -- retired service ids [ARCH 11.1] ------------------------------------------------------


def test_retired_service_id_waits_an_hour(tmp_path):
    authority = Authority(StateDirectory(tmp_path))
    assert authority.reuse_allowed(0x0A2)
    authority.retire_service(0x0A2, now=1_000)
    assert not authority.reuse_allowed(0x0A2, now=1_000 + SERVICE_ID_QUARANTINE_MS - 1)
    assert Authority(StateDirectory(tmp_path)).reuse_allowed(
        0x0A2, now=1_000 + SERVICE_ID_QUARANTINE_MS)


# -- bridge: what the authority refuses to sign -------------------------------------


@pytest.fixture(name="authority_node")
def _authority_node(tmp_path):
    RUNTIME.document = ConfigDocument()
    node = Node(StateDirectory(tmp_path / "authority"))
    node.authority.generate("usc")
    node.authority.generate("usd")
    RUNTIME.node = node
    yield node
    RUNTIME.node = None


def _commit(*, areas=None, services=None, mutations=None):
    """One commit of the authority objects, built from config models."""
    areas = areas if areas is not None else {
        "front": ServiceAreaConfig(name="front", id=1, prefix="10.80.0.0", prefix_length=16),
        "back": ServiceAreaConfig(name="back", id=2, prefix="10.90.0.0", prefix_length=16)}
    services = services if services is not None else {
        "web": ServiceConfig(name="web", id="0a1", area="front", vip="10.80.0.10")}
    mutations = mutations if mutations is not None else {
        "frontal": MutationConfig(name="frontal", services=["web"])}
    auth = bridge.AUTHORITY
    auth.record("usc", UscConfig())
    auth.record("usd", UsdConfig(name=USDN))
    auth.record("service-area", areas)
    auth.record("service", services)
    auth.record("mutation", mutations)
    asyncio.run(auth.settle())


def test_signs_a_coherent_domain(authority_node):
    _commit()
    assert authority_node.signed.usd is not None
    assert authority_node.signed.mutation_services("frontal") == ["web"]


def test_dependency_outside_catalogue_or_area_refused(authority_node):
    services = {
        "web": ServiceConfig(name="web", id="0a1", area="front", vip="10.80.0.10",
                             dependencies=["db"])}
    with pytest.raises(ValueError, match="not in the catalogue"):
        _commit(services=services)
    services["db"] = ServiceConfig(name="db", id="0b1", area="back", vip="10.90.0.10")
    with pytest.raises(ValueError, match="another area"):
        _commit(services=services)
    assert authority_node.signed.usd is None
    services["db"] = ServiceConfig(name="db", id="0b1", area="front", vip="10.80.0.11")
    _commit(services=services)
    assert authority_node.signed.usd is not None


def test_attached_files_travel_signed_and_land_in_files_dir(authority_node, tmp_path):
    """Files of a service: in the signed mutation, then in $USMD_FILES_DIR."""
    import os  # pylint: disable=import-outside-toplevel

    service_file = tmp_path / "web.yaml"
    service_file.write_text("name: web\nbuild:\n  - command: \"$USMD_FILES_DIR/start.sh\"\n")
    script, sql = tmp_path / "start.sh", tmp_path / "schema.sql"
    script.write_bytes(b"#!/bin/sh\necho up\n")
    sql.write_bytes(b"CREATE TABLE t (id uuid);\n")
    _commit(services={"web": ServiceConfig(name="web", id="0a1", area="front", vip="10.80.0.10",
                                           service_file=str(service_file),
                                           files=[str(script), str(sql)])})
    (spec,) = authority_node.mutation_specs("frontal")
    assert spec.files == {"start.sh": b"#!/bin/sh\necho up\n", "schema.sql": sql.read_bytes()}

    directory = authority_node.service_files_dir("web")
    directory.mkdir(parents=True)
    (directory / "stale.txt").write_text("gone")
    authority_node.sequence_environment(spec, "unbuild")
    assert sorted(os.listdir(directory)) == ["schema.sql", "start.sh"]
    if os.name != "nt":
        assert os.access(directory / "start.sh", os.X_OK)
        assert not os.access(directory / "schema.sql", os.X_OK)

    with pytest.raises(ValueError, match="no document with 'name: db'"):
        _commit(services={"web": ServiceConfig(name="web", id="0a1", area="front",
                                               vip="10.80.0.10"),
                          "db": ServiceConfig(name="db", id="0a2", area="front",
                                              vip="10.80.0.11", service_file=str(service_file))},
                mutations={"frontal": MutationConfig(name="frontal", services=["web", "db"])})
    with pytest.raises(ValueError, match="cannot read"):
        _commit(services={"web": ServiceConfig(name="web", id="0a1", area="front",
                                               vip="10.80.0.10", files=[str(tmp_path / "x")])})


def test_service_instances_come_from_the_node_table(authority_node):
    """Who runs what, seen by any node, mutation or not."""
    from usmd_rdsh.cli.actions import catalog  # pylint: disable=import-outside-toplevel

    _commit()
    assert catalog.instance_rows() == []
    authority_node.settings.address = "192.168.1.11"
    authority_node.token = authority_node.authority.mint_token(
        USDN, authority_node.key, [Role.NODE_EXECUTOR], validity_ms=3_600_000, founder=True)
    authority_node.mutation = "frontal"
    authority_node.management[0x0A1] = 0x0001
    authority_node.publish_record()
    (row,) = catalog.instance_rows()
    assert (row["service"], row["sp_address"], row["mutation"]) == ("web", "0a1.0001", "frontal")
    assert row["node_id"].endswith("(self)")


def test_service_file_names_and_sizes_are_checked():
    with pytest.raises(ValueError, match="not a file name"):
        parse_service_file("name: web\nfiles:\n  ../etc/passwd: aGk=\n")
    with pytest.raises(ValueError, match="base64"):
        parse_service_file("name: web\nfiles:\n  a.sh: '***'\n")
    big = "A" * (4 * (512 * 1024 // 3 + 2))
    with pytest.raises(ValueError, match="at most"):
        parse_service_file(f"name: web\nfiles:\n  a.bin: {big}\n")


def test_area_containing_a_node_address_refused(authority_node):
    authority_node.settings.address = "10.80.3.4"
    with pytest.raises(ValueError, match="node address"):
        _commit()
    assert authority_node.signed.usd is None


def test_mutation_service_outside_catalogue_refused(authority_node):
    with pytest.raises(ValueError, match="unknown service"):
        _commit(mutations={"frontal": MutationConfig(name="frontal", services=["ghost"])})
    rogue = MutationProperties("frontal", 0, 0, 1, 0, b"name: ghost\n")
    with pytest.raises(ValueError, match="not in the catalogue"):
        bridge._check_mutation(rogue, {"web": 1})  # pylint: disable=protected-access


def test_retired_service_id_not_reused_at_once(authority_node):
    services = {
        "web": ServiceConfig(name="web", id="0a1", area="front", vip="10.80.0.10"),
        "db": ServiceConfig(name="db", id="0a2", area="front", vip="10.80.0.11")}
    _commit(services=services)
    del services["db"]
    _commit(services=services)
    assert not authority_node.authority.reuse_allowed(0x0A2)
    services["cache"] = ServiceConfig(name="cache", id="0a2", area="front", vip="10.80.0.12")
    with pytest.raises(ValueError, match="retired"):
        _commit(services=services)
    assert [e.name for e in authority_node.signed.usd.catalog] == ["web"]


# -- offline authority [ARCH 3.3, 14] -------------------------------------------------


def test_export_import_round_trip(authority_node, tmp_path):
    _commit()
    exported = export_signed(authority_node.signed)
    usc, usd, mutations = import_signed(exported)
    assert usc is None and usd.encode() == authority_node.signed.usd.encode()
    assert [m.name for m in mutations] == ["frontal"]
    other = Node(StateDirectory(tmp_path / "other"))
    other.settings.usc_anchor = b64u(authority_node.authority.usc.public)

    async def inject():
        return other.inject(usc, usd, mutations)

    assert asyncio.run(inject()) == ["usd", "mutation frontal"]
    with pytest.raises(ValueError):
        import_signed({"usd": "00ff"})


# -- local settings [ARCH 4.3, 4.4] -----------------------------------------------------


def test_inconsistent_anchors_refused_once_a_token_is_set(tmp_path):
    RUNTIME.document = ConfigDocument()
    RUNTIME.node = Node(StateDirectory(tmp_path))
    try:
        asyncio.run(bridge.apply_local("system trust-anchor", TrustAnchorConfig()))  # no token
        RUNTIME.document.set_field(("system", "bootstrap"), "creation_token", "AAAA")
        with pytest.raises(ValueError, match="trust anchor"):
            asyncio.run(bridge.apply_local("system trust-anchor", TrustAnchorConfig()))
    finally:
        RUNTIME.node = None


def test_usc_and_usd_labels_are_signed_and_checked():
    """[NCP-03 6.8, 6.9]: the label is encoded after the identifier, covered by
    the signature, at most 64 bytes of UTF-8 without control characters."""
    from usmd_rdsh.node.crypto import SigningKey  # pylint: disable=import-outside-toplevel
    from usmd_rdsh.node.ncp.codec import (  # pylint: disable=import-outside-toplevel
        Area, UscProperties, UsdProperties, check_label)
    from usmd_rdsh.node.wire import WireError  # pylint: disable=import-outside-toplevel

    key = SigningKey.generate()
    usc = UscProperties("01JAB7R3KX0Y2P8M4T6VQ9C1DZ", 5, key.public, [], label="dho").sign(key)
    again = UscProperties.decode(usc.encode())
    assert again.label == "dho" and again.encode() == usc.encode()
    again.verify(key.public)
    again.label = "other"
    with pytest.raises(Exception):
        again.verify(key.public)  # the signature covers the label
    usd = UsdProperties("01JAB7R9F2W5H1N3S8D0Q4K6ME", 5, key.public,
                        [Area(1, "front", "10.0.0.0", 16)], [], {}, label="prod").sign(key)
    assert UsdProperties.decode(usd.encode()).label == "prod"
    check_label("é" * 32)  # 64 bytes
    for bad in ("é" * 33, "a\nb", "a\x85b"):
        with pytest.raises(WireError):
            check_label(bad)
    with pytest.raises(WireError):
        UsdProperties("01JAB7R9F2W5H1N3S8D0Q4K6ME", 5, key.public,
                      [Area(1, "front", "10.0.0.0", 16)], [], {}, label="x" * 65).validate()
