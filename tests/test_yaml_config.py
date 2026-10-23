"""usmd.yaml in the layout of usmd.example.yaml; development nodes."""

from pathlib import Path

import pytest

from usmd_rdsh.cli import yaml_config
from usmd_rdsh.cli.startup import dev_address

EXAMPLE = Path(__file__).resolve().parents[1] / "usmd.example.yaml"


def test_example_file_is_read_with_spec_roles_and_units():
    loaded = yaml_config.parse(EXAMPLE.read_text(encoding="utf-8"))
    doc = loaded.document
    assert doc.fields(("system", "bootstrap"))["roles"] == ["usc-operator"]
    assert any("ucd_operator" in w for w in loaded.warnings)
    usd = doc.fields(("usd",))
    assert usd["weakened_threshold"] == 800 and usd["emergency_threshold"] == 900
    assert usd["ping_tolerance"] == 200 and usd["reference_nodes"] == 5
    assert doc.fields(("protocol", "nndp"))["hia_interval"] == 30
    web = doc.fields(("system", "web-interface"))
    assert web["status"] is True and web["port"] == 8443 and web["tls_mode"] == "self-signed"
    assert any("5626" in w for w in loaded.warnings)  # NCP port differs from 9992
    assert any("nndp_listen" in w for w in loaded.warnings)  # fixed by NNDP-01


@pytest.mark.parametrize("role", ["usc-operator", "usd-operator", "node-operator",
                                  "node-executor"])
def test_spec_roles_are_kept(role):
    loaded = yaml_config.parse(f"node:\n  role: {role}\n")
    assert loaded.document.fields(("system", "bootstrap"))["roles"] == [role]
    assert loaded.warnings == []


def test_several_roles_with_the_daemon_names():
    loaded = yaml_config.parse("node:\n  roles: [executor, ucd_operator, usd_operator, "
                               "operator]\n")
    assert loaded.document.fields(("system", "bootstrap"))["roles"] == [
        "node-executor", "usc-operator", "usd-operator", "node-operator"]
    assert "roles:" in yaml_config.dump(loaded.document)


def test_unknown_role_is_refused():
    with pytest.raises(ValueError):
        yaml_config.parse("node:\n  role: superuser\n")


def test_round_trip_keeps_example_layout_and_tree_sections():
    text = (EXAMPLE.read_text(encoding="utf-8")
            + "\nsystem:\n  logging:\n    console-level: errors\n"
              "mutation:\n  frontal:\n    services: [web]\n    max-instances: 3\n")
    loaded = yaml_config.parse(text)
    dumped = yaml_config.dump(loaded.document, bootstrap=True, keys_file="keys.json")
    again = yaml_config.parse(dumped)
    assert again.document.to_dict() == loaded.document.to_dict()
    assert "- usc-operator" in dumped and "load_threshold: 0.8" in dumped
    assert "bootstrap: true" in dumped and again.keys_file == "keys.json"


def test_plain_http_web_interface_stays_plain_after_a_round_trip():
    loaded = yaml_config.parse("web:\n  enabled: true\n  port: 8080\n  tls: off\n")
    dumped = yaml_config.dump(loaded.document)
    again = yaml_config.parse(dumped)
    assert str(again.document.fields(("system", "web-interface")).get("tls_mode", "off")) == "off"
    assert "tls: 'off'" in dumped or "tls: off" in dumped


def test_dev_addresses():
    assert [dev_address(i) for i in (1, 2, 3)] == ["127.0.0.2", "127.0.0.3", "127.0.0.4"]


def test_readable_names_become_labels():
    """usmd.example.yaml's "human-readable USDN": the label; a ULID stays the name."""
    loaded = yaml_config.parse("usd:\n  name: my-domain\n  cluster_name: dho\n")
    assert loaded.document.fields(("usd",)) == {"label": "my-domain"}
    assert loaded.document.fields(("usc",)) == {"label": "dho"}
    ulid = "01JAB7R9F2W5H1N3S8D0Q4K6ME"
    loaded = yaml_config.parse(f"usd:\n  name: {ulid}\n  label: prod\n")
    assert loaded.document.fields(("usd",)) == {"name": ulid, "label": "prod"}
    again = yaml_config.parse(yaml_config.dump(loaded.document))
    assert again.document.fields(("usd",))["label"] == "prod"
