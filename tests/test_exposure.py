"""Services reached from outside USMD at 60000 + service id (extension)."""

import pytest

from usmd_rdsh.node.exposure import ExposureTable, Rule, public_port, ruleset
from usmd_rdsh.node.services import Exposure, ServiceFileError, parse_service_file

PG = Rule("pg", 60209, "tcp", "10.80.0.20", 5432, ("192.168.0.0/16",))


def test_the_port_is_60000_plus_the_service_id():
    assert public_port(0x0D1) == 60209
    assert public_port(0x001) == 60001 and public_port(0xFFE) == 64094


def test_expose_is_read_from_the_service_file():
    (spec,) = parse_service_file(
        "name: pg\nexpose: {port: 5432, allow: [192.168.1.7/16]}\n"
        "probe:\n  - command: 'true'\npeers_changed:\n  - command: 'true'\n")
    assert spec.expose == Exposure(5432, "tcp", ("192.168.0.0/16",))
    assert spec.sequences["probe"] and spec.sequences["peers_changed"]
    assert parse_service_file("name: web\n")[0].expose is None
    for wrong, reason in (("{port: 0}", "1 to 65535"), ("{port: 53, protocol: sctp}", "tcp or udp"),
                          ("{port: 53, allow: [nowhere]}", "allow"), ("{ports: 53}", "has port")):
        with pytest.raises(ServiceFileError, match=reason):
            parse_service_file(f"name: x\nexpose: {wrong}\n")


def test_the_table_is_replaced_at_once_and_removed_when_empty():
    text = ruleset([PG, Rule("dns", 60210, "udp", "10.80.0.21", 53)])
    assert text.startswith("table ip usmd\ndelete table ip usmd\ntable ip usmd {")
    rule = ("fib daddr type local tcp dport 60209 ip saddr { 192.168.0.0/16 } "
            "dnat to 10.80.0.20:5432")
    assert text.count(rule) == 2  # prerouting, and output for the node itself
    assert "udp dport 60210 dnat to 10.80.0.21:53" in text
    assert ruleset([]) == "table ip usmd\ndelete table ip usmd\n"


def test_rules_are_applied_once_and_a_refusal_is_kept():
    applied = []
    table = ExposureTable(apply=lambda text: applied.append(text) or "")
    table.update([PG])
    table.update([PG])
    assert len(applied) == 1 and table.error == ""
    table.update([])
    assert applied[-1] == ruleset([])
    refusing = ExposureTable(apply=lambda text: "Error: Could not process rule")
    refusing.update([PG])
    assert refusing.error.startswith("Error") and refusing.rules == [PG]
