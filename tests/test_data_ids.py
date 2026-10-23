"""Data identifiers and the environment of the sequences [ARCH-03 8.7, 11.6]."""

import asyncio
import sys
import uuid

import pytest

from usmd_rdsh.node import addresses, dataid
from usmd_rdsh.node.services import ServiceRunner, Step, ServiceSpec

DB = addresses.from_text("0b2.0003")


def test_identifier_starts_with_the_sp_address_and_is_a_version_8_uuid():
    value = dataid.encode(DB, 0x0192_3456_789A, 0x1234, 0x2ABCDEF)
    assert str(value).startswith("00b20003-0192-8")
    assert value.version == 8 and value.variant == uuid.RFC_4122
    decoded = dataid.decode(str(value))
    assert decoded == dataid.DataId(DB, 0x0192_3456_789A, 0x1234, 0x2ABCDEF)
    assert decoded.sp_text == "0b2.0003" and decoded.service_id == 0x0B2
    assert decoded.management_id == 3
    assert dataid.prefix(DB) == "00b20003"


def test_order_is_instance_then_time():
    early = dataid.encode(DB, 1_000, 0xFFFF, 0)
    late = dataid.encode(DB, 1_001, 0, 0)
    other = dataid.encode(addresses.from_text("0b2.0004"), 0, 0, 0)
    assert early.bytes < late.bytes < other.bytes


@pytest.mark.parametrize("address", ["0b2.0000", "0b2.ffff", "000.0001", "fff.0001"])
def test_only_instance_addresses_make_identifiers(address):
    with pytest.raises(ValueError):
        dataid.DataIdGenerator(addresses.from_text(address))


@pytest.mark.parametrize("text", [str(uuid.uuid4()), "10b20003-0192-8d3a-8000-000000000000",
                                  "00b20003-0192-8d3a-c000-000000000000"])
def test_other_uuids_are_not_data_identifiers(text):
    with pytest.raises(ValueError):
        dataid.decode(text)


def test_generator_never_goes_back_and_carries_over_the_sequence():
    now = [5_000]
    gen = dataid.DataIdGenerator(DB, clock=lambda: now[0])
    first = dataid.decode(gen.next())
    now[0] = 4_000  # the clock goes back
    second = dataid.decode(gen.next())
    assert second.timestamp_ms == 5_000 and second.sequence == first.sequence + 1
    gen._sequence = dataid.SEQUENCE_MAX  # pylint: disable=protected-access
    third = dataid.decode(gen.next())
    assert (third.timestamp_ms, third.sequence) == (5_001, 0)


def test_generator_identifiers_are_unique_and_sorted():
    gen = dataid.DataIdGenerator(DB)
    ids = [gen.next() for _ in range(50_000)]
    assert len(set(ids)) == len(ids)
    stamps = [(d.timestamp_ms, d.sequence) for d in map(dataid.decode, ids)]
    assert stamps == sorted(stamps)


def test_postgresql_text_sets_the_prefix_and_refuses_odd_database_names():
    sql = dataid.postgresql(DB, "orders")
    assert "CREATE OR REPLACE FUNCTION usmd_id()" in sql
    assert sql.rstrip().endswith("ALTER DATABASE orders SET usmd.data_id_prefix = '00b20003';")
    with pytest.raises(ValueError):
        dataid.postgresql(DB, "x; DROP TABLE t")


# --- Sequences [ARCH-03 8.7] -------------------------------------------------

def _spec(tmp_path, sequence, script):
    path = tmp_path / f"{sequence}.py"
    path.write_text(script, encoding="utf-8")
    command = f'"{sys.executable}" "{path}"'
    return ServiceSpec("db", "dynamic", [], {sequence: [Step(command, None, 30)]})


def test_sequences_get_the_usmd_variables(tmp_path):
    out = tmp_path / "seen.txt"
    spec = _spec(tmp_path, "build", "import os, pathlib\n"
                 f"pathlib.Path(r'{out}').write_text(os.environ['USMD_SP_ADDRESS'] + ' '"
                 " + os.environ['USMD_SEQUENCE'] + ' ' + os.environ['PATH'][:1])\n")
    runner = ServiceRunner(environment=lambda s, seq: {"USMD_SP_ADDRESS": "0b2.0003",
                                                      "USMD_SEQUENCE": seq})
    assert asyncio.run(runner.run(spec, "build")).ok
    seen = out.read_text()
    assert seen.startswith("0b2.0003 build ") and len(seen) > len("0b2.0003 build ")


@pytest.mark.parametrize("sequence,refused", [("build", True), ("update", True),
                                               ("check_health", True), ("unbuild", False),
                                               ("emergency", False)])
def test_no_sp_address_refuses_build_update_and_health(tmp_path, sequence, refused):
    spec = _spec(tmp_path, sequence, "pass\n")
    runner = ServiceRunner(environment=lambda s, seq: None)
    result = asyncio.run(runner.run(spec, sequence))
    assert result.ok is not refused
    if refused:
        assert "no SP address" in result.log[0]


def test_sequences_of_one_service_never_overlap(tmp_path):
    marker = tmp_path / "running"
    script = ("import pathlib, sys, time\n"
              f"m = pathlib.Path(r'{marker}')\n"
              "if m.exists(): sys.exit(1)\n"
              "m.write_text('x'); time.sleep(0.5); m.unlink()\n")
    build = _spec(tmp_path, "build", script)
    health = _spec(tmp_path, "check_health", script)
    spec = ServiceSpec("db", "dynamic", [], {**build.sequences, **health.sequences})
    runner = ServiceRunner(environment=lambda s, seq: {})

    async def both():
        return await asyncio.gather(runner.run(spec, "build"), runner.run(spec, "check_health"))

    assert all(r.ok for r in asyncio.run(both()))
