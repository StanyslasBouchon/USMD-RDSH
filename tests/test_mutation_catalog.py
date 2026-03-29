"""Tests for MutationCatalog and NCP summary merge."""

import unittest

from usmd.domain.usd import USDConfig, UnifiedSystemDomain
from usmd.mutation.catalog import MutationCatalog
from usmd.mutation.service import Service, ServiceType
from usmd.ncp.protocol.commands.send_mutation_properties import MutationSummary


class TestMutationCatalog(unittest.TestCase):
    def test_register_and_get(self):
        cat = MutationCatalog()
        s = Service(name="a", service_type=ServiceType.STATIC, version=3)
        cat.register(s, "type: static\nbuild: []\n")
        self.assertEqual(cat.get("a").version, 3)
        self.assertIn("type:", cat.get_yaml("a") or "")

    def test_apply_remote_yaml_replaces(self):
        cat = MutationCatalog()
        y = "build:\n  - command: echo one\n"
        cat.apply_remote_summaries(
            [MutationSummary("x", 10, definition_yaml=y)]
        )
        self.assertEqual(cat.get("x").version, 10)
        self.assertGreater(len(cat.get("x").build_commands), 0)

    def test_version_only_bumps_when_newer(self):
        cat = MutationCatalog()
        cat.register(Service(name="x", version=5), None)
        cat.apply_remote_summaries([MutationSummary("x", 7)])
        self.assertEqual(cat.get("x").version, 7)

    def test_summaries_for_broadcast_includes_yaml(self):
        cat = MutationCatalog()
        cat.register(Service(name="z", version=1), "build: []\n")
        summ = cat.summaries_for_broadcast()
        self.assertEqual(len(summ), 1)
        self.assertIsNotNone(summ[0].definition_yaml)

    def test_catalog_on_usd(self):
        cfg = USDConfig(name="t")
        usd = UnifiedSystemDomain(cfg, b"\x00" * 32)
        self.assertEqual(usd.mutation_catalog.count(), 0)


if __name__ == "__main__":
    unittest.main()
