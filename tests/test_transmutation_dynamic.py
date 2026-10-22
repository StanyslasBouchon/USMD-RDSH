"""Tests for dynamic-service load adjustment helpers."""

import unittest

from usmd.mutation.transmutation import (
    dynamic_service_effective_reference_load,
    dynamic_transmutation_delay_scale,
)


class TestDynamicTransmutation(unittest.TestCase):
    def test_effective_load_increases_with_data(self):
        base = 0.2
        eff = dynamic_service_effective_reference_load(base, 900e6, nominal_capacity_bytes=1e9)
        self.assertGreater(eff, base)
        self.assertLessEqual(eff, 1.0)

    def test_delay_scale_at_least_one(self):
        self.assertEqual(dynamic_transmutation_delay_scale(0, 12.5e6), 1.0)
        s = dynamic_transmutation_delay_scale(1e9, 1e6)
        self.assertGreaterEqual(s, 1.0)


if __name__ == "__main__":
    unittest.main()
