"""Tests for the distance formula and resource usage."""

import unittest

from usmd.mutation.transmutation import DistanceCalculator, ResourceUsage


class TestDistanceCalculator(unittest.TestCase):

    def setUp(self):
        self.calc = DistanceCalculator(ping_tolerance_ms=200)

    def test_zero_distance_best_case(self):
        d = self.calc.compute(ping_ms=0, reference_load=0.0,
                              same_service=False, is_already_reference=False)
        self.assertAlmostEqual(d, 0.0)

    def test_max_distance_worst_case(self):
        d = self.calc.compute(ping_ms=200, reference_load=1.0,
                              same_service=True, is_already_reference=True)
        self.assertAlmostEqual(d, 5.0)

    def test_same_service_adds_one(self):
        d_diff = self.calc.compute(100, 0.0, False, False)
        d_same = self.calc.compute(100, 0.0, True, False)
        self.assertAlmostEqual(d_same - d_diff, 1.0)

    def test_already_reference_adds_two(self):
        d_no_ref = self.calc.compute(0, 0.0, False, False)
        d_is_ref = self.calc.compute(0, 0.0, False, True)
        self.assertAlmostEqual(d_is_ref - d_no_ref, 2.0)

    def test_ping_component(self):
        # t/T = 100/200 = 0.5
        d = self.calc.compute(100, 0.0, False, False)
        self.assertAlmostEqual(d, 0.5)

    def test_load_component(self):
        # c = 0.3
        d = self.calc.compute(0, 0.3, False, False)
        self.assertAlmostEqual(d, 0.3)

    def test_ping_capped_at_one(self):
        # Even if ping > T, t/T is capped at 1.0
        d = self.calc.compute(ping_ms=9999, reference_load=0.0,
                              same_service=False, is_already_reference=False)
        self.assertAlmostEqual(d, 1.0)

    def test_negative_load_clamped(self):
        d = self.calc.compute(0, -5.0, False, False)
        self.assertAlmostEqual(d, 0.0)

    def test_detailed_result_components(self):
        r = self.calc.compute_detailed(100, 0.5, True, False)
        self.assertAlmostEqual(r.ping_component, 0.5)
        self.assertAlmostEqual(r.load_component, 0.5)
        self.assertAlmostEqual(r.service_penalty, 1.0)
        self.assertAlmostEqual(r.reference_penalty, 0.0)
        self.assertAlmostEqual(r.d, 2.0)

    def test_invalid_tolerance_raises(self):
        with self.assertRaises(ValueError):
            DistanceCalculator(ping_tolerance_ms=0)


class TestResourceUsage(unittest.TestCase):

    def test_reference_load_is_max(self):
        usage = ResourceUsage(ram_percent=0.6, cpu_percent=0.9,
                              disk_percent=0.3, network_percent=0.1)
        self.assertAlmostEqual(usage.reference_load(), 0.9)

    def test_is_weakened_above_threshold(self):
        usage = ResourceUsage(0.9, 0.5, 0.2, 0.1)
        self.assertTrue(usage.is_weakened(0.8))

    def test_is_not_weakened_below_threshold(self):
        usage = ResourceUsage(0.4, 0.4, 0.4, 0.4)
        self.assertFalse(usage.is_weakened(0.8))

    def test_is_weakened_at_threshold(self):
        usage = ResourceUsage(0.8, 0.0, 0.0, 0.0)
        self.assertTrue(usage.is_weakened(0.8))


if __name__ == "__main__":
    unittest.main()
