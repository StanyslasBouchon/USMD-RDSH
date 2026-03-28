"""Tests for NodeState enumeration."""

import unittest

from usmd.node.state import NodeState


class TestNodeState(unittest.TestCase):

    def test_active_is_active(self):
        self.assertTrue(NodeState.ACTIVE.is_active())

    def test_inactive_is_not_active(self):
        self.assertFalse(NodeState.INACTIVE.is_active())

    def test_pending_approval_is_pending(self):
        self.assertTrue(NodeState.PENDING_APPROVAL.is_pending())

    def test_synchronising_is_pending(self):
        self.assertTrue(NodeState.SYNCHRONISING.is_pending())

    def test_active_is_not_pending(self):
        self.assertFalse(NodeState.ACTIVE.is_pending())

    def test_inactive_variants_are_inactive(self):
        inactive_states = [
            NodeState.INACTIVE,
            NodeState.INACTIVE_MUTATING,
            NodeState.INACTIVE_TIMEOUT,
            NodeState.INACTIVE_EMERGENCY,
            NodeState.INACTIVE_EMERGENCY_OUT_OF_RESOURCES,
            NodeState.INACTIVE_EMERGENCY_DEPENDENCY_INACTIVE,
            NodeState.INACTIVE_EMERGENCY_HEALTH_CHECK_FAILED,
            NodeState.INACTIVE_EMERGENCY_UPDATE_FAILED,
            NodeState.INACTIVE_NNDP_NO_HIA,
        ]
        for state in inactive_states:
            with self.subTest(state=state):
                self.assertTrue(state.is_inactive(), f"{state} should be inactive")

    def test_excluded_variants_are_excluded(self):
        excluded = [
            NodeState.EXCLUDED_INVALID_NIT,
            NodeState.EXCLUDED_INVALID_ENDORSEMENT,
            NodeState.EXCLUDED_UNVERIFIABLE_ENDORSEMENT,
            NodeState.EXCLUDED_INVALID_REVOCATION,
            NodeState.EXCLUDED_INVALID_ENDORSEMENT_REVOCATION,
        ]
        for state in excluded:
            with self.subTest(state=state):
                self.assertTrue(state.is_excluded(), f"{state} should be excluded")

    def test_emergency_states_require_emergency(self):
        emergency_states = [
            NodeState.INACTIVE_EMERGENCY,
            NodeState.INACTIVE_EMERGENCY_OUT_OF_RESOURCES,
            NodeState.INACTIVE_EMERGENCY_DEPENDENCY_INACTIVE,
            NodeState.INACTIVE_EMERGENCY_HEALTH_CHECK_FAILED,
            NodeState.INACTIVE_EMERGENCY_UPDATE_FAILED,
        ]
        for state in emergency_states:
            with self.subTest(state=state):
                self.assertTrue(state.requires_emergency())

    def test_inactive_simple_does_not_require_emergency(self):
        self.assertFalse(NodeState.INACTIVE.requires_emergency())

    def test_str_returns_value(self):
        self.assertEqual(str(NodeState.ACTIVE), "active")


if __name__ == "__main__":
    unittest.main()
