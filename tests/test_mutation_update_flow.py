"""Tests for ServiceUpdateFlow."""

import unittest

from usmd.mutation.lifecycle import ServiceLifecycleRunner
from usmd.mutation.service import Service
from usmd.mutation.update_flow import ServiceUpdateFlow, ServiceUpdateOutcome
from usmd.utils.errors import Error, ErrorKind
from usmd.utils.result import Result


class TestServiceUpdateFlow(unittest.TestCase):
    def test_inactive_node_build_only_ok(self):
        ok_runner = ServiceLifecycleRunner(runner=lambda c: Result.Ok(None))
        new = Service(name="n", build_commands=["echo x"], health_check_commands=[])
        out = ServiceUpdateFlow.apply(None, new, ok_runner, service_active=False)
        self.assertEqual(out, ServiceUpdateOutcome.OK_PROPAGATE)

    def test_active_update_commands_fail_triggers_rollback_ok(self):
        """Failing update lines invoke rollback (unbuild new, rebuild old)."""

        def runner(_cmd: str) -> Result:
            return Result.Err(Error.new(ErrorKind.MUTATION_FAILED, "x"))

        r = ServiceLifecycleRunner(runner=runner)
        old = Service(name="s", unbuild_commands=[], build_commands=[])
        new = Service(name="s", update_commands=["bad"], health_check_commands=[])
        out = ServiceUpdateFlow.apply(old, new, r, service_active=True)
        self.assertEqual(out, ServiceUpdateOutcome.ROLLBACK_OK)

    def test_inactive_build_fails_no_propagate(self):
        def runner(_cmd: str) -> Result:
            return Result.Err(Error.new(ErrorKind.MUTATION_FAILED, "x"))

        r = ServiceLifecycleRunner(runner=runner)
        new = Service(name="n", build_commands=["anything"])
        out = ServiceUpdateFlow.apply(None, new, r, service_active=False)
        self.assertEqual(out, ServiceUpdateOutcome.FAILED_NO_PROPAGATE)


if __name__ == "__main__":
    unittest.main()
