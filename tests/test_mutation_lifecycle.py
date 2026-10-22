"""Tests for ServiceLifecycleRunner (mocked subprocess)."""

import unittest

from usmd.mutation.lifecycle import ServiceLifecycleRunner
from usmd.mutation.service import Service
from usmd.utils.errors import Error, ErrorKind
from usmd.utils.result import Result


class TestServiceLifecycleRunner(unittest.TestCase):
    def test_check_health_empty_is_true(self):
        svc = Service(name="s")
        r = ServiceLifecycleRunner(runner=lambda c: Result.Ok(None))
        self.assertTrue(r.check_health(svc))

    def test_action_unbuild_dispatches(self):
        calls: list[str] = []

        def runner(cmd: str) -> Result[None, Error]:
            calls.append(cmd)
            return Result.Ok(None)

        r = ServiceLifecycleRunner(runner=runner)
        svc = Service(
            name="s",
            unbuild_commands=["echo stop"],
            emergency_commands=["action:unbuild"],
        )
        res = r.execute_emergency(svc)
        self.assertTrue(res.is_ok())
        self.assertIn("echo stop", calls)

    def test_build_phase_records_failure(self):
        def runner(cmd: str) -> Result[None, Error]:
            return Result.Err(Error.new(ErrorKind.MUTATION_FAILED, "nope"))

        r = ServiceLifecycleRunner(runner=runner)
        svc = Service(name="s", build_commands=["false"])
        res = r.execute_build(svc)
        self.assertTrue(res.is_err())
        self.assertTrue(r.last_failures)


if __name__ == "__main__":
    unittest.main()
