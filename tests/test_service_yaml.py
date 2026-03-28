"""Tests for ServiceYamlParser."""

import os
import tempfile
import unittest

from usmd.mutation.service import Service, ServiceType
from usmd.mutation.yaml_parser import ServiceYamlParser


FULL_YAML = """
dependencies:
  - db
  - cache
build:
  - command: apt install myapp -y
  - command: systemctl enable myapp
unbuild:
  - command: systemctl disable myapp
  - command: apt remove myapp -y
emergency:
  - action: unbuild
  - command: cp /data/* /backup/
check_health:
  - command: curl -f http://localhost/health
"""

MINIMAL_YAML = """
build:
  - command: echo hello
"""

INVALID_YAML = "{ this: is: not: valid yaml ::::"


class TestServiceYamlParser(unittest.TestCase):

    def test_parse_returns_ok_for_valid_yaml(self):
        result = ServiceYamlParser.parse("mysvc", FULL_YAML)
        self.assertTrue(result.is_ok())

    def test_parse_service_name(self):
        result = ServiceYamlParser.parse("mysvc", FULL_YAML)
        self.assertEqual(result.unwrap().name, "mysvc")

    def test_parse_dependencies(self):
        svc = ServiceYamlParser.parse("svc", FULL_YAML).unwrap()
        self.assertIn("db", svc.dependencies)
        self.assertIn("cache", svc.dependencies)

    def test_parse_build_commands(self):
        svc = ServiceYamlParser.parse("svc", FULL_YAML).unwrap()
        self.assertEqual(len(svc.build_commands), 2)
        self.assertIn("apt install myapp -y", svc.build_commands[0])

    def test_parse_unbuild_commands(self):
        svc = ServiceYamlParser.parse("svc", FULL_YAML).unwrap()
        self.assertEqual(len(svc.unbuild_commands), 2)

    def test_parse_emergency_commands(self):
        svc = ServiceYamlParser.parse("svc", FULL_YAML).unwrap()
        self.assertEqual(len(svc.emergency_commands), 2)

    def test_parse_health_check_commands(self):
        svc = ServiceYamlParser.parse("svc", FULL_YAML).unwrap()
        self.assertEqual(len(svc.health_check_commands), 1)

    def test_parse_minimal_yaml(self):
        result = ServiceYamlParser.parse("minimal", MINIMAL_YAML)
        self.assertTrue(result.is_ok())
        svc = result.unwrap()
        self.assertEqual(len(svc.dependencies), 0)
        self.assertEqual(len(svc.build_commands), 1)

    def test_parse_empty_yaml(self):
        result = ServiceYamlParser.parse("empty", "")
        self.assertTrue(result.is_ok())
        svc = result.unwrap()
        self.assertEqual(len(svc.build_commands), 0)

    def test_parse_invalid_yaml_returns_err(self):
        result = ServiceYamlParser.parse("bad", INVALID_YAML)
        self.assertTrue(result.is_err())

    def test_parse_file_reads_from_disk(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(FULL_YAML)
            path = f.name

        try:
            result = ServiceYamlParser.parse_file(path)
            self.assertTrue(result.is_ok())
            # Service name should be derived from filename (without extension)
            svc = result.unwrap()
            expected_name = os.path.splitext(os.path.basename(path))[0]
            self.assertEqual(svc.name, expected_name)
        finally:
            os.unlink(path)

    def test_parse_file_missing_path_returns_err(self):
        result = ServiceYamlParser.parse_file("/nonexistent/path/service.yaml")
        self.assertTrue(result.is_err())

    def test_returns_service_instance(self):
        svc = ServiceYamlParser.parse("svc", FULL_YAML).unwrap()
        self.assertIsInstance(svc, Service)


if __name__ == "__main__":
    unittest.main()
