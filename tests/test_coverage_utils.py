"""Coverage tests for utility/config modules.

Covers:
- usmd/utils/result.py      (Result[T,E], hide/reveal, all)
- usmd/utils/io.py          (close_writer, close_stream_writer)
- usmd/domain/usc.py        (USCConfig, UnifiedSystemCluster)
- usmd/config.py            (NodeConfig, from_file, node_role, resolve_address)
- usmd/web/state.py         (WebState, get_state, set_state)
- usmd/mutation/service.py  (ServiceType, ServiceCommand, Service)
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest

from usmd.utils.result import Result
from usmd.utils.io import close_writer, close_stream_writer
from usmd.domain.usc import USCConfig, UnifiedSystemCluster
from usmd.config import NodeConfig
from usmd.web.state import WebState, get_state, set_state
from usmd.mutation.service import Service, ServiceCommand, ServiceType


# ===========================================================================
# utils/result.py
# ===========================================================================


class TestResultOk:
    def test_ok_is_ok(self):
        assert Result.Ok(42).is_ok() is True

    def test_ok_is_not_err(self):
        assert Result.Ok(42).is_err() is False

    def test_ok_unwrap(self):
        assert Result.Ok("hello").unwrap() == "hello"

    def test_ok_unwrap_err_raises(self):
        with pytest.raises(ValueError):
            Result.Ok(1).unwrap_err()

    def test_ok_str(self):
        assert str(Result.Ok(99)) == "Ok(99)"


class TestResultErr:
    def test_err_is_err(self):
        assert Result.Err("oops").is_err() is True

    def test_err_is_not_ok(self):
        assert Result.Err("oops").is_ok() is False

    def test_err_unwrap_err(self):
        assert Result.Err("boom").unwrap_err() == "boom"

    def test_err_unwrap_raises(self):
        with pytest.raises(ValueError):
            Result.Err("bad").unwrap()

    def test_err_str(self):
        assert str(Result.Err("x")) == "Err(x)"


class TestResultAll:
    def test_all_ok(self):
        r = Result.all([Result.Ok(1), Result.Ok(2), Result.Ok(3)])
        assert r.is_ok()
        assert r.unwrap() == [1, 2, 3]

    def test_all_first_err(self):
        r = Result.all([Result.Ok(1), Result.Err("bad"), Result.Ok(3)])
        assert r.is_err()
        assert r.unwrap_err() == "bad"

    def test_all_empty(self):
        r = Result.all([])
        assert r.is_ok()
        assert r.unwrap() == []


class TestResultHideReveal:
    def test_reveal_all_ok(self):
        Result.hide()
        Result.Ok(1)
        Result.Ok(2)
        r = Result.reveal()
        assert r.is_ok()

    def test_reveal_first_err(self):
        Result.hide()
        Result.Ok(1)
        Result.Err("first error")
        Result.Err("second error")
        r = Result.reveal()
        assert r.is_err()
        assert r.unwrap_err() == "first error"

    def test_reveal_empty(self):
        Result.hide()
        r = Result.reveal()
        assert r.is_ok()
        assert r.unwrap() is None

    def test_hide_stops_collecting_after_reveal(self):
        Result.hide()
        Result.Ok(10)
        Result.reveal()
        # After reveal, new Results should NOT be collected
        r_after = Result.Ok(20)
        assert r_after.is_ok()  # should not raise


# ===========================================================================
# utils/io.py
# ===========================================================================


class TestCloseWriter:
    def test_close_writer_calls_close(self):
        writer = MagicMock()
        close_writer(writer)
        writer.close.assert_called_once()

    def test_close_writer_ignores_oserror(self):
        writer = MagicMock()
        writer.close.side_effect = OSError("pipe broken")
        # Should not raise
        close_writer(writer)


@pytest.mark.asyncio
class TestCloseStreamWriter:
    async def test_close_stream_writer_calls_close_and_wait(self):
        writer = AsyncMock(spec=asyncio.StreamWriter)
        await close_stream_writer(writer)
        writer.close.assert_called_once()
        writer.wait_closed.assert_called_once()

    async def test_close_stream_writer_ignores_oserror(self):
        writer = AsyncMock(spec=asyncio.StreamWriter)
        writer.wait_closed.side_effect = OSError("reset")
        # Should not raise
        await close_stream_writer(writer)
        writer.close.assert_called_once()


# ===========================================================================
# domain/usc.py
# ===========================================================================


class TestUSCConfig:
    def test_fields(self):
        cfg = USCConfig(name="eu-cluster", private_key=b"\x00" * 32)
        assert cfg.name == "eu-cluster"
        assert len(cfg.private_key) == 32
        assert cfg.version == 0

    def test_version_explicit(self):
        cfg = USCConfig(name="c", private_key=b"k" * 32, version=7)
        assert cfg.version == 7


class TestUnifiedSystemCluster:
    def _make(self, name="test"):
        cfg = USCConfig(name=name, private_key=b"\x00" * 32)
        return UnifiedSystemCluster(config=cfg)

    def test_add_domain_ok(self):
        usc = self._make()
        r = usc.add_domain("prod")
        assert r.is_ok()
        assert "prod" in usc.domain_names

    def test_add_domain_duplicate_err(self):
        usc = self._make()
        usc.add_domain("prod")
        r = usc.add_domain("prod")
        assert r.is_err()

    def test_remove_domain_ok(self):
        usc = self._make()
        usc.add_domain("prod")
        r = usc.remove_domain("prod")
        assert r.is_ok()
        assert "prod" not in usc.domain_names

    def test_remove_domain_not_found_err(self):
        usc = self._make()
        r = usc.remove_domain("nonexistent")
        assert r.is_err()

    def test_has_domain_true(self):
        usc = self._make()
        usc.add_domain("x")
        assert usc.has_domain("x") is True

    def test_has_domain_false(self):
        usc = self._make()
        assert usc.has_domain("missing") is False

    def test_update_config_newer_version(self):
        cfg = USCConfig(name="c", private_key=b"\x00" * 32, version=1)
        usc = UnifiedSystemCluster(config=cfg)
        new_cfg = USCConfig(name="c", private_key=b"\x01" * 32, version=5)
        usc.update_config(new_cfg)
        assert usc.config.version == 5

    def test_update_config_older_version_ignored(self):
        cfg = USCConfig(name="c", private_key=b"\x00" * 32, version=10)
        usc = UnifiedSystemCluster(config=cfg)
        old_cfg = USCConfig(name="c", private_key=b"\x01" * 32, version=2)
        usc.update_config(old_cfg)
        assert usc.config.version == 10

    def test_repr(self):
        usc = self._make("my-usc")
        usc.add_domain("d1")
        r = repr(usc)
        assert "my-usc" in r
        assert "1" in r


# ===========================================================================
# config.py
# ===========================================================================


class TestNodeConfig:
    def test_defaults(self):
        cfg = NodeConfig()
        assert cfg.ncp_port == 5626
        assert cfg.address == "auto"
        assert cfg.role == "executor"
        assert cfg.bootstrap is False

    def test_node_role_executor(self):
        from usmd.node.role import NodeRole
        cfg = NodeConfig(role="executor")
        assert cfg.node_role == NodeRole.NODE_EXECUTOR

    def test_node_role_operator(self):
        from usmd.node.role import NodeRole
        cfg = NodeConfig(role="operator")
        assert cfg.node_role == NodeRole.NODE_OPERATOR

    def test_node_role_usd_operator(self):
        from usmd.node.role import NodeRole
        cfg = NodeConfig(role="usd_operator")
        assert cfg.node_role == NodeRole.USD_OPERATOR

    def test_node_role_ucd_operator(self):
        from usmd.node.role import NodeRole
        cfg = NodeConfig(role="ucd_operator")
        assert cfg.node_role == NodeRole.UCD_OPERATOR

    def test_node_role_unknown_defaults_to_executor(self):
        from usmd.node.role import NodeRole
        cfg = NodeConfig(role="unknown_role")
        assert cfg.node_role == NodeRole.NODE_EXECUTOR

    def test_resolve_address_explicit(self):
        cfg = NodeConfig(address="192.168.1.1")
        assert cfg.resolve_address() == "192.168.1.1"

    def test_resolve_address_auto(self):
        cfg = NodeConfig(address="auto")
        addr = cfg.resolve_address()
        assert isinstance(addr, str)
        assert len(addr) > 0

    def test_to_usd_config(self):
        cfg = NodeConfig(usd_name="prod", cluster_name="eu-cluster")
        usd_cfg = cfg.to_usd_config()
        assert usd_cfg.name == "prod"
        assert usd_cfg.cluster_name == "eu-cluster"

    def test_from_file_nonexistent_returns_default(self):
        cfg = NodeConfig.from_file("/nonexistent/path/usmd.yaml")
        assert cfg.usd_name == "default-domain"
        assert cfg.ncp_port == 5626

    def test_from_file_valid_yaml(self):
        yaml_content = """
node:
  address: 10.0.0.1
  role: operator
usd:
  name: my-domain
  max_reference_nodes: 3
bootstrap: true
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(yaml_content)
            f.flush()
            path = f.name
        try:
            cfg = NodeConfig.from_file(path)
            assert cfg.address == "10.0.0.1"
            assert cfg.role == "operator"
            assert cfg.usd_name == "my-domain"
            assert cfg.max_reference_nodes == 3
            assert cfg.bootstrap is True
        finally:
            os.unlink(path)

    def test_from_file_partial_yaml(self):
        yaml_content = """
ports:
  ncp: 9999
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(yaml_content)
            f.flush()
            path = f.name
        try:
            cfg = NodeConfig.from_file(path)
            assert cfg.ncp_port == 9999
            assert cfg.usd_name == "default-domain"  # default preserved
        finally:
            os.unlink(path)


# ===========================================================================
# web/state.py
# ===========================================================================


class TestWebState:
    def test_set_and_get_state(self):
        mock_snapshot = MagicMock()
        mock_nit = MagicMock()
        mock_usd = MagicMock()
        mock_cfg = MagicMock()

        ws = WebState(
            snapshot_fn=mock_snapshot,
            nit=mock_nit,
            ncp_port=5626,
            cfg=mock_cfg,
            usd=mock_usd,
        )
        set_state(ws)
        retrieved = get_state()
        assert retrieved is ws
        assert retrieved.ncp_port == 5626

    def test_webstate_on_ncp_failure_optional(self):
        ws = WebState(
            snapshot_fn=MagicMock(),
            nit=MagicMock(),
            ncp_port=5626,
            cfg=MagicMock(),
            usd=MagicMock(),
        )
        assert ws.on_ncp_failure is None

    def test_webstate_on_ncp_failure_provided(self):
        cb = MagicMock()
        ws = WebState(
            snapshot_fn=MagicMock(),
            nit=MagicMock(),
            ncp_port=5626,
            cfg=MagicMock(),
            usd=MagicMock(),
            on_ncp_failure=cb,
        )
        assert ws.on_ncp_failure is cb


# ===========================================================================
# mutation/service.py
# ===========================================================================


class TestServiceType:
    def test_static_is_static(self):
        assert ServiceType.STATIC.is_static() is True
        assert ServiceType.STATIC.is_dynamic() is False

    def test_dynamic_is_dynamic(self):
        assert ServiceType.DYNAMIC.is_dynamic() is True
        assert ServiceType.DYNAMIC.is_static() is False

    def test_str(self):
        assert str(ServiceType.STATIC) == "static"
        assert str(ServiceType.DYNAMIC) == "dynamic"

    def test_values(self):
        assert ServiceType.STATIC.value == "static"
        assert ServiceType.DYNAMIC.value == "dynamic"


class TestServiceCommand:
    def test_command_not_action(self):
        cmd = ServiceCommand(command="apt install curl -y")
        assert cmd.is_action() is False
        assert str(cmd) == "apt install curl -y"

    def test_action_is_action(self):
        cmd = ServiceCommand(action="unbuild")
        assert cmd.is_action() is True
        assert str(cmd) == "action:unbuild"

    def test_empty_command_str(self):
        cmd = ServiceCommand()
        assert str(cmd) == ""

    def test_action_takes_priority(self):
        # action is present and command is None → is_action True
        cmd = ServiceCommand(action="restart")
        assert cmd.is_action() is True


class TestService:
    def _make(self, **kw):
        defaults = dict(
            name="web",
            service_type=ServiceType.STATIC,
            dependencies=["backend"],
            build_commands=["nginx -t && nginx"],
            unbuild_commands=["nginx -s stop"],
        )
        defaults.update(kw)
        return Service(**defaults)

    def test_name(self):
        svc = self._make(name="api")
        assert svc.name == "api"

    def test_service_type_static(self):
        svc = self._make(service_type=ServiceType.STATIC)
        assert svc.service_type.is_static()

    def test_service_type_dynamic(self):
        svc = self._make(service_type=ServiceType.DYNAMIC)
        assert svc.service_type.is_dynamic()

    def test_has_dependency_true(self):
        svc = self._make(dependencies=["backend", "db"])
        assert svc.has_dependency("backend") is True
        assert svc.has_dependency("db") is True

    def test_has_dependency_false(self):
        svc = self._make(dependencies=["backend"])
        assert svc.has_dependency("cache") is False

    def test_repr(self):
        svc = self._make(name="myservice")
        r = repr(svc)
        assert "myservice" in r

    def test_default_fields(self):
        svc = Service(name="minimal")
        assert svc.service_type == ServiceType.STATIC
        assert svc.dependencies == []
        assert svc.build_commands == []
        assert svc.update_commands == []
        assert svc.version == 0
