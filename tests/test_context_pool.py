"""ContextPool 单元测试 — Scope 权限、TTL、Provider、wait_for、消费追踪"""

import asyncio
import tempfile
import time
from pathlib import Path

import pytest

from framework.context_pool import ContextPool, Scope, ProviderSpec, PoolEntry


@pytest.fixture
def pool():
    """创建临时工作区的 ContextPool。"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield ContextPool(Path(tmpdir))


class TestScopeAccess:
    """Scope 权限控制测试。"""

    def test_public_scope_anyone_can_read(self, pool):
        pool.put("open_ports", [22, 80, 443], Scope.PUBLIC, "M1", "phase_A")
        # 跨模块可读
        result = pool.get("open_ports", "M3", "phase_A")
        assert result == [22, 80, 443]

    def test_module_scope_same_module(self, pool):
        pool.put("session_cookie", "abc123", Scope.MODULE, "M2", "phase_A")
        # 同模块可读
        result = pool.get("session_cookie", "M2", "phase_B")
        assert result == "abc123"

    def test_module_scope_cross_module_blocked(self, pool):
        pool.put("session_cookie", "abc123", Scope.MODULE, "M2", "phase_A")
        # 跨模块不可读
        result = pool.get("session_cookie", "M3", "phase_A")
        assert result is None

    def test_phase_scope_same_phase_only(self, pool):
        pool.put("temp_data", {"x": 1}, Scope.PHASE, "M1", "phase_A")
        # 同 phase 可读
        assert pool.get("temp_data", "M1", "phase_A") == {"x": 1}
        # 同模块不同 phase 不可读
        assert pool.get("temp_data", "M1", "phase_B") is None
        # 跨模块不可读
        assert pool.get("temp_data", "M2", "phase_A") is None


class TestTTL:
    """TTL 过期测试。"""

    def test_not_expired(self, pool):
        pool.put("data", "value", Scope.PUBLIC, "M1", "phase_A", ttl=300)
        result = pool.get("data", "M2", "phase_A")
        assert result == "value"

    def test_expired_returns_none(self, pool):
        pool.put("data", "value", Scope.PUBLIC, "M1", "phase_A", ttl=1)
        # 手动设置过期
        for entry in pool._entries.values():
            entry.created_at = time.time() - 10  # 10秒前
        result = pool.get("data", "M2", "phase_A")
        assert result is None

    def test_zero_ttl_never_expires(self, pool):
        pool.put("data", "value", Scope.PUBLIC, "M1", "phase_A", ttl=0)
        for entry in pool._entries.values():
            entry.created_at = time.time() - 99999
        result = pool.get("data", "M2", "phase_A")
        assert result == "value"


class TestConsumedTracking:
    """消费追踪测试。"""

    def test_get_marks_consumed(self, pool):
        pool.put("data", "value", Scope.PUBLIC, "M1", "phase_A")
        pool.get("data", "M3", "phase_A")

        unconsumed = pool.get_unconsumed("M1")
        # PUBLIC scope 不参与 get_unconsumed (只检查 MODULE scope)
        assert "data" not in unconsumed

    def test_unconsumed_module_scope(self, pool):
        pool.put("internal_data", {"x": 1}, Scope.MODULE, "M2", "phase_A")
        # 未消费
        assert "internal_data" in pool.get_unconsumed("M2")
        # 消费后
        pool.get("internal_data", "M2", "phase_B")
        assert "internal_data" not in pool.get_unconsumed("M2")


class TestProvider:
    """Provider 机制测试。"""

    def test_register_provider(self, pool):
        spec = ProviderSpec(
            name="test_provider",
            callable_ref="bash:echo hello",
            scope=Scope.MODULE,
            ttl_seconds=60,
            output_key="test_output",
        )
        pool.register_provider(spec)
        assert "test_provider" in pool._providers

    def test_invoke_bash_provider(self, pool):
        spec = ProviderSpec(
            name="echo_test",
            callable_ref="bash:echo test_value",
            scope=Scope.PUBLIC,
            ttl_seconds=60,
            output_key="echo_result",
        )
        pool.register_provider(spec)
        result = asyncio.get_event_loop().run_until_complete(
            pool.invoke_provider("echo_test", "M1", "phase_A")
        )
        assert result == "test_value"
        # 结果已存入 pool
        stored = pool.get("echo_result", "M2", "phase_A")
        assert stored == "test_value"

    def test_invoke_unknown_provider(self, pool):
        result = asyncio.get_event_loop().run_until_complete(
            pool.invoke_provider("nonexistent", "M1", "phase_A")
        )
        assert result is None


class TestWaitFor:
    """异步 wait_for 测试。"""

    def test_wait_for_existing_key(self, pool):
        pool.put("ready_data", [1, 2, 3], Scope.PUBLIC, "M1", "phase_A")
        result = asyncio.get_event_loop().run_until_complete(
            pool.wait_for("ready_data", "M2", "phase_A", timeout=5)
        )
        assert result == [1, 2, 3]

    def test_wait_for_timeout(self, pool):
        result = asyncio.get_event_loop().run_until_complete(
            pool.wait_for("missing_key", "M2", "phase_A", timeout=1, poll_interval=0.3)
        )
        assert result is None


class TestPoolQueries:
    """查询方法测试。"""

    def test_list_keys(self, pool):
        pool.put("a", 1, Scope.PUBLIC, "M1", "phase_A")
        pool.put("b", 2, Scope.MODULE, "M1", "phase_A")
        pool.put("c", 3, Scope.PUBLIC, "M2", "phase_A")

        all_keys = pool.list_keys()
        assert set(all_keys) == {"a", "b", "c"}

        public_keys = pool.list_keys(scope=Scope.PUBLIC)
        assert set(public_keys) == {"a", "c"}

        m1_keys = pool.list_keys(module_id="M1")
        assert set(m1_keys) == {"a", "b"}

    def test_get_pool_summary(self, pool):
        pool.put("x", "val", Scope.PUBLIC, "M1", "phase_A")
        summary = pool.get_pool_summary()
        assert summary["total_entries"] == 1
        assert len(summary["entries"]) == 1

    def test_get_snapshot_for_phase(self, pool):
        pool.put("public_data", "pub", Scope.PUBLIC, "M1", "phase_A")
        pool.put("m2_data", "mod", Scope.MODULE, "M2", "phase_A")

        # M2 可看到 PUBLIC + 自己的 MODULE
        snap = pool.get_snapshot_for_phase("M2", "phase_A")
        assert "public_data" in snap
        assert "m2_data" in snap

        # M3 只能看到 PUBLIC
        snap = pool.get_snapshot_for_phase("M3", "phase_A")
        assert "public_data" in snap
        assert "m2_data" not in snap


class TestPersistence:
    """磁盘持久化测试。"""

    def test_index_survives_reload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = Path(tmpdir)
            # 写入数据
            pool1 = ContextPool(ws)
            pool1.put("persist_key", "persist_value", Scope.PUBLIC, "M1", "phase_A")

            # 重新加载
            pool2 = ContextPool(ws)
            result = pool2.get("persist_key", "M2", "phase_A")
            assert result == "persist_value"
