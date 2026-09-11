"""PhaseEngine 单元测试 — JSON 加载、拓扑排序、Evidence 合并"""

import json
import tempfile
from pathlib import Path

import pytest

from framework.phase_engine import (
    PhaseDef,
    ModulePhaseDef,
    PhaseDefinitionLoader,
    PhaseExecutionEngine,
)
from framework.context_pool import ContextPool, Scope


@pytest.fixture
def config_path():
    """创建临时 phase_definitions.json。"""
    config = {
        "version": "1.0",
        "providers": [
            {
                "name": "test_provider",
                "callable_ref": "bash:echo test",
                "scope": "MODULE",
                "ttl_seconds": 60,
                "output_key": "test_output",
                "description": "Test provider",
            }
        ],
        "modules": {
            "M1": {
                "phases": [
                    {
                        "id": "phase_A",
                        "name": "Phase A",
                        "clauses": ["5.6-1", "5.6-2"],
                        "depends_on": [],
                        "wait_for_pool_keys": [],
                        "tools": ["bash"],
                        "knowledge_additions": [],
                        "pool_outputs": [{"key": "open_ports", "scope": "PUBLIC"}],
                        "providers_used": [],
                    },
                    {
                        "id": "phase_B",
                        "name": "Phase B",
                        "clauses": ["5.5-2", "5.5-4"],
                        "depends_on": ["phase_A"],
                        "wait_for_pool_keys": [],
                        "tools": ["bash"],
                        "knowledge_additions": [],
                        "pool_outputs": [],
                        "providers_used": [],
                    },
                ]
            },
            "M3": {
                "phases": [
                    {
                        "id": "phase_A",
                        "name": "TLS Analysis",
                        "clauses": ["5.5-3", "5.5-6"],
                        "depends_on": [],
                        "wait_for_pool_keys": ["open_ports"],
                        "tools": ["bash"],
                        "knowledge_additions": [],
                        "pool_outputs": [],
                        "providers_used": [],
                    },
                    {
                        "id": "phase_B",
                        "name": "TLS Verify",
                        "clauses": ["5.5-1"],
                        "depends_on": ["phase_A"],
                        "wait_for_pool_keys": ["encryption_frontend"],
                        "tools": ["bash"],
                        "knowledge_additions": [],
                        "pool_outputs": [],
                        "providers_used": [],
                    },
                ]
            },
        },
    }

    tmpdir = tempfile.mkdtemp()
    path = Path(tmpdir) / "test_phase_defs.json"
    path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
    yield path


class TestPhaseDefinitionLoader:
    """Phase 定义加载测试。"""

    def test_load_modules(self, config_path):
        modules, providers = PhaseDefinitionLoader.load(config_path)

        assert "M1" in modules
        assert "M3" in modules
        assert len(modules["M1"].phases) == 2
        assert len(modules["M3"].phases) == 2

    def test_load_providers(self, config_path):
        modules, providers = PhaseDefinitionLoader.load(config_path)

        assert "test_provider" in providers
        spec = providers["test_provider"]
        assert spec.callable_ref == "bash:echo test"
        assert spec.scope == Scope.MODULE
        assert spec.ttl_seconds == 60

    def test_phase_fields(self, config_path):
        modules, _ = PhaseDefinitionLoader.load(config_path)
        m1_phases = modules["M1"].phases

        phase_a = m1_phases[0]
        assert phase_a.id == "phase_A"
        assert phase_a.clauses == ("5.6-1", "5.6-2")
        assert phase_a.depends_on == ()
        assert phase_a.pool_outputs == ({"key": "open_ports", "scope": "PUBLIC"},)

        phase_b = m1_phases[1]
        assert phase_b.depends_on == ("phase_A",)

    def test_wait_for_pool_keys(self, config_path):
        modules, _ = PhaseDefinitionLoader.load(config_path)
        m3_phase_a = modules["M3"].phases[0]
        assert m3_phase_a.wait_for_pool_keys == ("open_ports",)


class TestTopologicalSort:
    """Phase 拓扑排序测试。"""

    def test_linear_dependency(self):
        phases = [
            PhaseDef("A", "A", ("c1",), (), (), ("bash",), (), (), ()),
            PhaseDef("B", "B", ("c2",), ("A",), (), ("bash",), (), (), ()),
            PhaseDef("C", "C", ("c3",), ("B",), (), ("bash",), (), (), ()),
        ]
        batches = PhaseDefinitionLoader.topological_sort_phases(phases)
        assert len(batches) == 3
        assert batches[0][0].id == "A"
        assert batches[1][0].id == "B"
        assert batches[2][0].id == "C"

    def test_parallel_phases(self):
        phases = [
            PhaseDef("A", "A", ("c1",), (), (), ("bash",), (), (), ()),
            PhaseDef("B", "B", ("c2",), (), (), ("bash",), (), (), ()),
        ]
        batches = PhaseDefinitionLoader.topological_sort_phases(phases)
        assert len(batches) == 1
        assert len(batches[0]) == 2

    def test_diamond_dependency(self):
        phases = [
            PhaseDef("A", "A", ("c1",), (), (), ("bash",), (), (), ()),
            PhaseDef("B", "B", ("c2",), ("A",), (), ("bash",), (), (), ()),
            PhaseDef("C", "C", ("c3",), ("A",), (), ("bash",), (), (), ()),
            PhaseDef("D", "D", ("c4",), ("B", "C"), (), ("bash",), (), (), ()),
        ]
        batches = PhaseDefinitionLoader.topological_sort_phases(phases)
        assert len(batches) == 3
        assert batches[0][0].id == "A"
        assert len(batches[1]) == 2  # B and C in parallel
        assert batches[2][0].id == "D"

    def test_empty_phases(self):
        batches = PhaseDefinitionLoader.topological_sort_phases([])
        assert batches == []

    def test_circular_dependency_raises(self):
        phases = [
            PhaseDef("A", "A", ("c1",), ("B",), (), ("bash",), (), (), ()),
            PhaseDef("B", "B", ("c2",), ("A",), (), ("bash",), (), (), ()),
        ]
        with pytest.raises(ValueError, match="循环依赖"):
            PhaseDefinitionLoader.topological_sort_phases(phases)


class TestEvidenceMerge:
    """Evidence 合并测试。"""

    def test_merge_clauses_dedup(self):
        """Phase A 和 Phase B 的 clauses 去重合并。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            pool = ContextPool(Path(tmpdir))
            engine = PhaseExecutionEngine(
                Path(tmpdir), pool,
                runner=None, bus=None, telemetry=None, pipe_def=None,
            )

            # Mock module
            class MockModule:
                id = "M1"
                name = "Test Module"
                clauses = ("5.6-1", "5.6-2", "5.5-2", "5.5-4")

            ev_a = {
                "meta": {"moduleId": "M1"},
                "clauses": [
                    {"clauseId": "5.6-1", "verdict": "PASS"},
                    {"clauseId": "5.6-2", "verdict": "FAIL"},
                ],
                "execution_trace": [{"tool": "bash", "phase": "A"}],
            }
            ev_b = {
                "meta": {"moduleId": "M1"},
                "clauses": [
                    {"clauseId": "5.5-2", "verdict": "PASS"},
                    {"clauseId": "5.5-4", "verdict": "PASS"},
                ],
                "execution_trace": [{"tool": "burp", "phase": "B"}],
            }

            merged = engine._merge_phase_evidences([ev_a, ev_b], MockModule())

            assert len(merged["clauses"]) == 4
            assert merged["selfCheck"]["totalExpected"] == 4
            assert merged["selfCheck"]["actualInJson"] == 4
            assert merged["selfCheck"]["missingClauses"] == []
            assert merged["meta"]["phaseCount"] == 2

    def test_merge_detects_missing_clauses(self):
        """合并后检测缺失条款。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            pool = ContextPool(Path(tmpdir))
            engine = PhaseExecutionEngine(
                Path(tmpdir), pool,
                runner=None, bus=None, telemetry=None, pipe_def=None,
            )

            class MockModule:
                id = "M1"
                name = "Test"
                clauses = ("5.6-1", "5.6-2", "5.5-2")

            # 两份 evidence, 但只覆盖了 1 个条款
            ev_a = {
                "meta": {"moduleId": "M1"},
                "clauses": [{"clauseId": "5.6-1", "verdict": "PASS"}],
                "execution_trace": [],
            }
            ev_b = {
                "meta": {"moduleId": "M1"},
                "clauses": [],
                "execution_trace": [],
            }

            merged = engine._merge_phase_evidences([ev_a, ev_b], MockModule())
            assert merged["selfCheck"]["hasErrors"] is True
            assert "5.6-2" in merged["selfCheck"]["missingClauses"]
            assert "5.5-2" in merged["selfCheck"]["missingClauses"]

    def test_single_evidence_passthrough(self):
        """单 Phase 直接返回, 不合并。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            pool = ContextPool(Path(tmpdir))
            engine = PhaseExecutionEngine(
                Path(tmpdir), pool,
                runner=None, bus=None, telemetry=None, pipe_def=None,
            )

            class MockModule:
                id = "M1"
                name = "Test"
                clauses = ("5.6-1",)

            ev = {"clauses": [{"clauseId": "5.6-1"}], "meta": {"moduleId": "M1"}}
            merged = engine._merge_phase_evidences([ev], MockModule())
            assert merged == ev


def test_phase_task_context_is_functional_only_for_m1_m5(tmp_path):
    engine = PhaseExecutionEngine(
        tmp_path, ContextPool(tmp_path), runner=None, bus=None, telemetry=None, pipe_def=None,
    )

    class Module:
        id = "M3"
        name = "TLS"
        upstream_inputs = ()

    phase = PhaseDef("phase_B", "TLS 验证", ("5.5-1",), (), (), ("bash",), (), (), ())
    task = engine._build_phase_task_ctx(phase, Module(), {})["task"]
    assert "M1–M5 仅做功能性验证" in task
    assert "概念性测试只属于 M0" in task


class TestHasPhases:
    """has_phases 门控测试。"""

    def test_has_phases_true(self, config_path):
        with tempfile.TemporaryDirectory() as tmpdir:
            pool = ContextPool(Path(tmpdir))
            engine = PhaseExecutionEngine(
                Path(tmpdir), pool,
                runner=None, bus=None, telemetry=None, pipe_def=None,
            )
            engine.load_definitions(config_path)
            assert engine.has_phases("M1") is True
            assert engine.has_phases("M3") is True

    def test_has_phases_false(self, config_path):
        with tempfile.TemporaryDirectory() as tmpdir:
            pool = ContextPool(Path(tmpdir))
            engine = PhaseExecutionEngine(
                Path(tmpdir), pool,
                runner=None, bus=None, telemetry=None, pipe_def=None,
            )
            engine.load_definitions(config_path)
            # M0, M2, M4, M5 not in test config
            assert engine.has_phases("M0") is False
            assert engine.has_phases("M99") is False
