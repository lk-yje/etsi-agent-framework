"""Phase 附加知识的受限解析与 Work 公共能力知识测试。"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from framework.context_pool import ContextPool
from framework.phase_engine import PhaseExecutionEngine
from pipelines.etsi.agents import get_work_shared_knowledge


def _engine_with_skills_root(tmp_path: Path) -> tuple[PhaseExecutionEngine, Path]:
    skills_root = tmp_path / "skills"
    refs = skills_root / "etsi-ts103701-report" / "references"
    refs.mkdir(parents=True)
    shared = refs / "clause-reference.md"
    shared.write_text("# clause reference", encoding="utf-8")
    engine = PhaseExecutionEngine(
        tmp_path,
        ContextPool(tmp_path),
        runner=None,
        bus=None,
        telemetry=None,
        pipe_def=SimpleNamespace(shared_knowledge=(shared,)),
    )
    return engine, skills_root


def test_phase_knowledge_resolves_only_inside_skills_root(tmp_path: Path):
    engine, skills_root = _engine_with_skills_root(tmp_path)
    addition = skills_root / "etsi-ts103701-report" / "references" / "pcap-analyzer-reference.md"
    addition.write_text("# pcap", encoding="utf-8")

    resolved = engine._resolve_phase_knowledge((
        "etsi-ts103701-report/references/pcap-analyzer-reference.md",
    ))

    assert resolved == (addition.resolve(),)


def test_phase_knowledge_rejects_directory_escape(tmp_path: Path):
    engine, _ = _engine_with_skills_root(tmp_path)

    with pytest.raises(ValueError, match="escapes skills"):
        engine._resolve_phase_knowledge(("../../outside.md",))


def test_work_shared_knowledge_includes_capability_matrix(tmp_path: Path):
    refs = tmp_path / "etsi-ts103701-report" / "references"
    refs.mkdir(parents=True)
    for name in (
        "clause-reference.md",
        "capability-matrix.md",
        "verdict-criteria.md",
        "tool-error-kb.json",
    ):
        (refs / name).write_text("{}" if name.endswith(".json") else "# test", encoding="utf-8")

    names = {path.name for path in get_work_shared_knowledge(tmp_path)}
    assert names == {
        "clause-reference.md",
        "capability-matrix.md",
        "verdict-criteria.md",
        "tool-error-kb.json",
    }
