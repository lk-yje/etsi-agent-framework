"""条款—知识—工具—Phase 对齐基线测试。"""

from scripts.validate_clause_alignment import build_alignment_report, has_gaps


def test_alignment_report_accounts_for_all_module_clauses():
    report = build_alignment_report()

    assert report["summary"]["module_clause_count"] > 0
    assert report["summary"]["phase_clause_count"] == report["summary"]["module_clause_count"]
    assert report["unexpected"]["phase"] == {}


def test_alignment_report_is_complete_and_strict_ready():
    report = build_alignment_report()

    # E1 已覆盖全部模块条款；旧的“full 但没有工具声明”条目已经
    # 降为 partial 并补齐输入/工具边界，严格模式可以作为 CI 基线。
    assert report["missing"]["catalog"] == []
    assert report["missing"]["clause_reference"] == []
    assert report["quality_warnings"]["full_without_declared_tools"] == []
    assert has_gaps(report) is False
