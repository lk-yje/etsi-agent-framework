"""审计 outcome token 语义测试。"""

import pytest

from framework.audit_tokens import audit_outcome_token, record_audit_outcome
from framework.file_bus import FileBus
from pipelines.etsi.pipeline import CrossModuleAuditStage


def test_accept_is_the_only_accepted_token():
    assert audit_outcome_token("M1", "ACCEPT") == ".audit_M1_ACCEPTED"
    assert audit_outcome_token("M1", "FLAGGED") == ".audit_M1_REVIEW_REQUIRED"
    assert audit_outcome_token("M1", "REJECT") == ".audit_M1_REJECTED"
    assert audit_outcome_token("M1", "unexpected") == ".audit_M1_ERROR"


def test_audit_outcome_tokens_are_mutually_exclusive(tmp_path):
    bus = FileBus(tmp_path)
    record_audit_outcome(bus, "M4", "ACCEPT")
    record_audit_outcome(bus, "M4", "FLAGGED")

    assert not (bus.token_dir / ".audit_M4_ACCEPTED").exists()
    assert (bus.token_dir / ".audit_M4_REVIEW_REQUIRED").exists()
    assert not (bus.token_dir / ".audit_M4_REJECTED").exists()
    assert not (bus.token_dir / ".audit_M4_ERROR").exists()


def test_invalid_module_id_cannot_create_token_outside_expected_name():
    with pytest.raises(ValueError):
        audit_outcome_token("M1/../../oops", "ACCEPT")


def test_round2_accept_is_downgraded_when_deterministic_issue_is_high():
    outcome, blocking = CrossModuleAuditStage._determine_round2_outcome(
        "ACCEPT", [{"severity": "HIGH", "type": "inheritance_broken"}],
    )

    assert outcome == "FLAGGED"
    assert len(blocking) == 1


def test_round2_only_accepts_clean_accept_verdict():
    assert CrossModuleAuditStage._determine_round2_outcome("ACCEPT", []) == ("ACCEPT", [])
    assert CrossModuleAuditStage._determine_round2_outcome("REJECT", []) == ("REJECT", [])
    assert CrossModuleAuditStage._determine_round2_outcome("unknown", []) == ("ERROR", [])
