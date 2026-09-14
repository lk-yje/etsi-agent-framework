import json
from pathlib import Path

import pytest

from framework.runtime_config import RuntimeSettings


def _settings(tmp_path: Path) -> RuntimeSettings:
    return RuntimeSettings(
        project_root=tmp_path,
        auto_test_root=tmp_path / "runs",
        path_mapping_path=None,
    )


def test_relative_workspace_is_resolved_under_root(tmp_path):
    settings = _settings(tmp_path)
    workspace = settings.resolve_workspace("case-001", create=True)

    assert workspace == (tmp_path / "runs" / "case-001").resolve()
    assert workspace.is_dir()


def test_workspace_outside_root_is_rejected(tmp_path):
    settings = _settings(tmp_path)

    with pytest.raises(ValueError, match="AUTO_TEST_ROOT"):
        settings.resolve_workspace(tmp_path / "outside")


@pytest.mark.skipif(__import__("os").name != "nt", reason="non-C absolute workspace is a Windows desktop policy")
def test_non_c_absolute_workspace_is_allowed_on_windows(tmp_path):
    settings = _settings(tmp_path)
    external = Path("E:/codex-workspace-picker-test")
    assert settings.resolve_workspace(external) == external.resolve()


def test_public_summary_does_not_include_environment_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("BURP_MCP_TOKEN", "do-not-leak")
    summary = _settings(tmp_path).public_summary()

    assert "do-not-leak" not in str(summary)


def test_public_summary_reports_system_path_when_mapping_is_not_configured(tmp_path):
    summary = _settings(tmp_path).public_summary()

    assert summary["path_mapping"]["source"] == "system_path"


def test_private_mapping_supplies_firmware_root(tmp_path, monkeypatch):
    firmware_root = tmp_path / "firmware"
    firmware_root.mkdir()
    mapping = tmp_path / "private-mapping.json"
    mapping.write_text(json.dumps({"paths": {"DIR.FIRMWARE": {"windows": str(firmware_root)}}}), encoding="utf-8")
    monkeypatch.setenv("PATH_MAPPING", str(mapping))
    settings = RuntimeSettings.from_env(tmp_path)

    assert settings.firmware_roots == (firmware_root.resolve(),)
    assert settings.public_summary()["firmware_roots"][0]["exists"] is True


def test_traffic_intelligence_settings_are_loaded_without_exposing_worker_path(
    tmp_path, monkeypatch
):
    worker = tmp_path / "private" / "easytshark-analyzer.exe"
    monkeypatch.setenv("TRAFFIC_ANALYZER_BACKEND", "easytshark_batch")
    monkeypatch.setenv("TRAFFIC_AI_PAYLOAD_POLICY", "bounded_redacted")
    monkeypatch.setenv("TRAFFIC_MAX_STREAM_SAMPLE_BYTES", "2048")
    monkeypatch.setenv("TRAFFIC_EASYTSHARK_TIMEOUT_SECONDS", "900")
    monkeypatch.setenv("TRAFFIC_EASYTSHARK_PATH", str(worker))

    settings = RuntimeSettings.from_env(tmp_path)
    summary = settings.public_summary()["traffic_intelligence"]

    assert settings.traffic_analyzer_backend == "easytshark_batch"
    assert settings.traffic_max_stream_sample_bytes == 2048
    assert settings.traffic_easytshark_timeout_seconds == 900
    assert summary["easytshark_configured"] is True
    assert str(worker) not in str(summary)
