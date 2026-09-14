from framework.preflight import collect_environment_preflight
from framework.runtime_config import RuntimeSettings


def test_preflight_is_offline_and_reports_missing_tools(tmp_path):
    mapping = tmp_path / "mapping.json"
    mapping.write_text('{"paths": {}}', encoding="utf-8")
    settings = RuntimeSettings(tmp_path, tmp_path / "runs", mapping)

    result = collect_environment_preflight(settings, dut_ip="10.0.0.8", include_versions=False)

    assert result["readiness"]["offline_ready"] is True
    assert result["readiness"]["traffic_ready"] is False
    assert result["readiness"]["traffic_intelligence_ready"] is False
    assert result["traffic_intelligence"]["selected_backend"] == "direct_tshark"
    assert result["dut"]["reachability"] == "not_checked"
    assert result["deployment"]["path_mapping"]["source"] == "environment"
