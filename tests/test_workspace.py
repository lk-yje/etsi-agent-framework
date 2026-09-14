from framework.workspace import init_workspace


def test_workspace_does_not_precreate_analysis_output_directories(tmp_path):
    result = init_workspace(tmp_path)

    assert result["status"] == "ok"
    assert not (tmp_path / "pcap_analysis").exists()
    assert not (tmp_path / "traffic-intelligence").exists()
    assert (tmp_path / "evidence").is_dir()
