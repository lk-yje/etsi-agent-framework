import hashlib
import json

import pytest
from openpyxl import Workbook

from framework.input_manager import reference_firmware_sample, reference_ixit_source, import_ixit_json, import_ixit_xlsx, write_run_config
from pipelines.etsi.pipeline import TrafficCollectStage


def _ixit_bytes(model: str = "A1") -> bytes:
    return json.dumps(
        {"meta": {"model": model}, "ics": [], "ixit_tables": {}},
        ensure_ascii=False,
    ).encode("utf-8")


def test_import_preserves_exact_bytes_and_hash(tmp_path):
    content = _ixit_bytes()
    manifest = import_ixit_json(tmp_path, "device.json", content)

    assert (tmp_path / "inputs/ixit.json").read_bytes() == content
    assert (tmp_path / "ixit.json").read_bytes() == content
    assert manifest["inputs"]["ixit"]["sha256"] == hashlib.sha256(content).hexdigest()


def test_import_refuses_to_overwrite_different_ixit(tmp_path):
    import_ixit_json(tmp_path, "first.json", _ixit_bytes("A1"))

    with pytest.raises(FileExistsError, match="创建新 workspace"):
        import_ixit_json(tmp_path, "second.json", _ixit_bytes("B2"))


def test_firmware_reference_preserves_roles_and_keeps_ixit_manifest(tmp_path):
    import_ixit_json(tmp_path, "device.json", _ixit_bytes())
    firmware_root = tmp_path / "firmware-library"
    firmware_root.mkdir()
    old = firmware_root / "old.bin"
    tampered = firmware_root / "tampered.bin"
    old.write_bytes(b"old-firmware")
    tampered.write_bytes(b"tampered-firmware")
    manifest = reference_firmware_sample(tmp_path, "old", old, (firmware_root,))
    manifest = reference_firmware_sample(tmp_path, "tampered", tampered, (firmware_root,))

    assert manifest["inputs"]["ixit"]["path"] == "inputs/ixit.json"
    assert manifest["inputs"]["firmware"]["old"]["source_path"] == str(old.resolve())
    assert manifest["inputs"]["firmware"]["tampered"]["reference_mode"] == "local_path"
    assert not (tmp_path / "inputs/firmware").exists()
    with pytest.raises(ValueError, match="允许"):
        reference_firmware_sample(tmp_path, "old", tmp_path / "outside.bin", (firmware_root,))


def test_xlsx_import_reuses_project_parser_and_preserves_source(tmp_path):
    source = tmp_path / "source.xlsx"
    workbook = Workbook()
    workbook.active.title = "ICS"
    workbook.active.append(["Provision", "Status"])
    workbook.active.append(["5.6-1", "Yes"])
    workbook.create_sheet("1-AuthMech").append(["Field", "Value"])
    workbook.save(source)

    manifest = import_ixit_xlsx(tmp_path, "device.xlsx", source.read_bytes())

    assert (tmp_path / "inputs/ixit.source.xlsx").is_file()
    assert (tmp_path / "ixit.json").is_file()
    assert manifest["inputs"]["ixit"]["parser"] == "scripts/parse_ixit_xlsx.py"
    assert "ICS" in manifest["inputs"]["ixit"]["parse_summary"]["meta"]


def test_ixit_reference_generates_normalized_agent_input_without_copying_source(tmp_path):
    source_root = tmp_path / "input-library"
    source_root.mkdir()
    source = source_root / "device.json"
    source.write_bytes(_ixit_bytes())

    manifest = reference_ixit_source(tmp_path, source, (source_root,))

    assert manifest["inputs"]["ixit"]["reference_mode"] == "local_path"
    assert manifest["inputs"]["ixit"]["source_path"] == str(source.resolve())
    assert (tmp_path / "inputs/ixit.normalized.json").is_file()
    assert (tmp_path / "ixit.json").is_file()
    assert not (tmp_path / "inputs/device.json").exists()


def test_run_config_rejects_secret_fields(tmp_path):
    with pytest.raises(ValueError, match="secret"):
        write_run_config(tmp_path, {"run_id": "r1", "burp_token": "secret"})


def test_run_config_contains_runtime_override_without_secret(tmp_path):
    path = write_run_config(tmp_path, {"run_id": "r1", "dut_ip": "10.0.0.8"})
    data = json.loads(path.read_text(encoding="utf-8"))

    assert data["dut_ip"] == "10.0.0.8"
    assert "burp_token" not in data


def test_traffic_dut_ip_prefers_run_config_without_mutating_ixit(tmp_path):
    original = _ixit_bytes()
    import_ixit_json(tmp_path, "ixit.json", original)
    write_run_config(tmp_path, {"run_id": "r1", "dut_ip": "10.0.0.8"})

    assert TrafficCollectStage._get_dut_ip(tmp_path) == "10.0.0.8"
    assert (tmp_path / "ixit.json").read_bytes() == original
