import json

from framework.path_resolver import PathResolver


def test_resolver_does_not_automatically_load_repository_template(monkeypatch):
    monkeypatch.delenv("PATH_MAPPING", raising=False)

    resolver = PathResolver()

    assert resolver.mapping_path is None
    assert resolver.resolve("TOOL.TSHARK") is None


def test_resolver_loads_explicit_private_mapping(tmp_path, monkeypatch):
    mapping = tmp_path / "path-mapping.private.json"
    mapping.write_text(
        json.dumps({"paths": {"TOOL.TSHARK": {"windows": "D:/tools/tshark.exe"}}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH_MAPPING", str(mapping))

    resolver = PathResolver()

    assert resolver.mapping_path == mapping
    assert resolver.tool("tshark") == "D:/tools/tshark.exe"
