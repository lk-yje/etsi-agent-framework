"""所有 skills 资产必须具备明确消费者或明确排除结论。"""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "framework" / "skill_asset_registry.json"
SKILLS_ROOT = ROOT / "skills"


def test_skill_asset_registry_covers_every_skill_file():
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    entries = registry["assets"]
    registered = {entry["path"] for entry in entries}
    actual = {
        path.relative_to(ROOT).as_posix()
        for path in SKILLS_ROOT.rglob("*")
        if path.is_file()
    }

    assert registered == actual


def test_skill_asset_registry_has_valid_states_and_nonempty_rationale():
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    allowed = set(registry["allowed_statuses"])

    for entry in registry["assets"]:
        assert entry["status"] in allowed
        assert entry["consumer"].strip()
        assert entry["scope"].strip()
