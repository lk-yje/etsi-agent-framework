"""为非认证运行创建隔离工作区，保留父 workspace 的认证证据不被改写。"""

import json
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from contracts.run_plan import RunPlan


def create_isolated_run_workspace(parent: Path, plan: RunPlan) -> Path:
    """创建 ``parent/runs/<id>``，只复制当前运行必要的只读输入。"""
    parent = Path(parent).resolve()
    if plan.certification_claim:
        return parent
    if not (parent / "ixit.json").is_file():
        raise FileNotFoundError("functional profile 需要父 workspace 中已有 ixit.json")
    run_id = f"{plan.profile.value}-{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"
    run_root = parent / "runs" / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    for name in ("ixit.json", "run_config.json", "environment_snapshot.json"):
        source = parent / name
        if source.is_file():
            shutil.copy2(source, run_root / name)
    (run_root / "run_plan.json").write_text(
        plan.model_dump_json(indent=2, by_alias=True), encoding="utf-8"
    )
    (run_root / "run_parent.json").write_text(json.dumps({
        "parentWorkspace": str(parent), "createdAt": datetime.now().isoformat(),
        "certificationClaim": False,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return run_root
