"""Immutable workspace input import and non-secret run configuration."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

MAX_IXIT_BYTES = 20 * 1024 * 1024
MAX_IXIT_XLSX_BYTES = 50 * 1024 * 1024
FIRMWARE_ROLES = {"old", "new", "tampered"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_local_source(source_path: str | Path, allowed_roots: tuple[Path, ...], *, label: str) -> tuple[Path, Path]:
    if not allowed_roots:
        raise ValueError(f"服务端未配置 {label} 根目录；请设置 INPUT_ROOTS 或私有 PATH_MAPPING 的 DIR.IXIT/DIR.INPUT")
    source = Path(source_path).expanduser().resolve()
    roots = tuple(Path(root).resolve() for root in allowed_roots)
    root = next((candidate for candidate in roots if source.is_relative_to(candidate)), None)
    if root is None:
        raise ValueError(f"{label} 路径不在服务端允许的目录范围内")
    if not source.is_file():
        raise ValueError(f"{label} 本地路径不存在或不是普通文件")
    return source, root


def _write_normalized_ixit(workspace: Path, parsed: dict, source_entry: dict) -> dict:
    if not isinstance(parsed, dict):
        raise ValueError("IXIT 解析结果顶层必须是 object")
    missing = [key for key in ("ics", "ixit_tables") if key not in parsed]
    if missing:
        raise ValueError(f"IXIT 解析结果缺少字段: {', '.join(missing)}")
    normalized = json.dumps(parsed, ensure_ascii=False, indent=2).encode("utf-8")
    digest = _sha256(normalized)
    target = workspace / "inputs" / "ixit.normalized.json"
    compatibility = workspace / "ixit.json"
    for existing in (target, compatibility):
        if existing.exists() and _sha256(existing.read_bytes()) != digest:
            raise FileExistsError(f"workspace 已有不同的 {existing.relative_to(workspace)}；请创建新 workspace")
    _atomic_write(target, normalized)
    _atomic_write(compatibility, normalized)
    return _update_input_manifest(workspace, "ixit", {
        **source_entry,
        "path": "inputs/ixit.normalized.json",
        "compatibility_path": "ixit.json",
        "normalized_sha256": digest,
        "normalized_size_bytes": len(normalized),
    })


def reference_ixit_source(workspace: Path, source_path: str | Path, allowed_roots: tuple[Path, ...]) -> dict:
    """从受控本地路径读取 IXIT；只写 Agent 所需的归一化 JSON，不复制原件。"""
    source, root = _resolve_local_source(source_path, allowed_roots, label="IXIT")
    suffix = source.suffix.lower()
    if suffix not in {".json", ".xlsx"}:
        raise ValueError("IXIT 本地路径必须是 .json 或 .xlsx 文件")
    source_entry = {
        "original_name": source.name, "source_path": str(source), "allowed_root": str(root),
        "reference_mode": "local_path", "source_sha256": _sha256_file(source),
        "source_size_bytes": source.stat().st_size,
    }
    if suffix == ".xlsx":
        try:
            from scripts.parse_ixit_xlsx import parse_ixit_xlsx
            parsed, summary = parse_ixit_xlsx(str(source))
        except Exception as exc:
            raise ValueError(f"parse_ixit_xlsx.py 解析失败: {exc}") from exc
        source_entry.update({"parser": "scripts/parse_ixit_xlsx.py", "parse_summary": summary})
    else:
        try:
            parsed = json.loads(source.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"IXIT JSON 无法解析: {exc}") from exc
        source_entry["parser"] = "source_json"
    return _write_normalized_ixit(workspace, parsed, source_entry)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def _update_input_manifest(workspace: Path, entry_type: str, entry: dict) -> dict:
    """合并输入 manifest，避免导入固件时覆盖既有 IXIT 来源记录。"""
    path = workspace / "inputs" / "input_manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, json.JSONDecodeError):
        manifest = {}
    manifest.setdefault("schema_version", 1)
    manifest["imported_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    inputs = manifest.setdefault("inputs", {})
    if entry_type == "firmware":
        inputs.setdefault("firmware", {})[entry["role"]] = entry
    else:
        inputs[entry_type] = entry
    _atomic_write(path, json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8"))
    return manifest


def import_ixit_json(workspace: Path, filename: str, content: bytes) -> dict:
    """Validate and preserve a combined ICS/IXIT JSON input.

    The original bytes are stored under ``inputs/ixit.json``. A byte-identical
    root ``ixit.json`` is retained only as a compatibility view for the current
    pipeline. An existing different input is never overwritten.
    """
    if Path(filename).suffix.lower() != ".json":
        raise ValueError("当前仅支持解析后的 ICS/IXIT JSON 文件")
    if not content:
        raise ValueError("上传文件为空")
    if len(content) > MAX_IXIT_BYTES:
        raise ValueError(f"IXIT JSON 超过大小限制: {MAX_IXIT_BYTES} bytes")

    try:
        parsed = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"IXIT JSON 无法解析: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("IXIT JSON 顶层必须是 object")  # noqa: TRY004 - user input validation
    missing = [key for key in ("ics", "ixit_tables") if key not in parsed]
    if missing:
        raise ValueError(f"IXIT JSON 缺少字段: {', '.join(missing)}")

    digest = _sha256(content)
    preserved = workspace / "inputs" / "ixit.json"
    compatibility = workspace / "ixit.json"
    for existing in (preserved, compatibility):
        if existing.exists() and _sha256(existing.read_bytes()) != digest:
            raise FileExistsError(
                f"workspace 已有不同的 {existing.relative_to(workspace)}；请创建新 workspace"
            )

    _atomic_write(preserved, content)
    _atomic_write(compatibility, content)

    manifest = _update_input_manifest(
        workspace, "ixit", {
            "original_name": Path(filename).name, "path": "inputs/ixit.json",
            "compatibility_path": "ixit.json", "sha256": digest,
            "size_bytes": len(content), "content_type": "application/json",
        },
    )
    return manifest


def import_ixit_xlsx(workspace: Path, filename: str, content: bytes) -> dict:
    """复用仓库专业 parse_ixit_xlsx.py，将原件和归一化 JSON 一并冻结。"""
    if Path(filename).suffix.lower() != ".xlsx":
        raise ValueError("IXIT Excel 必须是 .xlsx 文件")
    if not content:
        raise ValueError("上传 IXIT Excel 为空")
    if len(content) > MAX_IXIT_XLSX_BYTES:
        raise ValueError(f"IXIT Excel 超过大小限制: {MAX_IXIT_XLSX_BYTES} bytes")
    source = workspace / "inputs" / "ixit.source.xlsx"
    digest = _sha256(content)
    if source.exists() and _sha256(source.read_bytes()) != digest:
        raise FileExistsError("workspace 已有不同的 inputs/ixit.source.xlsx；请创建新 workspace")
    _atomic_write(source, content)
    try:
        from scripts.parse_ixit_xlsx import parse_ixit_xlsx
        parsed, summary = parse_ixit_xlsx(str(source))
    except Exception as exc:  # 解析器错误需要如实回到 UI，不能生成半成品输入。
        raise ValueError(f"parse_ixit_xlsx.py 解析失败: {exc}") from exc
    normalized = json.dumps(parsed, ensure_ascii=False, indent=2).encode("utf-8")
    manifest = import_ixit_json(workspace, "ixit.normalized.json", normalized)
    entry = manifest["inputs"]["ixit"]
    entry.update({
        "source_xlsx": {"original_name": Path(filename).name, "path": "inputs/ixit.source.xlsx",
                        "sha256": digest, "size_bytes": len(content)},
        "parser": "scripts/parse_ixit_xlsx.py", "parse_summary": summary,
    })
    return _update_input_manifest(workspace, "ixit", entry)


def reference_firmware_sample(
    workspace: Path, role: str, source_path: str | Path, allowed_roots: tuple[Path, ...],
) -> dict:
    """登记工作机本地固件引用，不复制大型二进制样本到 workspace。"""
    if role not in FIRMWARE_ROLES:
        raise ValueError(f"firmware role 必须为: {', '.join(sorted(FIRMWARE_ROLES))}")
    if not allowed_roots:
        raise ValueError("服务端未配置固件根目录；请设置 FIRMWARE_ROOTS 或私有 PATH_MAPPING 的 DIR.FIRMWARE")
    target = Path(source_path).expanduser().resolve()
    roots = tuple(Path(root).resolve() for root in allowed_roots)
    root = next((candidate for candidate in roots if target.is_relative_to(candidate)), None)
    if root is None:
        raise ValueError("固件路径不在服务端允许的 FIRMWARE_ROOTS/DIR.FIRMWARE 范围内")
    if not target.is_file():
        raise ValueError("固件本地路径不存在或不是普通文件")
    digest = _sha256_file(target)
    size_bytes = target.stat().st_size
    return _update_input_manifest(workspace, "firmware", {
        "role": role,
        "original_name": target.name,
        "source_path": str(target),
        "allowed_root": str(root),
        "reference_mode": "local_path",
        "sha256": digest,
        "size_bytes": size_bytes,
        "content_type": "application/octet-stream",
    })


def _write_tampered_variant(source: Path, out_path: Path) -> str:
    """从 source 流式生成篡改变体：head/mid/tail 各翻转 1 字节 (XOR 0xFF)。

    确定性：同一 source 恒产出相同字节，因此 hash 固定。返回输出的 SHA-256。
    """
    size = source.stat().st_size
    offsets = {0x0000, size // 2, size - 0x100}
    digest = hashlib.sha256()
    with source.open("rb") as fin, out_path.open("wb") as fout:
        offset = 0
        while offset < size:
            chunk = bytearray(fin.read(1024 * 1024))
            if not chunk:
                break
            chunk_end = offset + len(chunk)
            for off in offsets:
                if offset <= off < chunk_end:
                    chunk[off - offset] ^= 0xFF
            fout.write(chunk)
            digest.update(chunk)
            offset += len(chunk)
    return digest.hexdigest()


def generate_tampered_from_new(
    workspace: Path, new_source_path: str | Path, allowed_roots: tuple[Path, ...],
) -> dict:
    """从 new 固件自动生成 tampered 变体，并用 SHA-256 对比确认已更改。

    生成到 ``<new 所在目录>/tampered/<stem>_tampered<suffix>``（与既有手动产物同约定；
    同源确定性 → 同 hash）。二者均只登记引用（路径 + hash + 大小），不复制进 workspace。
    """
    source, root = _resolve_local_source(new_source_path, allowed_roots, label="new 固件")
    new_sha256 = _sha256_file(source)
    out_dir = source.parent / "tampered"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{source.stem}_tampered{source.suffix}"
    tampered_sha256 = _write_tampered_variant(source, out_path)
    changed = new_sha256 != tampered_sha256
    if not changed:
        raise ValueError("篡改失败：tampered 与 new 的 SHA-256 相同，字节未发生改变")

    manifest = _update_input_manifest(workspace, "firmware", {
        "role": "new",
        "original_name": source.name,
        "source_path": str(source),
        "allowed_root": str(root),
        "reference_mode": "local_path",
        "sha256": new_sha256,
        "size_bytes": source.stat().st_size,
        "content_type": "application/octet-stream",
    })
    manifest = _update_input_manifest(workspace, "firmware", {
        "role": "tampered",
        "original_name": out_path.name,
        "source_path": str(out_path),
        "allowed_root": str(root),
        "reference_mode": "local_path",
        "sha256": tampered_sha256,
        "size_bytes": out_path.stat().st_size,
        "content_type": "application/octet-stream",
        "generated_from_new_sha256": new_sha256,
        "sha256_changed": changed,
    })
    return manifest


def write_run_config(workspace: Path, config: dict) -> Path:
    """Persist an atomic, explicitly non-secret run configuration."""
    forbidden = {"burp_token", "api_key", "anthropic_api_key"}
    leaked = forbidden.intersection(key.lower() for key in config)
    if leaked:
        raise ValueError(f"run_config 禁止保存 secret 字段: {sorted(leaked)}")

    path = workspace / "run_config.json"
    payload = {
        "schema_version": 1,
        **config,
    }
    _atomic_write(
        path,
        json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8"),
    )
    return path
