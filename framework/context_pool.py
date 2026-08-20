"""上下文池 (ContextPool) — Agent/Phase 间共享数据的统一通道。

设计保证:
1. 三层 Scope (PUBLIC / MODULE / PHASE) 控制数据可见性
2. Provider 机制: 可调用方法 + TTL, 支持获取 fresh cookie 等短时效数据
3. 消费追踪: get() 自动标记 consumed_by, L1 Gate 可检查未消费数据
4. 异步 wait_for: 轮询等待 key 出现 (复用 FileBus 的 poll 模式)
5. 原子写入: .tmp + rename, 与 FileBus 保持一致

存储布局:
    workspace/context/
      _pool_index.json              # 元数据索引
      public/{key}.json             # PUBLIC scope
      {module_id}/{key}.json        # MODULE scope
      {module_id}/{phase_id}/{key}.json  # PHASE scope
      providers/_provider_specs.json     # Provider 定义缓存
"""

import asyncio
import importlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============================================================
# 枚举与数据结构
# ============================================================

class Scope(Enum):
    """数据可见性范围。"""
    PUBLIC = "PUBLIC"    # 任何模块/阶段可读
    MODULE = "MODULE"    # 仅同模块的阶段可读
    PHASE = "PHASE"      # 仅同阶段可读


@dataclass(frozen=True)
class ProviderSpec:
    """Provider 定义 — 描述如何获取短时效数据。

    callable_ref 格式:
      - "tool:tool_name"       → ToolRegistry.execute(tool_name, {})
      - "bash:command"         → asyncio.create_subprocess_shell(command)
      - "python:module.func"   → importlib import + call
    """
    name: str
    callable_ref: str
    scope: Scope = Scope.MODULE
    ttl_seconds: int = 60
    output_key: str = ""          # 为空时默认 = name
    description: str = ""

    @property
    def effective_output_key(self) -> str:
        return self.output_key or self.name


@dataclass
class PoolEntry:
    """池条目 — 一条数据的完整元信息。"""
    key: str
    value: Any
    scope: Scope
    module_id: str
    phase_id: str
    provider_name: Optional[str] = None
    ttl_seconds: int = 0
    created_at: float = 0.0
    consumed_by: List[str] = field(default_factory=list)

    def is_expired(self) -> bool:
        if self.ttl_seconds <= 0:
            return False
        return (time.time() - self.created_at) > self.ttl_seconds

    def to_index_dict(self) -> dict:
        """序列化为 _pool_index.json 条目。"""
        return {
            "key": self.key,
            "scope": self.scope.value,
            "module_id": self.module_id,
            "phase_id": self.phase_id,
            "provider_name": self.provider_name,
            "ttl_seconds": self.ttl_seconds,
            "created_at": self.created_at,
            "consumed_by": self.consumed_by,
        }


# ============================================================
# ContextPool
# ============================================================

class ContextPool:
    """上下文池 — Phase/Module 间共享数据的统一通道。

    用法:
        pool = ContextPool(workspace)
        pool.put("open_ports", [...], Scope.PUBLIC, "M1", "phase_A")
        data = pool.get("open_ports", "M3", "phase_A")  # → 可读到
        data = pool.get("session_cookie", "M2", "phase_A")  # → MODULE scope, 跨模块返回 None
    """

    INDEX_FILE = "_pool_index.json"

    def __init__(self, workspace: Path):
        self.root = Path(workspace) / "context"
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "public").mkdir(exist_ok=True)
        (self.root / "providers").mkdir(exist_ok=True)

        # 内存索引 (启动时从磁盘加载)
        self._entries: Dict[str, PoolEntry] = {}
        self._providers: Dict[str, ProviderSpec] = {}
        self._load_index()

    # ===== 写入 =====

    def put(
        self,
        key: str,
        value: Any,
        scope: Scope,
        module_id: str,
        phase_id: str,
        ttl: int = 0,
        provider: Optional[str] = None,
    ) -> Path:
        """写入数据到池。原子写入, 更新索引。"""
        entry = PoolEntry(
            key=key,
            value=value,
            scope=scope,
            module_id=module_id,
            phase_id=phase_id,
            provider_name=provider,
            ttl_seconds=ttl,
            created_at=time.time(),
        )

        # 确定存储路径
        file_path = self._key_path(key, scope, module_id, phase_id)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # 原子写入
        content = json.dumps({"key": key, "value": value}, indent=2, ensure_ascii=False)
        tmp = file_path.with_suffix(file_path.suffix + ".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(file_path)

        # 更新内存索引 + 持久化
        index_key = self._index_key(key, scope, module_id, phase_id)
        self._entries[index_key] = entry
        self._save_index()

        logger.debug(
            "[ContextPool] put %s (scope=%s, module=%s, phase=%s)",
            key, scope.value, module_id, phase_id,
        )
        return file_path

    # ===== 读取 =====

    def get(
        self,
        key: str,
        reader_module_id: str,
        reader_phase_id: str,
    ) -> Optional[Any]:
        """读取池数据。Scope 权限检查 → TTL 检查 → 标记消费 → 返回 value。

        返回 None 表示: key 不存在 / 无权读取 / 已过期。
        """
        for index_key, entry in self._entries.items():
            if entry.key != key:
                continue

            # Scope 权限检查
            if not self._can_read(entry, reader_module_id, reader_phase_id):
                continue

            # TTL 检查
            if entry.is_expired():
                logger.debug("[ContextPool] get %s: expired (TTL=%ds)", key, entry.ttl_seconds)
                return None

            # 标记消费
            consumer = f"{reader_module_id}/{reader_phase_id}"
            if consumer not in entry.consumed_by:
                entry.consumed_by.append(consumer)
                self._save_index()

            logger.debug(
                "[ContextPool] get %s → %s (consumed_by: %s)",
                key, consumer, entry.consumed_by,
            )
            return entry.value

        return None

    async def wait_for(
        self,
        key: str,
        reader_module_id: str,
        reader_phase_id: str,
        timeout: float = 300.0,
        poll_interval: float = 5.0,
    ) -> Optional[Any]:
        """轮询等待 key 出现并可读。超时返回 None。"""
        elapsed = 0.0
        while elapsed < timeout:
            result = self.get(key, reader_module_id, reader_phase_id)
            if result is not None:
                return result
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            # 重新加载索引 (其他进程/模块可能已写入)
            self._load_index()

        logger.warning(
            "[ContextPool] wait_for %s timed out (%.1fs), reader=%s/%s",
            key, timeout, reader_module_id, reader_phase_id,
        )
        return None

    # ===== Provider 机制 =====

    def register_provider(self, spec: ProviderSpec) -> None:
        """注册一个 Provider。"""
        self._providers[spec.name] = spec
        logger.debug("[ContextPool] registered provider: %s (%s)", spec.name, spec.callable_ref)

    async def invoke_provider(
        self,
        name: str,
        module_id: str,
        phase_id: str,
        tools=None,
    ) -> Optional[Any]:
        """执行 Provider, 结果存入池。返回结果值或 None (失败时)。

        Args:
            name: Provider 名称
            module_id: 请求模块
            phase_id: 请求阶段
            tools: ToolRegistry 实例 (仅 "tool:" 格式需要)
        """
        spec = self._providers.get(name)
        if not spec:
            logger.warning("[ContextPool] provider not found: %s", name)
            return None

        try:
            value = await self._execute_callable(spec.callable_ref, tools)
        except Exception as e:
            logger.error("[ContextPool] provider %s failed: %s", name, e)
            return None

        if value is not None:
            self.put(
                key=spec.effective_output_key,
                value=value,
                scope=spec.scope,
                module_id=module_id,
                phase_id=phase_id,
                ttl=spec.ttl_seconds,
                provider=name,
            )

        return value

    # ===== 查询 =====

    def list_keys(
        self,
        scope: Optional[Scope] = None,
        module_id: Optional[str] = None,
    ) -> List[str]:
        """列出匹配的 key (去重)。"""
        keys = set()
        for entry in self._entries.values():
            if scope and entry.scope != scope:
                continue
            if module_id and entry.module_id != module_id:
                continue
            keys.add(entry.key)
        return sorted(keys)

    def get_unconsumed(self, module_id: str) -> List[str]:
        """返回该模块 MODULE scope 下未被同模块消费的 key。L1 Gate 用。"""
        result = []
        for entry in self._entries.values():
            if entry.scope != Scope.MODULE:
                continue
            if entry.module_id != module_id:
                continue
            # 检查是否有同模块的其他 phase 消费过
            same_module_consumers = [
                c for c in entry.consumed_by
                if c.startswith(f"{module_id}/")
            ]
            if not same_module_consumers:
                result.append(entry.key)
        return result

    def get_pool_summary(self) -> dict:
        """池摘要 — 供 CrossModuleAuditStage 使用。"""
        entries = []
        for entry in self._entries.values():
            entries.append({
                "key": entry.key,
                "scope": entry.scope.value,
                "module_id": entry.module_id,
                "phase_id": entry.phase_id,
                "consumed_by": entry.consumed_by,
                "expired": entry.is_expired(),
            })
        return {
            "total_entries": len(entries),
            "providers": list(self._providers.keys()),
            "entries": entries,
        }

    def get_snapshot_for_phase(
        self,
        module_id: str,
        phase_id: str,
    ) -> Dict[str, Any]:
        """获取指定 phase 可见的所有 pool 数据快照。用于注入 task_context。"""
        snapshot = {}
        for entry in self._entries.values():
            if entry.is_expired():
                continue
            if self._can_read(entry, module_id, phase_id):
                snapshot[entry.key] = entry.value
        return snapshot

    # ===== 内部方法 =====

    def _can_read(self, entry: PoolEntry, reader_module: str, reader_phase: str) -> bool:
        """Scope 权限检查。"""
        if entry.scope == Scope.PUBLIC:
            return True
        if entry.scope == Scope.MODULE:
            return entry.module_id == reader_module
        if entry.scope == Scope.PHASE:
            return entry.module_id == reader_module and entry.phase_id == reader_phase
        return False

    def _key_path(self, key: str, scope: Scope, module_id: str, phase_id: str) -> Path:
        """根据 scope 确定存储路径。"""
        safe_key = key.replace("/", "_").replace("\\", "_")
        if scope == Scope.PUBLIC:
            return self.root / "public" / f"{safe_key}.json"
        elif scope == Scope.MODULE:
            return self.root / module_id / f"{safe_key}.json"
        else:  # PHASE
            return self.root / module_id / phase_id / f"{safe_key}.json"

    def _index_key(self, key: str, scope: Scope, module_id: str, phase_id: str) -> str:
        """索引键: scope:module:phase:key"""
        return f"{scope.value}:{module_id}:{phase_id}:{key}"

    def _load_index(self) -> None:
        """从磁盘加载索引。"""
        index_path = self.root / self.INDEX_FILE
        if not index_path.exists():
            return
        try:
            data = json.loads(index_path.read_text(encoding="utf-8"))
            for item in data.get("entries", []):
                scope = Scope(item["scope"])
                key = item["key"]
                module_id = item["module_id"]
                phase_id = item["phase_id"]

                # 从数据文件读取 value
                file_path = self._key_path(key, scope, module_id, phase_id)
                value = None
                if file_path.exists():
                    try:
                        file_data = json.loads(file_path.read_text(encoding="utf-8"))
                        value = file_data.get("value")
                    except (json.JSONDecodeError, KeyError):
                        pass

                idx_key = self._index_key(key, scope, module_id, phase_id)
                self._entries[idx_key] = PoolEntry(
                    key=key,
                    value=value,
                    scope=scope,
                    module_id=module_id,
                    phase_id=phase_id,
                    provider_name=item.get("provider_name"),
                    ttl_seconds=item.get("ttl_seconds", 0),
                    created_at=item.get("created_at", 0.0),
                    consumed_by=item.get("consumed_by", []),
                )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning("[ContextPool] failed to load index: %s", e)

    def _save_index(self) -> None:
        """持久化索引到磁盘。"""
        index_path = self.root / self.INDEX_FILE
        data = {
            "entries": [e.to_index_dict() for e in self._entries.values()],
        }
        tmp = index_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(index_path)

    async def _execute_callable(self, callable_ref: str, tools=None) -> Optional[Any]:
        """执行 Provider callable_ref。

        支持三种格式:
          "tool:tool_name"     → ToolRegistry.execute(tool_name, {})
          "bash:command"       → asyncio.create_subprocess_shell(command)
          "python:module.func" → importlib import + call
        """
        if ":" not in callable_ref:
            logger.error("[ContextPool] invalid callable_ref: %s", callable_ref)
            return None

        prefix, target = callable_ref.split(":", 1)

        if prefix == "tool":
            if tools is None:
                logger.error("[ContextPool] tool provider requires tools registry, got None")
                return None
            result = await tools.execute(target, {})
            if hasattr(result, "output"):
                return result.output
            return str(result) if result else None

        elif prefix == "bash":
            if os.name == "nt":
                # create_subprocess_shell() 会触发 cmd.exe 的 AutoRun；部分机器的
                # AutoRun 包含 chcp，导致 "Active code page: 65001" 污染 stdout。
                # /d 禁用 AutoRun，同时保留 Provider 原有的 shell 命令语义。
                proc = await asyncio.create_subprocess_exec(
                    os.environ.get("COMSPEC", "cmd.exe"),
                    "/d", "/s", "/c", target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.warning("[ContextPool] bash provider exited %d: %s", proc.returncode, stderr.decode())
            return stdout.decode("utf-8").strip() if stdout else None

        elif prefix == "python":
            parts = target.rsplit(".", 1)
            if len(parts) != 2:
                logger.error("[ContextPool] invalid python ref: %s", target)
                return None
            mod_path, func_name = parts
            try:
                mod = importlib.import_module(mod_path)
                func = getattr(mod, func_name)
                result = func()
                if asyncio.iscoroutine(result):
                    result = await result
                return result
            except (ImportError, AttributeError) as e:
                logger.error("[ContextPool] python provider error: %s", e)
                return None

        else:
            logger.error("[ContextPool] unknown callable prefix: %s", prefix)
            return None
