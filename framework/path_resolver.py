"""工具路径解析器 — 从 path-mapping.json 加载工具路径映射。

path-mapping.json 是所有工具路径的唯一解析源 (Single Source of Truth)。
换机器只需改这一个文件。
"""

import json
import os
import shutil
from pathlib import Path
from typing import Optional, Dict


class PathResolver:
    """根据 path-mapping.json 解析本地工具路径。

    用法:
        resolver = PathResolver(Path("C:/Users/<user>/.claude/skills/path-mapping.json"))
        nmap_path = resolver.tool("nmap")  # → D:/Nmap/nmap.exe
        tshark_path = resolver.tool("tshark")  # → D:/Wireshark/tshark.exe
        xray_path = resolver.dir("xray")  # → D:/Xray/
    """

    def __init__(self, mapping_path: Path | None = None):
        if mapping_path is None:
            env_path = os.environ.get("PATH_MAPPING")
            if env_path:
                mapping_path = Path(env_path)
            else:
                # 优先使用项目内 skills/path-mapping.json
                _local = Path(__file__).resolve().parent.parent / "skills" / "path-mapping.json"
                mapping_path = _local if _local.exists() else Path.home() / ".claude" / "skills" / "path-mapping.json"
        self.mapping_path = Path(mapping_path)
        self._paths: Dict[str, Dict[str, str]] = {}
        self._loaded = False
        self._load()

    def _load(self) -> None:
        """加载 path-mapping.json"""
        if not self.mapping_path.exists():
            self._loaded = True
            return
        try:
            data = json.loads(self.mapping_path.read_text(encoding="utf-8"))
            self._paths = data.get("paths", {})
            self._loaded = True
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[PathResolver] 警告: 无法解析 {self.mapping_path}: {e}")
            self._loaded = True

    def resolve(self, key: str) -> Optional[str]:
        """解析任意 key 的 windows 路径。

        key 格式: "TOOL.NMAP", "DIR.WIRESHARK", "CFG.XRAY" 等。
        返回 windows 值，如果不存在返回 None。
        """
        entry = self._paths.get(key, {})
        path = entry.get("windows")
        if path:
            return path
        return None

    def tool(self, name: str) -> Optional[str]:
        """解析工具可执行文件路径。

        Args:
            name: 工具名 (小写, 如 "nmap", "tshark", "xray", "sqlmap")

        Returns:
            可执行文件完整路径, 若不存在则返回 None
        """
        key = f"TOOL.{name.upper()}"
        return self.resolve(key)

    def dir(self, name: str) -> Optional[str]:
        """解析工具目录路径。

        Args:
            name: 目录名 (小写, 如 "nmap", "wireshark", "xray")

        Returns:
            目录完整路径, 若不存在则返回 None
        """
        key = f"DIR.{name.upper()}"
        return self.resolve(key)

    def config(self, name: str) -> Optional[str]:
        """解析配置文件路径。

        Args:
            name: 配置名 (小写, 如 "xray")

        Returns:
            配置文件完整路径, 若不存在则返回 None
        """
        key = f"CFG.{name.upper()}"
        return self.resolve(key)

    def check_tool(self, name: str) -> bool:
        """检查工具是否可用 (先查映射表, 再查 PATH)。

        Args:
            name: 工具名 (如 "nmap", "tshark")

        Returns:
            True 如果工具文件存在或可在 PATH 中找到
        """
        # 1. 查 path-mapping.json
        mapped = self.tool(name)
        if mapped and os.path.isfile(mapped):
            return True

        # 2. 查系统 PATH
        if shutil.which(name) or shutil.which(name + ".exe"):
            return True

        return False

    def get_tool_path(self, name: str) -> Optional[str]:
        """获取工具完整路径 (映射表优先, 再查 PATH)。

        Args:
            name: 工具名 (如 "nmap", "tshark")

        Returns:
            可执行文件完整路径, 若都找不到则返回 None
        """
        # 1. 查 path-mapping.json
        mapped = self.tool(name)
        if mapped and os.path.isfile(mapped):
            return mapped

        # 2. 查系统 PATH
        found = shutil.which(name) or shutil.which(name + ".exe")
        if found:
            return found

        return None

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def tool_count(self) -> int:
        """已映射的工具数量"""
        return sum(1 for k in self._paths if k.startswith("TOOL."))
