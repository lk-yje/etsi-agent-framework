#!/usr/bin/env python3
"""
目录/路径爆破 (条款 5.6-2 / 5.13-1) — 发现隐藏路径与未登记 API 面。

统一替代原 dirsearch 角色（5.6-2 与 5.13-1 共用同一脚本）：
- 走 Burp http_fuzz → 认证天然带（经 Burp 代理），无 dirsearch 认证过期"0 paths found"静默假阴性
- 词表覆盖 sitemap 之外隐藏路径（.git/backup/config/调试端点/ISAPI 段）
- --base=<path> 递归子路径深挖：顶层命中目录后逐级下钻

纯确定性脚本：内置 IoT 摄像机/NVR + 通用 Web 路径词表，生成 MCP 指令 + 结果筛别。
不自持 MCP 连接 —— 生成模式输出 mcp_call 供 agent 执行，--ingest 处理执行结果。

用法:
  # 生成 http_fuzz MCP 指令 (exit 1，待 agent 执行 MCP)
  python dir_brute_force.py <workspace> --target=IP [--port=80] [--tls] [--wordlist=FILE] [--base=/path] [--label=5.6-2]

  # 处理 http_fuzz 结果 (exit 0)，筛出非 404 命中路径 + 给出下一轮递归指令
  python dir_brute_force.py <workspace> --target=IP --ingest=fuzz_result.json [--label=5.6-2]

输出 (生成模式):
  {"status":"ready", "clause":"5.6-2", "mcp_calls":[{"step":1,"action":"mcp__burp__http_fuzz",...}], "ingest":"..."}

输出 (处理模式):
  {"status":"ok", "clause":"5.6-2", "total":N, "hits":[...], "summary":{...}, "next_round":[...]}
"""

from __future__ import annotations  # Python 3.8 兼容：注解延迟求值

import json
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:  # Python < 3.7
    pass

# ── 顶层路径词表 (配合 "GET /FUZZ") ──
# IoT 摄像机/NVR (ISAPI/ONVIF) + 通用 Web 隐藏路径。扩展名直接内联进条目
# (http_fuzz 的 FUZZ 是精确替换，无独立 -e 扩展名机制，故 *.bak/*.zip 显式列出)。
TOP_LEVEL = [
    # IoT / 设备协议
    "ISAPI", "onvif", "axis-cgi", "cgi-bin", "Streaming", "SDK", "Media",
    "Content", "record", "playback", "snapshot", "video", "alarm", "event",
    "encode", "decode", "channels", "VirtualNetwork", "DeviceMgmt",
    "Network", "System", "Security", "user", "User", "config", "Config",
    # 通用 Web
    "api", "v1", "v2", "admin", "login", "manage", "manager", "console",
    "dashboard", "debug", "test", "dev", "devtools", "swagger", "swagger-ui",
    "api-docs", "docs", "graphql", "doc", "documentation", "status", "info",
    "version", "health", "actuator", "metrics", "monitor", "tools", "utility",
    "web", "static", "assets", "js", "css", "images", "img", "upload",
    "uploads", "download", "downloads", "files", "file", "data", "backup",
    "backups", "tmp", "temp", "old", "new", "bak", "archive", "logs", "log",
    "public", "private", "internal", "external", "hidden", "secret",
    # 源码/备份/配置泄露面
    ".git", ".svn", ".hg", ".DS_Store", ".well-known", "robots.txt",
    "sitemap.xml", "favicon.ico", "README", "README.md", "LICENSE", "COPYING",
    ".env", ".gitignore", "composer.json", "package.json", "web.config",
    "config.json", "config.xml", "config.php", "config.bak", "settings.php",
    "database.sql", "dump.sql", "backup.zip", "backup.sql", "phpinfo.php",
    "info.php", "server-status", "server-info", "cgi-bin/", "crossdomain.xml",
    "web.xml", "index.php", "index.html", "default.asp", "default.aspx",
    "shell.php", "upload.php", "delete.php",
]

# ── 子路径词表 (配合 "GET /<base>/FUZZ"，--base 递归时使用) ──
SUB_PATHS = [
    # 目录下的常见文件/配置
    "config", "config.php", "config.xml", "config.json", "config.bak",
    "settings", "settings.php", "setting.xml", "db.php", "database.php",
    "database.sql", "db.sql", "dump.sql", "users.sql", "users.php",
    "user.php", "admin.php", "login.php", "index.php", "index.html",
    "default.php", "default.aspx", "default.asp", "info.php", "phpinfo.php",
    "test.php", "debug.php", "env.php", ".env", ".htaccess", ".gitignore",
    "web.config", "web.xml", "README", "README.md", "version", "version.json",
    "swagger.json", "openapi.json", "api.js", "api.json", "package.json",
    "composer.json", "credentials", "credential", "password", "passwd.txt",
    "password.txt", "pass.txt", "backup.zip", "backup.sql", "dump",
    "upload.php", "upload", "download.php", "export.php", "import.php",
    "auth", "token", "session", "login", "logout", "register", "userinfo",
    "status", "info", "health", "ping", "version", "list", "detail",
    "upload", "delete", "save", "get", "set", "search",
]


def load_wordlist(ws: str, override: str | None, base: str | None) -> list[str]:
    """词表解析：--wordlist 覆盖优先；否则按是否 --base 递归选 TOP_LEVEL / SUB_PATHS。"""
    if override:
        if not os.path.exists(override):
            print(json.dumps({"status": "error", "error": f"词表不存在: {override}"}, ensure_ascii=False))
            sys.exit(1)
        with open(override, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    return list(SUB_PATHS) if base else list(TOP_LEVEL)


def _base_slug(base: str | None) -> str:
    """--base 路径转文件名 slug，用于 save_to 命名避免多轮覆盖。"""
    if not base:
        return "root"
    return re.sub(r"[^A-Za-z0-9]+", "_", base.strip("/")).strip("_") or "root"


def build_fuzz_call(target: str, port: int, use_tls: bool, payloads: list[str], ws: str,
                    base: str | None, label: str) -> dict:
    """构造 http_fuzz FUZZ 模式的 MCP 调用。base 非空时爆破 /base/FUZZ 子路径。"""
    prefix = f"/{base.strip('/')}" if base else ""
    req = (f"GET {prefix}/FUZZ HTTP/1.1\r\n"
           f"Host: {target}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
    slug = _base_slug(base)
    save_to = os.path.join(ws, f"fuzz_dir_{label}_{slug}.json")
    return {
        "step": 1,
        "action": "mcp__burp__http_fuzz",
        "params": {
            "request": req,
            "host": target,
            "port": port,
            "use_tls": use_tls,
            "payloads": payloads,
        },
        "save_to": save_to,
        "note": f"对 {target} 做{'子路径' if base else '顶层'}路径爆破 (base={base or '/'})，payload 数={len(payloads)}。"
                f"执行后把返回结果存到 save_to，再跑 ingest。",
    }


def parse_fuzz_result(raw: str) -> list[dict]:
    """解析 http_fuzz 输出，返回扁平响应条目列表 (防御式，兼容 MCP wrapper)。"""
    try:
        data = json.loads(raw)
    except Exception:
        return []
    # MCP wrapper: [{"text":"..."}]
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict) and "text" in data[0]:
        try:
            data = json.loads(data[0]["text"])
        except Exception:
            return []
    if isinstance(data, dict):
        for key in ("responses", "results", "items"):
            if isinstance(data.get(key), list):
                return data[key]
    if isinstance(data, list):
        return data
    return []


def _is_dir_like(path: str) -> bool:
    """判断命中路径是否像目录 (无文件扩展名) → 可继续递归。"""
    if path in (".git", ".svn", ".hg", ".well-known"):
        return True
    last = path.split("/")[-1]
    return "." not in last


def process_hits(items: list[dict], base: str | None, label: str) -> tuple[list[dict], list[str]]:
    """筛出非 404 的命中路径，返回 (hits, next_round_cmds)。"""
    hits = []
    next_round = []
    seen = set()
    for it in items:
        if not isinstance(it, dict):
            continue
        sc = it.get("status_code", it.get("status", 0))
        if isinstance(sc, str):
            try:
                sc = int(sc)
            except Exception:
                sc = 0
        # 404/0 视为未命中；其余 (200/301/401/403/500...) 视为存在
        if sc in (0, 404):
            continue
        path = it.get("path", it.get("payload", it.get("url", "?")))
        # http_fuzz 通常回填 FUZZ 位置的实际 payload；无 path 字段时从 payload 还原
        if path == "?" or "/FUZZ" in str(path):
            path = it.get("payload", "?")
        full = f"{base.rstrip('/')}/{path}" if base else path
        key = f"{full}:{sc}"
        if key in seen:
            continue
        seen.add(key)
        hits.append({
            "path": full,
            "status_code": sc,
            "content_length": it.get("content_length", it.get("body_length", 0)),
        })
        # 顶层命中的目录型路径 → 生成下一轮递归指令 (避免无限下钻，只扩一层)
        if not base and _is_dir_like(path):
            next_round.append(
                f"python dir_brute_force.py {{workspace}} --target=<IP> --base={full} --label={label}"
            )
    # 按状态码排序，敏感路径优先 (200 在前)
    hits.sort(key=lambda h: (h["status_code"] != 200, h["status_code"]))
    return hits, next_round


def main():
    ws = ""
    target = ""
    ingest = ""
    port = 80
    use_tls = False
    wordlist_override = None
    base = None
    label = "5.6-2"

    for a in sys.argv[1:]:
        if a.startswith("--target="):
            target = a.split("=", 1)[1]
        elif a.startswith("--port="):
            port = int(a.split("=", 1)[1])
        elif a == "--tls":
            use_tls = True
        elif a.startswith("--ingest="):
            ingest = a.split("=", 1)[1]
        elif a.startswith("--wordlist="):
            wordlist_override = a.split("=", 1)[1]
        elif a.startswith("--base="):
            base = a.split("=", 1)[1]
            # MSYS (Git Bash) 会把 /ISAPI 自动转换成本地盘符路径 D:/Git/ISAPI，剥掉盘符前缀
            base = re.sub(r"^[A-Za-z]:/", "", base)
        elif a.startswith("--label="):
            label = a.split("=", 1)[1]
        elif not a.startswith("--"):
            ws = a

    if not ws:
        print("用法: python dir_brute_force.py <workspace> --target=IP [--port=80] [--tls] [--wordlist=FILE] [--base=/path] [--label=5.6-2]", file=sys.stderr)
        sys.exit(2)

    # ── 处理模式 ──
    if ingest:
        if not os.path.exists(ingest):
            print(json.dumps({"status": "error", "error": f"文件不存在: {ingest}"}, ensure_ascii=False))
            sys.exit(1)
        with open(ingest, "r", encoding="utf-8") as f:
            raw = f.read()
        items = parse_fuzz_result(raw)
        hits, next_round = process_hits(items, base, label)
        result = {
            "status": "ok",
            "clause": label,
            "base": base or "/",
            "total_responses": len(items),
            "hits": hits,
            "hit_count": len(hits),
            "next_round": next_round,
            "summary": {
                "verdict_hint": "存在非 404 隐藏路径" if hits else "未发现隐藏路径 (全部 404/空)",
                "clause": label,
                "next": (
                    "对命中路径用 bash curl 采集 banner 内容作为 evidence；关键路径尝试未认证访问。"
                    + (f" 顶层目录型命中 → 跑 next_round 递归子路径深挖。" if next_round else "")
                ),
            },
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0)

    # ── 生成模式 ──
    if not target:
        print(json.dumps({"status": "error", "error": "生成模式需 --target=IP"}, ensure_ascii=False))
        sys.exit(2)

    payloads = load_wordlist(ws, wordlist_override, base)
    mcp_call = build_fuzz_call(target, port, use_tls, payloads, ws, base, label)
    result = {
        "status": "ready",
        "clause": label,
        "detail": f"目录爆破 {target}:{port} ({'https' if use_tls else 'http'}) base={base or '/'}",
        "mcp_calls": [mcp_call],
        "ingest": f"python dir_brute_force.py {ws} --target={target} --ingest={mcp_call['save_to']}"
                  + (f" --base={base}" if base else "") + f" --label={label}",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(1)  # 需 agent 执行 MCP


if __name__ == "__main__":
    main()
