# 方案：agent → burpmcp → sqlmap4burp++ → sqlmap 搭桥（已完成）

> 本文件是 sqlmap 桥工作的执行记录。桥已建成、编译通过、功能验证通过、框架四处已对齐、残留已清。
> 新窗口接续此任务（或维护桥工具）先读本文件，不必重读 sqlmap4burp++ 全量源码。
>
> **v2 接续（进行中）**：桥是绕道——驱动 sqlmap 的逻辑应住在正确的层。重设计方案见
> [`SQLMAP4BURP_V2_设计.md`](SQLMAP4BURP_V2_设计.md)；Phase 1 已开工：
> 把桥的 Runner/LogParser/三态种子搬进 `com.burpmcp.ultra.sqlmap` 分层模块，MCP 工具改薄客户端，
> 外部契约（工具名/参数/返回 JSON）不变，框架侧对齐零改动。

---

## 〇、实现落点（关键路径）

| 项 | 路径 | 状态 |
|---|---|---|
| 桥工具实现 | `d:\Penetration tools\BurpMCP-Ultra-2.0.1\src\main\kotlin\com\burpmcp\ultra\bridge\AnalysisBridge.kt` | `sqlmapBridgeRun()` + helpers（tokenizeArgs / findSqlmapLogFiles / analyzeSqlmapLog） |
| 工具注册 | `d:\Penetration tools\BurpMCP-Ultra-2.0.1\src\main\kotlin\com\burpmcp\ultra\tools\etsi\EtsiSqlmapBridgeTools.kt` | `sqlmap_bridge_run` |
| 挂载点 | `d:\Penetration tools\BurpMCP-Ultra-2.0.1\src\main\kotlin\com\burpmcp\ultra\transport\ToolRegistry.kt` | 注册调用 |
| 脚本改向 | `scripts\sqli_probe.py` | 输出 `bridge_calls[]`（quick/deep 各一条），保留写 .req |
| recipe | `framework\clause_tool_map.json` 5.13-1 | `burp_mcp` 含 `sqlmap_bridge_run`；method 描述桥流程 |
| 弹药库 | `skills\exploit\references\web-sqli.md` | §2.1 / §2.4 / §2.5 / §2.6 对齐；备选 URL / 数据提取标"手动兜底，不走桥" |
| ETSI skill | `skills\etsi-ts103701-report\SKILL.md` + `references\clause-reference.md` + `module-split.md` + `capability-matrix.md` + `pipelines\etsi\personas\work-agent.md` | 全部改指桥 |
| 功能验证样例 | `experiments\2026-08-17-sqlmap-bridge\bridge-test\` | vuln_server.py（本地靶）+ bridge_logic_check.py（Kotlin 逻辑 1:1 镜像）+ 两个 manifest + 产物目录 |

---

## 一、桥工具契约（已实现）

### 1.1 入参

```
workspace      : string   // 工作区绝对路径
endpoint_id    : string   // sqlmap_manifest.json endpoints[].seq（或直接 .req 文件路径）
mode           : string   // quick | deep
python         : string?  // 缺省 saveExtensionSetting("PYTHON_NAME") → "python"
sqlmap_path    : string?  // 缺省 saveExtensionSetting("SQLMAP_PATH") → "sqlmap"
extra_options  : string?  // 追加原始 sqlmap 参数
timeout_seconds: int?     // 缺省 600
```

### 1.2 出参（JSON）

```
ok / status(found|clean|blocked) / injection_found / injected_parameter / payload
output_dir / request_file / stdout_tail / mode / url / method / path / exit_code
timed_out / injection_points / log_files[] / note / error
```

### 1.3 mode 预设

- quick：`--batch --smart --delay=1 --level=1 --risk=1`
- deep：`--batch --level=3 --risk=2 --time-sec=5 --tamper=space2comment,between`

### 1.4 实现要点（复刻 sqlmap4burp++ 启动逻辑 + 三处增强）

1. **写 .req**：复刻 `Util.getTempReqName`/`writeFile`，目标 `{workspace}/sqlmap/{METHOD}_{path}.req`，内容 = manifest 端点 request 原文（已含认证头）。Kotlin `File.writeText` 字节精确（无 Windows CRLF 翻译），Python 侧镜像必须 `open("wb")` 二进制写。
2. **拼命令**：复刻 SqlmapStarter 核心行 `{python} "{sqlmap}" -r "{req}" {options}`，追加 `--output-dir={workspace}/sqlmap/output`。**sqlmap 路径含空格/中文 → 路径作为独立 list 元素传 ProcessBuilder，不做字符串拼接**（`tokenizeArgs(pythonCmd) + listOf(sqlmapCmd) + ["-r", req] + optionTokens`）。
3. **执行**：不用 `cmd /c start` 分离终端；`ProcessBuilder.redirectOutput(stdoutFile)` / `redirectError(stderrFile)` 避免管道死锁；`waitFor(timeoutSeconds, TimeUnit.SECONDS)` 超时强杀。
4. **解析日志**：`--output-dir` 下 walk `log` 文件（`{output-dir}/{host}/log`），正则 `^Parameter:` / `^Payload:` 提取注入点与 payload。
5. **三态判定**：日志含 Parameter 块 → found；`isNotInjectable` 命中两种措辞（老版 "appear to be not injectable" + 1.10.x "do not appear to be injectable"）→ clean；其余（超时/异常退出/无明确日志）→ blocked。

### 1.5 保留的 carve-out（非残留）

- **数据提取**（`--dbs/--tables/--dump`）与**备选 URL 直接模式**（无 manifest 时）：由 M5 agent 手动直调 sqlmap CLI，桥不覆盖。见 `web-sqli.md` §备选/§数据提取（均标"手动兜底，不走桥"）。
- `clause_tool_map.json` 5.13-1 bash 工具数组仍保留 `sqlmap`，供上述 carve-out；主流程走 `sqlmap_bridge_run`。

---

## 二、验证记录（全部已跑通）

| 验证项 | 结果 |
|---|---|
| `gradlew.bat compileKotlin`（前台，无管道） | BUILD SUCCESSFUL |
| 真 sqlmap 1.10.5 打本地靶 `/vuln?id=` | mode=quick → status **found**（injected_parameter=id，payload 取自 sqlmap 日志） |
| 对照组 `/benign?id=`（参数化查询） | status **clean** |
| deep 模式（tamper 生效） | status **found** |
| `.req` 直入路径分支 | status **found** |
| Cookie + SessionTag 双头 .req 字节精确 | 确认 |
| `clause_tool_map.json` JSON 校验 | OK |
| `build_clause_recipe_text(['5.13-1'])` | burp: `proxy_latest_auth,sqlmap_targets,sqlmap_bridge_run,sitemap_query,http_fuzz,repeater_send` |
| 残留检查（grep `sqli_probe.*--batch` / `ProcessBuilder.*sqlmap` / 直连） | 活动代码路径无直跑 sqlmap 残留 |

---

## 三、备选方案（记录，不展开）

sqlmap 官方 `sqlmapapi.py` 的 REST-JSON API（`task/new` → `scan/start` → `scan/data`/`scan/status`）天然是程序化 evidence 源，可彻底不弹窗。主方案按用户要求走 sqlmap4burp++ 同构逻辑，此条只留备注。

---

## 四、已建立事实（防换窗口后重读）

- sqlmap4burp++ 核心命令拼装只有一行（`Menu.java` 右键入口 + `SqlmapStarter.java` 拼装 + `Util.java` 写文件 + `Config.java` saveExtensionSetting），与 sqlmap CLI `-r` 模式完全吻合，已内嵌进 burpmcp。
- burpmcp 的 `sqlmap_targets` 输出 `sqlmap_manifest.json` 是桥工具输入源，字段 `endpoints[].request / seq / method / path / priority / dynamic / params[]`。
- proxy_latest_auth 认证头已内嵌在 `endpoints[].request` 原文里，桥工具不需要再单独拿认证头。
- sqlmap 日志结构：`{output-dir}/{host}/log`；sqlmap 1.10.x 的 not-injectable 措辞是 "do not appear to be injectable"（老版是 "appear to be not injectable"），两者都要判。
- 编译验证纪律：`gradlew.bat compileKotlin` 前台跑看 exit code，不套管道。
