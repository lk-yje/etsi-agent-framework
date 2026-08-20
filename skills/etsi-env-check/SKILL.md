---
name: etsi-env-check
description: >
  Check environment readiness before starting any ETSI TS 103701 certification task.
  Use this skill whenever the user says "先检查一下", "准备开始", "检查环境",
  "before we start", or mentions verifying environment before ETSI report generation,
  security testing, or certification work. Also trigger when the user begins an ETSI-related
  task and asks to verify tools are available first. Catches unavailable tools (Burp, nmap,
  tshark, sqlmap, etc.) before tests begin, preventing wasted effort mid-task.
---

# ETSI 任务环境检查

> **路径约定：** 本文件中 `${NAMESPACE.NAME}` 为路径占位符（`TOOL`=可执行文件, `DIR`=目录, `CFG`=配置文件）。
> 实际路径见仓库根目录 [`path-mapping.json`](../path-mapping.json)。PowerShell 取 `windows` 值，Git Bash 取 `bash` 值。
> 换机器只需修改映射表，所有 skill 文件自动生效。

在开始 ETSI TS 103701 认证检测任务之前，逐项检查本地环境和工具链是否可用。
发现不通过时立即报告，不要继续执行后续任务。

## 检查范围

按以下顺序执行检查，逐项输出结果。

---

### 1. MCP 服务连通性

检查 Claude Code 的 MCP 工具链是否联通。

#### 1.1 配置文件

Claude Code 的 MCP 配置可能位于两处（优先级从高到低）：

| 位置 | 作用域 | 说明 |
|------|--------|------|
| `~/.claude.json` → `mcpServers` | 全局 | 所有项目生效，推荐 Burp 放这里 |
| `~/.claude.json` → `projects.<path>.mcpServers` | 项目级 | 仅特定目录生效 |
| 项目根 `.mcp.json` | 项目级 | 可提交到 git，团队共享 |

```bash
# 检查全局配置
cat ~/.claude.json 2>&1 | python -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('mcpServers',{}), indent=2))"
```

**验证要点：**
- 文件存在，JSON 可解析
- 包含 `mcpServers` 对象（全局或项目级均可）
- Burp server 的 `type` 为 `"sse"`，`url` 为 `http://127.0.0.1:9876/`（注意末尾 `/`）
- Playwright MCP server（替代 Chrome DevTools），用于浏览器自动化验证前端安全
- 各 server 的 `disabled` 不存在或为 `false`

#### 1.2 SSE 端口监听

```bash
netstat -ano | findstr :9876
```

**通过标准：** 输出中包含 `LISTENING` 状态。

#### 1.3 SSE endpoint 探测

```bash
curl --connect-timeout 5 --max-time 10 -s http://127.0.0.1:9876/ 2>&1
```

**通过标准：** 响应中包含 `sessionId`（curl 的 exit code 28 是正常的——SSE 是长连接，curl 超时退出但在此之前已读到 sessionId）。

#### 1.4 MCP 工具调用验证

通过以上检查后，Claude Code 会将 Burp 的 MCP 工具暴露给 Agent。调用时**无需手动构造 HTTP 请求**，直接像使用内置工具一样调用即可。

**工具命名规则：** MCP 工具在 Claude Code 中的名称为 `mcp__<server名>__<工具名>`。例如 Burp server 名为 `burp`，则 `proxy_history` 工具对应 `mcp__burp__proxy_history`。

**验证 MCP 工具可用：** 调用一个轻量级只读工具：

```
调用 mcp__burp__proxy_history 工具，参数 {"limit": 1}
```

如果返回了正常的 JSON 响应（含 `total_filtered` 和 `items`），说明工具链完全就绪。

#### 1.5 Playwright MCP 验证

**启动入口（自维护降级启动器）：** Playwright MCP 的 `command` 指向本 skill 的自维护脚本，而非裸 `npx @playwright/mcp@latest`：

```cjs
// ~/.claude.json → mcpServers.playwright
{
  "command": "node",
  "args": [
    "${DIR.SKILLS}\\etsi-env-check\\scripts\\playwright-mcp-launch.cjs",
    "--browser", "msedge", "--isolated"
  ],
  "cwd": "${DIR.PLAYWRIGHT}",
  "disabled": false
}
```

**降级策略（脚本内置，env-check 应知晓）：**
- 脚本以短超时（npm 短超时 + 0 重试，约 4s）探测 npm registry 连通性
- **能联网** → 解析 `@playwright/mcp@latest` 并启动最新版（保留自动更新能力）
- **连不上** → 回落本地 `_npx` 缓存 / 上次成功版本（记录在 `~/.claude/playwright-mcp-version.json`），秒连不卡启动
- 根因：裸 `npx @latest` 在 registry 不可达时会卡 60-74s 直到超时；脚本用短超时快断 + 本地回落解决

```
调用 mcp__playwright__browser_tabs 工具，参数 {"action": "list"}
```

**通过标准：** 返回当前浏览器打开的标签页列表（含 `title` 和 `url`）。若浏览器未启动或 MCP 未连接，返回错误——此时 agent 必须 `report_to_main` 暂停主流程，禁止降级为 Burp 密文分析或手工 DevTools 替代。playwright 就绪前不裁决 5.1-3/5.5-1。

**降级状态检查（`--check` 模式，供报告）：**
```bash
node "${DIR.SKILLS}\etsi-env-check\scripts\playwright-mcp-launch.cjs" --check
```
输出 JSON 含 `registry`(reachable/unreachable)、`used`(实际采用版本)、`source`(online-latest/last-success/cache)、`cachedVersion`、`lastSuccessVersion`。Env-check 据此在报告里标注 Playwright 用的是最新版还是降级缓存版。

---

### 2. 本地安全工具

逐个检查 ETSI 检测所需的本地安全工具。每个工具不仅检查路径/版本，还要发送一条**功能性测试指令**来验证工具实际可用。

---

#### 2.1 Burp Suite（MCP 后端）

通过 MCP 调用 `mcp__burp__burp_version` 获取版本和版次信息。

**版次判定逻辑：**

| 版次 | 总工具数 | Community 可用 | 需 Professional |
|:----:|:------:|:------------:|:-------------:|
| **Professional** | ~149 | 149 | 0 |
| **Community** | ~149 | ~124 | ~25 |

> MCP 扩展层（BurpMCP-Ultra）统一暴露全部 149 个工具接口，不受版次影响。下表 25 个工具为 Burp Suite Professional 版专属功能，Community 版不含对应功能模块，调用时后端返回空结果或降级响应——属 Burp 许可限制，非 MCP 工具链故障。

**Community 版不具备的 Professional 专属功能（25 个）：**

| 类别 | 数量 | Professional 专属工具 |
|------|:----:|-----------|
| Scanner | 8 | `scanner_start_crawl`, `scanner_start_audit`, `scanner_get_all_issues`, `scanner_generate_report`, `scanner_create_issue`, `scanner_import_bcheck`, `scanner_register_check`, `scanner_unregister_check` |
| Collaborator | 7 | `collaborator_create_client`, `collaborator_restore_client`, `collaborator_generate_payload`, `collaborator_poll`, `collaborator_server_info`, `collaborator_get_secret`, `collaborator_default_payload` |
| Intruder | 3 | `intruder_send`, `intruder_send_with_positions`, `intruder_register_payload_processor` |
| ScanCheck | 2 | `scancheck_create_passive`, `scancheck_create_active` |
| BCheck | 2 | `bcheck_create`, `bcheck_import` |
| AI/Bambda | 3 | `ai_status`, `ai_prompt`, `bambda_import` |

**Community 版 ETSI 检测覆盖率（EN 303 645 V2.1.1）：**

| 覆盖级别 | ETSI 条款 | Community 可用工具 | 说明 |
|:--------:|-----------|-------------------|------|
| ✅ 完全 | 5.5-4 未认证访问、5.5-5 越权、5.6-2 信息泄露、5.5-6/5.5-7 CSP 传输加密 | Proxy / Repeater / Passive Intel / Access Control Sweep / Auth Diff | 核心 HTTP 交互与流量分析工具完整可用 |
| ⚠️ 部分 | 5.1-5 口令爆破、5.13-1 输入验证 | Injection Probe / HTTP Fuzz（缺 Intruder、缺 Scanner） | 爆破改用 Hydra（Bash）；漏洞扫描改用 sqlmap + Burp http_fuzz（路径爆破走 dir_brute_force.py）；注入探针可用但无自动化扫描 |
| ❌ 受限 | 5.13-1 SSRF/OOB 子项、5.6-1 隐蔽服务发现（OOB 依赖） | —（缺 Collaborator） | 无 OOB 回调检测能力，SSRF/盲注入等需人工架设外网回调服务 |

**报告时需注明：** 「本报告使用 Burp Suite Community Edition 生成，Scanner/Collaborator/Intruder 等 Professional 专属功能不可用。受影响条款已通过手工/半自动替代方案弥补，详见各条款备注。」

---

#### 2.2 nmap

```bash
# 路径
${TOOL.NMAP} --version
# 功能验证（ping 扫描本机，1 秒内返回）
${TOOL.NMAP} -sn 127.0.0.1
```

**通过标准：** 版本号正常输出 + ping 扫描返回 `Host is up`。

---

#### 2.3 tshark

```bash
# 路径
${TOOL.TSHARK} --version
# 功能验证（列出可用抓包接口，验证引擎正常加载）
${TOOL.TSHARK} -D
```

**通过标准：** 版本号正常输出 + `-D` 列出至少 1 个网络接口。

---

#### 2.4 sqlmap

```bash
# 路径（注意：不是 sqlmap-1.10/sqlmap-1.10/ 那层）
python "${TOOL.SQLMAP}" --version --batch
# 功能验证（对本地空端口快速探测，验证引擎加载 + 网络栈可用）
python "${TOOL.SQLMAP}" -u "http://127.0.0.1:1/" --batch --timeout 2 --retries 0
```

**通过标准：** 出现 sqlmap banner（`__H__`）且引擎正常初始化。`icmpsh_m` 模块缺失的 CRITICAL 报错可忽略——这是非核心的子功能（ICMP shell），不影响 SQL 注入检测。

---

#### 2.5 Wireshark GUI

```powershell
# PowerShell: ${DIR.TSHARK} 原生路径，不依赖 MSYS2 挂载
if (Test-Path "${TOOL.WIRESHARK}") { Write-Output "Wireshark.exe found" } else { Write-Output "NOT found" }
```

**通过标准：** 文件存在即可。GUI 不需要在此启动。

---

#### 2.6 Playwright（浏览器自动化）

通过 MCP 调用 `mcp__playwright__browser_tabs` 工具验证连通性（已在 1.5 节完成）。

**通过标准：** 返回标签页列表即表示 Playwright MCP 已连接浏览器实例。

**版本与降级判定（与 1.5 联动）：** 运行：
```bash
node "${DIR.SKILLS}\etsi-env-check\scripts\playwright-mcp-launch.cjs" --check
```
- `registry: reachable` + `source: online-latest` → 在用最新版，正常
- `registry: unreachable` + `source: cache|last-success` → 降级到缓存版，功能不受影响，但记录「当前为离线缓存版 `used`」，若 Edge 大版本更新过可能需要联网升级 playwright 以保持驱动兼容
- 无可用版本且离线 → Playwright 不可用，agent 必须 `report_to_main` 暂停主流程（禁止降级为半自动替代方案），playwright 就绪前不裁决 5.1-3/5.5-1

---

#### 2.7 xray（被动漏洞扫描）

xray 挂载在 Burp 下游做被动扫描，与 MCP 共享同一条流量——Burp 代理转发至 xray，xray 自动检测漏洞，MCP 仍正常读写全量流量，互不干扰。

**环境检查时做两件事：**
1. 将目标 IP 写入 xray 配置文件，限制 xray 只处理该 IP 的流量
2. 启动 xray 代理做功能验证，确认引擎 + PoC + 代理正常后立即停止

**步骤 1：注入目标 IP**

```powershell
# PowerShell: ${DIR.XRAY} 原生路径，Python open() 无法解析 MSYS2 的 /d/ 前缀
$content = Get-Content "${CFG.XRAY}" -Raw
$content = $content -replace 'hostname_allowed: \[.*?\]', "hostname_allowed: ['<目标IP>']"
Set-Content "${CFG.XRAY}" -Value $content -Encoding utf8
Write-Output "xray config updated: hostname_allowed = ['<目标IP>']"
```

**步骤 2：功能验证**

```bash
# 启动 xray MITM 代理 → curl 发一次请求 → 确认引擎正常 → 停止
cd ${DIR.XRAY} && ${TOOL.XRAY} webscan --listen 127.0.0.1:7778 --html-output /tmp/xray_test.html &
sleep 2
# 用目标 IP 的请求验证（非目标 IP 的请求会被 xray 拒绝，证明过滤生效）
curl --connect-timeout 2 --max-time 3 -s -o /dev/null -w "proxy status: %{http_code}\n" -x http://127.0.0.1:7778 http://<目标IP>:80/
kill %1 2>/dev/null
```

**通过标准：**
- 引擎启动，看到 `Enabled plugins:` 列表（16 个插件）
- 看到 `819 pocs have been loaded`
- 看到 `starting mitm server at 127.0.0.1:7778`
- curl 通过代理返回 HTTP 状态码（非 000），证明代理转发正常
- xray 只处理 IP 在 `hostname_allowed` 内的流量，其余全部拒绝

> **注意：** 配置修改后会持久保留。如果更换目标设备，需重新运行 env-check 更新配置。

---

### 3. 网络基础连通性

#### 3.1 目标设备 IP

**如果用户已在上下文中提供了目标 IP：** 直接进入 3.2 检查。
**如果尚未提供目标 IP：** 向用户提问：

```
请提供待检测设备的 IP 地址，以便检查网络连通性。
（例如 192.168.1.100）
```

拿到 IP 后继续 3.2。

#### 3.2 目标可达性

```bash
# Ping 测试（Windows 下默认 4 次，约 3 秒完成）
ping -n 2 <目标IP>
```

**通过标准：** 至少收到 1 个回复（`TTL=...`）。

#### 3.3 常见端口探测

用 curl 对目标 IP 的 ETSI 检测常用端口做快速 TCP 连接探测（不用 nmap——nmap 的 `--host-timeout` 在 Windows 下容易卡住，curl 的 `--connect-timeout` 更干净）：

```bash
for port in 80 443 8080 8443 554; do
  curl --connect-timeout 2 --max-time 3 -s -o /dev/null -w "port $port: %{http_code} (%{time_total}s)\n" "http://<目标IP>:$port" 2>&1
done
```

**通过标准：** 至少有 1 个端口返回 HTTP 响应（或 TCP 握手成功），确保后续 HTTP 测试有目标。全部 `000`（连接拒绝/超时）报告警告但可继续（设备可能只开了冷门端口或防火墙屏蔽探测）。


---

### 4. 固件文件确认（5.3-2 / 5.3-9 固件完整性测试用）

若本次检测涉及固件更新条款（5.3-2、5.3-9），需提前准备固件文件。

#### 4.1 目录与文件检查

向用户提问确认固件存放目录：

```
固件完整性测试（5.3-2 降级拒绝 / 5.3-9 错包拒绝）需要固件文件。
请提供固件存放目录路径，该目录下应包含：
  ├── old/   ← 存放旧版本固件（降级测试用）
  └── new/   ← 存放当前版本固件（将被篡改生成错包）

例如: ${DIR.FIRMWARE}\
```

拿到目录后检查：

```powershell
Get-ChildItem "<固件目录>\old\" -File
Get-ChildItem "<固件目录>\new\" -File
```

**通过标准：**
- `old/` 下至少有 1 个固件文件
- `new/` 下至少有 1 个固件文件

**缺失处理：**
- 缺少旧固件 → 提醒用户下载旧版本固件放入 `old/`；降级测试将标 INCONCLUSIVE
- 缺少新固件 → 提醒用户下载当前版本固件放入 `new/`；错包测试将标 INCONCLUSIVE
- 用户确认「不测固件」→ 5.3-2 和 5.3-9 标 INCONCLUSIVE，跳过 4.2

#### 4.2 生成篡改固件

`new/` 下有固件后，运行篡改脚本生成 1 个变体（头/中/尾各翻转 1 字节）：

```bash
python "${DIR.SKILLS}\etsi-env-check\scripts\tamper_firmware.py" "<固件目录>\new\<固件文件名>"
```

> 脚本流式复制、不爆内存。仅生成 `multi_3byte` 变体（偏移 0x0 / 文件中间 / 文件尾-0x100 各 XOR 0xFF），输出到 `<固件目录>\new\tampered\`。

**通过标准：** 脚本正常退出，`tampered/` 目录下存在篡改固件。

#### 4.3 输出

```
[4/4] 固件文件确认
  [4.1] old/ 降级固件         ✅ <文件名> (<大小> MB)  / ⚠️ 缺失，降级测试标 INCONCLUSIVE
  [4.2] new/ 当前固件         ✅ <文件名> (<大小> MB)
  [4.3] 篡改固件生成           ✅ <文件名>_tampered.dav
```

---

## 输出格式

```
=== ETSI 任务环境检查 ===

[1/4] MCP 服务连通性
  [1.1] ~/.claude.json        ✅ burp server (type=sse, url=http://127.0.0.1:9876/)
  [1.2] :9876 端口监听        ✅ LISTENING (PID xxxxx)
  [1.3] SSE endpoint           ✅ 返回 sessionId (xxxx)
  [1.4] MCP 工具调用           ✅ proxy_history 正常 (total_filtered: xxxx)
  [1.5] Playwright MCP          ✅ browser_tabs 正常 (x 个标签页) | v0.0.78 (离线缓存版) / ✅ v0.0.88 (在线最新版)

[2/4] 本地安全工具
  [2.1] Burp Suite             ✅ <Professional|Community> <版本> — 以 mcp__burp__burp_version 实测为准
  [2.2] nmap                   ✅ 7.94 — ping 扫描正常 (Host is up in 1.2s)
  [2.3] tshark                 ✅ 4.6.6 — 列出 12 个接口
  [2.4] sqlmap                 ✅ 1.10 — 引擎加载正常
  [2.5] Wireshark GUI          ✅ ${TOOL.WIRESHARK}
  [2.6] Playwright              ✅ browser_tabs 连通 | 降级/最新版判定见 1.5
  [2.7] xray 1.9.11 (CE)       ✅ 819 PoCs | hostname_allowed=192.0.2.54 | 代理转发正常

[3/4] 网络基础连通性
  [3.1] 目标 IP                ✅ 192.168.1.100 (用户提供)
  [3.2] Ping 可达              ✅ 回复正常 (TTL=64)
  [3.3] 端口探测               ✅ 80/tcp HTTP 200 | 443/tcp refused


[4/4] 固件文件确认
  [4.1] old/ 降级固件         ✅ / ⚠️
  [4.2] new/ 当前固件         ✅ / ❌
  [4.3] 篡改固件生成           ✅ / ❌

=== 结果: 全部已检查项通过 ✅ ===
```

失败时用 `❌`，通过用 `✅`，未配置用 `⏭️`。Community 版用 `⚠️` 标注。

失败时附加修复建议：
```
⚠️  问题 & 建议:
  - burp: 端口 9876 未监听 — 请启动 Burp Suite MCP Server
  - nmap: 未找到 — 请确认 ${TOOL.NMAP} 存在
  - sqlmap: icmpsh_m 模块缺失 — 非阻塞，核心功能正常
  - 目标 192.168.1.100: 端口全部 filtered — 检查防火墙或目标是否在线
```
