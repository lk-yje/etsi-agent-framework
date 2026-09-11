# Tier 3 编排下沉 · 进度与交接文档

> 生成：2026-08-17。本窗口上下文耗尽，此文件给下一个窗口做完整交接。
> **当前状态：阶段 (a) 已完成 ✅；阶段 (b) MCP 连通性全量拨测完成 ✅（139 工具矩阵见 §七）+ 启发式认证头冒烟验证完成 ✅（2026-08-17，Burp 重载新 jar 后实测 X-API-Key 识别成功，见 §五 schema）；阶段 (c) KB 对齐完成 ✅（2026-08-17）；proxy_latest_auth 认证头启发式扫描增强已完成并通过 Burp 重载验证（见 §五 schema）。**

---

## 一、项目全局（三件套）

ETSI TS 103 701 合规检测（5.5-4 / 5.5-5 授权与越权检测）= 两个组件协作：

1. **framework**（本工作区 `d:\HIKvision\etsi-agent-framework-master`，git 仓库）— Python 编排 + Claude agent，经 MCP 调 Burp 工具
2. **BurpMCP-Ultra 2.0.1**（`D:\Penetration tools\BurpMCP-Ultra-2.0.1`，**非 git 仓库**）— Kotlin 扩展，把 Burp 暴露为 MCP 工具（Montoya API 2026.2，Kotlin 2.1.20，JVM 17）

**Tier 3 全局目标**：把认证编排逻辑（凭据提取、端点收集、逐端点对比、裁决矩阵）从 Python 下沉进扩展 → 聚合工具 + 单次调用 + 判定可独立驱动、可复用。

**已批准工具面**：2 新工具（`proxy_latest_auth`、`auth_scan_endpoints`）+ `auth_diff` 增强 + `proxy_history` 加 `max_results` 别名。

**用户拍板的分阶段交付**：
- **(a) 只改扩展源码（Kotlin）** ✅ 已完成
- **(b) 构建 + Burp 加载 + MCP 连通性验证** ← 下一步
- **(c) 连通正常后，按 pending-issues.md 对齐 tool-error-kb.json** ✅ 已完成（2026-08-17）

---

## 二、当前进度（阶段 a — 已完成）

### 扩展侧改动（9 处 + 2 新文件，全部编译通过）

| 文件 | 改动 |
|---|---|
| `bridge/AnalysisBridge.kt` | **核心重构**：auth_diff 增强（多头注入 headers[] / 默认剥 base 认证头 / preserve_headers / device_hint isapi 双头校验 / CRLF+结构校验）+ `runAuthDiffCore` 三层拆分 + 裁决矩阵（零漂移镜像 apply_matrix）+ `findLatestAuthTokens`（**真频率分析**）+ `scanAuthEndpoints`（镜像 cmd_endpoints/cmd_verdict）+ 辅助方法（collectEndpoints/rewriteRequestLine/normalizeRequestCrlf/validateRequestStructure/extractPath/...） |
| `bridge/AuthValidationException.kt` | **新建**：结构化校验异常（`code`/`message`/`fix`） |
| `tools/authdiff/AuthDiffTools.kt` | 新参数透传（device_hint / preserve_headers）+ 描述更新 + AuthValidationException 结构化错误输出 |
| `tools/etsi/EtsiAuthTools.kt` | **新建**：注册 `proxy_latest_auth` + `auth_scan_endpoints`（getBurpApi 反射同 AuthDiffTools 模式） |
| `transport/ToolRegistry.kt` | import + `EtsiAuthTools.register(server, bridges)` + 计数注释 134→136 |
| `core/BurpMcpUltraExtension.kt` | 硬编码计数 137→139（L68 UI log / L75 output log） |
| `transport/McpServerManager.kt` | 注释计数 137→139 |
| `tools/proxy/ProxyTools.kt` | `proxy_history` 加 `max_results` 别名（`count` 优先，fallback `max_results`，默认 100） |
| `build.gradle.kts` | 未动（可选后续加 test 依赖） |
| `bridge/HttpBridge.kt` | **未动**（HEADER_DROPS rootCause 证伪，无需改） |

### framework 侧

- **新建** `skills/etsi-ts103701-report/references/pending-issues.md`：9 条已亲验病灶落盘，KB 对齐留 (c)。
- 其余脚本/文档/KB **一律未动**（阶段 a 约定）。

### 构建产物

- `gradlew.bat build` → **BUILD SUCCESSFUL**（JDK 21）
- fat jar：`build/libs/burpmcp-ultra-2.0.1.jar`（13,124,182 字节）+ 根目录复制件 `burpmcp-ultra.jar`（**Burp 加载用这个**）
- 编译告警仅 Montoya 弃用方法（host()/url()/path()/method()/port()/secure()），与现有 ProxyBridge 同款用法，**零功能影响**
- 注：build/libs 旧 jar 已被本次覆盖，无备份；如需回滚需改回源码重新 build

---

## 三、接下来要做的（阶段 b + c）

### 阶段 b：连通性验证（需用户操作 Burp）

1. Burp → Extensions → Add(Java) → 选 `D:\Penetration tools\BurpMCP-Ultra-2.0.1\burpmcp-ultra.jar`
2. Output 确认 `Tools registered: 139`
3. MCP client 连 `http://127.0.0.1:9877/mcp`（Streamable HTTP）或 `http://127.0.0.1:9876/sse`（SSE），`tools/list` 确认含 `proxy_latest_auth` / `auth_scan_endpoints`
4. **无 DUT 冒烟（关键，逐项验证）**：
   - `proxy_latest_auth{host:"127.0.0.1"}` → `{"status":"no_traffic",...}`，不抛异常
   - `auth_scan_endpoints{host:"127.0.0.1", request:..., auth_levels:...}` 空 sitemap → `total_endpoints_found:0` + `overall_verdict:"INCONCLUSIVE"`
   - `auth_diff` 传缺 Host 的 request → isError + `AUTH_DIFF_STRUCTURE` + `fix`
   - `auth_diff` 传 `header_name` 无 `header_value` → `AUTH_DIFF_HEADER_VALUE_MISSING`（验证 no-op bug 修复）
   - `proxy_history{host:"x", max_results:1}` → 正常返回（别名生效）
5. 有 DUT 冒烟：本地 `python -m http.server` 经 Burp，用同一 proxy 帧的 Cookie+SessionTag 双 token 打两条 → 验证同框、responses/verdict 正确

### 阶段 c：KB 对齐（连通验证通过后）— ✅ 已完成（2026-08-17）

按 `pending-issues.md` 逐条改写 `skills/etsi-ts103701-report/references/tool-error-kb.json`（均已执行）：

| 条目 | 处置 |
|---|---|
| HTTP_SEND_REQUEST_DROPS_HEADERS | rootCause **证伪** → 重写为「双头认证配对/令牌过期」 |
| BURP_PROXY_HISTORY_OVERFLOW | 真根因=参数名不匹配（**已修**）→ 重写根因 |
| AUTH_SESSION_EXPIRED | 频率分析**已真实现** → 更新 |
| AUTH_DUAL_HEADER_REQUIRED | **已解决**（isapi 双头校验）→ 标 resolved |
| AUTH_DIFF_LEAKS_ORIGINAL_AUTH | **已解决**（默认剥 base 认证头）→ 标 resolved |
| AUTH_DIFF_CRLF_TIMEOUT | **已解决**（CRLF 规范化）→ 标 resolved |
| device_hint 静默忽略 | **已真参数化** → 更新文档/KB |
| 302 裁决信号增强 | Location 头优先 + body 兜底（**有意偏差**）→ 确认是否反向同步 Python |

---

## 四、关键技术事实（新窗口零重读）

### 工具注册链

```
BurpMcpUltraExtension.kt → McpServerManager.createMcpServer() → ToolRegistry.registerAll()
    → AuthDiffTools.register(server, bridges)   # 原有
    → EtsiAuthTools.register(server, bridges)   # 新增，在 ApiImportTools 之前
```

### getBurpApi 反射（工具层拿 MontoyaApi，两种 tool 同模式）

```kotlin
private fun getBurpApi(bridges: BridgeFactory.Bridges): burp.api.montoya.MontoyaApi {
    val field = bridges.burpSuite.javaClass.getDeclaredField("api")
    field.isAccessible = true
    return field.get(bridges.burpSuite) as burp.api.montoya.MontoyaApi
}
```

### 裁决矩阵（apply_matrix，零漂移镜像；阈值别改）

```
admin ∉ {200,201,204}                                    → SKIP
admin=200 + none∈{401,403}                               → PASS
admin=200 + none=302 + Location/body 含 login/signin/auth/unauthorized → PASS
admin=200 + none=302 + 不明确                            → SUSPICIOUS
admin=200 + none=200 + findings 含 "identical"           → FAIL (IDOR)
admin=200 + none=200 + sim < 50%                         → PASS
admin=200 + none=200 + sim > 80%                         → FAIL (MissingAuth)
admin=200 + none=200 + sim 50-80%                        → SUSPICIOUS
admin=200 + none=其他                                    → SUSPICIOUS
```

相似度 = differences 里**第一个** `body_content` 的 `similarity_percent`（Python parse_auth_diff_output 同规则）。

### auth_diff 输出 schema（原字段 + 新增）

```
auth_levels_tested, responses[{level,status_code,body_length,response_time_ms,body_preview}],
differences[{level_a,level_b,differences[]}], findings[], all_same_status, all_same_body,
errors?,
verdict{verdict,confidence,reason,matrix_rule,details{admin_status,none_status,body_similarity,
  none_body_preview,burp_findings,all_same_status,all_same_body,admin_body_length,none_body_length}},
auth_headers_stripped[], lint{result,checks[{check,result,note?}]}
```

### 新工具输出 schema

- **proxy_latest_auth**：
  `{status: ok|expired|no_traffic|no_auth, tokens{cookie,session_tag,authorization}, auth_headers_detected[...], auth_headers{name→value}, source{index,timestamp,status_code,path,method,port,secure,path_frequency,frames_scanned}, endpoint, frequency[{path,count}], verify{performed,status_code,valid,url}}`
  - **2026-08-17 增强（已编译+打包 burpmcp-ultra.jar）**：认证头识别从固定三类（Cookie/SessionTag/Authorization）扩为「三类 + 启发式疑似认证头」（头名含 token/apikey/api_key/api-key/auth/session/credential/secret 且值非空，如 X-API-Key/X-Auth-Token/Token）。新增 `auth_headers_detected`（识别到的头名清单）+ `auth_headers`（完整 名→值 字典），verify 带全量认证头打 live GET——换认证头名的设备不再静默 no_auth，agent 可直接拿 auth_headers 拼 auth_levels。改动：AnalysisBridge.kt `extractAuthHeaders`/`isLikelyAuthHeader`/`findAuthValue`/`verifyTokens`/`findLatestAuthTokens` 输出 + EtsiAuthTools.kt 描述。
  - **2026-08-17 冒烟验证（Burp 重载新 jar 后实测，通过 ✅）**：本地 `python -m http.server 8123` 走 Burp:8080，三类流量各验证：
    1. **X-API-Key 启发式识别**：3× `X-API-Key: smoke-test-key-abc123` → `{"status":"ok","auth_headers_detected":["X-API-Key"],"auth_headers":{"X-API-Key":"smoke-test-key-abc123"},"verify":{"performed":true,"status_code":200,"valid":true}}` —— **换认证头名设备不再静默 no_auth**。
    2. **已知头回归**：带 `Cookie` 流量 → `auth_headers_detected:["Cookie"]`，`tokens.cookie` 正确提取。
    3. **no_traffic 边界**：不存在 host → `{"status":"no_traffic"}`,不抛异常。
    - 频率分析验证：路径计数取最高频（`/`×3 胜），无认证头帧被跳过；复跑脚本 `scratch/smoke_proxy_latest_auth.py`（`python311` 运行，mcp 2.0.0 SDK）。
- **auth_scan_endpoints**：
  `{overall_verdict: PASS|FAIL|INCONCLUSIVE, summary, stats{PASS,FAIL,SUSPICIOUS,SKIP,INCONCLUSIVE,ERROR}, total, effective, total_endpoints_found, sampled_endpoints, dropped, drop_note, results[{seq,method,endpoint,verdict,confidence,reason,auth_diff_result}], fail_details[]?}`

### Python 参考实现（镜像对象，字段/阈值以此为准）

| 文件 | 内容 |
|---|---|
| `scripts/auth_verdict_decider.py` | apply_matrix L47-146；parse_auth_diff_output L149-190（**302 分支读 body_preview**，扩展版改 Location 头优先） |
| `scripts/auth_token_discovery.py` | find_best_token L65-97（**频率分析原本虚构**，proxy_latest_auth 真实现） |
| `scripts/auth_orchestrator.py` | cmd_endpoints L76-188（STATIC_EXTS/EXCLUDE_PATH_KW/HIGH_RISK_KW 过滤、(method,path) 去重、写>GET+high_risk>GET>other 排序、max 50 采样）；cmd_verdict L191-273（FAIL>0→FAIL, suspicious>0→INCONCLUSIVE, PASS==0→INCONCLUSIVE, else PASS; effective=total-SKIP-ERROR） |

### KB 现有条目（tool-error-kb.json，2026-08-17 已按阶段 c 对齐：9 条处置 + 4 实测 bug）

`HTTP_SEND_REQUEST_DROPS_HEADERS`[rootCause 证伪] · `BURP_PROXY_HISTORY_OVERFLOW`[真根因=参数名] · `AUTH_DUAL_HEADER_REQUIRED` · `AUTH_DIFF_LEAKS_ORIGINAL_AUTH` · `AUTH_DIFF_CRLF_TIMEOUT` · `AUTH_SESSION_EXPIRED`

### Montoya API 关键点

- `sendRequest` 无 timeout 重载 → `RequestOptions.requestOptions().withResponseTimeout(ms)`；import `burp.api.montoya.http.RequestOptions`
- proxy history：`api.proxy().history(ProxyHistoryFilter { item -> item.host().contains(host, true) })`；`item` 有 `id()/host()/port()/secure()/method()/url()/path()/time()/request()/response()/hasResponse()`
- sitemap：`api.siteMap().requestResponses(SiteMapFilter.prefixFilter(urlPrefix))`；`entry.request()?.url()`、`entry.response()?.statusCode()?.toInt()`
- 响应头 map：`resp?.headers()?.associate { it.name() to it.value() }`
- body：`resp?.body()?.length()`（Montoya ByteArray 有 length()）、`resp?.bodyToString()`
- `item.time()` 返回 `ZonedDateTime` → `item.time()?.toInstant()?.epochSecond`
- ISAPI 双头认证：Cookie（WebSession_xxx）+ SessionTag 必须**同 proxy 帧**提取，缺一 → AUTH_TOKEN_PAIR_MISMATCH

---

## 五、环境与构建命令

- **JDK 21**：`C:\Program Files\Java\jdk-21`。注意 **git-bash 默认 PATH 是 Java 8**，每次构建必须显式设：
```bash
cd "/d/Penetration tools/BurpMCP-Ultra-2.0.1"
export JAVA_HOME='C:\Program Files\Java\jdk-21'
export PATH="/c/Program Files/Java/jdk-21/bin:$PATH"
./gradlew.bat build                        # 编译 + shadowJar
cp -f build/libs/burpmcp-ultra-2.0.1.jar burpmcp-ultra.jar   # Burp 加载用根目录件
```
- **扩展仓库非 git**：编辑不可回滚，改前先 Read 目标文件；大改前备份 build/libs jar。
- Gradle 首次构建需下载依赖（数分钟），daemon 已起，后续快。

---

## 六、账本 / 未结项

| 项 | 状态 |
|---|---|
| 阶段 (a) 全部源码改动 + 编译 | ✅ 完成 |
| 阶段 (b) MCP 连通验证（139 工具全量拨测） | ✅ 完成（矩阵见 §七） |
| 阶段 (b) 启发式认证头冒烟（本地服务走 Burp，X-API-Key/Cookie/no_traffic 三用例） | ✅ 完成（2026-08-17，实测见 §五 schema；复跑脚本 `scratch/smoke_proxy_latest_auth.py`） |
| 阶段 (b) 有 DUT 冒烟（真实设备，双 token 打两条） | ⬜ 待真 DUT（可选，本机模拟已覆盖核心路径） |
| 新发现 bug 4 处（§七·四）→ 阶段 (c) 纳入 KB | ✅ 完成（已作为 4 条新 entry 加入 tool-error-kb.json：CONFIG_MATCH_REPLACE_ADD_SHADOW / CONFIG_PROXY_LISTENER_ADD_SHADOW / COOKIE_JAR_SET_DOMAIN_PATH_SWAP / SCANNER_CREATE_ISSUE_SHADOW） |
| 阶段 (c) KB 对齐（pending-issues 9 条 + 4 实测 bug） | ✅ 完成（2026-08-17，见 §五阶段c表） |
| 可选：加 test 依赖，单测 parseAuthLevels / extractPath / decideVerdict 全矩阵(9 条) / collectEndpoints | ⬜ 可选 |

**给新窗口的起点**：`pending-issues.md` 是 (c) 对齐的依据；`burpmcp-ultra.jar` 已就位；139 工具连通性矩阵与残留物清单见 §七。

---

## 七、139 工具连通性矩阵（2026-08-17 全量实测存档）

> 环境：**BurpMCP-Ultra 2.0.1 × Burp Community 2026.4.3（CE，build 47818）**，MCP SSE `http://127.0.0.1:9876`。
> 图例：✅ 可用 · ⚠️ bug/异常行为 · ❌ Pro 门控 · 🔸 可调用但 CE 惰性（工具跑通、无实际功能）· ⏭ 跳过（破坏性/不可逆，未测）。
> 总账：**111 ✅ · 4 ⚠️ · 10 ❌ · 8 🔸 · 6 ⏭ = 139**。
> 关键结论：**Tier3 关键路径（auth_diff / auth_scan_endpoints / proxy_latest_auth）CE 下全通，不依赖 Pro API**。
> **框架侧工具名一致性审计（2026-08-17，见 §八）**：全部工具名与 139 注册名一致，无需改名；但发现 3 处参数/行为级不一致并已修复。

### 一、Tier3 新工具（关键路径）— 全 ✅

| 工具 | 实测 |
|---|---|
| `proxy_latest_auth` | ✅ `{"status":"no_traffic",...}`，真频率分析路径无异常 |
| `auth_scan_endpoints` | ✅ 空 sitemap → `total_endpoints_found:0` + `overall_verdict:"INCONCLUSIVE"` |
| `auth_diff` | ✅ 缺 Host → isError `AUTH_DIFF_STRUCTURE`+`fix`；缺 header_value → `AUTH_DIFF_HEADER_VALUE_MISSING`（no-op 修复生效） |
| `proxy_history`(+max_results 别名) | ✅ 别名 `max_results:1` 生效 |

### 二、analyze / HTTP 核心 — 全 ✅

`analyze_request` `analyze_response` `analyze_diff` `analyze_extract_params` `analyze_find_reflected` `analyze_insertion_points` `analyze_response_body_search`（7）· `http_send_request` `http_send_request_chain` `http_send_raw_bytes` `http_send_requests_parallel` `repeater_send` `passive_intel` `http_analyze_keywords` `http_analyze_variations` `http_list_traffic_rules` `http_set_traffic_rule` `http_remove_traffic_rule`（11）· `intruder_send` `intruder_send_with_positions` `intruder_register_payload_processor`（3）

### 三、项目 / 配置 / 状态 — 全 ✅

`burp_version` `burp_command_line_args` `burp_export_project_config` `burp_export_user_config` `burp_import_project_config` `burp_import_user_config` `burp_task_engine_set` `burp_task_engine_state` `project_info` `extension_info` `ai_status`（enabled:false）· `scope_check` `scope_get_config` `scope_include` `scope_exclude`（scope 往返干净）· `session_create_token_rule` `session_list_rules` `session_remove_rule` · `persistence_store` `persistence_list` `persistence_get` `persistence_delete`（往返干净）· `preference_get` `preference_store`（⚠️ 残留：无删除工具）· `events_get` `events_get_by_type` `events_subscribe` `events_unsubscribe`（往返干净）· `log_event` `log_message` · `decoder_send` `comparer_send` · `bambda_import`（CE 可导入）

### 四、⚠️ bug（写入声称成功、读回不一致 — 阶段 (c) 纳入 pending-issues.md）

| 工具 | 实测证据 | 判断 |
|---|---|---|
| `config_match_replace_add` | add 返回 `total_rules:13`，`config_match_replace_list`/`burp_export_project_config(proxy.match_replace_rules)` 仍 12 条；remove(12) 报 Invalid index | **影子计数器，add 写内存副本未持久化** |
| `config_proxy_listener_add` | add 返回 `total_listeners:2`，`config_proxy_listeners_list` 仍 1（8080）；remove(127.0.0.1:18099) 报 No listener | **同上** |
| `http_cookie_jar_set` | set 报 `cookie_set:true`，cookie 确实入 jar，但 **domain/path 字段错位**（真实域名跑进 path、domain 显示 "/"），按 domain 过滤读不回 | **字段映射 bug（set 或 get 序列化交换 domain/path）** |
| `scanner_create_issue` | 报 `created:true`，但 `sitemap_get_issues`/`scanner_get_all_issues` 均读不回 | **影子存储或写入非 Burp sitemap** |

对照组：`http_set_traffic_rule`/`http_remove_traffic_rule` 往返干净、`scope_include`/`scope_exclude` 往返干净、`persistence_*` 往返干净 → 扩展自有存储正常，**坏的是走 Burp config API 的那几个 add 工具**。

### 五、❌ Pro 门控（10）

`ai_prompt` · `bcheck_create` · `bcheck_import` · `scanner_start_audit` · `scanner_start_crawl` · `scanner_import_bcheck` · `http_fuzz`（超时）· `http_race`（超时）· `collaborator_create_client`（CE 下 CollaboratorClient API 返回 null → NPE）· `collaborator_restore_client`（同上）

### 六、🔸 CE 可达但惰性（8）

| 工具 | 说明 |
|---|---|
| `scanner_task_status` `scanner_task_add_request` `scanner_task_issues` `scanner_task_delete` | 全部执行并返回结构化 `Task not found`，但 CE 无法创建扫描任务（start_audit/crawl 是 Pro），task 仓永远空 → 惰性 |
| `collaborator_generate_payload` `collaborator_poll` `collaborator_server_info` `collaborator_get_secret` | 执行正常，但 client 仓永远空（CE 建不了 client）→ 惰性 |

### 七、⏭ 跳过（破坏性/不可逆，未测）

`burp_shutdown`（杀 Burp）· `events_clear`（清空事件缓冲不可逆）· `config_upstream_proxy_set`（**已实测为 no-op**：导入顶层 `upstream_proxy` 键，Burp 真实路径是 `project_options.connections.upstream_proxy.servers`，`importProjectOptionsFromJson` 按精确键合并 → 顶层键无对应 → 静默丢弃，servers 恒为 `[]`；正确配置/清除走 `burp_import_project_config`）· `websocket_close`（会断用户活动连接）· `websocket_send_binary` / `websocket_send_text`（往用户活动连接灌数据）

### 八、工具组已测清单（✅ 确认可用，明细）

- **bcheck/scancheck**：`bcheck_templates` `bcheck_list` `bcheck_remove`（not-found 路径）✅；`scancheck_templates` `scancheck_list` `scancheck_create_passive` `scancheck_create_active` `scancheck_remove` ✅
- **scanner/sitemap 读**：`scanner_get_all_issues` `scanner_generate_report` `scanner_register_check` `scanner_task_list` `sitemap_query` `sitemap_add_request` `sitemap_add_issue` `sitemap_get_issues` ✅
- **proxy**：`proxy_history` `proxy_history_search` `proxy_annotate`（空 history 报 not-found）`proxy_auto_auth`（+`proxy_remove_rule` 可撤销）`proxy_intercept_status` `proxy_intercept_enable` `proxy_intercept_disable`（往返恢复）`proxy_list_rules` `proxy_remove_rule` `proxy_set_request_rule` `proxy_set_response_rule`（tag 规则往返干净）`proxy_websocket_history` `proxy_websocket_history_search` ✅
- **websocket**：`websocket_list` `websocket_create`（死端点报预期错）`websocket_get_messages`（not-found）`websocket_set_intercept_rule`（disabled 惰性规则，无 remove 工具）✅
- **util（13）**：`util_base64_encode` `util_base64_decode` `util_compress` `util_decompress` `util_decode_smart` `util_hash` `util_html_encode` `util_jwt_decode` `util_random_bytes` `util_random_string` `util_shell_execute`（⚠️ 需可执行文件全路径+args，`echo` 内建会 CreateProcess error 2）`util_url_decode` `util_url_encode` ✅
- **api**：`api_import_openapi` ✅（⚠️ 自动加 scope include + sitemap，有残留）

### 九、实测残留物清单（无法自动清理，需用户手动）

1. sitemap 条目：`http://127.0.0.1/tier3-smoke`（`sitemap_add_request`）
2. sitemap 自定义 issue ×2：`tier3-sweep-issue`（`scanner_create_issue`）、`sitemap_add_issue` 建的同名 issue
3. organizer 条目：`GET /tier3-smoke`（`organizer_send`）
4. scope include：`http://127.0.0.1:1/`（`api_import_openapi` 自动加）；scope exclude：`http://127.0.0.1/tier3-scope-test`（本次测试，可留可删）
5. 报告文件：系统临时目录中的 `tier3-smoke-report.html`
6. cookie jar：`tier3_test_cookie`（127.0.0.1）、`bug_cookie`（bug.test）——无删除工具，无害残留
7. preference：`tier3_sweep_test`=ok——无删除工具，无害残留
8. websocket 拦截规则：`tier3-ws-rule`（enabled:false，惰性）
9. Intruder tab：`tier3-sweep`；decoder/comparer tab（无害）

---

## 八、框架侧工具名一致性审计（2026-08-17）

> 范围：`framework/` + `pipelines/` + `scripts/` + `skills/` 中全部 burp MCP 工具名/参数引用，对照 §七 实测的 139 注册名。

### 结论：工具名全部一致 ✅，无需改名

- framework 内部走 `MCPClientManager.call_tool()` / `ToolRegistry`，用 **MCP 原生名**（tools/list 动态发现，无前缀）——正确。
- scripts / skills 产出 `mcp__burp__<name>` 指令——`mcp__burp__` 是 Claude Code 命名空间前缀（server 名 `burp`），供外部 runtime 消费，正确。
- 引用的工具名（auth_diff / http_fuzz / proxy_history / proxy_websocket_history / websocket_list / websocket_get_messages / burp_export_project_config / burp_import_project_config / burp_version / proxy_history_search / sitemap_query / repeater_send / intruder_send / config_upstream_proxy_set / http_send_request）**全部存在于 139 注册名中**，无一错名。

### 但发现 3 处参数/行为级不一致（均已修复）

| # | 位置 | 问题 | 修复 |
|---|---|---|---|
| 1 | `scripts/firmware_traffic_verify.py` step2、`scripts/tls_downgrade_test.py` step4 | `proxy_websocket_history` 只认 `start_index`/`count`，**不读 `max_results`**（ProxyTools.kt L111-112）→ 传 `max_results:20` 被静默忽略、count 落回默认 100 → "max_results≤20 防超时" 失效 | 参数改 `count:20` + 注释说明 |
| 2 | `pipelines/etsi/pipeline.py` `_configure_burp_upstream` | 用 `config_upstream_proxy_set`（**实测 no-op**）→ Burp→xray 上游从未生效；且传 `enabled`（扩展不读）、`destination_host:".*"`（glob 匹配不到任何主机） | 改用 `burp_import_project_config` 走 `project_options.connections.upstream_proxy`，`destination_host:"*"`，配置前导出原上游备份 |
| 3 | `pipelines/etsi/pipeline.py` `_remove_burp_upstream` | 原用 `config_upstream_proxy_set(host:"", port:0)` 想"清空" → 因 no-op 实际没做任何事；若工具将来修好，这会让 servers 变成一条 enabled 空上游、弄断用户 Burp | 改为恢复 configure 时备份的原配置（无备份则 `servers:[]`） |
| 4 | `scripts/tls_downgrade_test.py` `TLS_DOWNGRADE_CONFIG` | 模板用 `proxy.tls_protocols` / `proxy.http2`（Burp 配置**无此字段**，import 静默丢弃 = no-op，同 upstream 病灶）；而 clause_tool_map.json 5.3-2 写的正确字段是 `custom_tls_protocols` + `enable_http2` | 模板改为 listener 真实字段：`listener_port:8080` + `use_custom_tls_protocols:true` + `custom_tls_protocols:["TLSv1","TLSv1.1"]` + `enable_http2:false` |

### 关键实测证据（config_upstream_proxy_set 是 no-op）

1. `config_upstream_proxy_set(host:"127.0.0.1", port:7778, destination_host:"test.nonexistent.invalid")` → 返回 `{"status":"configured",...}`
2. `burp_export_project_config(paths:["project_options.connections.upstream_proxy"])` → `servers:[]`（**没生效**）
3. `burp_import_project_config({"project_options":{"connections":{"upstream_proxy":{"servers":[{...}]}}}})` → 导出确认 servers 出现条目（**正确路径生效**）
4. 已用 `servers:[]` 清空恢复，用户 Burp 配置原样（was `[]`，now `[]`）

### 遗留（未改，仅记录）

- **扩展 input_schema 全空**：`tools/list` 返回 `input_schema:{"type":"object"}`（无 properties）。框架 `MCPToolAdapter._mcp_to_tooldef` 据此构建 **零参数 ToolDef** → 框架 agent 拿到工具名+描述但无参数 schema，只能靠描述猜参数（Claude Code 同样如此，靠描述即可用）。建议后续：framework 侧为 clause 用到的 burp 工具加一份硬编码参数 schema，或扩展侧 addTool 补齐 input_schema。
- **`http_fuzz` Pro 门控**：`sqli_probe.py` / `dir_brute_force.py` / `login_lockout_probe.py` 三个脚本依赖 `http_fuzz`（名字/参数都正确），但 CE 下 `http_fuzz` 超时（Pro 功能）→ 这些脚本的指令在 CE 下会失败，需 Pro 环境。
- **pipeline 原始 HTTP fallback**：POST 到 `http://{host}:{port}/tools/call`（非 MCP 协议端点），从未可用，保留为 best-effort 意图。
