# M1 auth_diff 越权检测 — 脚本化工作流

> ETSI TS 103701 条款 **5.5-5（越权防护）** 功能性测试。结果复用于 **5.5-4（未认证访问）**、**5.13-1（输入端点认证）**。
> 5.5-5-2 裁决模型：A (API 越权) + B (前端加密) + 端口登记。本流程产出**证据 A**。

## 脚本速查

> 路径: `${DIR.SKILLS}/etsi-ts103701-report/scripts/`

| 脚本 | 用途 | 阶段 |
|------|------|:---:|
| `auth_request_lint.py` | auth_diff 请求硬检查 (CRLF/header泄漏/双头) | B |
| `auth_error_decider.py` | MCP 错误 → KB 签名匹配 → 决策指令 | 任意 |
| `auth_verdict_decider.py` | auth_diff 响应 → 裁决矩阵 | C/E |
| `auth_orchestrator.py endpoints` | sitemap 过滤去重 → 端点列表 | D |
| `auth_orchestrator.py verdict` | 批量结果汇总 → 整体裁决 | E |

**铁律**: 每阶段脚本 exit != 0 → 禁止进入下一阶段。MCP 调用失败 → 先跑 `auth_error_decider.py` 再决策。

---

## 阶段 A: 取认证头（proxy_latest_auth 一步法）

> 替代旧的两步法 session_ensure.py（已废弃）。一步从 Burp proxy history 拿最新有效认证头。

```
mcp__burp__proxy_latest_auth{host:<DUT_IP>}
  → status:"ok" + tokens{cookie, session_tag, authorization} + auth_headers_detected + auth_headers
    + verify{valid:true}（live GET 已验有效）→ 用返回 tokens 继续
  → status:"expired"/"no_auth"/"no_traffic" → 提示用户经 Burp 代理刷新 DUT 页面后重调
  凭据刷新不计入 retry 次数
```

换认证头名的设备（如 X-API-Key）也能被启发式发现：`auth_headers_detected` 列出头名，`auth_headers` 给全量名值。

## 阶段 B: 请求构造 + lint

```
4. 用阶段 A 输出的 token 构造请求 JSON:
   {
     "request": "GET {endpoint} HTTP/1.1\r\nHost: {dut_ip}\r\nSessionTag: {stag}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
     "auth_levels": [{"name":"admin","headers":[{"name":"Cookie","value":"{cookie}"},{"name":"SessionTag","value":"{stag}"}]},{"name":"none"}],
     "device_hint": "isapi"
   }

5. 强制 lint:
   echo '<JSON>' | python scripts/auth_request_lint.py --stdin
   PASS → 阶段 C。FAIL → 按 fix 修 → 重新 lint。
```

## 阶段 C: 预检

```
6. 用 lint PASS 的参数发 auth_diff:
   mcp__burp__auth_diff(...) → 保存到 {workspace}/auth_precheck.json

7. 裁决:
   python scripts/auth_verdict_decider.py {workspace}/auth_precheck.json
   PASS → 阶段 D。其他 → 回阶段 A。
```

## 阶段 D: 全量端点

```
8. 收集 API 端点 (sitemap_query 不递归，需逐前缀查询):
   方式 A (推荐): 从 proxy_history 提取 API 目录前缀
     → 提取所有非静态 200 响应的 URL 路径 → 取第一段目录名 → 去重
   方式 B (fallback): 尝试常见前缀
     → /ISAPI/, /SDK/, /api/, /rest/, /v1/, /codebase/
   → 逐前缀 sitemap_query → 合并到 {workspace}/sitemap_all.json

9. 端点过滤:
   python scripts/auth_orchestrator.py endpoints {workspace}/sitemap_all.json

10. 逐端点 auth_diff (用阶段 B 的模板，仅替换路径):
    结果追加到 {workspace}/auth_results.jsonl
    每批 ≤10 个。连续 5 超时 → 停止，剩余标 INCONCLUSIVE。
    任何失败 → python scripts/auth_error_decider.py burp_mcp "<错误>" → 按决策执行。
```

## 阶段 E: 批量裁决

```
11. python scripts/auth_orchestrator.py verdict {workspace}/auth_results.json
    → overall_verdict + stats + fail_details

12. 写入 evidence JSON 的 5.5-5 条款。
```

---

## 裁决矩阵

> `auth_verdict_decider.py` 内置，无需手动判断。

| admin | none | 相似度 | 裁决 |
|:---:|:---:|:---:|:---:|
| 200 | 401/403 | — | PASS |
| 200 | 302→/login | — | PASS |
| 200 | 200 | <50% | PASS |
| 200 | 200 | >80% | FAIL |
| 200 | 200 | 50-80% | SUSPICIOUS |
| ≠200 | — | — | SKIP |

---

## 错误处理

不查文档，跑脚本:
```bash
python scripts/auth_error_decider.py <tool_name> "<error_text>"
```
自动匹配 `tool-error-kb.json` 签名 → 输出决策。常见:

| 签名 | 脚本给的修复 |
|------|------------|
| `AUTH_DIFF_CRLF_TIMEOUT` | `\n` → `\r\n` |
| `AUTH_DIFF_LEAKS_ORIGINAL_AUTH` | 删 base request 中的 Cookie |
| `AUTH_DUAL_HEADER_REQUIRED` | SessionTag 放 base request |
| `AUTH_TOKEN_PAIR_MISMATCH` | 同帧取 Cookie+SessionTag（proxy_latest_auth 保证同帧，不应再出现） |
| `AUTH_SESSION_EXPIRED` | 重调 proxy_latest_auth{host} 一步刷新（verify.valid=true 后重试；status=expired/no_auth → 提示用户经 Burp 代理刷新 DUT 页面）。凭据刷新不计入 retry 次数 |

## 单用户退化

仅一个 admin 账户: auth_levels 仅 admin + none。证据注明: `⚠️ 仅单用户可用，跨角色 IDOR 不可测`。

## 证据输出

5.5-5-2: 端点总数 + PASS/FAIL 统计 + FAIL 详情(路径/状态码/相似度) + 引用 `auth_results.json` 和 `sitemap_all.json`。
