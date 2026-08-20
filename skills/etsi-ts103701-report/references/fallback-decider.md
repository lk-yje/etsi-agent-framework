# LlmFallbackDecider：工具错误降级决策器

> 当 Mx agent 的工具调用失败时，不是简单重试——而是执行一个结构化的降级决策流程：识别错误签名 → 检索 ToolErrorKnowledgeBase → 做出决策 → 记录到 executionTrace。

## 决策流程

```
工具调用失败
    │
    ├──→ 1. 错误分类
    │       提取 error.signature: 匹配已知模式 OR 新错误
    │
    ├──→ 2. 知识库检索
    │       Read tool-error-kb.json → entries[tool].errors[signature]
    │       命中 → 执行条目中的 decision
    │       未命中 → 进入通用决策树
    │
    └──→ 3. 执行决策
            ├── retry              → 同工具，调整参数，最多 1 次
            ├── retry_different_params → 换参数重试，最多 1 次
            ├── fallback_alternative_tool → 切换到替代工具
            ├── degrade_semiauto   → 退化到手工分析，证据级别 L3
            ├── skip_with_inconclusive → 条款标 INCONCLUSIVE
            ├── ignore_noncritical → 忽略，继续执行
            └── report_to_main     → 暂停，等待主线程指令
```

## ⚠️ 已知未解决问题

### AUTH_SESSION_COOKIE_MISMATCH (待解决)

**现象**：Burp MCP `auth_diff` 测试时，已通过浏览器登录 DUT，proxy_history 中可见完整认证流量，但 agent 从 proxy_history 提取 Cookie/SessionTag 后重放仍返回 401/403。

**当前临时处理**：auth_diff 退化为手工模式——agent 提示用户在 Burp Repeater 中手工复制认证请求的完整 Cookie header，粘贴给 agent。证据级别降为 L3。

**根因猜测** (待验证)：
- Cookie 中包含动态 token (如 CSRF、timestamp nonce) 未一并提取
- 认证绑定 IP/User-Agent，重放时缺失
- Session 在 Burp 代理链中因某种原因未正确维持

**影响条款**：5.5-5 (越权)、5.5-4 (未认证访问)

> 🏷️ 待解决后更新本条 + tool-error-kb.json 中 `burp_mcp.AUTH_SESSION_COOKIE_MISMATCH` 条目。

## 通用决策树（知识库未命中时）

```
FOR each error:

1. 错误看起来是瞬态的还是永久的？
   ├── 超时/连接拒绝 (可能是瞬态) → retry (1 次)
   ├── 权限/配置/文件缺失 (永久) → 不重试，直接决策
   └── 不确定 → retry (1 次)，仍失败则视为永久

2. 工具是否对当前条款的裁决是必需的？
   ├── 是核心依赖 (如 M3 没有 tshark = 无法裁决) →
   │   ├── 有替代工具吗？ → fallback_alternative_tool
   │   └── 无替代工具 → skip_with_inconclusive
   └── 不是核心依赖 (如 passive_intel 只是补充) → degrade_semiauto

3. 同一工具是否已失败 2 次以上？
   ├── 是 → 停止重试，执行降级决策
   └── 否 → 允许重试
```

## 工具依赖等级（辅助判断"是否必需"）

| 等级 | 工具 | 依赖条款 | 无此工具影响 |
|:----:|------|---------|------------|
| 🔴 核心 | tshark (M3) | 5.5-1, 5.5-6, 5.5-7, 5.8-2 | M3 全部功能条款无法裁决 |
| 🔴 核心 | nmap | 5.6-1, 5.6-5, 5.5-5 (端口比对) | 攻击面无法量化 |
| 🟡 重要 | Burp MCP (M1, M2, M5) | 5.5-4, 5.5-5, 5.6-2, 5.13-1 | 可降级到 curl + 手工 |
| 🟡 重要 | sqlmap (M5) | 5.13-1 SQLi 子项 | dir_brute_force.py + http_fuzz 可部分覆盖 |
| 🔴 核心 | playwright MCP (M2) | 5.1-3, 5.5-1 前端加密 + 5.5-4 加密项 + 5.5-5 证据B + 5.2-1/5.8-3/5.12-3/6-1/6-5 文档访问 + 5.4-3/5.6-2 硬编码密钥 + 5.1-1/5.1-4/5.3-6/5.3-16 Web UI 交互 | playwright 不可用时 → report_to_main（暂停，不允许降级） |
| 🟢 补充 | xray (M5) | 5.13-1 被动扫描广度 | sqlmap + dir_brute_force.py 主动探测为主 |

## 决策记录格式

每次降级决策必须记录到 executionTrace：

```json
{
  "seq": N,
  "phase": "pivot",
  "summary": "<工具名> <错误简述>",
  "tool": "<工具名>",
  "finding": null,
  "clauseIds": ["<受影响条款>"],
  "durationSec": 0,
  "error": {
    "signature": "<ERROR_SIGNATURE>",
    "kb_lookup": "tool-error-kb.json → <tool> → <signature>",
    "kb_hit": true,
    "decision": "<retry|fallback_alternative_tool|degrade_semiauto|skip_with_inconclusive|report_to_main>",
    "fallback": "<具体降级措施>",
    "affectedClauses": ["<条款ID>"]
  }
}
```

知识库未命中时 (`kb_hit: false`)，走通用决策树，`decision` 字段注明推理链：

```
"decision": "degrade_semiauto (通用决策树: 非核心依赖 + 无替代工具)",
```

## 集成点

| 位置 | 内容 |
|------|------|
| fc-loop-spec.md §四 自检协议 | 「停滞检测」→ 查 ToolErrorKnowledgeBase |
| module-split.md agent prompt 模板 | preflight 失败时按本 decider 决策 |
| etsi-report-auditor skill (Step 1.5) | 三角对照时检查 pivot 决策是否合理 |

## 使用示范

agent 在遇到错误时：

```
1. 工具调用返回了错误 → 不要立即重试
2. 匹配错误签名 → 查 tool-error-kb.json
3. 找到对应条目 → 执行条目中的 decision
4. 没找到 → 按通用决策树推理 → 做出决策
5. 追加 pivot 步骤到 executionTrace.steps
6. 继续 FC-Loop，受影响条款在裁决时引用降级措施

禁止:
❌ 不做错误分析直接重试
❌ 重试 2 次以上 (除非 kb 明确要求)
❌ 降级后不记录到 executionTrace
❌ 用降级掩盖"懒得试替代工具"
```
