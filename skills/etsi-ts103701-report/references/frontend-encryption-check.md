# 前端加密验证（playwright MCP）

> 用于 ETSI TS 103701 条款 **5.1-3（口令传输加密）** 和 **5.5-1（通信加密）** 的前端实现验证。
> 目的：判断登录/通信请求里密码或敏感字段提交时是**明文 / 可逆密文 / 不可逆摘要**，并定位前端加密函数与 IXIT 声明比对。
> 依赖：`playwright` MCP（`npx @playwright/mcp@latest --browser msedge --isolated`）。

## 工具名映射（重要）

playwright MCP 的工具名统一为 `mcp__playwright__browser_<action>` 格式：

| 用途 | 实际 MCP 工具 | 参数要点 |
|------|-------------|---------|
| 列出标签页 | `browser_tabs` | `action: "list"` |
| 导航 | `browser_navigate` | `url: "http://..."` |
| 截图存档 | `browser_take_screenshot` | `type: "png"`, `filename` 可选 |
| 拿 DOM 树 (a11y) | `browser_snapshot` | 返回 `ref=fXeY` 格式的元素引用 |
| 填单个字段 | `browser_type` | `target: "[ref=...]"`, `text: "..."` |
| 批量填表单 | `browser_fill_form` | `fields: [{target, name, type, value}]` |
| 点击 | `browser_click` | `target: "[ref=...]"`, `element: "描述"` |
| 列出网络请求 | `browser_network_requests` | `static: false`（过滤静态资源） |
| 取请求详情 | `browser_network_request` | `index: N`（1-based），`part: "request-body"` |
| 执行 JS | `browser_evaluate` | `function: "() => { ... }"` |
| 等待 | `browser_wait_for` | `time: N`（秒），或 `text: "..."` |
| 任意 Playwright 代码 | `browser_run_code_unsafe` | `code: "async (page) => { ... }"`（escape hatch） |

> ⚠️ 没有独立的 capture/stop 工具。`browser_network_requests` 自动记录自上次导航以来的所有请求。
> ⚠️ `browser_snapshot` 返回的 `ref=` 值是临时的（session-scoped），不要跨调用复用，每次操作前重新 snapshot。

## 已知坑

- `browser_snapshot` 返回的 `ref=fXeY` 值**每次 snapshot 会变**。填表或点击前必须先 snapshot 获取当前 ref，不要用之前保存的值。
- `browser_take_screenshot` 返回的图像当前模型无多模态读取能力，**判定靠 `browser_snapshot`（DOM 文本）+ `browser_network_request`（请求/响应文本），不靠截图内容**。截图仅作存档证据。
- `browser_fill_form` 一次填多个元素，比多次 `browser_type` 快且可靠，优先用。但 ref 必须在同一个 snapshot 中。
- 部分设备的登录是**两步 challenge-response**：先 GET 登录能力端点取 `salt`/`challenge`/`iterations`/`isIrreversible`，再 POST 登录端点提交摘要。要看两步才能判断算法。

## 8 步标准流程（playwright MCP）

按顺序执行，每步回报结果。哪步失败就停在哪步并报告。

1. **`browser_tabs`** (action=list) — 确认 MCP 连接正常。
2. **`browser_navigate`** (url=DUT 登录页) — 导航后 MCP 自动开始记录网络请求。
3. **`browser_take_screenshot`** — 存档登录页。
4. **`browser_snapshot`** — 拿 a11y 树，定位输入框 `ref=` 和登录按钮。
5. **`browser_fill_form`** — 填测试值（用户名 `test`，密码 `Test12345!`），fields 中的 target 用步骤 4 的 ref。
6. **`browser_click`** — 点击登录按钮，target 用步骤 4 的 ref。
7. **`browser_network_requests`** (static=false) → **`browser_network_request`** (index=N, part="request-body") 取登录 POST 的 body。看密码字段：
   - 明文 → FAIL
   - 64 hex → SHA-256 摘要（不可逆）
   - 32 hex → MD5（弱算法，FAIL）
   - base64（含 `=`/`+`/`/`）→ 需进一步判定是否可逆
8. **`browser_evaluate`** 抓 JS 源码 grep 加密关键词：
    ```js
    async () => {
      const scripts = Array.from(document.scripts).map(s => s.src).filter(s => s && s.includes('/doc/js/'));
      const results = [];
      for (const url of scripts) {
        try {
          const r = await fetch(url, {cache:'force-cache'});
          const txt = await r.text();
          const hits = new Set();
          const m = txt.match(/encrypt|RSA|CryptoJS|btoa|MD5|SHA1|SHA-?256|AES|PBKDF|salt|challenge|sessionLogin|isIrreversible|iterations|digest|hexString|forge|sjcl|jsencrypt/gi);
          if (m) m.forEach(x => hits.add(x.toLowerCase()));
          if (hits.size === 0) continue;
          const snippets = [];
          const re = /(sessionLogin|isIrreversible|iterations|SHA-?256|hexString|CryptoJS|encodePwd|encrypt|salt|challenge|digest)/gi;
          let mm, count = 0;
          while ((mm = re.exec(txt)) !== null && count < 5) {
            snippets.push(txt.slice(Math.max(0, mm.index - 70), Math.min(txt.length, mm.index + 110)).replace(/\s+/g, ' '));
            count++;
          }
          results.push({ f: url.split('/').pop(), size: txt.length, hits: [...hits], snippets });
        } catch(e) {}
      }
      return results;
    }
    ```
    命中后对疑似加密函数（如 `encodePwd`）再 `browser_evaluate` 精确拿函数体确认算法。

## 判定逻辑

| 密码字段提交值特征 | 算法判定 | ETSI 裁决 |
|---|---|---|
| 明文（`test` / `Test12345!` 原样出现） | 无加密 | **FAIL**（5.1-3 / 5.5-1） |
| 32 hex | MD5 摘要 | **FAIL**（弱算法，不在 SOGIS 推荐列表） |
| base64 且 `atob()` 可还原为明文 | `btoa` 伪装加密 | **FAIL**（编码非加密） |
| 64 hex，结合 challenge/salt/iterations | SHA-256 不可逆挑战-响应 | **PASS**（前提：IXIT 声明一致 + 传输层 TLS） |
| 长 base64/二进制，JS 含 RSA 实现 | RSA 公钥加密 | 需看密钥长度（≥2048 bit）与 IXIT 一致 → PASS；RSA-512/1024 或与 IXIT 不一致 → FAIL |
| AES 密文，JS 含 AES 实现 | AES 对称加密 | 看模式（CBC/GCM）、密钥来源；前端硬编码密钥 → FAIL |

> **重要**：前端加密判定不能只看前端。前端"加密"可能被绕过（直接构造请求）。最终裁决需结合 **Burp MCP 重放**（后端是否接受绕过前端加密的明文/弱构造）+ **tshark 传输层**（是否 TLS）。三端一致才算 PASS。

## 两步 challenge-response 的匿名化示例

目标 `https://dut.example.test/portal/login`，工具链 10 步全程跑通。

**登录链路（两步）**：
1. GET `/ISAPI/Security/sessionLogin/capabilities?username=test&random=10780173` → 返回 XML：
   ```xml
   <SessionLoginCap version="2.0">
     <sessionID>...</sessionID>
     <challenge>165528821e2892d6e47365f8a628ebab</challenge>
     <iterations>100</iterations>
     <isIrreversible>true</isIrreversible>
     <salt>366e43db17908d26e39174f2f1a95dac78dd6a01df4a461cb6cc81eadbe07c85</salt>
     ...
   </SessionLoginCap>
   ```
2. POST `/ISAPI/Security/sessionLogin?timeStamp=...`（`content-type: application/x-www-form-urlencoded`），body：
   ```xml
   <SessionLogin><userName>test</userName><password>a38e8b66703a182680bdf6008dc951cc4e338bf60835cf72ced0c6d95ab44ce4</password><sessionID>...</sessionID>...</SessionLogin>
   ```
   - `<password>` = 64 hex = SHA-256 摘要，非明文非 base64。
   - 401 响应是因为 `test` 账号不存在（`retryLoginTime=4`），加密流程本身完整执行，不影响判定。

**算法定位**（`evaluate_script` 抓 JS 源码）：
- `encodePwd` 函数在 `com_cbf697a8_3feae759.5504cc4a.js`：
  ```js
  encodePwd(t, e, n) {  // t=password, e={userName,salt,challenge,iIterate,...}, n=isIrreversible
    var r = "";
    if (n) {            // 不可逆分支（本次 isIrreversible=true）
      r = this.sha256(e.userName + e.salt + t);          // r0
      r = this.sha256(r + e.challenge);                   // r1
      for (var i = 2; i < e.iIterate; i++) r = this.sha256(r);  // 迭代到共 100 次
    } else {            // 可逆分支
      r = this.sha256(t) + e.challenge;
      for (var o = 1; o < e.iIterate; o++) r = this.sha256(r);
    }
    return r;
  }
  ```
- 调用点：`com_771c94be_dd03631b.js` 的 `_sessionLogin()`、`com_cbf697a8_c751954b.js`。
- `sha256` 底层：`1099.72856b0a.js`（CryptoJS 风格，`r.SHA256=i._createHelper(u)`）。
- 同站并存但非登录主流程的加密模块：RSA（`com_cbf697a8_3feae759.js`、`forge`）、AES-CBC+PKCS7（`com_076e9c97.js`，含固定盐 `"AaBbCcDd1234!@#$"` 用于 key 派生）。

**结论**：5.1-3 前端实现 = SHA-256 不可逆挑战-响应摘要，迭代 100 次，密码从不以明文/可逆密文上链路。前端侧 PASS（最终裁决需补 tshark 传输层 TLS 验证 + Burp 重放确认后端不接受绕过构造）。

## playwright 不可用时的处理

playwright MCP 不可用（`PLAYWRIGHT_MCP_UNAVAILABLE`）时，**不允许降级为 Burp 密文格式分析或手工 DevTools 替代**。相关条款（5.1-3、5.5-1 及依赖它们的 5.5-4 加密项、5.5-5 证据B）标 **INCONCLUSIVE**，agent 必须 `report_to_main` 暂停主流程，playwright 就绪后再继续。

> 禁止用 Burp proxy_history 猜测密文替代 playwright 真实浏览器验证。前端加密是否与 IXIT 一致必须由浏览器真实执行判定。
