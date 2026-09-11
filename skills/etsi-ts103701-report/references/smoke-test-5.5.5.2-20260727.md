# 5.5-5-2 功能性冒烟测试报告

**目标**: 10.19.199.54 (海康 NVR DS-7608NXI-I2/VPro, V5.05.375, 前端 V5.1.69_R0102 build 251229)  
**时间**: 2026-07-27 16:06-17:07  
**结论**: ⚠️ **三证据链 (A+B+C) 全部可执行。证据 A 发现 3 个未认证可访问端点。**

---

## 证据 A — API 越权 (Burp MCP auth_diff)

**端点枚举**: 从 proxy_history 解析 73 条 10.19.199.54 条目，去重过滤得 10 个 API 端点。

**令牌获取**: `proxy_history_search` (pattern: `sessionHeartbeat`) → index #2221, 17:04  
**令牌**: `Cookie: WebSession_812ede82bd=579fc263...` + `SessionTag: e056ec1de2...`

**逐端点结果** (10/10):

| # | 方法 | 端点 | Admin | None | 相似度 | 裁决 |
|---|------|------|:---:|:---:|:---:|:---:|
| 1 | GET | /ISAPI/System/deviceInfo | 200 | 401 | 16.4% | ✅ PASS |
| 2 | GET | /ISAPI/System/upgradeStatus | 200 | 401 | 18.3% | ✅ PASS |
| 3 | GET | /ISAPI/Security/token | 200 | 401 | 3.0% | ✅ PASS |
| 4 | PUT | /ISAPI/Security/sessionHeartbeat | 200 | 401 | 19.3% | ✅ PASS |
| 5 | GET | /ISAPI/System/updateFirmware | 403 | 401 | 17.6% | ✅ PASS |
| 6 | POST | /ISAPI/IoTGateway/Childmanage/SearchChild | 400 | 401 | 18.8% | ✅ PASS |
| 7 | GET | /ISAPI/Security/extern/capabilities | 403 | 403 | 100% | ⚠️ SKIP |
| 8 | GET | /codebase/VersionInfo.xml | 200 | 200 | **100%** | ❌ FAIL |
| 9 | GET | /SDK/activateStatus | 200 | 200 | **100%** | ❌ FAIL |
| 10 | GET | /SDK/language | 200 | 200 | **100%** | ❌ FAIL |

### ❌ FAIL 详情

**GET /codebase/VersionInfo.xml** — 未认证可读取完整 SBOM:
```xml
<FileVersion>
  <BaseVersion>4.0.2512.3</BaseVersion>
  <SBOM>
    <Platform name="Win32">
      <Component name="JsonCpp" version="1.6.0"/>
      <Component name="OpenSSL" version="1.1.1w"/>
      <Component name="libsrtp" version="2.2.0"/>
      ...
```
> 披露了第三方组件及版本号（OpenSSL 1.1.1w 等），攻击者可据此定位已知漏洞。

**GET /SDK/activateStatus** — 未认证可读取设备激活状态:
```xml
<ActivateStatus><Activated>true</Activated>...</ActivateStatus>
```

**GET /SDK/language** — 未认证可读取语言配置 (低风险)。

### 裁决

- 10 端点中：7 通过、1 跳过 (禁用的 extern/capabilities)、**3 FAIL**
- 5.5-5-2 证据 A: ❌ FAIL — 3 个端点缺少认证保护

---

## 证据 B — 前端加密 (Playwright MCP)

### B1. 页面信息

- **URL**: `http://10.19.199.54/doc/index.html#/portal/login`
- **前端版本**: V5.1.69_R0102 build 251229
- **登录方式**: 双因子 — `_digestLogin` (Digest 认证) + `_sessionLogin` (Session 认证)

### B2. 登录链路 (Network)

**Step 1 — 获取 capabilities**:
```
GET /ISAPI/Security/sessionLogin/capabilities?username=admin&random=31613291 → 200
```
响应:
```xml
<SessionLoginCap version="2.0">
  <sessionID>e8b31f45afb9360148d8d092be59f9b97989778711d7cbd8d24bfd0d5a1edc16</sessionID>
  <challenge>e92ad56c3ebef37aa097bc7e02ad4992</challenge>
  <iterations>100</iterations>
  <isIrreversible>true</isIrreversible>
  <salt>bfb48b4d42c78444ac329797f68b67dc4f823a23a9b485f4e8fcb2985c985b95</salt>
  <isSessionIDValidLongTerm opt="true,false">false</isSessionIDValidLongTerm>
  <isSupportSessionTag opt="true,false">true</isSupportSessionTag>
  <sessionIDVersion>2</sessionIDVersion>
</SessionLoginCap>
```

**Step 2 — 提交登录**:
```
POST /ISAPI/Security/sessionLogin?timeStamp=1785141273285 → 401
```
Body:
```xml
<SessionLogin>
  <userName>admin</userName>
  <password>061315db376b113411cf3f7ddf7fa0d5ebf1b749909373cbc4ab2c2130d7c27d</password>
  <sessionID>e8b31f45afb9360148d8d092be59f9b97989778711d7cbd8d24bfd0d5a1edc16</sessionID>
  <isSessionIDValidLongTerm>false</isSessionIDValidLongTerm>
  <sessionIDVersion>2</sessionIDVersion>
  <isNeedSessionTag>true</isNeedSessionTag>
</SessionLogin>
```

> `<password>` = 64 hex → **SHA-256 不可逆摘要**。401 是因为测试密码错误，加密链路完整执行，不影响判定。

### B3. JS 源码分析 (browser_evaluate)

扫描 25 个 `/doc/` 路径 JS 文件，命中加密关键字的文件：

#### 核心加密库

| 文件 | 大小 | 命中关键词 |
|------|:---:|------|
| `1099.72856b0a.js` | 78KB | md5, sha256, sha1, aes, pbkdf, salt, encrypt, iterations |
| `com_cbf697a8_3feae759.5504cc4a.js` | 103KB | rsa, sha256, sha1, aes, pbkdf, md5, salt, challenge, encrypt, iterations |
| `com_076e9c97.781af683.js` | 1.7MB | aes, md5, rsa, sha256, sha1, salt, challenge, digest, hexstring, btoa, iterations, encrypt |

**`1099.72856b0a.js`** — CryptoJS 库:
```js
// SHA-256 实现
var a=[], u=c.SHA256=i.extend({
  _doReset:function(){this._hash=new n.init(s.slice(0))},
  ...
});
r.SHA256=i._createHelper(u);
r.HmacSHA256=i._createHmacHelper(u);
```
> 确认为 CryptoJS 风格 SHA-256 实现，无 `CryptoJS` 全局命名（经过 webpack 模块化）。

**`com_cbf697a8_3feae759.5504cc4a.js`** — RSA 签名 + SHA-256 摘要:
```js
q.prototype.signStringWithSHA256=function(t){
  return t=Z(t,this.n.bitLength(),"sha256"),
  this.doPrivate(z(t,16)).toString(16)
};
```

#### 登录流程编排

| 文件 | 大小 | 关键方法 |
|------|:---:|------|
| `com_771c94be_dd03631b.bf24757f.js` | 42KB | `_digestLogin()`, `_sessionLogin()`, `_setAuthType()` |
| `com_771c94be_aeda76d6.cf467976.js` | 53KB | sha256 密钥派生 (含硬编码盐 `AaBbCcDd1234!@#$`) |

**`com_771c94be_dd03631b.bf24757f.js`** — 登录认证编排:
```js
// capabilities 响应解析
e.sessionCap = {
  szSessionID: (0,o.E8A)(n,"sessionID"),
  szChallenge: (0,o.E8A)(n,"challenge"),
  iIterate: (0,o.E8A)(n,"iterations","i"),
  bIrreversible: (0,o.E8A)(n,"isIrreversible")
};

// 认证方式选择: _digestLogin → _sessionLogin
case 2: if(2!==this.iAuthType){e.n=4;break}
  return e.n=3, this._digestLogin();
case 4: return e.n=5, this._sessionLogin();
```

**`com_771c94be_aeda76d6.cf467976.js`** — 密钥派生:
```js
// isIrreversible 分支: sha256(username + salt + password)
if(e.oSecurityCap.isIrreversible){
  var a=e.oSecurityCap.salt;
  return o.A.sha256(n+a+t)  // n=username, a=salt, t=password
}

// 迭代: sha256(prev + hardcodedSalt), iKeyIterateNum 次
a = o.A.sha256("".concat(prevResult, "AaBbCcDd1234!@#$"));
for(var i=1; i<e.oSecurityCap.iKeyIterateNum; i++)
  a = o.A.sha256(a);
```

> ⚠️ 硬编码盐 `AaBbCcDd1234!@#$` 出现在密钥派生函数中（非登录主流程，用于 AES key 派生），不是 `encodePwd` 的 challenge-response 迭代。

#### 其他加密相关

| 文件 | 命中 | 用途 |
|------|------|------|
| `com_67191618_5ba4548c.f91d6a37.js` | forge, rsa | RSA 库 (forge) |
| `com_7db64881_f4f2ac9e.dcca57c1.js` | forge | RSA 库 (forge) |
| `com_9a674b1c_1b4b36b8.2956a001.js` | sessionLogin, encrypt | API 端点定义 (sessionLogin, sessionHeartbeat, EncryptInfo...) |
| `com_2329af1b_80033543.886331e2.js` | aes | 流加密相关 |
| `com_1891ea61_3282a89e.5fddede4.js` | isIrreversible, encrypt, digest, rsa | 设备能力声明 (`bSupportIrreversibleEncrypt:!1`, `bSupportStreamEncrypt:!1`) |

### B4. 加密判定

| 检查项 | 结果 |
|--------|------|
| 密码提交格式 | 64 hex → SHA-256 不可逆摘要 |
| 挑战-响应 | ✅ salt + challenge + iterations=100 |
| 不可逆标记 | isIrreversible=true |
| 加密库 | CryptoJS (1099.72856b0a.js) |
| RSA 实现 | forge 库 (com_67191618 / com_7db64881) + 自实现 (com_cbf697a8_3feae759) |
| AES 实现 | CryptoJS + 自实现 (com_076e9c97, 1.7MB) |
| 硬编码密钥 | `AaBbCcDd1234!@#$` (AES key 派生用，非登录凭据) |

**裁决**: 前端加密实现为 SHA-256 不可逆挑战-响应摘要 + RSA 签名 + AES 流加密。符合 SOGIS 推荐算法。与 IXIT 声明一致性待正式检测时比对。

---

## 证据 C — 端口登记 (Nmap)

**命令**: `nmap -Pn -n -sS --open --top-ports 100 10.19.199.54` (0.43s)

| 端口 | 服务 | 协议推测 |
|:---:|------|------|
| 80 | http | Web 管理界面 |
| 443 | https | Web 管理界面 (HTTPS) |
| 554 | rtsp | 视频流 |
| 8000 | http-alt | SDK/API 服务 |
| 8443 | https-alt | SDK/API 服务 (HTTPS) |

> 全端口 UDP 扫描耗时长 (222s 已完成 TCP)，正式检测建议补充 `--top-ports 1000` TCP + 按需 UDP。

---

## 工作流实操发现

| 问题 | 影响 | 解决方案 |
|------|------|------|
| auth_diff request 需 `\r\n` 行尾 | `\n` → 8s 超时无响应 | 强制 `\r\n` (已写入 auth-diff-workflow.md 已知坑) |
| 双认证头设备 (Cookie + SessionTag) | auth_diff 单 level 只能注入 1 个 header | 辅助头写 base request，主凭据放 auth_levels (已写入 Step 3a+) |
| Element UI ref 不稳定 | browser_fill_form / browser_type 不可用 | browser_evaluate JS 原生注入绕过 (已在前端加密流程中验证) |
| `http_send_request` url 模式丢弃自定义 headers | 无法直接发包验证令牌 | 改用 auth_diff (raw_request 模式保留 headers) |
| proxy_history url_prefix 过滤不生效 | 全量返回 156KB | 改用 proxy_history_search 精确搜索 |

---

## 三证据可行性结论

| 证据 | 工具 | 耗时 | 自动化 | 产出 |
|------|------|:---:|:---:|------|
| A — API 越权 | Burp MCP auth_diff | ~4s/端点 | ✅ 全自动 | 10 端点 admin vs none，3 FAIL |
| B — 前端加密 | Playwright MCP | ~20s | ✅ 全自动 | capabilities + login body + JS 源码分析 |
| C — 端口登记 | Nmap | 0.4s (top-100) | ✅ 全自动 | 5 端口开放 |

**5.5-5-2 裁决: ❌ FAIL** — 证据 A 发现 3 个端点未认证可访问。核心工作流已沉淀至 `auth-diff-workflow.md`。
