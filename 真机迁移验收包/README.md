# 内网真机迁移与验收包

本目录是把当前离线实现迁移到内网工作机前使用的静态交接包。它不含真实 IP、账号、Burp Token、私有映射或固件；这些只在受授权的工作机环境中设置，不能提交到仓库。

## 迁移顺序

1. 在工作机取得 DUT 测试授权、维护窗口和恢复负责人确认；不要在未授权网络上启动任何扫描、代理或固件操作。
2. 安装项目 Python 3.11 环境与项目依赖。确认 `openpyxl` 已随项目依赖安装，供既有 `scripts/parse_ixit_xlsx.py` 使用。
3. 在仓库外创建工作机私有 mapping，例如 `%LOCALAPPDATA%\etsi-agent\path-mapping.private.json`。它至少应含工作机实际的 `TOOL.TSHARK`、`TOOL.XRAY`、`DIR.FIRMWARE`；不要修改仓库的 `skills/path-mapping.json`。
4. 设定本机环境变量。可复制并填充 [环境变量.template.ps1](环境变量.template.ps1)，但不得把真实 Token 写入该文件或 PowerShell 历史。
5. 把 ICS/IXIT 原件放进 `INPUT_ROOTS` 之一下，把 old/tampered 固件放进 `FIRMWARE_ROOTS` 之下。浏览器只登记本地路径；不会上传或复制原件。IXIT 会由现有解析器产出工作区内的 `inputs/ixit.normalized.json` 和兼容 `ixit.json`，供 Agent 消费。
6. 启动 Web 控制台后，先创建 workspace、填写 DUT IP、登记 IXIT/固件本地路径并运行离线 preflight。确认 snapshot 中工具路径与版本正确后，才开始 run。
7. 进入 Traffic 后，先确认 Burp 链路为“浏览器 → Burp:8080 → xray:7778 → DUT”，再点击“确认通道就绪，开始操作”。逐项记录完成/N-A、说明及证据相对路径，最后点击“完成采集”。

## 本地路径引用规则

- `INPUT_ROOTS`：以 Windows `;` 分隔的 IXIT/XLSX 原件根目录；可配置多个。
- `FIRMWARE_ROOTS`：以 Windows `;` 分隔的固件根目录；可配置多个。私有 mapping 的 `DIR.FIRMWARE` 也会自动纳入。
- API 拒绝根目录之外的路径，且只写入来源路径、大小与 SHA-256。固件不复制到 workspace。
- 标准浏览器出于安全模型不能把文件选择器中的“本机路径”交给服务端而不上传文件，因此当前 B/S 页采用“粘贴/填写受控完整路径”。如需要图形化本地路径选择器，应在工作机另行部署受信任的桌面 helper；不要把上传重新作为替代方案。

## 验收产物与签收

运行 [生成条款验收清单.py](生成条款验收清单.py) 后，会按当前 `framework/clause_tool_map.json` 输出 `条款验收清单.md`，其中列出每一个 `full`/`partial` 条款的当前方法和工具类别。manual 条款不伪装为自动化验收，保留在报告的手工指引中。

每条 full/partial 条款签收时必须同时核对：recipe 版本、真实 tool receipt、原始 artifact 或 IXIT 摘录、expected/actual、三态 oracle、Round-1/2 audit 结果及报告中的同一条款。任一缺失只能记为 `INCONCLUSIVE` 或 `PENDING_MANUAL`，不能补写 PASS。

详细环境、Traffic 与停止收尾检查见 [验收步骤.md](验收步骤.md)。

真机期间允许修改文件、生成证据和处理异常的边界见 [真机阶段变更与证据保全原则.md](真机阶段变更与证据保全原则.md)。
