# 仅复制到工作机私有位置后填值；不要提交真实路径、IP、账号或 Token。
# PATH_MAPPING 必须是私有映射 JSON 的文件路径，绝不是 exe 路径或 JSON 内容。

$env:PATH_MAPPING = "C:\\Users\\<user>\\AppData\\Local\\etsi-agent\\path-mapping.private.json"
$env:AUTO_TEST_ROOT = "D:\\Auto-TEST"

# 可设置多处，以 ; 分隔。IXIT 与固件均为本地路径引用，浏览器不会上传文件。
$env:INPUT_ROOTS = "D:\\ETSI-Inputs;E:\\Project-Inputs"
$env:FIRMWARE_ROOTS = "D:\\Firmware;E:\\Firmware-Archive"

# 仅在当前受控 PowerShell 会话中输入；不要写进 .ps1、run_config、日志或截图。
# $env:BURP_MCP_TOKEN = Read-Host "Burp MCP Token" -AsSecureString

# 启动示例：
# .\\.venv\\Scripts\\python.exe web\\server.py --port 8000
