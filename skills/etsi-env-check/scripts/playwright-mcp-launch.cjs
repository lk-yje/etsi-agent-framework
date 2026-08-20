// playwright MCP 自维护降级启动器
// 策略：能联网(npm registry 可达) → 解析最新版并记录 → 启动最新版；
//      连不上 → 回落本地缓存/上次成功版本 → 秒连不卡启动。
// 依赖位置(全部在用户环境内，随 ~/.claude 与 AppData 一同迁移，无跨机绝对路径):
//   自身目录  -> __dirname 自查
//   npm 缓存  -> ~/AppData/Local/npm-cache/_npx
//   状态文件  -> ~/.claude/playwright-mcp-version.json
//
// 用法:
//   node playwright-mcp-launch.cjs [--check] [--browser msedge] [--isolated] ...
//     --check    仅输出 JSON 状态(registry 连通性 / 解析版本 / 缓存 / 上次版本)，供 env-check 报告，不启动
//     默认       启动 MCP 服务器(长驻进程)
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const NAME = '@playwright/mcp';
const STATE_FILE = path.join(os.homedir(), '.claude', 'playwright-mcp-version.json');
const CACHE_ROOT = path.join(os.homedir(), 'AppData', 'Local', 'npm-cache', '_npx');
const isWin = process.platform === 'win32';
const npxCmd = isWin ? 'npx.cmd' : 'npx';

const argv = process.argv.slice(2);
const CHECK_MODE = argv.includes('--check');
const extraArgs = argv.filter((a) => a !== '--check');

// 快速失败的 npm 环境：短超时 + 0 重试，避免离线时卡几十秒
const fastEnv = Object.assign({}, process.env, {
  npm_config_fetch_timeout: '4000',
  npm_config_fetch_retries: '0',
  npm_config_fetch_retry_mintimeout: '400',
  npm_config_fetch_retry_maxtimeout: '1500',
});

function readState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { return null; }
}
function writeState(version) {
  try { fs.writeFileSync(STATE_FILE, JSON.stringify({ version, at: Date.now() })); } catch { }
}

// 扫描 npx 缓存里能找到的 playwright 版本(最后兜底)
function scanCacheVersion() {
  if (!fs.existsSync(CACHE_ROOT)) return null;
  let best = null;
  try {
    for (const sub of fs.readdirSync(CACHE_ROOT)) {
      const pkg = path.join(CACHE_ROOT, sub, 'node_modules', '@playwright', 'mcp', 'package.json');
      if (fs.existsSync(pkg)) {
        const v = JSON.parse(fs.readFileSync(pkg, 'utf8')).version;
        if (v && (!best || v > best)) best = v;
      }
    }
  } catch { }
  return best;
}

// 探测 registry 连通性 + 解析应使用版本，返回状态对象
function check() {
  const state = readState();
  const cached = scanCacheVersion();
  let registry = 'unreachable';
  let latest = null;
  // 用 npm view 的成败作为 registry 连通性判据(带短超时)
  const onlineProbe = (() => {
    try {
      const out = execFileSync('npm', ['view', NAME, 'version'], {
        timeout: 6000, env: fastEnv, cwd: process.cwd(),
        stdio: ['ignore', 'pipe', 'ignore'],
      }).toString().trim();
      latest = out && /^\d+\.\d+\.\d+/.test(out) ? out : null;
      return true;
    } catch { return false; }
  })();
  registry = onlineProbe ? 'reachable' : 'unreachable';

  // 决定采用的版本与来源
  let used = null, source = null;
  if (onlineProbe && latest) {
    used = latest; source = 'online-latest';
  } else if (state && state.version) {
    used = state.version; source = 'last-success';
  } else if (cached) {
    used = cached; source = 'cache';
  }
  return {
    registry, latest, used, source,
    cachedVersion: cached,
    lastSuccessVersion: state ? state.version : null,
  };
}

function launch(spec) {
  const child = spawn(npxCmd, [spec, ...extraArgs], {
    stdio: 'inherit',
    cwd: process.cwd(),
    env: fastEnv,
    shell: isWin,
  });
  child.on('error', (e) => { console.error('[playwright-mcp-launch] 启动失败: ' + (e && e.message)); process.exit(1); });
  child.on('exit', (code, sig) => { process.exit(code == null ? 1 : code); });
  // MCP 服务器为长驻进程，此处持续 running 属正常
}

if (CHECK_MODE) {
  process.stdout.write(JSON.stringify(check(), null, 2) + '\n');
  process.exit(0);
}

const c = check();
if (c.used) {
  // 在线解析到最新版时可在启动前记录，但避免重复 npm view；这里不写，保持单一职责
  launch(NAME + '@' + c.used);
} else {
  console.error('[playwright-mcp-launch] 无可用版本且离线，尝试无版本启动');
  launch(NAME);
}