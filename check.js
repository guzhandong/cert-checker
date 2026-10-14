#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import { checkAll } from './lib/checker.js';
import { checkAllWhois } from './lib/whois.js';
import { loadState, saveState, shouldNotify, markNotified } from './lib/state.js';
import { notifyAllChannels, sendTest, fmtDate } from './lib/notifier.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------- 参数解析 ----------
function parseArgs(argv) {
  const args = { config: path.join(__dirname, 'config.yml') };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--config') args.config = path.resolve(argv[++i]);
    else if (a === '--watch') args.watch = parseInt(argv[++i], 10) || 3600;
    else if (a === '--test') args.test = argv[++i] || 'all';
    else if (a === '--dry-run') args.dryRun = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else {
      console.error(`未知参数：${a}`);
      process.exit(1);
    }
  }
  return args;
}

const HELP = `
cert-checker — 轻量证书 / 域名到期监控

用法:
  node check.js                          检测一轮后退出（配 cron / systemd timer 用）
  node check.js --watch 3600             常驻模式，每 3600 秒检测一轮
  node check.js --test feishu            向指定渠道发测试消息（feishu / wecom / dingtalk / email / all）
  node check.js --test ops               向指定通知模板的全部渠道发测试消息（参数为模板名）
  node check.js --dry-run                只检测和打印，不发送通知
  node check.js --config /path/cfg.yml   指定配置文件路径

配置（默认读取脚本同目录下的 config.yml，参考 config.example.yml）:
  domains        HTTPS 证书到期检测（TLS 握手取证书剩余天数）
  whois.domains  域名注册到期检测（注册局 RDAP/WHOIS，与注册商无关）
  两套配置独立设置阈值；域名的 notify 字段引用 templates 实现分域名走不同通知渠道
`;

// ---------- 配置加载 ----------
function loadConfig(file) {
  if (!fs.existsSync(file)) {
    console.error(`✖ 配置文件不存在：${file}`);
    console.error(`  请复制模板：cp config.example.yml config.yml 后编辑`);
    process.exit(1);
  }
  const cfg = yaml.load(fs.readFileSync(file, 'utf8'));
  if (!cfg.domains?.length && !cfg.whois?.domains?.length) {
    console.error(`✖ 配置文件中没有域名，请编辑 ${file} 的 domains（证书）或 whois.domains（域名到期）部分`);
    process.exit(1);
  }
  // 校验域名引用的通知模板都存在，避免告警静默丢失
  const templates = cfg.templates || {};
  const RESERVED = ['email', 'feishu', 'wecom', 'dingtalk', 'all'];
  for (const name of Object.keys(templates)) {
    if (RESERVED.includes(name)) {
      console.error(`✖ 模板名「${name}」是保留字（${RESERVED.join(' / ')}），会导致 --test 无法区分渠道和模板，请改名`);
      process.exit(1);
    }
  }
  for (const d of [...(cfg.domains || []), ...(cfg.whois?.domains || [])]) {
    if (d.notify && !templates[d.notify]) {
      console.error(`✖ 域名 ${d.host} 引用的通知模板「${d.notify}」未在 templates 中定义`);
      console.error(`  已定义的模板：${Object.keys(templates).join('、') || '（无）'}`);
      process.exit(1);
    }
  }
  return cfg;
}

// ---------- 彩色输出（重定向到文件时自动去色） ----------
const C = process.stdout.isTTY
  ? { red: (s) => `\x1b[31m${s}\x1b[0m`, green: (s) => `\x1b[32m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m` }
  : { red: (s) => s, green: (s) => s, yellow: (s) => s, dim: (s) => s };

function printTable(rows, defaultThreshold) {
  console.log(`\n${C.dim('──'.repeat(30))}`);
  for (const r of rows) {
    const target = `${r.host}:${r.port || 443}`;
    const remark = r.remark ? C.dim(` # ${r.remark}`) : '';
    if (!r.ok) {
      console.log(`${C.red('✖')} ${target.padEnd(38)} ${C.red(`检测失败：${r.error}`)}${remark}`);
    } else {
      const threshold = r.threshold ?? defaultThreshold;
      const days = `${r.daysLeft} 天`;
      const colorFn = r.daysLeft < 0 ? C.red : r.daysLeft <= 7 ? C.red : r.daysLeft <= threshold ? C.yellow : C.green;
      const mark = r.daysLeft < 0 ? C.red('已过期') : r.daysLeft <= threshold ? C.yellow('需关注') : C.green('正常');
      console.log(
        `${C.green('✔')} ${target.padEnd(38)} 剩余 ${colorFn(days.padStart(7))}  到期 ${fmtDate(r.validTo)}  ${mark}${remark}`
      );
    }
  }
  console.log(C.dim('──'.repeat(30)));
}

function printWhoisTable(rows, defaultThreshold) {
  console.log(`\n${C.dim('── 域名到期检测 ' + '─'.repeat(48))}`);
  for (const r of rows) {
    const remark = r.remark ? C.dim(` # ${r.remark}`) : '';
    if (!r.ok) {
      console.log(`${C.red('✖')} ${r.host.padEnd(38)} ${C.red(r.error)}${remark}`);
    } else {
      const threshold = r.threshold ?? defaultThreshold;
      const days = `${r.daysLeft} 天`;
      const colorFn = r.daysLeft < 0 ? C.red : r.daysLeft <= 7 ? C.red : r.daysLeft <= threshold ? C.yellow : C.green;
      const mark = r.daysLeft < 0 ? C.red('已过期') : r.daysLeft <= threshold ? C.yellow('需关注') : C.green('正常');
      console.log(
        `${C.green('✔')} ${r.host.padEnd(38)} 剩余 ${colorFn(days.padStart(7))}  到期 ${fmtDate(r.validTo)}  ${mark}  ${C.dim(r.source)}${remark}`
      );
    }
  }
  console.log(C.dim('──'.repeat(30)));
}

/** 旧版 state key 无类型前缀（host:port），迁移为 cert: 前缀，避免升级当天重复通知 */
function migrateState(state) {
  for (const k of Object.keys(state)) {
    if (!k.startsWith('cert:') && !k.startsWith('domain:')) {
      state[`cert:${k}`] = state[k];
      delete state[k];
    }
  }
}

/**
 * 通用告警处理：判定 → 去重 → 按模板分组发送。
 * entries: [{ host, result, threshold, remark, notifyTpl, stateKey }]
 * 返回本轮是否存在告警（含被去重跳过的）。
 */
async function processAlerts(cfg, args, state, entries, kind) {
  const alerts = [];
  let skippedToday = 0;
  for (const e of entries) {
    const r = e.result;
    const isAlert = !r.ok || r.daysLeft <= e.threshold;
    if (shouldNotify(state, e.stateKey, { isAlert, daysLeft: r.ok ? r.daysLeft : null })) {
      alerts.push({ ...r, remark: e.remark, threshold: e.threshold, notifyTpl: e.notifyTpl });
    } else if (isAlert) {
      skippedToday++;
    }
  }

  if (!alerts.length) {
    if (skippedToday) {
      console.log(C.yellow(`有 ${skippedToday} 个域名仍在告警状态，今天已通知过，跳过重复提醒。`));
    } else {
      console.log(C.dim('全部正常，无需通知。'));
    }
    return skippedToday > 0;
  }

  if (args.dryRun) {
    console.log(C.yellow(`[dry-run] 以下 ${alerts.length} 个满足通知条件，已跳过发送：`));
    for (const a of alerts) {
      const tpl = a.notifyTpl ? ` → 模板「${a.notifyTpl}」` : '';
      console.log(`  - ${a.host}${a.ok ? `（剩余 ${a.daysLeft} 天）` : `（${a.error}）`}${tpl}`);
    }
    return true;
  }

  // 按通知模板分组发送：同组多个域名合并为一条消息；未指定模板的走顶层 notify（默认渠道）
  const groups = new Map();
  for (const a of alerts) {
    if (!groups.has(a.notifyTpl)) groups.set(a.notifyTpl, []);
    groups.get(a.notifyTpl).push(a);
  }

  for (const [tpl, items] of groups) {
    const notifyCfg = tpl ? cfg.templates[tpl] : cfg.notify;
    const label = tpl ? `模板「${tpl}」` : '默认渠道';
    if (!notifyCfg || !Object.keys(notifyCfg).length) {
      console.error(C.red(`✖ ${label}未配置任何渠道，${items.length} 个域名的告警未发送（${items.map((i) => i.host).join('、')}）`));
      continue;
    }
    console.log(`发送通知 → ${label}（${items.length} 个域名触发）...`);
    const sendResults = await notifyAllChannels(notifyCfg, items, kind);
    for (const s of sendResults) {
      console.log(s.ok ? C.green(`  ✔ ${s.channel} 发送成功`) : C.red(`  ✖ ${s.channel} 发送失败：${s.error}`));
    }
    // 任一渠道成功即记录"今天已通知"；全部失败则不记录，下一轮会重试
    if (sendResults.some((s) => s.ok)) {
      for (const a of items) {
        const e = entries.find((x) => x.host === a.host);
        markNotified(state, e.stateKey, { reason: a.ok ? 'expire' : 'error', daysLeft: a.ok ? a.daysLeft : null });
      }
    }
  }
  return true;
}

// ---------- 一轮完整检测 ----------
async function runOnce(cfg, args) {
  const state = loadState(args.config);
  migrateState(state);
  let hasAlert = false;

  // ---- HTTPS 证书到期 ----
  if (cfg.domains?.length) {
    const results = await checkAll(cfg.domains, cfg.timeout ?? 10);
    printTable(results, cfg.threshold ?? 30);
    const entries = cfg.domains.map((d) => {
      const r = results.find((x) => x.host === d.host && (x.port || 443) === (d.port || 443));
      return {
        host: d.host,
        result: r,
        threshold: d.threshold ?? cfg.threshold ?? 30,
        remark: d.remark,
        notifyTpl: d.notify || '',
        stateKey: `cert:${d.host}:${d.port || 443}`,
      };
    });
    if (await processAlerts(cfg, args, state, entries, 'cert')) hasAlert = true;
  }

  // ---- 域名注册到期（whois，独立配置独立阈值）----
  if (cfg.whois?.domains?.length) {
    const results = await checkAllWhois(cfg.whois.domains, cfg.whois.timeout ?? cfg.timeout ?? 15, path.dirname(path.resolve(args.config)));
    printWhoisTable(results, cfg.whois.threshold ?? 30);
    const entries = cfg.whois.domains.map((d) => {
      const r = results.find((x) => x.host === d.host);
      return {
        host: d.host,
        result: r,
        threshold: d.threshold ?? cfg.whois.threshold ?? 30,
        remark: d.remark,
        notifyTpl: d.notify || '',
        stateKey: `domain:${d.host}`,
      };
    });
    if (await processAlerts(cfg, args, state, entries, 'domain')) hasAlert = true;
  }

  saveState(args.config, state);
  return hasAlert;
}

// ---------- 主流程 ----------
const args = parseArgs(process.argv);
if (args.help) {
  console.log(HELP);
  process.exit(0);
}

if (args.test) {
  const cfg = loadConfig(args.config);
  const CHANNELS = ['email', 'feishu', 'wecom', 'dingtalk'];
  const t = args.test;

  // 组装测试目标：渠道名测顶层 notify，模板名测该模板全部已配渠道，all 测所有配置
  const configured = (nc) => CHANNELS.filter((c) => nc[c]);
  let targets;
  if (t === 'all') {
    targets = [];
    if (cfg.notify) targets.push({ label: '默认渠道', notifyCfg: cfg.notify, channels: configured(cfg.notify) });
    for (const [name, nc] of Object.entries(cfg.templates || {})) {
      targets.push({ label: `模板「${name}」`, notifyCfg: nc, channels: configured(nc) });
    }
    if (!targets.some((tg) => tg.channels.length)) {
      console.error('✖ config.yml 中未配置任何通知渠道（notify / templates）');
      process.exit(1);
    }
    targets = targets.filter((tg) => tg.channels.length);
  } else if (CHANNELS.includes(t)) {
    if (!cfg.notify) {
      console.error(`✖ 顶层 notify 中未配置 ${t}（模板里的渠道请用 --test 模板名 测试）`);
      process.exit(1);
    }
    targets = [{ label: '默认渠道', notifyCfg: cfg.notify, channels: [t] }];
  } else {
    const nc = cfg.templates?.[t];
    if (!nc) {
      console.error(`✖ 未找到通知模板「${t}」`);
      console.error(`  已定义的模板：${Object.keys(cfg.templates || {}).join('、') || '（无）'}`);
      process.exit(1);
    }
    const chs = configured(nc);
    if (!chs.length) {
      console.error(`✖ 模板「${t}」里没有配置任何渠道`);
      process.exit(1);
    }
    targets = [{ label: `模板「${t}」`, notifyCfg: nc, channels: chs }];
  }

  for (const tg of targets) {
    for (const ch of tg.channels) {
      try {
        await sendTest(tg.notifyCfg, ch);
        console.log(C.green(`✔ [${tg.label}] ${ch} 测试消息发送成功`));
      } catch (e) {
        console.error(C.red(`✖ [${tg.label}] ${ch} 测试消息发送失败：${e.message}`));
        process.exitCode = 1;
      }
    }
  }
  process.exit();
}

const cfg = loadConfig(args.config);
if (args.watch) {
  console.log(`常驻模式：每 ${args.watch} 秒检测一轮（Ctrl+C 退出）`);
  await runOnce(cfg, args);
  setInterval(() => runOnce(cfg, args).catch(errHandle), args.watch * 1000);
} else {
  const hasAlert = await runOnce(cfg, args);
  if (hasAlert) process.exitCode = 1; // 有告警时非零退出码，方便外部脚本感知
}

function errHandle(err) {
  console.error(C.red(`本轮检测异常：${err.message}`));
}
