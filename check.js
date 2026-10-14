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
  node check.js --test feishu            向 default 分组的指定渠道发测试消息（feishu / wecom / dingtalk / email / all）
  node check.js --test ops               向指定分组的全部渠道发测试消息（参数为分组名）
  node check.js --dry-run                只检测和打印，不发送通知
  node check.js --config /path/cfg.yml   指定配置文件路径

配置（默认读取脚本同目录下的 config.yml，参考 config.example.yml）:
  domains        HTTPS 证书到期检测（TLS 握手取证书剩余天数）
  whois.domains  域名注册到期检测（注册局 RDAP/WHOIS，与注册商无关）
  两套配置独立设置阈值；通知渠道统一在 groups 里按分组配置，
  域名用 notify 指定分组（可填多个，如 notify: [ops, boss]），不填走 default 分组
`;

// ---------- 配置加载 ----------
/** 归一化域名的 notify 字段：不填 → ['default']；支持字符串或数组（同一域名推多个分组） */
function resolveNotifyGroups(notify) {
  const list = notify == null ? [] : Array.isArray(notify) ? notify : [notify];
  const groups = [...new Set(list.filter(Boolean))];
  return groups.length ? groups : ['default'];
}

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

  // 兼容旧版写法（提示迁移）：templates → groups，顶层 notify → groups.default
  const groups = { ...(cfg.templates || {}), ...(cfg.groups || {}) };
  if (cfg.templates && cfg.groups) {
    console.warn(C.yellow('⚠ templates 与 groups 同时存在，已按 groups 处理，请删除 templates 以免混淆'));
  } else if (cfg.templates) {
    console.warn(C.yellow('⚠ 检测到旧版 templates 写法，本次已按 groups 处理，请尽快改名为 groups'));
  }
  if (cfg.notify && Object.keys(cfg.notify).length) {
    if (groups.default) {
      console.warn(C.yellow('⚠ 顶层 notify 与 groups.default 同时存在，已忽略顶层 notify，请删除以免混淆'));
    } else {
      groups.default = cfg.notify;
      console.warn(C.yellow('⚠ 检测到旧版顶层 notify 写法，本次按 default 分组处理，请尽快迁移到 groups.default'));
    }
  }
  cfg.groups = groups;

  // 校验分组名与域名引用的分组都存在，避免告警静默丢失
  const RESERVED = ['email', 'feishu', 'wecom', 'dingtalk', 'all'];
  for (const name of Object.keys(groups)) {
    if (RESERVED.includes(name)) {
      console.error(`✖ 分组名「${name}」是保留字（${RESERVED.join(' / ')}），会导致 --test 无法区分渠道和分组，请改名`);
      process.exit(1);
    }
  }
  for (const d of [...(cfg.domains || []), ...(cfg.whois?.domains || [])]) {
    for (const g of resolveNotifyGroups(d.notify)) {
      // default 分组允许不配置（发送阶段会提示未配渠道）；显式引用其他分组必须存在
      if (g === 'default' && !groups.default) continue;
      if (!groups[g]) {
        console.error(`✖ 域名 ${d.host} 引用的通知分组「${g}」未在 groups 中定义`);
        console.error(`  已定义的分组：${Object.keys(groups).join('、') || '（无）'}`);
        process.exit(1);
      }
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

/** state key 迁移：旧版无类型前缀（host:port）的补 cert: 前缀；分组功能前的 key 无「|分组」后缀，
 *  删除避免残留死数据（升级当天会重新通知一次） */
function migrateState(state) {
  for (const k of Object.keys(state)) {
    if (!k.startsWith('cert:') && !k.startsWith('domain:')) {
      state[`cert:${k}`] = state[k];
      delete state[k];
    } else if (!k.includes('|')) {
      delete state[k];
    }
  }
}

/**
 * 通用告警处理：判定 → 按「域名 × 分组」去重 → 聚合发送。
 * entries: [{ host, result, threshold, remark, notifyGroups, stateKey }]
 * 同一域名配了多个分组时，每个分组各发一条；去重粒度也是域名 × 分组，
 * 某个分组发送失败时下一轮只重试该分组，不会重复打扰已成功的分组。
 * 返回本轮是否存在告警（含被去重跳过的）。
 */
async function processAlerts(cfg, args, state, entries, kind) {
  const batches = new Map(); // 分组名 → 该分组待发送的条目
  let skippedToday = 0;
  for (const e of entries) {
    const r = e.result;
    const isAlert = !r.ok || r.daysLeft <= e.threshold;
    const pending = e.notifyGroups.filter((g) =>
      shouldNotify(state, `${e.stateKey}|${g}`, { isAlert, daysLeft: r.ok ? r.daysLeft : null })
    );
    if (!pending.length) {
      if (isAlert) skippedToday++;
      continue;
    }
    const item = { ...r, remark: e.remark, threshold: e.threshold, stateKey: e.stateKey };
    for (const g of pending) {
      if (!batches.has(g)) batches.set(g, []);
      batches.get(g).push(item);
    }
  }

  if (!batches.size) {
    if (skippedToday) {
      console.log(C.yellow(`有 ${skippedToday} 个域名仍在告警状态，今天已通知过，跳过重复提醒。`));
    } else {
      console.log(C.dim('全部正常，无需通知。'));
    }
    return skippedToday > 0;
  }

  if (args.dryRun) {
    console.log(C.yellow(`[dry-run] 以下域名满足通知条件，已跳过发送：`));
    for (const [g, items] of batches) {
      console.log(`  ▸ 分组「${g}」（${items.length} 个域名）`);
      for (const a of items) {
        console.log(`    - ${a.host}${a.ok ? `（剩余 ${a.daysLeft} 天）` : `（${a.error}）`}`);
      }
    }
    return true;
  }

  // 同一分组触发的多个域名合并为一条消息；未配置渠道的分组提示后跳过
  for (const [g, items] of batches) {
    const notifyCfg = cfg.groups[g];
    const label = `分组「${g}」`;
    if (!notifyCfg || !Object.keys(notifyCfg).length) {
      console.error(C.red(`✖ ${label}未配置任何渠道，${items.length} 个域名的告警未发送（${items.map((i) => i.host).join('、')}）`));
      continue;
    }
    console.log(`发送通知 → ${label}（${items.length} 个域名触发）...`);
    const sendResults = await notifyAllChannels(notifyCfg, items, kind);
    for (const s of sendResults) {
      console.log(s.ok ? C.green(`  ✔ ${s.channel} 发送成功`) : C.red(`  ✖ ${s.channel} 发送失败：${s.error}`));
    }
    // 任一渠道成功即记录该分组"今天已通知"；全部失败则不记录，下一轮会重试
    if (sendResults.some((s) => s.ok)) {
      for (const a of items) {
        markNotified(state, `${a.stateKey}|${g}`, { reason: a.ok ? 'expire' : 'error', daysLeft: a.ok ? a.daysLeft : null });
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
        notifyGroups: resolveNotifyGroups(d.notify),
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
        notifyGroups: resolveNotifyGroups(d.notify),
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

  // 组装测试目标：渠道名测 default 分组的该渠道，分组名测该分组全部已配渠道，all 测所有分组
  const configured = (nc) => CHANNELS.filter((c) => nc[c]);
  let targets;
  if (t === 'all') {
    targets = Object.entries(cfg.groups)
      .map(([name, nc]) => ({ label: `分组「${name}」`, notifyCfg: nc, channels: configured(nc) }))
      .filter((tg) => tg.channels.length);
    if (!targets.length) {
      console.error('✖ config.yml 中未配置任何通知渠道（groups）');
      process.exit(1);
    }
  } else if (CHANNELS.includes(t)) {
    const nc = cfg.groups.default;
    if (!nc || !nc[t]) {
      console.error(`✖ 分组「default」中未配置 ${t} 渠道（其他分组请用 --test 分组名 测试）`);
      process.exit(1);
    }
    targets = [{ label: '分组「default」', notifyCfg: nc, channels: [t] }];
  } else {
    const nc = cfg.groups[t];
    if (!nc) {
      console.error(`✖ 未找到通知分组「${t}」`);
      console.error(`  已定义的分组：${Object.keys(cfg.groups).join('、') || '（无）'}`);
      process.exit(1);
    }
    const chs = configured(nc);
    if (!chs.length) {
      console.error(`✖ 分组「${t}」里没有配置任何渠道`);
      process.exit(1);
    }
    targets = [{ label: `分组「${t}」`, notifyCfg: nc, channels: chs }];
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
