import fs from 'node:fs';
import path from 'node:path';

/**
 * state.json 记录每个域名最近一次通知的状态，用于"每天最多提醒一次"去重。
 * 结构：
 * {
 *   "example.com": { "date": "2026-10-14", "reason": "expire|error", "daysLeft": 15 }
 * }
 * - reason=expire：因到期通知；证书续期后（剩余天数回升超过阈值）自动清除，下次到期重新提醒
 * - reason=error：因检测失败通知；恢复正常后自动清除
 */

function stateFile(configPath) {
  return path.join(path.dirname(path.resolve(configPath)), 'state.json');
}

export function loadState(configPath) {
  const file = stateFile(configPath);
  if (!fs.existsSync(file)) return {};
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return {}; // state.json 损坏时不影响检测，当作无记录
  }
}

export function saveState(configPath, state) {
  fs.writeFileSync(stateFile(configPath), JSON.stringify(state, null, 2) + '\n');
}

function today() {
  return new Date().toISOString().slice(0, 10); // UTC 日期，全天一致
}

/**
 * 判断某域名本轮是否应该通知，并在通知后更新状态。
 * 返回 true 表示应该通知。
 */
export function shouldNotify(state, host, { isAlert, daysLeft }) {
  const rec = state[host];

  if (!isAlert) {
    // 状态恢复正常（续期完成 / 检测成功）：清除记录，后续到期会重新提醒
    if (rec) delete state[host];
    return false;
  }

  if (rec && rec.date === today()) return false; // 今天已通知过
  return true;
}

/** 通知发送成功后调用，记录本次通知 */
export function markNotified(state, host, { reason, daysLeft }) {
  state[host] = { date: today(), reason, daysLeft };
}
