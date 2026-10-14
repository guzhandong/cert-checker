import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';

/**
 * 域名（注册）到期检测：数据来自 TLD 注册局，与注册商无关（阿里云/GoDaddy 等均可查）。
 * 优先 RDAP（标准化 JSON，覆盖所有 gTLD），不支持的 TLD（如 .cn）回退 WHOIS 43 端口。
 */

const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const BOOTSTRAP_TTL = 7 * 86400 * 1000; // bootstrap 文件缓存 7 天

// 常见 TLD 的 WHOIS 服务器（避免每次走 IANA referral 两跳）；未列出的 TLD 走 whois.iana.org 转发
const KNOWN_WHOIS = {
  com: 'whois.verisign.com', net: 'whois.verisign.com',
  cn: 'whois.cnnic.cn', 'com.cn': 'whois.cnnic.cn', 'net.cn': 'whois.cnnic.cn', org: 'whois.pir.org',
  io: 'whois.nic.io', me: 'whois.nic.me', info: 'whois.nic.info', xyz: 'whois.nic.xyz',
  top: 'whois.nic.top', vip: 'whois.nic.vip', cc: 'ccwhois.verisign-grs.com', tv: 'tvwhois.verisign-grs.com',
};

// 各注册局 WHOIS 输出里到期时间的字段写法五花八门，逐个匹配
const EXPIRY_PATTERNS = [
  /Registry Expiry Date:\s*(.+)/i,
  /Expiration Time:\s*(.+)/i,
  /Expiration Date:\s*(.+)/i,
  /Expiry Date:\s*(.+)/i,
  /Expiry\s*:\s*(.+)/i,
  /Expires On:\s*(.+)/i,
  /Renewal Date:\s*(.+)/i,
  /paid-till:\s*(.+)/i,
];

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

/** 解析 WHOIS 里的各种日期写法：ISO、"2027-03-17 12:48:36"、"13-Aug-2027"、"2027年3月17日" 等 */
function parseDate(str) {
  str = str.trim().split('\n')[0].trim();
  let d = new Date(str);
  if (!isNaN(d.getTime())) return d;
  let m = str.match(/(\d{1,2})-([A-Za-z]{3})-(\d{4})/); // 13-Aug-2027
  if (m) return new Date(+m[3], MONTHS[m[2].toLowerCase()] ?? 0, +m[1]);
  m = str.match(/(\d{4})年(\d{1,2})月(\d{1,2})日/);
  if (m) return new Date(+m[1], +m[2] - 1, +m[3]);
  m = str.match(/(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})/); // 2027.3.17 / 2027/3/17
  if (m) return new Date(+m[1], +m[2] - 1, +m[3]);
  return null;
}

/** TLD → RDAP 服务器映射（带磁盘缓存） */
async function getRdapMap(timeout, cacheDir) {
  const file = path.join(cacheDir, 'rdap-bootstrap.json');
  try {
    const stat = fs.statSync(file);
    if (Date.now() - stat.mtimeMs < BOOTSTRAP_TTL) {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
  } catch { /* 无缓存或损坏，走下载 */ }
  const res = await fetch(BOOTSTRAP_URL, { signal: AbortSignal.timeout(timeout * 1000) });
  if (!res.ok) throw new Error(`bootstrap 下载失败 HTTP ${res.status}`);
  const { services } = await res.json();
  const map = {};
  for (const [tlds, urls] of services) {
    for (const tld of tlds) map[tld.toLowerCase()] = urls[0];
  }
  try {
    fs.writeFileSync(file, JSON.stringify(map)); // 缓存失败不影响本次结果
  } catch { /* 只读目录等情况 */ }
  return map;
}

function tldOf(host) {
  const parts = host.toLowerCase().split('.');
  return parts.length >= 3 && KNOWN_WHOIS[parts.slice(-2).join('.')]
    ? parts.slice(-2).join('.') // 二级后缀如 com.cn
    : parts[parts.length - 1];
}

async function rdapLookup(host, timeout, cacheDir) {
  const map = await getRdapMap(timeout, cacheDir);
  const tld = host.toLowerCase().split('.').pop();
  const base = map[tld];
  if (!base) return null; // 该 TLD 不支持 RDAP（如 .cn）
  const res = await fetch(`${base.replace(/\/$/, '')}/domain/${host}`, {
    headers: { Accept: 'application/rdap+json' },
    signal: AbortSignal.timeout(timeout * 1000),
  });
  if (res.status === 404) throw new Error('域名不存在（RDAP 404）');
  if (!res.ok) return null;
  const data = await res.json();
  const evt = data.events?.find((e) => e.eventAction === 'expiration');
  return evt?.eventDate ? { expiry: evt.eventDate, source: 'RDAP' } : null;
}

function whoisQuery(server, host, timeout) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(43, server);
    let data = '';
    socket.setTimeout(timeout * 1000);
    socket.on('connect', () => socket.write(host + '\r\n'));
    socket.on('data', (c) => (data += c.toString('utf8')));
    socket.on('close', () => resolve(data));
    socket.on('timeout', () => { socket.destroy(); reject(new Error(`WHOIS 查询超时（${server}）`)); });
    socket.on('error', reject);
  });
}

async function whoisLookup(host, timeout) {
  const tld = tldOf(host);
  let server = KNOWN_WHOIS[tld] || 'whois.iana.org';
  let text = await whoisQuery(server, host, timeout);
  if (server === 'whois.iana.org') {
    // IANA 返回 referral，跳到 TLD 注册局的 whois 再查一次
    const m = text.match(/^whois:\s*(\S+)/im);
    if (m && m[1] !== 'whois.iana.org') {
      server = m[1];
      text = await whoisQuery(server, host, timeout);
    }
  }
  for (const re of EXPIRY_PATTERNS) {
    const m = text.match(re);
    if (m) {
      const d = parseDate(m[1]);
      if (d) return { expiry: d.toISOString(), source: `WHOIS(${server})` };
    }
  }
  return null; // 查到了记录但没有到期字段（部分 ccTLD 不公布）
}

/** 检测单个域名的注册到期时间 */
export async function checkWhois(host, timeout = 10, cacheDir = '.') {
  try {
    const r = await rdapLookup(host, timeout, cacheDir);
    if (r) return finish(host, r);
  } catch (e) {
    if (e.message.includes('域名不存在')) {
      return { host, ok: false, error: e.message };
    }
    // RDAP 网络失败 → 尝试 WHOIS 兜底
  }
  try {
    const r = await whoisLookup(host, timeout);
    if (r) return finish(host, r);
  } catch (e) {
    return { host, ok: false, error: e.message };
  }
  return { host, ok: false, error: '无法获取到期时间（该 TLD 可能不支持 RDAP 且 WHOIS 未公布到期日期）' };
}

function finish(host, { expiry, source }) {
  const d = new Date(expiry);
  return {
    host,
    ok: true,
    expiry,
    validTo: expiry, // 与证书结果字段对齐，复用通知模板
    daysLeft: Math.ceil((d.getTime() - Date.now()) / 86400000),
    source,
  };
}

/** 并发检测全部域名 */
export async function checkAllWhois(domains, timeout, cacheDir) {
  const CONCURRENCY = 8;
  const results = [];
  for (let i = 0; i < domains.length; i += CONCURRENCY) {
    const batch = domains.slice(i, i + CONCURRENCY);
    const list = await Promise.all(batch.map((d) => checkWhois(d.host, timeout, cacheDir)));
    results.push(...list);
  }
  return results;
}
