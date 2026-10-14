import tls from 'node:tls';
import net from 'node:net';

/**
 * 检测单个域名的 HTTPS 证书
 * rejectUnauthorized 故意设为 false：过期 / 自签证书也要能读到信息，而不是直接握手报错
 */
export function checkCert(host, port = 443, timeout = 10) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port,
        ...(net.isIP(host) ? {} : { servername: host }), // SNI 仅对域名设置，IP 直连时设 servername 会有弃用警告
        rejectUnauthorized: false,
        timeout: timeout * 1000,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          socket.end();
          if (!cert || !cert.valid_to) {
            return resolve({ host, port, ok: false, error: '未获取到证书（服务可能未启用 TLS）' });
          }
          const validTo = new Date(cert.valid_to);
          const daysLeft = Math.ceil((validTo.getTime() - Date.now()) / 86400000);
          resolve({
            host,
            port,
            ok: true,
            subject: cert.subject?.CN || host,
            issuer: [cert.issuer?.O, cert.issuer?.CN].filter(Boolean).join(' / ') || '未知',
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysLeft,
          });
        } catch (err) {
          resolve({ host, port, ok: false, error: err.message });
        }
      }
    );

    socket.on('error', (err) => {
      socket.destroy();
      resolve({ host, port, ok: false, error: friendlyError(err.message) });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ host, port, ok: false, error: `连接超时（${timeout}s）` });
    });
  });
}

function friendlyError(msg) {
  if (msg.includes('ENOTFOUND')) return '域名解析失败（ENOTFOUND）';
  if (msg.includes('ECONNREFUSED')) return '连接被拒绝（ECONNREFUSED）';
  if (msg.includes('ECONNRESET')) return '连接被重置（ECONNRESET）';
  if (msg.includes('EHOSTUNREACH')) return '主机不可达（EHOSTUNREACH）';
  return msg;
}

/** 并发检测全部域名（限制并发数，避免域名多时瞬间打满连接） */
export async function checkAll(domains, timeout) {
  const CONCURRENCY = 8;
  const results = [];
  for (let i = 0; i < domains.length; i += CONCURRENCY) {
    const batch = domains.slice(i, i + CONCURRENCY);
    const list = await Promise.all(
      batch.map((d) => checkCert(d.host, d.port || 443, timeout))
    );
    results.push(...list);
  }
  return results;
}
