import crypto from 'node:crypto';
import nodemailer from 'nodemailer';

/** 把 TLS 证书的 valid_to（如 "Oct 29 12:00:00 2026 GMT"）格式化为 YYYY-MM-DD */
export function fmtDate(validTo) {
  const d = new Date(validTo);
  if (isNaN(d.getTime())) return String(validTo);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/**
 * 根据待通知条目构造各渠道消息内容
 * items: [{ host, port, remark, ok, daysLeft, validTo, error, threshold }]
 * kind: 'cert'（HTTPS 证书到期）| 'domain'（域名注册到期）
 */
function buildContent(items, now, kind = 'cert') {
  const lines = [];
  let expired = 0;
  let failed = 0;

  for (const it of items) {
    const label = it.remark ? `${it.host}（${it.remark}）` : it.host;
    if (!it.ok) {
      failed++;
      lines.push(`❌ ${label} 检测失败：${it.error}`);
    } else if (it.daysLeft < 0) {
      expired++;
      lines.push(`🔴 ${label} 已过期 ${-it.daysLeft} 天（${fmtDate(it.validTo)}）`);
    } else {
      lines.push(`🟠 ${label} 剩余 ${it.daysLeft} 天（${fmtDate(it.validTo)} 到期，阈值 ${it.threshold} 天）`);
    }
  }

  const parts = [];
  if (expired) parts.push(`${expired} 个已过期`);
  if (items.length - expired - failed > 0) parts.push(`${items.length - expired - failed} 个即将到期`);
  if (failed) parts.push(`${failed} 个检测失败`);
  const kindLabel = kind === 'domain' ? '域名到期告警' : 'HTTPS 证书告警';
  const title = `【${kindLabel}】${parts.join('，')}`;

  const text = `${title}\n${lines.join('\n')}\n\n检测时间：${now}\n来自 cert-checker`;
  const html = `
    <div style="font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;max-width:560px">
      <h3 style="margin:0 0 12px">${title}</h3>
      <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;font-size:14px">
        <tr style="background:#f5f5f5"><th>域名</th><th>状态</th><th>详情</th></tr>
        ${items
          .map((it) => {
            const st = !it.ok
              ? '<span style="color:#d00">检测失败</span>'
              : it.daysLeft < 0
                ? '<span style="color:#d00">已过期</span>'
                : '<span style="color:#c80">即将到期</span>';
            const detail = !it.ok ? it.error : `${fmtDate(it.validTo)} 到期，剩余 ${it.daysLeft} 天`;
            return `<tr><td>${it.host}${it.remark ? `（${it.remark}）` : ''}</td><td>${st}</td><td>${detail}</td></tr>`;
          })
          .join('')}
      </table>
      <p style="color:#888;font-size:12px;margin-top:12px">检测时间：${now} · 来自 cert-checker</p>
    </div>`;
  return { title, text, html };
}

/** 飞书自定义机器人签名（配置了 secret 时启用）：Base64(HMAC-SHA256(key=timestamp\nsecret, msg='')) */
function feishuSign(timestamp, secret) {
  return crypto.createHmac('sha256', `${timestamp}\n${secret}`).update('').digest('base64');
}

async function sendFeishu(cfg, { title, text }) {
  const body = {
    msg_type: 'text',
    content: { text: text.replace(/【HTTPS 证书告警】[^\n]*/, title) },
  };
  if (cfg.secret) {
    const ts = Math.floor(Date.now() / 1000);
    body.timestamp = String(ts);
    body.sign = feishuSign(ts, cfg.secret);
  }
  const res = await fetch(cfg.webhook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (data.code !== 0) throw new Error(`飞书返回：${data.msg || JSON.stringify(data)}`);
}

async function sendWecom(cfg, { title, text }) {
  // 企微 markdown 不支持表格，直接用纯文本行
  const res = await fetch(cfg.webhook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ msgtype: 'markdown', markdown: { content: text } }),
  });
  const data = await res.json();
  if (data.errcode !== 0) throw new Error(`企微返回：${data.errmsg || JSON.stringify(data)}`);
}

/** 钉钉加签（机器人安全设置选了"加签"时启用）：
 *  sign = urlencode(Base64(HMAC-SHA256(key=secret, msg=timestamp毫秒 + "\n" + secret)))，拼到 webhook URL 上 */
function dingtalkSignedUrl(cfg) {
  if (!cfg.secret) return cfg.webhook; // 未配 secret（关键词/IP 白名单方式）不做签名
  const ts = Date.now();
  const stringToSign = `${ts}\n${cfg.secret}`;
  const sign = encodeURIComponent(
    crypto.createHmac('sha256', cfg.secret).update(stringToSign).digest('base64')
  );
  return `${cfg.webhook}&timestamp=${ts}&sign=${sign}`;
}

async function sendDingtalk(cfg, { title, text }) {
  const res = await fetch(dingtalkSignedUrl(cfg), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ msgtype: 'markdown', markdown: { title, text } }),
  });
  const data = await res.json();
  if (data.errcode !== 0) throw new Error(`钉钉返回：${data.errmsg || JSON.stringify(data)}`);
}

async function sendEmail(cfg, { title, text, html }) {
  const transporter = nodemailer.createTransport({
    host: cfg.smtp.host,
    port: cfg.smtp.port,
    secure: cfg.smtp.secure ?? cfg.smtp.port === 465, // 默认 465 走 SSL
    auth: { user: cfg.smtp.user, pass: cfg.smtp.pass },
  });
  await transporter.sendMail({
    from: cfg.from || cfg.smtp.user,
    to: cfg.to.join(','),
    subject: title,
    text,
    html,
  });
}

/**
 * 把告警发到所有已配置渠道。
 * kind: 'cert' | 'domain'，决定消息标题（证书告警 / 域名到期告警）
 * 返回 [{ channel, ok, error }]，单渠道失败不影响其他渠道。
 */
export async function notifyAllChannels(notify, items, kind = 'cert') {
  const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
  const content = buildContent(items, now, kind);
  const results = [];

  if (notify?.email) {
    try {
      await sendEmail(notify.email, content);
      results.push({ channel: 'email', ok: true });
    } catch (e) {
      results.push({ channel: 'email', ok: false, error: e.message });
    }
  }
  if (notify?.feishu) {
    try {
      await sendFeishu(notify.feishu, content);
      results.push({ channel: 'feishu', ok: true });
    } catch (e) {
      results.push({ channel: 'feishu', ok: false, error: e.message });
    }
  }
  if (notify?.wecom) {
    try {
      await sendWecom(notify.wecom, content);
      results.push({ channel: 'wecom', ok: true });
    } catch (e) {
      results.push({ channel: 'wecom', ok: false, error: e.message });
    }
  }
  if (notify?.dingtalk) {
    try {
      await sendDingtalk(notify.dingtalk, content);
      results.push({ channel: 'dingtalk', ok: true });
    } catch (e) {
      results.push({ channel: 'dingtalk', ok: false, error: e.message });
    }
  }
  return results;
}

/** --test 用：向指定渠道发一条测试消息 */
export async function sendTest(notify, channel) {
  const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
  const content = {
    title: '【cert-checker】证书监控测试消息',
    // 文案带"证书"字样：钉钉机器人若设置了关键词安全校验（如"证书"），测试消息也能通过
    // 文案同时含"证书/域名/告警"字样：钉钉机器人设置了关键词安全校验（如"证书"或"告警"），测试消息都能通过
    text: `【cert-checker】证书/域名监控测试告警\n这是一条测试通知，收到说明渠道配置正确。\n发送时间：${now}`,
    html: `<h3>【cert-checker】证书/域名监控测试告警</h3><p>这是一条测试通知，收到说明渠道配置正确。</p><p style="color:#888;font-size:12px">发送时间：${now}</p>`,
  };
  const senders = { email: sendEmail, feishu: sendFeishu, wecom: sendWecom, dingtalk: sendDingtalk };
  const cfg = notify?.[channel];
  if (!senders[channel]) throw new Error(`未知渠道：${channel}（可选 email / feishu / wecom / dingtalk）`);
  if (!cfg) throw new Error(`当前通知配置中未配置 ${channel} 渠道`);
  await senders[channel](cfg, content);
}
