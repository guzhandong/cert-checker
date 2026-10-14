# cert-checker — 轻量证书 / 域名到期监控

单脚本 + 一个 YAML 配置文件：定时检测域名 **HTTPS 证书** 和 **域名注册** 的剩余天数，到期前 N 天通过 **邮箱 / 飞书 / 企业微信 / 钉钉** 发送告警。默认跑完一轮即退出（也可 `--watch` 常驻），无数据库。

- 证书到期（TLS 握手取证书）与域名到期（注册局 RDAP/WHOIS）两套独立配置、独立阈值
- 每域名可独立设置阈值、端口、通知渠道组合（模板）
- 每天最多提醒一次，到期后自动重置，多域名合并成一条消息不刷屏
- 仅 2 个依赖（js-yaml、nodemailer），需要 Node.js ≥ 18

**告警消息长这样：**

```
【HTTPS 证书告警】1 个即将到期，1 个检测失败
🟠 example.com（生产官网） 剩余 15 天（2026-10-29 到期，阈值 30 天）
❌ api.example.com 检测失败：域名解析失败（ENOTFOUND）

检测时间：2026/10/14 09:00:00
来自 cert-checker
```

## 快速使用

```bash
npm install                            # 或 bash setup.sh（装依赖 + 生成 config.yml）
cp config.example.yml config.yml       # 用 setup.sh 的可跳过
vim config.yml                         # 填域名和通知渠道
node check.js                          # 立即检测一轮，终端输出剩余天数
node check.js --test feishu            # 验证通知渠道（收到测试消息即通）
```

脚本检测完一轮即退出。周期执行用 cron / systemd timer 调用 `node check.js` 即可（`deploy/` 目录有参考单元文件）；也可用 `--watch` 常驻模式。

## 配置说明（config.yml）

完整模板见 `config.example.yml`，每个字段有注释。

### 全局

| 字段 | 默认值 | 说明 |
|---|---|---|
| `threshold` | 30 | 剩余天数 ≤ 该值时告警（域名可覆盖） |
| `timeout` | 10 | 连接超时（秒） |

### domains 域名列表

| 字段 | 必填 | 说明 |
|---|---|---|
| `host` | 是 | 域名或 IP |
| `port` | 否 | 端口，默认 443 |
| `threshold` | 否 | 该域名的专属阈值 |
| `remark` | 否 | 备注，显示在通知里 |
| `notify` | 否 | 通知模板名，走 `templates` 对应渠道；不填走顶层 `notify` |

```yaml
threshold: 30

domains:
  - host: www.example.com
  - host: api.example.com
    port: 8443
    threshold: 14
    remark: API 网关
  - host: open.example.com
    notify: boss           # 走「boss」模板的渠道
```

### 域名注册到期检测（whois，可选）

上面检测的是**证书**到期；域名本身的注册有效期（续费时间）是另一回事，用独立的 `whois` 段配置，机制与证书检测完全一样（独立阈值、独立域名列表、同样支持 `notify` 模板分组和每日去重）：

```yaml
whois:
  threshold: 30          # 域名到期阈值（独立于证书的 threshold）
  timeout: 15            # 查询超时（秒，whois 查询比证书握手慢）
  domains:
    - host: example.com          # 只填主域名，不带 www 和路径
      remark: 主域名
      notify: ops                # 走「ops」模板，证书域名告警都发飞书
    - host: example.cn
      threshold: 14
```

- 数据来自域名**注册局**（RDAP 优先、WHOIS 43 端口兜底），与注册商无关——阿里云、腾讯云、GoDaddy、Namecheap 等注册的域名都能查
- 所有国际后缀（.com/.net/.io/.dev/.xyz 等 1200+ TLD）走 RDAP；`.cn` 等走 CNNIC WHOIS
- 证书告警和域名告警是两条独立消息（标题分别为【HTTPS 证书告警】【域名到期告警】），互不干扰
- RDAP 服务器映射文件会缓存到脚本目录（`rdap-bootstrap.json`，7 天更新一次）
- 个别国家后缀的注册局不公布到期时间，会显示为检测失败，属正常现象

### 通知渠道（notify / templates）

顶层 `notify` 是默认渠道，四个渠道均可选、配了哪个发哪个，可多选：

```yaml
notify:
  email:
    smtp: { host: smtp.qq.com, port: 465, user: your@qq.com, pass: 授权码 }
    to: [admin@example.com]
  feishu:
    webhook: https://open.feishu.cn/open-apis/bot/v2/hook/xxx
  wecom:
    webhook: https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx
  dingtalk:
    webhook: https://oapi.dingtalk.com/robot/send?access_token=xxx
```

各渠道字段：

| 渠道 | 字段 | 说明 |
|---|---|---|
| `email` | `smtp.host/port/user/pass` | SMTP 参数，`pass` 是**授权码**不是登录密码（465=SSL，587=STARTTLS） |
| | `from` / `to` | 发件人（可选，默认同 user）/ 收件人列表 |
| `feishu` | `webhook` | 群自定义机器人地址 |
| | `secret` | 签名密钥，机器人开了"签名校验"才填 |
| `wecom` | `webhook` | 群机器人地址 |
| `dingtalk` | `webhook` | 群自定义机器人地址 |
| | `secret` | 加签密钥，安全设置选了"加签"才填 |

**webhook / 授权码从哪里拿：**

- **飞书**：群聊 → 设置 → 群机器人 → 添加「自定义机器人」→ 复制 webhook（开签名校验则同时复制密钥）
- **企微**：群聊 → 群机器人 → 添加机器人 → 复制 webhook
- **钉钉**：群聊 → 机器人 → 添加「自定义」→ 复制 webhook。安全设置三选一：关键词填 `告警`（证书/域名告警和测试消息都含"告警"二字，可直接通过）；选加签则把 SEC 密钥填到 `secret`
- **邮箱**：QQ/163 等需在网页版设置开启 SMTP 并生成授权码。常用服务器：QQ `smtp.qq.com`、163 `smtp.163.com`、腾讯企业邮 `smtp.exmail.qq.com`，端口均 465

### 分域名通知（templates，可选）

不同域名通知到不同渠道组合：

```yaml
domains:
  - host: a.example.com
    notify: ops            # → 飞书
  - host: b.example.com
    notify: boss           # → 钉钉 + 邮箱
  - host: c.example.com     # → 顶层默认渠道

templates:
  ops:
    feishu:
      webhook: https://open.feishu.cn/open-apis/bot/v2/hook/xxx
  boss:
    dingtalk:
      webhook: https://oapi.dingtalk.com/robot/send?access_token=xxx
    email:
      smtp: { host: smtp.qq.com, port: 465, user: your@qq.com, pass: 授权码 }
      to: [boss@example.com]
```

- 模板名自定义，**用英文**（如 `ops`、`boss`、`team-a`），不可用保留字 `email` / `feishu` / `wecom` / `dingtalk` / `all`
- 同一模板触发的多个域名合并为一条消息
- 引用未定义的模板名会报错退出，不会静默丢告警

### 通知触发规则

- 触发条件：剩余天数 ≤ 阈值（域名覆盖值优先），或检测失败（DNS 错误、超时、whois 查不到等）
- 证书与域名的告警分开判定、分开成消息；同一域名可以同时出现在两处（证书快到期 + 域名快到期会收到两条）
- 同一检测项（证书按 host:port、域名按 host）**每天最多通知一次**，记录在脚本目录的 `state.json`
- 到期处理后（换证/续费）自动重置，下次临近到期会重新提醒
- 退出码：本轮有告警时为 1，正常为 0

## 命令

| 命令 | 作用 |
|---|---|
| `node check.js` | 检测一轮后退出 |
| `node check.js --watch 3600` | 常驻模式，每 3600 秒一轮 |
| `node check.js --test feishu` | 发测试消息验证渠道（`feishu` / `wecom` / `dingtalk` / `email` / `all`） |
| `node check.js --test ops` | 向指定模板的全部渠道发测试消息（参数为模板名） |
| `node check.js --dry-run` | 只检测打印，不发通知 |
| `node check.js --config /路径/cfg.yml` | 指定配置文件（默认脚本目录下 config.yml，state.json 也存同目录） |

## FAQ

**想先看看通知效果？** 把 `threshold` 临时改成 `9999` 跑一次，所有域名都会触发告警。

**通知收不到？** 按序排查：手动 `node check.js` 看检测输出 → `node check.js --test 渠道名` 看报错信息（webhook 无效 / 授权码错误会直接打印）→ 邮件查垃圾箱 → 钉钉检查安全设置关键词是否匹配。

**为什么在告警状态却没再提醒？** 每天去重所致，`rm state.json` 重置后下一轮会重新通知。

**whois 域名查不到到期时间？** 国际后缀走 RDAP 需要访问 `data.iana.org`（首次会下载映射文件，失败自动回退 WHOIS）；`.cn` 走 CNNIC 的 43 端口，服务器需放行出网 43 端口。个别国家后缀注册局不公布到期时间，属正常限制。

**改了配置要重启吗？** 每轮运行都重新读配置，cron/timer 方式改完即生效；`--watch` 常驻模式需重启进程。

## 项目结构

```
check.js               # 主脚本（入口）
lib/                   # 证书检测 / 域名到期检测（whois） / 通知 / 去重逻辑
config.example.yml     # 配置模板（复制为 config.yml 使用）
setup.sh               # 一键初始化（装依赖 + 生成配置）
deploy/                # cron / systemd 参考文件
config.yml             # 你的配置（含密钥，已 gitignore）
state.json             # 通知去重状态（自动生成）
rdap-bootstrap.json    # RDAP 服务器映射缓存（自动生成，7 天更新）
```
