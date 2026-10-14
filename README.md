# cert-checker — 轻量证书 / 域名到期监控

单脚本 + 一个 YAML 配置文件：定时检测域名 **HTTPS 证书** 和 **域名注册** 的剩余天数，到期前 N 天通过 **邮箱 / 飞书 / 企业微信 / 钉钉** 发送告警。默认跑完一轮即退出（配 cron / systemd timer 用，也可 `--watch` 常驻），无数据库，仅 2 个依赖（js-yaml、nodemailer），需要 Node.js ≥ 18。

- 证书到期（TLS 握手取证书）与域名到期（注册局 RDAP/WHOIS）两套独立检测、独立阈值
- 通知渠道统一按 `groups` 分组配置；每个域名可指定一个或多个分组，不指定走 `default` 分组
- 每天最多提醒一次（按域名 × 分组去重），续费 / 换证后自动重置；同组多个域名合并成一条消息不刷屏

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

周期执行用 cron / systemd timer 调用 `node check.js`（`deploy/` 目录有参考单元文件）。

## 完整配置示例

一份覆盖全部功能的 `config.yml`，可直接复制后按需删改（各字段说明见下一节）：

```yaml
# ---- 全局设置 ----
threshold: 30            # 剩余天数 ≤ 30 时开始告警（每个域名可单独覆盖）
timeout: 10              # 连接超时（秒）

# ---- 证书到期检测（TLS 握手）----
domains:
  - host: www.example.com          # 必填
    remark: 官网                    # 备注，会显示在通知里
  - host: api.example.com
    port: 8443                     # 非标端口才需要填，默认 443
    threshold: 14                  # 该域名专属阈值，覆盖全局
    remark: API 网关
    notify: ops                    # 告警发到 ops 分组
  - host: intranet.example.com
    notify: [ops, boss]            # 支持同时推多个分组，每个分组都会收到

# ---- 域名注册到期检测（RDAP/WHOIS，可选，与证书检测完全独立）----
whois:
  threshold: 30                    # 域名到期阈值（独立于证书的 threshold）
  timeout: 15                      # 查询超时（秒），whois 比证书握手慢
  domains:
    - host: example.com            # 只填主域名，不带 www 和路径
      remark: 主域名
      notify: [default, ops]       # 同样支持多分组

# ---- 通知分组：所有通知渠道统一配在这里 ----
groups:
  default:                         # 域名没配 notify 时走这个分组
    feishu:
      webhook: https://open.feishu.cn/open-apis/bot/v2/hook/xxx
      # secret: 加签密钥           # 机器人开了"签名校验"才填
  ops:                             # 分组名自定义，用英文
    wecom:
      webhook: https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx
  boss:
    dingtalk:
      webhook: https://oapi.dingtalk.com/robot/send?access_token=xxx
      secret: SECxxxxxxxx          # 机器人安全设置选了"加签"时必填
    email:                         # 一个分组里可配多个渠道，告警会同时发
      smtp:
        host: smtp.qq.com          # QQ: smtp.qq.com / 163: smtp.163.com / 腾讯企业邮: smtp.exmail.qq.com
        port: 465                  # 465 = SSL，587 = STARTTLS（国内一般用 465）
        user: your@qq.com
        pass: SMTP授权码            # 不是登录密码！邮箱网页版设置里开启 SMTP 后生成
      to: [boss@example.com]       # 收件人列表
```

就这三块：**检测什么**（`domains` / `whois.domains`）、**发给谁**（`groups` 分组）、**谁发给哪个组**（域名的 `notify` 字段，不填走 `default`）。只用证书检测就删掉 `whois` 段，反之亦然。

## 字段参考

### 全局

| 字段 | 默认值 | 说明 |
|---|---|---|
| `threshold` | 30 | 剩余天数 ≤ 该值时告警（域名可覆盖） |
| `timeout` | 10 | 连接超时（秒） |

### domains / whois.domains 里的每个域名

| 字段 | 必填 | 说明 |
|---|---|---|
| `host` | 是 | 域名或 IP；whois 检测只填主域名，不带 www 和路径 |
| `port` | 否 | 端口，默认 443（仅证书检测有意义） |
| `threshold` | 否 | 该域名的专属阈值 |
| `remark` | 否 | 备注，显示在通知里 |
| `notify` | 否 | 通知分组名，字符串或数组（如 `ops` / `[ops, boss]`）；不填走 `default` 分组 |

### groups 里的每个分组

每个分组可配以下四个渠道的**任意组合**，配了哪个就发哪个，全不配则只打印结果：

| 渠道 | 字段 | 说明 |
|---|---|---|
| `feishu` | `webhook` | 群机器人地址 |
| | `secret` | 签名密钥，机器人开了"签名校验"才填 |
| `wecom` | `webhook` | 群机器人地址 |
| `dingtalk` | `webhook` | 群机器人地址 |
| | `secret` | 加签密钥，机器人安全设置选了"加签"才填 |
| `email` | `smtp.host/port/user/pass` | SMTP 参数，`pass` 是**授权码**不是登录密码 |
| | `from` / `to` | 发件人（可选，默认同 user）/ 收件人列表 |

- 分组名用英文（如 `ops`、`boss`、`team-a`），不可用保留字 `email` / `feishu` / `wecom` / `dingtalk` / `all`
- 域名引用未定义的分组名会报错退出，不会静默丢告警
- 旧版写法（顶层 `notify`、`templates`）仍可运行，但会提示迁移到 `groups`

**webhook / 授权码从哪里拿：**

- **飞书**：群聊 → 设置 → 群机器人 → 添加「自定义机器人」→ 复制 webhook（开签名校验则连密钥一起复制）
- **企微**：群聊 → 群机器人 → 添加机器人 → 复制 webhook
- **钉钉**：群聊 → 机器人 → 添加「自定义」→ 复制 webhook。安全设置三选一：关键词填 `告警`（告警和测试消息都含"告警"二字，可直接通过）；选加签则把 SEC 密钥填到 `secret`
- **邮箱**：QQ/163 等在网页版设置开启 SMTP 并生成授权码

## 通知行为

- 触发条件：剩余天数 ≤ 阈值（域名覆盖值优先），或检测失败（DNS 错误、超时、whois 查不到等）
- 证书与域名的告警分开判定、分开成消息；同一域名可以两条都收到（证书快到期 + 域名快到期）
- 每个检测项（证书按 host:port、域名按 host）**每天最多通知一次**，记录在脚本目录的 `state.json`
- 配了多个分组的域名按「域名 × 分组」独立去重：某个分组发送失败时，下一轮只重试失败的分组
- 续费 / 换证后自动重置，下次临近到期会重新提醒；`rm state.json` 可手动重置
- 退出码：本轮有告警时为 1，正常为 0

## whois 检测说明

- 数据来自域名**注册局**（RDAP 优先、WHOIS 43 端口兜底），与注册商无关——阿里云、腾讯云、GoDaddy、Namecheap 等注册的域名都能查
- 国际后缀（.com/.net/.io/.dev/.xyz 等 1200+ TLD）走 RDAP，首次会从 `data.iana.org` 下载映射文件（缓存为 `rdap-bootstrap.json`，7 天更新一次）；`.cn` 等走 CNNIC 的 WHOIS 43 端口，服务器需放行出网
- 个别国家后缀的注册局不公布到期时间，会显示为检测失败，属正常限制

## 命令

| 命令 | 作用 |
|---|---|
| `node check.js` | 检测一轮后退出 |
| `node check.js --watch 3600` | 常驻模式，每 3600 秒一轮 |
| `node check.js --test feishu` | 发测试消息验证渠道（`feishu` / `wecom` / `dingtalk` / `email`，渠道名测 default 分组；`all` 测全部分组） |
| `node check.js --test ops` | 向指定分组的全部渠道发测试消息（参数为分组名） |
| `node check.js --dry-run` | 只检测打印，不发通知 |
| `node check.js --config /路径/cfg.yml` | 指定配置文件（默认脚本目录下 config.yml，state.json 也存同目录） |

## FAQ

**想先看看通知效果？** 把 `threshold` 临时改成 `9999` 跑一次，所有域名都会触发告警。

**通知收不到？** 按序排查：手动 `node check.js` 看检测输出 → `node check.js --test 渠道名` 看报错信息（webhook 无效 / 授权码错误会直接打印）→ 邮件查垃圾箱 → 钉钉检查安全设置关键词是否匹配。

**为什么在告警状态却没再提醒？** 每天去重所致，`rm state.json` 重置后下一轮会重新通知。

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
