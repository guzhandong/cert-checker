#!/usr/bin/env bash
# cert-checker 一键初始化脚本
# 用法：bash setup.sh
set -e

cd "$(dirname "$0")"

echo "==> [1/3] 检查 Node.js 环境 ..."
if ! command -v node >/dev/null 2>&1; then
  echo "✖ 未检测到 Node.js，请先安装 Node 18+（https://nodejs.org）"
  exit 1
fi
NODE_MAJOR=$(node -e 'console.log(process.versions.node.split(".")[0])')
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "✖ Node 版本过低（当前 $(node -v)），需要 18+，请升级"
  exit 1
fi
echo "    Node $(node -v) ✔"

echo "==> [2/3] 安装依赖 ..."
npm install --no-fund --no-audit

echo "==> [3/3] 生成配置文件 ..."
if [ -f config.yml ]; then
  echo "    config.yml 已存在，跳过（不覆盖你已有的配置）"
else
  cp config.example.yml config.yml
  echo "    已生成 config.yml"
fi

cat <<'EOF'

初始化完成 ✔ 接下来两步：

  1. 编辑配置文件，填入要监控的域名和通知渠道：
       vim config.yml
       （证书到期检测配 domains；域名注册到期检测配 whois.domains，两者可只用其一）

  2. 立即检测一轮（先不用配通知也能看到结果）：
       node check.js

配好通知渠道后，发条测试消息验证：
       node check.js --test feishu   # 或 wecom / dingtalk / email / all

周期执行可参考 deploy/ 目录下的 cron / systemd 示例文件。

EOF
