#!/usr/bin/env bash
# =============================================================
# 聊天室一键安装脚本
#  适用：Ubuntu / Debian / CentOS / Rocky / AlmaLinux 等主流 Linux
#  功能：安装 Node.js 22 → 安装依赖 → 生成随机后台路径 → systemd 开机自启
#  用法：
#     sudo bash install.sh
#   或自定义：
#     sudo PORT=9000 ADMIN_PATH=/my-admin bash install.sh
# =============================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="chat"
ADMIN_PATH="${ADMIN_PATH:-}"
PORT="${PORT:-8080}"
HTTPS_PORT="${HTTPS_PORT:-8443}"
NODE_MAJOR="22"

say(){ printf '\033[36m==>\033[0m %s\n' "$1"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$1"; }
die(){ printf '\033[31m[X]\033[0m %s\n' "$1"; exit 1; }

# ---------- 0. 检查 root ----------
if [ "$(id -u)" -ne 0 ]; then
  die "请用 root 运行：sudo bash install.sh"
fi

# ---------- 1. 检测并安装 Node.js 22 ----------
if command -v node >/dev/null 2>&1; then
  NODE_V="$(node -v 2>/dev/null | sed 's/^v//')"
  NODE_MAJ="$(echo "$NODE_V" | cut -d. -f1)"
  if [ "${NODE_MAJ:-0}" -ge 22 ]; then
    say "已检测到 Node.js v${NODE_V}（满足 ≥22），跳过安装"
  else
    warn "已检测到 Node.js v${NODE_V}（过低，需要 ≥22）"
    say "将为你升级到 Node.js ${NODE_MAJOR}…"
    install_node
  fi
else
  say "未检测到 Node.js，开始安装 Node.js ${NODE_MAJOR}（nvm 方式，不影响系统其它软件包）…"
  install_node
fi

install_node(){
  # 优先用 nodesource 官方源；失败再退回 nvm
  if command -v curl >/dev/null 2>&1 && [ -f /etc/os-release ]; then
    if curl -fsSL "https://rpm.nodesource.com/setup_${NODE_MAJOR}.x" -o /tmp/nodesource-setup.sh 2>/dev/null \
      || curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" -o /tmp/nodesource-setup.sh 2>/dev/null; then
      bash /tmp/nodesource-setup.sh >/dev/null 2>&1 && \
      (command -v apt-get >/dev/null 2>&1 && apt-get install -y nodejs >/dev/null 2>&1) || \
      (command -v yum >/dev/null 2>&1 && yum install -y nodejs >/dev/null 2>&1) || true
      rm -f /tmp/nodesource-setup.sh
    fi
  fi
  if ! command -v node >/dev/null 2>&1 || [ "$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1)" -lt 22 ]; then
    warn "nodesource 安装未生效，改用 nvm 安装 Node.js ${NODE_MAJOR}…"
    export NVM_DIR="${NVM_DIR:-/usr/local/nvm}"
    if [ ! -s "$NVM_DIR/nvm.sh" ]; then
      curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh -o /tmp/nvm-install.sh
      bash /tmp/nvm-install.sh >/dev/null 2>&1 || die "nvm 安装失败，请手动安装 Node.js ≥22"
      rm -f /tmp/nvm-install.sh
      export NVM_DIR="$HOME/.nvm"
    fi
    # shellcheck disable=SC1091
    [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
    nvm install "$NODE_MAJOR" >/dev/null 2>&1 || die "nvm install ${NODE_MAJOR} 失败"
    nvm alias default "$NODE_MAJOR" >/dev/null 2>&1 || true
  fi
  command -v node >/dev/null 2>&1 || die "Node.js 安装失败，请手动安装 Node.js ≥22 后重试"
  say "Node.js 就绪：$(node -v)"
}

# ---------- 2. 安装依赖 ----------
say "安装 npm 依赖…"
cd "$APP_DIR"
npm install --omit=dev --no-fund --no-audit || die "npm install 失败"

# ---------- 3. 生成管理后台路径 ----------
if [ -z "$ADMIN_PATH" ]; then
  ADMIN_PATH="/$(head -c 6 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 8)"
  [ -z "$ADMIN_PATH" ] && ADMIN_PATH="/admin-$(date +%s)"
fi
[[ "$ADMIN_PATH" != /* ]] && ADMIN_PATH="/$ADMIN_PATH"

# ---------- 4. 写 systemd 服务 ----------
UNIT="/etc/systemd/system/${APP_NAME}.service"
ENV_FILE="$APP_DIR/.env"
cat > "$ENV_FILE" <<EOF
PORT=$PORT
HTTPS_PORT=$HTTPS_PORT
ADMIN_PATH=$ADMIN_PATH
EOF
chmod 600 "$ENV_FILE"

cat > "$UNIT" <<EOF
[Unit]
Description=Chat Server (Node.js realtime chat)
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$(command -v node) server.js
Restart=always
RestartSec=3
# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=$APP_DIR/data

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$APP_NAME" >/dev/null 2>&1 || warn "systemctl enable 失败（不影响本次启动）"
systemctl restart "$APP_NAME" || die "服务启动失败，请查看：journalctl -u ${APP_NAME} -n 50"

# ---------- 5. 健康检查 ----------
sleep 3
CODE="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:${PORT}/" 2>/dev/null || echo 000)"
case "$CODE" in
  200|302|403) say "服务已启动，HTTP 响应 $CODE" ;;
  *) warn "健康检查返回 $CODE（可能端口被占用，可用 PORT=xxxx 指定别的端口）" ;;
esac

# ---------- 6. 输出结果 ----------
IP="$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo '你的服务器IP')"
say "==================== 安装完成 ===================="
say "  聊天室：      http://${IP}:${PORT}"
say "  管理后台：    http://${IP}:${PORT}${ADMIN_PATH}"
say "  初始管理员：  首次启动自动创建，见："
say "               cat ${APP_DIR}/data/INITIAL_ADMIN.txt"
say "  服务管理：    systemctl status chat | restart chat | stop chat | logs: journalctl -u chat"
say "  防火墙：      请放通 ${PORT}（HTTP）与 ${HTTPS_PORT}（HTTPS）端口"
say "=================================================="
echo ""
echo "⚠  首次使用请登录后立刻在后台修改初始管理员密码。"
echo "   数据全部保存在 ${APP_DIR}/data/（含加密密钥 secret.key，务必定期备份）。"
