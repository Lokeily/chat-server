# 聊天室服务端
# 构建并运行（数据保存在 ./data，删容器不丢数据）：
#   docker build -t chat-server .
#   docker run -d --name chat -p 8080:8080 -p 8443:8443 -v "$PWD/data:/app/data" chat-server
# 或者直接用 docker compose：docker compose up -d
FROM node:22-alpine

WORKDIR /app

# 先装依赖再拷代码：只要 package.json 没变，改代码不用重装依赖
COPY package.json ./
RUN npm install --omit=dev --no-fund --no-audit

COPY server.js install.sh ./
COPY lib ./lib
COPY public ./public

# 运行时数据（SQLite + 加密密钥 + 上传文件）全部挂在这里
VOLUME ["/app/data"]

EXPOSE 8080 8443

ENV NODE_ENV=production

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null --no-verbose http://127.0.0.1:${PORT:-8080}/ || exit 1

CMD ["node", "server.js"]
