'use strict';

/**
 * 实时聊天平台 · 服务端
 * 运行时：Node.js >= 22（使用内置 node:sqlite，无需编译原生模块）
 * 依赖：express / socket.io / multer / bcryptjs
 *
 * 功能：账号登录鉴权、公共聊天室、WebSocket 实时推送、文件上传（不限制大小）、
 *      后台账号管理、数据全部落盘保存。
 */

const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const zlib = require('zlib');
const { Transform } = require('stream');
const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');
const { DatabaseSync } = require('node:sqlite');
const vault = require('./lib/crypto');
const geo = require('./lib/geo');
const { rateLimit } = require('./lib/ratelimit');
const { canAccessFile, resolveReplyTo } = require('./lib/access');

const ROOT = __dirname;
// 数据目录默认在 data/，可用 CHAT_DATA_DIR 环境变量覆盖（测试/多实例用）
const DATA_DIR = path.resolve(process.env.CHAT_DATA_DIR || path.join(ROOT, 'data'));
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const PUBLIC_DIR = path.join(ROOT, 'public');
const CERT_DIR = path.join(ROOT, 'certs');
const PORT = Number(process.env.PORT || 8080);
const HTTPS_PORT = Number(process.env.HTTPS_PORT || 8443);
const HOST = process.env.HOST || '0.0.0.0';
const SESSION_TTL = 30 * 24 * 3600 * 1000; // 登录有效期 30 天
const COOKIE_NAME = 'chat_session';
const MAX_TEXT = 4000;
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 12);
// 单文件上传上限（默认 5MB）。图片/语音/普通文档足够；如确需传大视频再调 UPLOAD_MAX_MB。
// 无上限 = 任意大文件占满磁盘 + 拖垮 4Mbps 带宽，是未认证放大的资源耗尽面。
const UPLOAD_MAX_MB = Number(process.env.UPLOAD_MAX_MB || 5);
const UPLOAD_MAX_BYTES = UPLOAD_MAX_MB * 1024 * 1024;
// 关键词检索时最多扫描的历史条数（正文加密，SQL 不能直接 LIKE，只能取出解密后过滤）
const SEARCH_SCAN_MAX = Number(process.env.SEARCH_SCAN_MAX || 20000);
const FAIL_WINDOW = 10 * 60 * 1000;  // （已迁移到账号级封禁）为兼容旧配置保留
const FAIL_MAX = 10;
// 服务器出口带宽（Mbps）：只用于前端估算「下载大概要多久」，不影响实际传输。
// 按你的服务器实际带宽调整（或设 LINK_BANDWIDTH_MBPS）。
const LINK_BANDWIDTH_MBPS = Number(process.env.LINK_BANDWIDTH_MBPS) || 4;

// 地域准入配置存这个文件：后台改完立即生效，重启也不丢
const GEO_CONF_FILE = path.join(DATA_DIR, 'geo.json');
// 紧急开关：这个文件一旦存在就完全关闭地域拦截。
// 忘了自己把规则配错导致进不来时，SSH 上去 touch 一下就恢复了。
const GEO_KILL_FILE = path.join(DATA_DIR, 'geo-guard-off');
// 仅本地验证用：见 clientIp() 的说明
const GEO_TEST_IP = process.env.GEO_TEST_IP || '';

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// P1 修复：收紧数据目录与数据库文件权限 —— 数据库含会话令牌等明文敏感信息，
// 644 意味着同机其他用户可读（被拖库面）。
// ① 全局 umask 077：之后由本进程创建的一切文件（chat.db / WAL / secret.key / 上传密文）
//    天然就是 600/700，不依赖单个文件逐个 chmod；
// ② 显式 chmod 兼容已存在的旧目录/旧库（冷启动时 db 尚未创建，也要事后补一次）。
try {
  process.umask(0o077);
  fs.chmodSync(DATA_DIR, 0o700);
  fs.chmodSync(UPLOAD_DIR, 0o700);
  const tightenDb = () => {
    try {
      if (fs.existsSync(path.join(DATA_DIR, 'chat.db'))) fs.chmodSync(path.join(DATA_DIR, 'chat.db'), 0o600);
      for (const sfx of ['-wal', '-shm']) {
        const p = path.join(DATA_DIR, 'chat.db' + sfx);
        if (fs.existsSync(p)) fs.chmodSync(p, 0o600);
      }
    } catch (e) { /* 收紧失败不阻断启动 */ }
  };
  tightenDb();
  // 冷启动后 db 刚创建，文件模式由 umask 保证（077 → 600），再保险地补一次
  setTimeout(tightenDb, 1500);
} catch (e) {
  console.warn('[chat] 数据目录权限收紧失败（不影响运行，建议手动 chmod）：', e.message);
}

// 初始化加密密钥 —— 必须早于任何加解密操作
const KEY_SOURCE = vault.initKey(DATA_DIR);

/* ==================== 数据库 ==================== */

const db = new DatabaseSync(path.join(DATA_DIR, 'chat.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  nickname      TEXT    NOT NULL,
  role          TEXT    NOT NULL DEFAULT 'member',
  disabled      INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  last_seen     INTEGER,
  created_by    TEXT,
  known_ips     TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ua         TEXT
);
CREATE TABLE IF NOT EXISTS files (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL,
  orig_name   TEXT    NOT NULL,
  stored_name TEXT    NOT NULL,
  size        INTEGER NOT NULL,
  mime        TEXT,
  created_at  INTEGER NOT NULL,
  encrypted   INTEGER NOT NULL DEFAULT 0,
  iv          TEXT,
  tag         TEXT
);
CREATE TABLE IF NOT EXISTS messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL,
  kind       TEXT    NOT NULL DEFAULT 'text',
  body       TEXT,
  file_id    INTEGER,
  created_at INTEGER NOT NULL,
  revoked    INTEGER NOT NULL DEFAULT 0,
  reply_to   INTEGER,
  duration   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_msg_id ON messages(id DESC);
CREATE INDEX IF NOT EXISTS idx_sess_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id);
CREATE TABLE IF NOT EXISTS message_reads (
  message_id INTEGER NOT NULL,
  user_id    INTEGER NOT NULL,
  read_at    INTEGER NOT NULL,
  PRIMARY KEY (message_id, user_id)
);
CREATE TABLE IF NOT EXISTS message_reactions (
  message_id INTEGER NOT NULL,
  user_id    INTEGER NOT NULL,
  emoji      TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (message_id, user_id, emoji)
);
CREATE INDEX IF NOT EXISTS idx_reactions_msg ON message_reactions(message_id);
CREATE INDEX IF NOT EXISTS idx_reads_msg ON message_reads(message_id);
CREATE TABLE IF NOT EXISTS message_deletes (
  user_id    INTEGER NOT NULL,
  message_id INTEGER NOT NULL,
  deleted_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, message_id)
);
`);

// 老版本数据库补齐新增列（列已存在时会报错，忽略即可）
for (const ddl of [
  'ALTER TABLE files ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE files ADD COLUMN iv TEXT',
  'ALTER TABLE files ADD COLUMN tag TEXT',
  'ALTER TABLE users ADD COLUMN last_ip TEXT',
  'ALTER TABLE messages ADD COLUMN reply_to INTEGER',
  'ALTER TABLE messages ADD COLUMN duration INTEGER'
]) {
  try { db.exec(ddl); } catch (_) { /* 已存在 */ }
}

// IP 归属地缓存 + 访问审计
db.exec(`
CREATE TABLE IF NOT EXISTS ip_region (
  ip         TEXT PRIMARY KEY,
  country    TEXT,
  province   TEXT,
  city       TEXT,
  isp        TEXT,
  src        TEXT,
  ok         INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS access_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ip         TEXT    NOT NULL,
  region     TEXT,
  province   TEXT,
  city       TEXT,
  isp        TEXT,
  allowed    INTEGER NOT NULL DEFAULT 1,
  reason     TEXT,
  path       TEXT,
  method     TEXT,
  username   TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_access_time ON access_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_ip ON access_log(ip);

-- 账号级登录封禁（1 分钟 → 5 分钟 → 10 分钟 → 永久）
CREATE TABLE IF NOT EXISTS login_bans (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL UNIQUE,
  level       INTEGER NOT NULL DEFAULT 1,     -- 1=1min 2=5min 3=10min 4=永久
  strike      INTEGER NOT NULL DEFAULT 0,     -- 当前周期内已连续错误次数
  banned_until INTEGER,                       -- 临时封禁解禁时间；永久封禁为 NULL
  reason      TEXT,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

-- 陌生 IP 登录待放行（仅本次有效）
CREATE TABLE IF NOT EXISTS login_approvals (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL,
  username    TEXT    NOT NULL,
  ip          TEXT    NOT NULL,
  region      TEXT,
  province    TEXT,
  city        TEXT,
  isp         TEXT,
  ua          TEXT,
  status      TEXT    NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
  used        INTEGER NOT NULL DEFAULT 0,          -- 1=已使用（本次登录已完成）
  decided_by  TEXT,
  decided_at  INTEGER,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approval_pending ON login_approvals(status, used);

-- 登录动态日志（每次登录尝试一条）
CREATE TABLE IF NOT EXISTS login_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER,
  username    TEXT,
  ip          TEXT,
  region      TEXT,
  province    TEXT,
  city        TEXT,
  isp         TEXT,
  ua          TEXT,
  result      TEXT    NOT NULL,   -- success | fail | banned | locked | pending | denied | geo_blocked
  reason      TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_loginlog_time ON login_log(id DESC);
CREATE INDEX IF NOT EXISTS idx_loginlog_user ON login_log(user_id);
-- 管理操作审计（管理员在后台的敏感动作：增删用户、改权限、重置密码、改地域规则等）
CREATE TABLE IF NOT EXISTS admin_audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id    INTEGER,
  admin_user  TEXT,
  action      TEXT    NOT NULL,
  target      TEXT,
  detail      TEXT,
  ip          TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON admin_audit(id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_admin ON admin_audit(admin_user);
-- 离线 @ 提醒落库（P2-1）：被 @ 的用户无论在线与否都记一条，登录/连接时补推
CREATE TABLE IF NOT EXISTS mentions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL,
  user_id    INTEGER NOT NULL,
  read_at    INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mentions_user ON mentions(user_id, read_at);
-- 会话置顶（F2）：user 把自己的私聊会话置顶，pinned_at 越大越靠前
CREATE TABLE IF NOT EXISTS conversation_pins (
  user_id   INTEGER NOT NULL,
  peer_id   INTEGER NOT NULL,
  pinned_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, peer_id)
);
-- 会话偏好（F12）：每用户每会话的主题色/背景，key 只收白名单内的
CREATE TABLE IF NOT EXISTS conversation_settings (
  user_id   INTEGER NOT NULL,
  peer_id   INTEGER NOT NULL,
  key       TEXT    NOT NULL,
  value     TEXT,
  PRIMARY KEY (user_id, peer_id, key)
);
-- 群公告（F8）
CREATE TABLE IF NOT EXISTS announcements (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  title       TEXT,
  body        TEXT    NOT NULL,
  created_by  INTEGER,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  active      INTEGER NOT NULL DEFAULT 1
);
-- 敏感词（F9）
CREATE TABLE IF NOT EXISTS sensitive_words (
  word       TEXT PRIMARY KEY,
  created_by INTEGER,
  created_at INTEGER NOT NULL
);
`);

geo.configure({
  base: process.env.GEO_API_BASE || undefined,
  timeout: process.env.GEO_TIMEOUT_MS ? Number(process.env.GEO_TIMEOUT_MS) : undefined,
  enabled: process.env.GEO_LOOKUP !== '0',
  store: {
    get(ip) {
      const r = db.prepare('SELECT * FROM ip_region WHERE ip = ?').get(ip);
      if (!r) return null;
      return {
        ok: !!r.ok, country: r.country || '', province: r.province || '',
        city: r.city || '', isp: r.isp || '', src: r.src || '', at: r.updated_at
      };
    },
    put(ip, rec) {
      db.prepare(
        'INSERT INTO ip_region (ip, country, province, city, isp, src, ok, updated_at) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?) ' +
        'ON CONFLICT(ip) DO UPDATE SET country=excluded.country, province=excluded.province, ' +
        'city=excluded.city, isp=excluded.isp, src=excluded.src, ok=excluded.ok, updated_at=excluded.updated_at'
      ).run(ip, rec.country || '', rec.province || '', rec.city || '', rec.isp || '',
        rec.src || '', rec.ok ? 1 : 0, rec.at || Date.now());
    }
  }
});

const MSG_SELECT = `
SELECT m.id, m.user_id, m.kind, m.body, m.file_id, m.created_at, m.revoked, m.reply_to, m.duration, m.peer_id,
       u.username, u.nickname, u.role AS user_role,
       f.orig_name AS file_name, f.size AS file_size, f.mime AS file_mime,
       ru.nickname AS reply_nick, ru.username AS reply_user,
       rf.orig_name AS reply_fname,
       rm.body AS reply_body, rm.revoked AS reply_revoked, rm.kind AS reply_kind
FROM messages m
LEFT JOIN users u ON u.id = m.user_id
LEFT JOIN files f ON f.id = m.file_id
LEFT JOIN messages rm ON rm.id = m.reply_to
LEFT JOIN users ru ON ru.id = rm.user_id
LEFT JOIN files rf ON rf.id = rm.file_id
`;

/* ==================== 工具函数 ==================== */

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) {
      try { out[k] = decodeURIComponent(v); } catch (_) { out[k] = v; }
    }
  }
  return out;
}

// multer 默认按 latin1 解析文件名，中文会乱码，这里还原成 UTF-8
function fixFilename(name) {
  if (!name) return 'file';
  try {
    const utf = Buffer.from(name, 'latin1').toString('utf8');
    return utf.includes('\uFFFD') ? name : utf;
  } catch (_) {
    return name;
  }
}

// 解密失败（例如密钥被换过）不应该让整页崩溃，降级成占位文案
function safeDecrypt(v, fallback) {
  try {
    const out = vault.decryptText(v);
    return out === null || out === undefined ? fallback : out;
  } catch (_) {
    return fallback;
  }
}

function serializeMessage(r) {
  let file = null;
  if (r.file_id) {
    file = {
      id: r.file_id,
      name: safeDecrypt(r.file_name, '[文件名无法解密]') || '文件',
      size: r.file_size || 0,
      mime: r.file_mime || 'application/octet-stream',
      url: '/api/files/' + r.file_id
    };
  }
  const out = {
    id: r.id,
    kind: r.kind,
    // 没有正文（如纯图片/文件消息）要老老实实返回 null，
    // 否则 safeDecrypt 会把兜底文案「[内容无法解密]」当成说明显示出来。
    body: r.revoked ? null : (r.body ? safeDecrypt(r.body, '[内容无法解密]') : null),
    revoked: !!r.revoked,
    createdAt: r.created_at,
    peer: Number(r.peer_id || 0),          // 0=公共房间；>0=与该用户的私聊
    duration: (r.duration && Number(r.duration) > 0) ? Number(r.duration) : null,
    user: {
      id: r.user_id,
      username: r.username || '',
      nickname: r.nickname || '已注销用户',
      role: r.user_role || 'member'
    },
    file
  };
  // 引用回复：带上被引用消息的作者和摘要（只取展示用字段，不回溯更深）
  if (r.reply_to) {
    let text = '';
    if (r.reply_fname) text = '[文件] ' + safeDecrypt(r.reply_fname, '文件');
    else if (r.reply_revoked) text = '（该消息已撤回）';
    else text = (safeDecrypt(r.reply_body, '') || '').slice(0, 80);
    out.reply = {
      id: r.reply_to,
      nickname: r.reply_nick || '已注销用户',
      username: r.reply_user || '',
      text: text || '[内容无法解密]'
    };
  }
  return out;
}

/**
 * 已读回执：返回「消息 id -> 已读该消息的人昵称数组」，只针对作者为 authorId 的消息。
 * 用于历史加载时就把发送者自己消息的已读情况带回去，避免刷新后看不到之前的已读名单。
 */
function readersFor(messages, authorId) {
  const ids = messages.filter(m => m.user && m.user.id === authorId).map(m => m.id);
  if (!ids.length) return {};
  const qmarks = ids.map(() => '?').join(',');
  const rows = db.prepare(
    'SELECT mr.message_id AS mid, u.nickname AS nick FROM message_reads mr ' +
    'LEFT JOIN users u ON u.id = mr.user_id ' +
    'WHERE mr.message_id IN (' + qmarks + ')'
  ).all(...ids);
  const map = {};
  for (const r of rows) {
    if (!r.nick) continue;
    (map[r.mid] = map[r.mid] || []).push(r.nick);
  }
  return map;
}

function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    nickname: row.nickname,
    role: row.role,
    disabled: !!row.disabled
  };
}

// 语音未读标记：别人的语音消息，在「消息里没有我的已读记录」时标红点。
function voiceUnreadIds(messages, uid) {
  if (!uid) return new Set();
  const targets = messages.filter(m => m.user && m.user.id !== uid &&
    m.kind === 'file' && m.file && /^audio\//.test(m.file.mime || ''));
  if (!targets.length) return new Set();
  const qmarks = targets.map(() => '?').join(',');
  const rows = db.prepare(
    'SELECT DISTINCT message_id FROM message_reads WHERE user_id = ? AND message_id IN (' + qmarks + ')'
  ).all(uid, ...targets.map(m => m.id));
  const readIds = new Set(rows.map(r => r.message_id));
  const out = new Set(targets.map(m => m.id).filter(id => !readIds.has(id)));
  return out;
}
const NOT_DELETED_BY = 'm.id NOT IN (SELECT message_id FROM message_deletes WHERE user_id = ?)';

/* ---------- 表情回应（微信式 reactions）----------
 * 一条消息可以被多人用不同表情回应；同一个人对同一条消息的同一个表情只能有一次
 * （再点一次即取消）。这里按 message_id 批量取，避免每条消息各查一次把接口拖成 N+1。
 * 返回结构：[{ emoji, count, mine, users:['昵称',…] }]，users 用于悬浮显示「谁回应了」。
 */
function reactionsFor(messages, uid) {
  const ids = messages.map(m => m.id).filter(Boolean);
  if (!ids.length) return {};
  const qmarks = ids.map(() => '?').join(',');
  const rows = db.prepare(
    'SELECT r.message_id AS mid, r.emoji AS emoji, r.user_id AS uid, u.nickname AS nick ' +
    'FROM message_reactions r LEFT JOIN users u ON u.id = r.user_id ' +
    'WHERE r.message_id IN (' + qmarks + ') ORDER BY r.created_at ASC'
  ).all(...ids);
  const map = {};
  for (const r of rows) {
    const list = (map[r.mid] = map[r.mid] || []);
    let slot = list.find(x => x.emoji === r.emoji);
    if (!slot) { slot = { emoji: r.emoji, count: 0, mine: false, users: [] }; list.push(slot); }
    slot.count++;
    if (r.nick) slot.users.push(r.nick);
    if (uid && r.uid === uid) slot.mine = true;
  }
  return map;
}

/** 单条消息的表情回应（socket 事件里广播时用，避免调用方再拼一遍 SQL） */
function reactionsOf(messageId, uid) {
  return reactionsFor([{ id: messageId }], uid)[messageId] || [];
}

/** 取某条消息的明文正文（库里存的是密文，必须经 serializeMessage 解密后才拿得到） */
function srcBodyOf(row) {
  try {
    const m = serializeMessage(row);
    return m && m.body ? m.body : null;
  } catch (_) { return null; }
}

/** 只把事件发给某个用户的全部在线连接 */
function emitToUser(userId, event, data) {
  const set = onlineUsers.get(Number(userId));
  if (!set) return;
  for (const sid of set) io.to(sid).emit(event, data);
}

/* 会话范围：peer=0 → 公共房间；peer>0 → 我与该用户的双向私聊 */
function convScope(me, peer) {
  const p = Number(peer) || 0;
  if (p > 0) {
    return {
      sql: '((m.user_id = ? AND m.peer_id = ?) OR (m.user_id = ? AND m.peer_id = ?))',
      args: [me, p, p, me]
    };
  }
  return { sql: 'm.peer_id = 0', args: [] };
}

function getMessages(before, limit, userId, peer) {
  const lim = Math.min(Math.max(Number(limit) || 40, 1), 100);
  const uid = Number(userId) || 0;
  const scope = convScope(uid, peer);
  const conds = [];
  const args = [];
  if (before && Number(before) > 0) { conds.push('m.id < ?'); args.push(Number(before)); }
  conds.push(scope.sql); args.push.apply(args, scope.args);
  if (uid) { conds.push(NOT_DELETED_BY); args.push(uid); }
  const sql = MSG_SELECT + (conds.length ? ' WHERE ' + conds.join(' AND ') : '') +
    ' ORDER BY m.id DESC LIMIT ?';
  args.push(lim);
  const stmt = db.prepare(sql);
  return stmt.all.apply(stmt, args).reverse().map(serializeMessage);
}

// 断线重连后补齐漏掉的消息：取 id 大于游标的那些
function getMessagesAfter(after, limit, userId, peer) {
  const lim = Math.min(Math.max(Number(limit) || 100, 1), 200);
  const uid = Number(userId) || 0;
  const scope = convScope(uid, peer);
  const conds = ['m.id > ?'];
  const args = [Number(after)];
  conds.push(scope.sql); args.push.apply(args, scope.args);
  if (uid) { conds.push(NOT_DELETED_BY); args.push(uid); }
  const sql = MSG_SELECT + ' WHERE ' + conds.join(' AND ') + ' ORDER BY m.id ASC LIMIT ?';
  args.push(lim);
  const stmt = db.prepare(sql);
  return stmt.all.apply(stmt, args).map(serializeMessage);
}

function countMessages(peer) {
  const scope = convScope(0, peer);
  // 注意：convScope 里的条件都是 m. 前缀，这里必须给表起别名 m
  const stmt = db.prepare('SELECT COUNT(*) AS c FROM messages m WHERE ' + scope.sql);
  return stmt.get.apply(stmt, scope.args).c;
}

/**
 * 历史检索。
 * 注意：消息正文与文件名都是密文入库的，SQL 里的 LIKE 只能匹配到密文，毫无意义，
 * 所以必须把最近 SEARCH_SCAN_MAX 条取出来、解密之后在内存里过滤。
 * 这是"加密存储"换来的必然代价：安全了，但检索变成全表扫描。
 */
function searchMessages(q, limit, userId) {
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 100);
  const uid = Number(userId) || 0;
  // 只搜「我看得见的」：公共消息 + 与我相关的私聊。绝不能把别人的私聊搜出来。
  const vis = uid
    ? { sql: '(m.peer_id = 0 OR m.user_id = ? OR m.peer_id = ?)', args: [uid, uid] }
    : { sql: 'm.peer_id = 0', args: [] };
  const conds = [vis.sql];
  const args = vis.args.slice();
  if (uid) { conds.push(NOT_DELETED_BY); args.push(uid); }
  const sql = MSG_SELECT + ' WHERE ' + conds.join(' AND ') + ' ORDER BY m.id DESC LIMIT ?';
  args.push(SEARCH_SCAN_MAX);
  // P1 修复：只 prepare 一次（原实现把同一条 SQL prepare 了两遍，第二份实例从未被使用）
  const stmt = db.prepare(sql);
  const rows = stmt.all.apply(stmt, args);
  const needle = q.toLowerCase();
  const hits = [];
  for (const r of rows) {
    const body = r.revoked ? '' : (safeDecrypt(r.body, '') || '');
    const fname = r.file_id ? (safeDecrypt(r.file_name, '') || '') : '';
    const hay = (body + '\n' + fname + '\n' + (r.nickname || '') + '\n' + (r.username || '')).toLowerCase();
    if (hay.indexOf(needle) >= 0) {
      hits.push(r);
      if (hits.length >= lim) break;
    }
  }
  return hits.reverse().map(serializeMessage);
}

// 敏感词表（F9）：启动时加载进内存，发消息时统一命中替换
let sensitiveWords = [];
(function loadSensitiveWords() {
  try {
    sensitiveWords = db.prepare('SELECT word FROM sensitive_words').all().map(r => r.word);
  } catch (_) { sensitiveWords = []; }
})();
/** F9：命中敏感词 → 替换成 ***。返回 { text, censored } */
function censorText(text) {
  if (!sensitiveWords.length || !text) return { text, censored: false };
  let out = String(text);
  let hit = false;
  for (const w of sensitiveWords) {
    if (!w) continue;
    if (out.indexOf(w) >= 0) {
      hit = true;
      out = out.split(w).join('***');
    }
  }
  return { text: out, censored: hit };
}

function createMessage(userId, kind, body, fileId, replyTo, duration, peerId) {
  const now = Date.now();
  const dur = (duration && Number(duration) > 0) ? Math.min(Math.round(Number(duration)), 600) : null;
  const peer = (peerId && Number(peerId) > 0) ? Number(peerId) : 0;
  // F9：文本消息统一过敏感词（密文之前替换，落库即已净化）。
  // 文件/图片消息的说明文字（caption，kind='file'）同样是面向所有人的文本，
  // 必须走同一道过滤，否则「发文件+含敏感词说明」就成了绕过敏感词的通道。
  let finalBody = body;
  if ((kind === 'text' || kind === 'file') && body) {
    const c = censorText(String(body));
    finalBody = c.text;
  }
  const info = db.prepare(
    'INSERT INTO messages (user_id, kind, body, file_id, created_at, reply_to, duration, peer_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(userId, kind, finalBody ? vault.encryptText(finalBody) : null, fileId || null, now,
    (replyTo && Number(replyTo) > 0) ? Number(replyTo) : null, dur, peer);
  const row = db.prepare(MSG_SELECT + ' WHERE m.id = ?').get(info.lastInsertRowid);
  const msg = serializeMessage(row);
  // 标记被替换过（可选：前端据此提示「内容含敏感词，已替换」）；文件说明同规则
  if ((kind === 'text' || kind === 'file') && body && censorText(String(body)).censored) msg.censored = true;
  return msg;
}

/**
 * 通话留痕消息（微信式）：通话结束后在聊天窗口显示一条系统说明，如
 *   「通话 00:35」         —— 已接通并结束
 *   「未接通」             —— 呼叫无应答 / 对方拒绝
 * body 存 JSON 字符串（加密）：{ st: missed|canceled|declined|ended, dur: 秒 }
 * kind='call'，duration 列再冗余存一次秒数（方便聚合统计，不依赖解析 body）。
 */
function createCallNote(userId, st, dur, peerId) {
  const body = JSON.stringify({ st: String(st || 'ended'), dur: Math.max(0, Math.round(dur || 0)) });
  return createMessage(userId, 'call', body, null, null, dur, peerId);
}

function createSession(userId, ua, ip) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at, ua, ip) VALUES (?, ?, ?, ?, ?, ?)')
    .run(token, userId, now, now + SESSION_TTL, String(ua || '').slice(0, 200), String(ip || '').slice(0, 64));
  return token;
}

function cookieString(token, maxAgeSec, secure) {
  return COOKIE_NAME + '=' + token +
    '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + maxAgeSec +
    (secure ? '; Secure' : '');
}

// 走 HTTPS（或经反代 X-Forwarded-Proto: https）时给会话 Cookie 加 Secure，
// 防止明文信道携带会话令牌；纯 HTTP 下不加，避免把用户锁在门外。
function isSecureReq(req) {
  return !!(req.secure || (req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https');
}

function authFromHeaders(headers) {
  const cookies = parseCookies(headers && headers.cookie);
  const token = cookies[COOKIE_NAME];
  if (!token) return null;
  const s = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!s) return null;
  if (s.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(s.user_id);
  if (!u || u.disabled) return null;
  return u;
}

/* ==================== 登录封禁（账号级，梯度循环） ==================== */

/**
 * 规则（需求）：
 *   连续错误 5 次 → 封 1 分钟
 *   再次连续错误 5 次 → 封 5 分钟
 *   再次连续错误 5 次 → 封 10 分钟
 *   然后回到第 1 档重新循环；循环满一整轮（1+5+10）后若仍继续错误 → 永久封禁，需管理员解封。
 * 管理员账号：不受「登录失败封禁」限制（密码对即可），但地域校验更严——
 * 必须在放行区域内、且归属地与运营商都能识别，才允许登录。
 */
const BAN_STRIKES_PER_LEVEL = 5;      // 每档需要连续错误几次
const BAN_LEVELS_MS = [60 * 1000, 5 * 60 * 1000, 10 * 60 * 1000]; // 1/5/10 分钟
const BAN_CYCLE_LEN = BAN_LEVELS_MS.length;                        // 3 档为一个循环

function banLockFor(userId, ua) {
  const row = db.prepare('SELECT * FROM login_bans WHERE user_id = ?').get(userId);
  if (!row) return null;
  if (row.level >= 4) {
    return { permanent: true, level: 4, until: null };
  }
  // 只有设了 banned_until 才算在锁定期（纯 strike 累计、未到 5 次不算封禁）
  if (!row.banned_until) return null;
  // 临时封禁过期：自动解除，但保留档位记录（下次再满 5 次会升到下一档）
  if (Date.now() >= row.banned_until) {
    db.prepare('UPDATE login_bans SET banned_until = NULL WHERE user_id = ?').run(userId);
    return null;
  }
  return { permanent: false, level: row.level, until: row.banned_until };
}

function banRemainMs(lock) {
  if (!lock) return 0;
  if (lock.permanent) return -1;
  return Math.max(0, lock.until - Date.now());
}

/**
 * 登录失败一次：strike+1，够 5 次就按序执行封禁档位并推进。
 * 档位语义（level = 已执行过的临时封禁次数）：
 *   level 0 → 封 1 分钟 → level 1
 *   level 1 → 封 5 分钟 → level 2
 *   level 2 → 封 10 分钟 → level 3
 *   level 3 → 永久封禁 → level 4（需管理员解封）
 * 解禁后记录不清除，档位持续推进；因此梯度是 1→5→10 一轮后仍错误 → 永久。
 */
function noteLoginFail(userId) {
  const now = Date.now();
  const row = db.prepare('SELECT * FROM login_bans WHERE user_id = ?').get(userId);
  if (row) {
    if (row.level >= 4) {
      db.prepare('UPDATE login_bans SET updated_at = ? WHERE user_id = ?').run(now, userId);
      return { permanent: true, level: 4 };
    }
    const strike = row.strike + 1;
    if (strike >= BAN_STRIKES_PER_LEVEL) {
      // 轮到一个临时档位执行
      if (row.level < BAN_LEVELS_MS.length) {
        const until = now + BAN_LEVELS_MS[row.level];
        const nextLevel = row.level + 1;
        db.prepare('UPDATE login_bans SET level = ?, strike = 0, banned_until = ?, updated_at = ? WHERE user_id = ?')
          .run(nextLevel, until, now, userId);
        return { permanent: false, level: nextLevel, until, durationMs: BAN_LEVELS_MS[row.level] };
      }
      // 1/5/10 分钟全部执行过一轮，本次满 5 次 → 永久封禁
      db.prepare("UPDATE login_bans SET level = 4, strike = 0, banned_until = NULL, reason = '连续错误次数过多，已永久封禁', updated_at = ? WHERE user_id = ?")
        .run(now, userId);
      return { permanent: true, level: 4, escalated: true };
    }
    db.prepare('UPDATE login_bans SET strike = ?, updated_at = ? WHERE user_id = ?').run(strike, now, userId);
    return { strike };
  }
  db.prepare(
    'INSERT INTO login_bans (user_id, level, strike, banned_until, created_at, updated_at) VALUES (?, 0, 1, NULL, ?, ?)'
  ).run(userId, now, now);
  return { strike: 1 };
}

/** 登录成功：清掉该账号的全部封禁记录 */
function clearBan(userId) {
  db.prepare('DELETE FROM login_bans WHERE user_id = ?').run(userId);
}

/* ==================== IP 级兜底限流（防止无差别爆破，不误伤正常用户） ==================== */

const ipFails = new Map();
const IP_FAIL_MAX = 20;              // 单个 IP 一分钟内失败超过 20 次才临时掐一下
const IP_FAIL_WINDOW = 60 * 1000;

function ipBlocked(ip) {
  const rec = ipFails.get(ip);
  if (!rec) return false;
  if (Date.now() - rec.at > IP_FAIL_WINDOW) {
    ipFails.delete(ip);
    return false;
  }
  return rec.count >= IP_FAIL_MAX;
}

function noteIpFail(ip) {
  const rec = ipFails.get(ip);
  if (!rec || Date.now() - rec.at > IP_FAIL_WINDOW) {
    ipFails.set(ip, { count: 1, at: Date.now() });
  } else {
    rec.count += 1;
  }
}

function clearIpFails(ip) {
  ipFails.delete(ip);
}

/* ==================== 地域准入 ==================== */

// 放行范围：**默认不限制任何地区**（开源部署后由管理员在后台「访问安全」自行配置）。
// 两级独立限制：省（provOn/provinces）、市（cityOn/cities）。
// 两个开关相互独立、可同时开启；开启的开关对应列表非空时才算限制，列表为空=不限制。
// 环境变量可作初始值：GEO_PROVINCES / GEO_CITIES（逗号分隔），
// 并可用 GEO_GUARD=on 启动即开启拦截（后台仍可改）。
const GEO_DEFAULT = {
  mode: process.env.GEO_GUARD || 'off',        // off | log | on
  provOn: process.env.GEO_PROV_ON === '1' || process.env.GEO_GUARD === 'on',
  provinces: (process.env.GEO_PROVINCES || '').split(',').map(s => s.trim()).filter(Boolean),
  cityOn: process.env.GEO_CITY_ON === '1',
  cities: (process.env.GEO_CITIES || '').split(',').map(s => s.trim()).filter(Boolean),
  allowIps: (process.env.GEO_ALLOW_IPS || '').split(',').map(s => s.trim()).filter(Boolean),
  // 查不到归属地 → 默认拦截（最高保密档）。归属地未知本身就是风险信号，
  // 不能再静默放行；确需临时放宽时显式设 GEO_FAIL_OPEN=1（或后台开关）。
  failOpen: process.env.GEO_FAIL_OPEN === '1'
};

// 规则版本号：
//   v2 = 「省 + 市」叠加（provinces 必填、cities 可选，cities 是省的下级过滤）
//   v3 = 「省/市」两级独立开关（provOn/cityOn + 各自列表）
// v2→v3 迁移：旧 provinces 保留；若旧配置是「云南 + 昆明」这种省+市叠加，
// 迁移后默认把省开关打开（保持原行为），市开关关闭（避免新逻辑下变成
// 「必须同时命中省和市」导致原已放行的城市被误伤）。
const GEO_RULE_VERSION = 3;

let geoConf = loadGeoConf();

function loadGeoConf() {
  let saved = {};
  try {
    if (fs.existsSync(GEO_CONF_FILE)) saved = JSON.parse(fs.readFileSync(GEO_CONF_FILE, 'utf8')) || {};
  } catch (e) {
    console.error('[chat] 地域配置读不出来，用默认值：', e.message);
    saved = {};
  }
  // v2 → v3 迁移：老配置是「省+市叠加」，转成新结构时只保留省开关，市开关默认关闭
  // （避免旧「云南+昆明」配置在新逻辑下变成必须省市都命中，把老用户全挡出去）。
  if (Number(saved.ruleVersion) < 3) {
    if (saved.provinces && saved.provinces.length) saved.provOn = true;
    else saved.provOn = false;
    saved.cityOn = false;
  }
  const c = Object.assign({}, GEO_DEFAULT, saved);
  c.ruleVersion = GEO_RULE_VERSION;
  if (!Array.isArray(c.provinces)) c.provinces = GEO_DEFAULT.provinces.slice();
  if (!Array.isArray(c.cities)) c.cities = GEO_DEFAULT.cities.slice();
  if (!Array.isArray(c.allowIps)) c.allowIps = GEO_DEFAULT.allowIps.slice();
  c.provOn = !!c.provOn;
  c.cityOn = !!c.cityOn;
  if (['off', 'log', 'on'].indexOf(c.mode) < 0) c.mode = 'on';
  if (process.env.GEO_GUARD) c.mode = String(process.env.GEO_GUARD).toLowerCase();
  return c;
}

function saveGeoConf(next) {
  geoConf = Object.assign({}, geoConf, next, { ruleVersion: GEO_RULE_VERSION });
  if (['off', 'log', 'on'].indexOf(geoConf.mode) < 0) geoConf.mode = 'on';
  try {
    fs.writeFileSync(GEO_CONF_FILE, JSON.stringify(geoConf, null, 2), { mode: 0o600 });
  } catch (e) {
    console.error('[chat] 地域配置写入失败：', e.message);
  }
  return geoConf;
}

function geoKillSwitchOn() {
  try { return fs.existsSync(GEO_KILL_FILE); } catch (_) { return false; }
}

/**
 * 取访问者真实 IP。
 * 特意不读 X-Forwarded-For —— 没挂反向代理时，那个头客户端想写什么就写什么，
 * 拿它做地域拦截等于把拦截范围让攻击者自己填。真挂了 Nginx 再用 TRUST_PROXY 指定。
 */
function clientIp(req) {
  const raw = (req.socket && req.socket.remoteAddress) ||
    (req.connection && req.connection.remoteAddress) || '';
  const ip = geo.normalizeIp(raw);
  // GEO_TEST_IP 是本地验证用的：把来源 IP 伪装成指定值，好在一台没有公网入口的机器上
  // 试拦截规则。它只对确实来自本机/内网的请求生效，外部访客拿到的仍是自己真实 IP，
  // 所以线上即使误设了这个变量，也不会削弱拦截。
  if (GEO_TEST_IP && geo.isPrivateIp(ip)) return GEO_TEST_IP;
  return ip;
}

/** 判定某个 IP 是否放行。返回 { allow, reason, region, mode } */
async function geoDecide(ip) {
  const mode = geoKillSwitchOn() ? 'off' : geoConf.mode;
  if (mode === 'off') return { allow: true, reason: '地域拦截已关闭', mode, region: null };

  // 本机回环地址永远放行：它不可能是外部访客（服务器自身的健康检查、同机进程用），
  // 归属地查询对回环地址也没有意义，不放行会导致部署自检被自己的规则挡住。
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost' || ip === '::ffff:127.0.0.1') {
    return { allow: true, reason: '本机回环地址', mode, region: null };
  }

  // 内网地址不再默认放行：10.x / 172.x / 192.168.x 通常是 NAT 出口，
  // 对方真实公网 IP 未知，按最高保密档一律走归属地查询判定（查不到则按 failOpen 拦截）。
  if (geoConf.allowIps.indexOf(ip) >= 0) {
    return { allow: true, reason: '在 IP 白名单中', mode, region: null };
  }

  const region = await geo.resolve(ip);
  const m = geo.matchRules(region, geoConf);

  if (m.hit === null) {
    const allow = geoConf.failOpen;
    return {
      allow, mode, region,
      reason: m.reason + (allow ? '，按「查不到就放行」处理，归属地未知有风险' : '，按「查不到就拦截」处理')
    };
  }
  return { allow: m.hit, reason: m.reason, mode, region };
}

/* ---------- 访问审计 ---------- */

const accessLastLog = new Map();      // ip -> 上次记录时间
const ACCESS_DEDUP_MS = 30 * 60 * 1000;
const ACCESS_KEEP = 3000;

function logAccess(rec) {
  try {
    db.prepare(
      'INSERT INTO access_log (ip, region, province, city, isp, allowed, reason, path, method, username, created_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      rec.ip || '', rec.region || '', rec.province || '', rec.city || '', rec.isp || '',
      rec.allowed ? 1 : 0, rec.reason || '',
      String(rec.path || '').slice(0, 120), String(rec.method || '').slice(0, 10),
      rec.username || null, Date.now()
    );
    // 只留最近 ACCESS_KEEP 条，免得日志表无限长
    const c = db.prepare('SELECT COUNT(*) AS c FROM access_log').get().c;
    if (c > ACCESS_KEEP) {
      db.prepare('DELETE FROM access_log WHERE id IN (SELECT id FROM access_log ORDER BY id DESC LIMIT -1 OFFSET ?)')
        .run(ACCESS_KEEP);
    }
  } catch (e) {
    console.error('[chat] 访问日志写入失败：', e.message);
  }
}

function shouldLogAccess(ip, allowed, kind) {
  const now = Date.now();
  if (!allowed) return true;                 // 被拦的一律记
  if (kind === 'login') return true;         // 登录一律记
  const last = accessLastLog.get(ip) || 0;
  if (now - last > ACCESS_DEDUP_MS) {
    accessLastLog.set(ip, now);
    return true;                             // 同一个 IP 最多半小时记一条
  }
  return false;
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** 从 User-Agent 解析出「设备 + 系统 + 浏览器」摘要，如「手机 · Android 14 · Chrome 126」。查不到就返回空。 */
function deviceFromUA(ua) {
  const s = String(ua || '');
  if (!s) return '';
  const os = /Windows NT 10\.0/.test(s) ? 'Windows 10/11'
    : /Windows NT 6\.3/.test(s) ? 'Windows 8.1'
    : /Windows NT 6\.1/.test(s) ? 'Windows 7'
    : /Android 1[4-9]/.test(s) ? 'Android ' + (s.match(/Android (1[4-9])/) || [])[1]
    : /Android 1[0-3]/.test(s) ? 'Android ' + (s.match(/Android (1[0-3])/) || [])[1]
    : /iPhone|iPad|iPod/.test(s) ? 'iOS'
    : /Mac OS X/.test(s) ? 'macOS'
    : /Linux/.test(s) ? 'Linux'
    : '';
  const dev = /iPad/.test(s) ? '平板' : /iPhone/.test(s) ? '手机' : /Android/.test(s) ? '手机' : /Mac|Windows|Linux/.test(s) ? '电脑' : '';
  const br = /Edg\//.test(s) ? 'Edge'
    : /OPR\//.test(s) ? 'Opera'
    : /Firefox\//.test(s) ? 'Firefox'
    : /Chrome\//.test(s) ? 'Chrome'
    : /Safari\//.test(s) ? 'Safari'
    : '';
  const parts = [dev, os, br].filter(Boolean);
  return parts.join(' · ') || '未知设备';
}

/* ---------- 登录动态日志 ---------- */

const LOGIN_LOG_KEEP = 5000;

/** result: success|fail|banned|locked|pending|denied|geo_blocked */
function logLogin(rec) {
  try {
    db.prepare(
      'INSERT INTO login_log (user_id, username, ip, region, province, city, isp, ua, result, reason, created_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      rec.user_id || null, rec.username || null, rec.ip || '', rec.region || '',
      rec.province || '', rec.city || '', rec.isp || '',
      String(rec.ua || '').slice(0, 200), rec.result,
      String(rec.reason || '').slice(0, 300), Date.now()
    );
    const n = db.prepare('SELECT COUNT(*) AS c FROM login_log').get().c;
    if (n > LOGIN_LOG_KEEP) {
      db.prepare('DELETE FROM login_log WHERE id IN (SELECT id FROM login_log ORDER BY id DESC LIMIT -1 OFFSET ?)')
        .run(LOGIN_LOG_KEEP);
    }
  } catch (e) {
    console.error('[chat] 登录日志写入失败：', e.message);
  }
}

function blockedPage(ip, d) {
  // 封锁页只展示访问者「自己的」IP 与归属地（配合"防自动程序"的观感），
  // 不泄露任何内部信息（放行规则、省市名单、管理员提示都不展示）。
  const region = (d && d.region) || null;
  const hasRegion = region && (region.province || region.city);
  const regionText = hasRegion ? geo.prettyRegion(region) : '未知';
  const ispText = (hasRegion && region.isp) || '';
  const safeIp = escapeHtml(ip || '');
  const safeRegion = escapeHtml(regionText);
  const safeIsp = escapeHtml(ispText);
  const riskNote = hasRegion ? '' :
    '<span class="risk">归属地未知 · 有风险</span>';

  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>访问已拒绝</title>
<style>
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0;display:grid;place-items:center;padding:24px;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
    background:#ededed;color:#111}
  .box{width:100%;max-width:440px;background:#fff;border-radius:12px;padding:36px 30px 28px;
    border:1px solid #e0e0e0;text-align:center}
  .ico{width:62px;height:62px;margin:0 auto 18px;border-radius:12px;display:grid;place-items:center;
    background:#e8f8ef;color:#07c160}
  .ico svg{width:28px;height:28px}
  h1{margin:0 0 10px;font-size:19px;font-weight:650}
  .threat{font-size:14px;color:#6b6b6b;line-height:1.7;margin:0 auto 20px;max-width:340px}
  .info{background:#f7f7f7;border:1px solid #ececec;border-radius:10px;padding:13px 15px;
    font-size:13px;color:#6b6b6b;line-height:1.85;margin-bottom:20px;text-align:left}
  .info .row{display:flex;gap:10px;align-items:baseline}
  .info .k{flex:0 0 58px;color:#a8a8a8;font-size:12.5px}
  .info .v{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;color:#111;word-break:break-all}
  .info .v.reg{font-family:inherit}
  .appeal{font-size:12.5px;color:#8b8b8b;line-height:1.8;margin:0 0 18px}
  .risk{display:inline-block;margin-left:6px;font-size:11px;font-weight:700;letter-spacing:.02em;
    color:#e64340;background:#fdecec;border:1px solid #f8c4c3;border-radius:999px;padding:1px 8px;vertical-align:1px}
  @media (max-width:480px){.box{padding:30px 20px 24px}}
</style></head>
<body><div class="box">
  <div class="ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
    stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <line x1="4.9" y1="4.9" x2="19.1" y2="19.1"/></svg></div>
  <h1>访问已拒绝</h1>
  <p class="threat">当前网络所在地不在允许范围内。<br>如有疑问，请联系管理员。</p>
  <div class="info">
    <div class="row"><span class="k">IP 地址</span><span class="v">${safeIp}</span></div>
    <div class="row"><span class="k">IP 归属地</span><span class="v reg">${safeRegion}${riskNote}</span></div>
    ${safeIsp ? '<div class="row"><span class="k">运营商</span><span class="v reg">' + safeIsp + '</span></div>' : ''}
  </div>
  <p class="appeal">如果您认为自己属于放行范围却被拦截，请把上面的 IP 地址发给管理员。<br>
    运营商对本机归属地的判定偶尔会漂到外省市，管理员核对后可单独放行。</p>
</div></body></html>`;
}

/**
 * 安全验证遮挡页（只服务「已放行」的访客）。
 *
 * 职责变化：以前这一页同时承担放行与拒绝两种结果（先转圈，转完原地变红），
 * 结果有一部分人被卡在「一直转圈」：慢网络、老浏览器、以及 cookie 被禁用的环境里，
 * setTimeout 之后的原地切换跑不完，页面看起来就是在无限加载。
 * 现在拒绝已经改由 geoGuard 直接 302 到独立的拒绝页（/__denied），
 * 这一页只剩「放行前转个圈」一件事，转完 reload 一次就进站。
 *
 * 三道兜底，确保任何时候都不会卡在转圈：
 *   ① 验证 cookie 由服务端下发（Set-Cookie），不依赖页面 JS 自己写；
 *   ② 重载次数计数，超过 2 次说明 cookie 写不进去（隐私模式 / App 内置浏览器），
 *      直接给一张说明卡 + 手动入口，而不是继续空转；
 *   ③ 无 JS 环境由 <noscript> 给出直链。
 */
// 转圈时长：够看清「正在验证」，又不至于让人以为卡了。
// 原来是 1.8s，实测偏长；公开使用时这是每次新会话都要付的首屏成本，压到 1.2s。
const CHALLENGE_WAIT_MS = 1200;

function challengePage(d, ip) {
  const region = (d && d.region) || null;
  const hasRegion = region && (region.province || region.city);
  const regionText = hasRegion ? geo.prettyRegion(region) : '未知';
  const ispText = (hasRegion && region.isp) || '';
  const safeIp = escapeHtml(ip || '');
  const safeRegion = escapeHtml(regionText);
  const safeIsp = escapeHtml(ispText);
  const riskNote = hasRegion ? '' : '<span class="risk">归属地未知 · 有风险</span>';

  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>正在验证状态，请稍后</title>
<style>
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0;display:grid;place-items:center;padding:24px;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
    background:#ededed;color:#111}
  .box{width:100%;max-width:440px;background:#fff;border-radius:12px;padding:40px 30px;
    border:1px solid #e0e0e0;text-align:center;transition:padding .3s ease}
  .ring{width:56px;height:56px;margin:0 auto 20px;position:relative;border-radius:50%;
    background:conic-gradient(from 0deg,#d9f7e5 0 25%,#07c160 25% 60%,#06ad56 60% 100%);
    -webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 6px),#000 calc(100% - 5px));
    mask:radial-gradient(farthest-side,transparent calc(100% - 6px),#000 calc(100% - 5px));
    animation:spin .9s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  h1{margin:0 0 10px;font-size:19px;font-weight:650}
  .desc{font-size:13.5px;color:#6b6b6b;line-height:1.8;margin:0 auto;max-width:340px}
  .step{margin-top:18px;font-size:12.5px;color:#8b8b8b;min-height:18px}
  .step i{display:inline-block;width:6px;height:6px;border-radius:50%;background:#c7c7c7;margin-right:6px;
    vertical-align:1px;animation:blink 1.2s ease-in-out infinite}
  .step i:nth-child(2){animation-delay:.2s} .step i:nth-child(3){animation-delay:.4s}
  @keyframes blink{0%,100%{opacity:.3}50%{opacity:1}}
  /* 拒绝态 */
  .deny{display:none}
  .deny.show{display:block;animation:fade .3s ease}
  @keyframes fade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
  .ico{width:62px;height:62px;margin:0 auto 18px;border-radius:12px;display:grid;place-items:center;
    background:#fdecec;color:#e64340}
  .ico.ok{background:#e8f8ef;color:#07c160}
  .ico svg{width:28px;height:28px}
  .retry{display:inline-block;margin-top:6px;padding:9px 22px;border-radius:8px;text-decoration:none;
    background:#07c160;color:#fff;font-size:13.5px;font-weight:600}
  .retry:hover{background:#06ad56}
  .threat{font-size:14px;color:#6b6b6b;line-height:1.8;margin:0 auto 20px;max-width:340px}
  .info{background:#f7f7f7;border:1px solid #ececec;border-radius:10px;padding:13px 15px;
    font-size:13px;color:#6b6b6b;line-height:1.85;margin-bottom:20px;text-align:left}
  .info .row{display:flex;gap:10px;align-items:baseline}
  .info .k{flex:0 0 58px;color:#a8a8a8;font-size:12.5px}
  .info .v{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;color:#111;word-break:break-all}
  .info .v.reg{font-family:inherit}
  .risk{display:inline-block;margin-left:6px;font-size:11px;font-weight:700;letter-spacing:.02em;
    color:#e64340;background:#fdecec;border:1px solid #f8c4c3;border-radius:999px;padding:1px 8px;vertical-align:1px}
  @media (max-width:480px){.box{padding:32px 20px}}
</style></head>
<body><div class="box">

  <!-- 第一段：核验中 -->
  <div id="verify">
    <div class="ring" aria-hidden="true"></div>
    <h1>正在验证状态，请稍后</h1>
    <p class="desc">本网站使用安全服务防护恶意自动程序。<br>在验证您不是自动程序期间，将显示此页面。</p>
    <div class="step" id="step"><i></i><i></i><i></i> <span id="stepText">正在核验访问来源…</span></div>
  </div>

  <!-- 第二段：放行结果（判定为放行时才展示，见下方脚本） -->
  <div class="deny ok" id="pass" style="display:none">
    <div class="ico ok"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"
      stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></div>
    <h1>验证通过，正在进入</h1>
    <p class="threat">正在为您跳转到聊天室……</p>
  </div>

  <!-- 第三段：兜底（cookie 写不进去 / 环境异常，绝不让页面停在无限转圈） -->
  <div class="deny fail" id="fail" style="display:none">
    <div class="ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
      stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v5"/>
      <path d="M12 16.5v.01"/></svg></div>
    <h1>验证未能完成</h1>
    <p class="threat">当前浏览器可能禁用了 Cookie，本站的安全核验无法写入通过凭证。<br>
      请换用普通浏览器窗口重试，或在浏览器设置里允许本站 Cookie。</p>
    <div class="info">
      <div class="row"><span class="k">IP 地址</span><span class="v">${safeIp}</span></div>
      <div class="row"><span class="k">IP 归属地</span><span class="v reg">${safeRegion}${riskNote}</span></div>
      ${safeIsp ? '<div class="row"><span class="k">运营商</span><span class="v reg">' + safeIsp + '</span></div>' : ''}
    </div>
    <a class="retry" href="/" id="retryBtn">重试一次</a>
  </div>

  <noscript>
    <div class="deny fail" style="display:block">
      <h1>需要 JavaScript</h1>
      <p class="threat">本站的安全核验需要 JavaScript，<br>请开启后<a class="retry" href="/">重新进入</a>。</p>
    </div>
  </noscript>

</div>
<script>
  // 说明：服务端在返回本页时就已经下发了 kmc_challenge cookie（见 geoGuard），
  // 这里只负责「等一下 + 重载一次」，重载时浏览器会带上那个 cookie 直接进站。
  (function(){
    var key = 'kmc_challenge_tries';
    var tries = 0;
    try { tries = parseInt(sessionStorage.getItem(key) || '0', 10) || 0; } catch (_) {}
    if (tries >= 2) { showFail(); return; }
    try { sessionStorage.setItem(key, String(tries + 1)); } catch (_) {}

    var WAIT = ${CHALLENGE_WAIT_MS};
    var stepEl = document.getElementById('stepText');
    var steps = ['正在核验访问来源…', '正在比对安全策略…', '正在生成验证结果…'];
    var si = 0;
    var stepTimer = setInterval(function(){
      si++;
      if (si < steps.length && stepEl) stepEl.textContent = steps[si];
    }, Math.round(WAIT / 3));

    function showFail(){
      hide('verify');
      var f = document.getElementById('fail');
      if (f) f.style.display = 'block';
    }
    function hide(id){
      var el = document.getElementById(id);
      if (el) el.style.display = 'none';
    }

    setTimeout(function(){
      clearInterval(stepTimer);
      hide('verify');
      var p = document.getElementById('pass');
      if (p) p.style.display = 'block';
      try { document.cookie = 'kmc_challenge=1;path=/;max-age=${CHALLENGE_COOKIE_TTL};SameSite=Lax'; } catch (_) {}
      setTimeout(function(){
        // 重载后如果又被打回来（说明 cookie 没写进去），上面的 tries 计数会触发 fail 卡，
        // 不会形成「刷新—转圈—再刷新」的死循环。
        try { document.cookie = 'kmc_challenge=1;path=/;max-age=${CHALLENGE_COOKIE_TTL};SameSite=Lax'; } catch (_) {}
        location.replace(location.pathname + location.search + location.hash);
      }, 600);
    }, WAIT);

    // 最后一道保险：无论中间出了什么岔子，8 秒后必定有结果，绝不停在转圈
    setTimeout(function(){
      var v = document.getElementById('verify');
      if (v && v.style.display !== 'none') showFail();
    }, WAIT + 8000);
  })();
</script>
</body></html>`;
}

/** 判断当前请求是否已通过一次安全验证（带 kmc_challenge cookie，由服务端下发）。 */
// 验证结果的保留时长。
// 原来是 10 分钟：用户离开超过 10 分钟回来就要重新转一圈，日常使用成本太高。
// 改成 30 天：正常用户基本只验一次；爬虫不会持久化 cookie，拦截效果不受影响。
const CHALLENGE_COOKIE_TTL = 30 * 24 * 3600; // 秒

function hasChallengePassed(req) {
  const c = String(req.headers.cookie || '');
  return c.indexOf('kmc_challenge=') >= 0;
}

/** 拒绝页路径：被拦的人统一跳到这里，页面本身不参与放行判定。 */
const DENY_PATH = '/__denied';
// 一次性通行证：把「这次判定」的结果带到拒绝页去展示（IP / 归属地 / 运营商）。
// 之所以由服务端生成串再一次性作废，是为了避免有人直接构造 /__denied 探测，
// 也避免被浏览器历史前进后退反复消费。
const denyTokens = new Map();
const DENY_TOKEN_TTL = 10 * 60 * 1000;
const DENY_TOKEN_KEEP = 500;

function issueDenyToken(ip, d) {
  const k = crypto.randomBytes(12).toString('hex');
  denyTokens.set(k, { ip: ip, d: d, at: Date.now() });
  if (denyTokens.size > DENY_TOKEN_KEEP) {
    const cut = Date.now() - DENY_TOKEN_TTL;
    for (const key of Array.from(denyTokens.keys())) {
      const v = denyTokens.get(key);
      if (!v || v.at < cut) denyTokens.delete(key);
    }
  }
  return k;
}

function takeDenyToken(k) {
  if (!k) return null;
  const v = denyTokens.get(String(k));
  if (!v) return null;
  denyTokens.delete(String(k));
  return (Date.now() - v.at < DENY_TOKEN_TTL) ? v : null;
}

/** 判定失败/超时时的兜底决策（走 failOpen 策略），三处 catch 共用一份，避免口径漂移 */
function geoFallbackDecision(err) {
  console.error('[chat] 地域判定异常：', (err && err.message) || err);
  return {
    allow: !!geoConf.failOpen,
    reason: '归属地查询异常，按「查不到就' + (geoConf.failOpen ? '放行' : '拦截') + '」处理',
    mode: geoConf.mode,
    region: null
  };
}

/** 把一次「拒绝」落到响应上：接口回 JSON、页面 302 到拒绝页，两者都写审计 */
function respondBlocked(req, res, ip, d, isApi, wantsHtml) {
  setBlockedHeaders(res, false);
  if (req.path === '/api/login') {
    const un = String((req.body && req.body.username) || '').trim();
    logLogin({
      username: un || null, ip, region: geo.prettyRegion(d.region),
      province: d.region && d.region.province, city: d.region && d.region.city,
      isp: d.region && d.region.isp, ua: req.headers['user-agent'],
      result: 'geo_blocked', reason: d.reason
    });
  }
  if (isApi) {
    return res.status(403).json({
      error: '当前网络所在地不在允许范围内', detail: d.reason, code: 'GEO_BLOCKED'
    });
  }
  if (!wantsHtml) {
    // 静态资源之类没有页面的请求：直接把拒绝页塞进响应体，不牵扯跳转
    return res.status(403).type('html').send(blockedPage(ip, d));
  }
  // 页面请求：不再是「先转圈，转完原地变红」——那种写法在慢网络/老浏览器上很容易
  // 表现成「一直转圈没反应」。现在判定为拒绝就直接跳到一个独立的拒绝页。
  const k = issueDenyToken(ip, d);
  return res.redirect(302, DENY_PATH + '?k=' + k);
}

function geoGuard(req, res, next) {
  const ip = clientIp(req);

  // 拒绝页自身不做放行判定（否则会 302 到自身形成死循环）。
  // 带一次性凭证的请求：直接用签发时那次判定的结果渲染，不再重复查归属地（快且口径一致）。
  // 没有凭证的请求（手敲 / 收藏 / 历史前进）：重算一次判定，放行区的人就直接送回首页。
  if (req.path === DENY_PATH) {
    const hit = takeDenyToken(req.query.k);
    if (hit) {
      req.clientIp = ip;
      req.geoDecision = hit.d;
      setBlockedHeaders(res, false);
      return res.status(403).type('html').send(blockedPage(hit.ip, hit.d));
    }
    return geoDecide(ip).then(function (d) {
      req.clientIp = ip;
      req.geoDecision = d;
      if (d.allow || d.mode !== 'on') return res.redirect(302, '/');   // 放行区的人不该停在这页
      setBlockedHeaders(res, false);
      return res.status(403).type('html').send(blockedPage(ip, d));
    }).catch(function (e) {
      const d = geoFallbackDecision(e);
      req.clientIp = ip;
      req.geoDecision = d;
      setBlockedHeaders(res, false);
      return res.status(403).type('html').send(blockedPage(ip, d));
    });
  }

  const isApi = req.path.indexOf('/api/') === 0 || req.path.indexOf('/socket.io') === 0;
  const wantsHtml = !!req.headers.accept && req.headers.accept.indexOf('text/html') >= 0;
  const isHtmlPage = !isApi && wantsHtml;

  geoDecide(ip).then(function (d) {
    req.clientIp = ip;
    req.geoDecision = d;

    const blocked = !d.allow && d.mode === 'on';
    if (blocked || shouldLogAccess(ip, d.allow, req.path === '/api/login' ? 'login' : 'http')) {
      logAccess({
        ip, region: geo.prettyRegion(d.region),
        province: d.region && d.region.province, city: d.region && d.region.city, isp: d.region && d.region.isp,
        allowed: !blocked, reason: d.reason, path: req.path, method: req.method
      });
    }
    if (blocked) return respondBlocked(req, res, ip, d, isApi, wantsHtml);

    // 放行的访客：首次访问页面仍走一次「安全核验」遮挡页（挡廉价爬虫 + 观感），
    // 页面会自己 reload 一次带着 cookie 回来，之后不再重复核验。
    const preUser = authFromHeaders(req.headers);
    const isAdminUser = !!(preUser && preUser.role === 'admin');
    if (isHtmlPage && !isAdminUser && !hasChallengePassed(req)) {
      // 验证 cookie 改由服务端下发：靠页面 JS 写 cookie，一旦浏览器禁用 cookie
      // （隐私模式 / 部分 App 内置浏览器）就会「刷新—转圈—再刷新」无限循环。
      res.setHeader('Set-Cookie', 'kmc_challenge=1; Path=/; Max-Age=' + CHALLENGE_COOKIE_TTL + '; SameSite=Lax');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      return res.status(200).type('html').send(challengePage(d, ip));
    }
    next();
  }).catch(function (e) {
    // 判定过程本身出错（归属地接口挂了、超时）：按最高保密档处理——
    // 查不到归属地默认拦截（failOpen=false），绝不静默放行。
    const d = geoFallbackDecision(e);
    req.clientIp = ip;
    req.geoDecision = d;
    logAccess({
      ip, region: '未知', province: '', city: '', isp: '',
      allowed: d.allow, reason: d.reason, path: req.path, method: req.method
    });
    if (!d.allow) return respondBlocked(req, res, ip, d, isApi, wantsHtml);
    next();
  });
}

// 内容安全策略：只允许本站资源 + 内联脚本（本页无外部脚本，socket.io.js 由本站提供）。
// 作为单一来源，供正常页面 / 封禁页 / 异常页三处统一引用，避免改一处漏一处。
const CSP_HEADER =
  "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' ws: wss:; " +
  "frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

/** 给任意响应打上「封禁/异常页」用的安全头（含全禁 CSP 与禁止缓存） */
function setBlockedHeaders(res, micAllowed) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy',
    micAllowed
      ? 'camera=(self), microphone=(self), geolocation=(), payment=()'
      : 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Content-Security-Policy', CSP_HEADER);
}

/* ==================== Express ==================== */

const app = express();
app.disable('x-powered-by');
// 默认不信任 X-Forwarded-For：本服务是直接对外暴露 8080 的，
// 信任代理头会让客户端能自报 IP，地域拦截和登录限流都会被绕过。
// 如果以后在宝塔/Nginx 后面跑，再把 TRUST_PROXY 设成那台代理的地址。
if (process.env.TRUST_PROXY && process.env.TRUST_PROXY !== '0') {
  app.set('trust proxy', process.env.TRUST_PROXY === '1' ? true : process.env.TRUST_PROXY);
}
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

/* ---------- 静态资源压缩（启动提速核心） ----------
 * 首页 index.html 未压缩 238KB、socket.io.js 156KB，走 4Mbps 出口带宽要一两秒。
 * 用 zlib 的 gzip/brotli 按 Accept-Encoding 压缩后：
 *   index.html → br 55KB（降 77%），socket.io.js → br 32KB，首屏能明显变快。
 * 策略：响应头带 Content-Type 时，只压缩 text/html、application/javascript、
 *       application/json、text/css、text/plain、image/svg+xml 这些文本型；
 *       图片/音视频/已压缩文件一律跳过，避免 CPU 空烧。
 * brotli 优先级高于 gzip：现代浏览器都支持 br，省更多流量。
 *
 * 说明：express.static / res.sendFile 内部用 createReadStream().pipe(res)，
 * 数据走 write() 流过去、end() 不带 chunk，下面 res.send/res.end 的补丁覆盖不到。
 * 所以静态文件（含首页）由挂在 geoGuard 之后、express.static 之前的
 * STATIC_COMPRESS 中间件直接接管（见页面区），本补丁只负责 API 的 res.json/send/end。
 */
const COMPRESS_TYPES = /^(text\/|application\/(javascript|json|xml)|image\/svg\+xml)/;
app.use((req, res, next) => {
  // socket.io 握手和文件上传（multipart）不压缩
  if (req.path.indexOf('/socket.io') === 0) return next();
  const accept = String(req.headers['accept-encoding'] || '');
  const enc = accept.indexOf('br') >= 0 ? 'br' : (accept.indexOf('gzip') >= 0 ? 'gzip' : null);
  if (!enc) return next();
  const send = res.send;
  const end = res.end;
  const json = res.json;
  // 覆盖 res.json：API 响应也压缩
  res.json = function (body) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    return send.call(this, JSON.stringify(body));
  };
  res.send = function (body) {
    const type = String(this.getHeader('Content-Type') || '');
    if (!COMPRESS_TYPES.test(type) || typeof body !== 'string' && !Buffer.isBuffer(body)) {
      return send.apply(this, arguments);
    }
    this.setHeader('Content-Encoding', enc);
    this.removeHeader('Content-Length');
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
    const out = enc === 'br' ? zlib.brotliCompressSync(buf) : zlib.gzipSync(buf);
    this.setHeader('Content-Length', out.length);
    return send.call(this, out);
  };
  res.end = function (chunk, encoding, cb) {
    if (chunk !== undefined && chunk !== null && !this.getHeader('Content-Encoding')) {
      const type = String(this.getHeader('Content-Type') || '');
      if (COMPRESS_TYPES.test(type)) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const out = enc === 'br' ? zlib.brotliCompressSync(buf) : zlib.gzipSync(buf);
        this.setHeader('Content-Encoding', enc);
        this.removeHeader('Content-Length');
        this.setHeader('Content-Length', out.length);
        return end.call(this, out, encoding, cb);
      }
    }
    return end.apply(this, arguments);
  };
  next();
});

/* ---------- 安全响应头（隐私/安全增强） ----------
 * X-Content-Type-Options: 防 MIME 嗅探；Referrer-Policy: 不向外站泄露本站地址；
 * Permissions-Policy: 关掉本站用不到的摄像头/定位/麦克风等权限（录音只在授权时开）。
 * CSP 不全局加：聊天页要内联脚本 + socket.io 长连接 + 图片 blob，全局收紧会误伤功能，
 * 这里先上"零副作用"的头，CSP 留给后续按页定制。
 */
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=(self), payment=(), usb=()');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});

/* ---------- 扫描欺骗（scanner deception） ----------
 * 目的：让扫描器 / 漏洞探测器「以为打到了一台没东西可挖的机器」，
 * 而不是拿到「访问已被拒绝」这类一眼看出"本站有防护系统"的页面——
 * 防护系统一旦被识别，反而会招来更针对性的探测。
 *
 * 策略：命中常见扫描特征路径 → 返回一个和普通静态服务器一模一样的朴素 404
 * （无品牌、无防护痕迹、无任何本站特征），扫描器多半直接放弃。
 * 位置：放在 geoGuard 与 HTTPS 跳转之前，因此无论扫描器来自哪个省/国家，
 * 拿到的都是同一个朴素 404，无法据此判断"本站在做地域拦截"。
 * 只匹配「绝不可能是本站正常功能」的路径，正常页面/接口/静态资源一律不受影响。
 */
const SCAN_PATH_RE = [
  /^\/geoserver/i, /^\/evox/i, /^\/hnap1$/i, /^\/wp-(admin|login|content|includes|json)/i,
  /^\/wordpress/i, /^\/phpmyadmin/i, /^\/pma\//i, /^\/myadmin/i, /^\/xmlrpc\.php/i,
  /^\/cgi-bin/i, /^\/shell/i, /^\/vendor\/phpunit/i, /^\/actuator/i, /^\/druid/i,
  /^\/solr/i, /^\/console/i, /^\/manager\/html/i, /^\/jenkins/i, /^\/hudson/i,
  /^\/struts/i, /^\/nacos/i, /^\/eureka/i, /^\/jolokia/i, /^\/zabbix/i, /^\/grafana/i,
  /^\/kibana/i, /^\/elasticsearch/i, /^\/owa\//i, /^\/autodiscover/i, /^\/ecp\//i,
  /^\/dana-na/i, /^\/webui/i, /^\/\.env/i, /^\/\.git/i, /^\/\.svn/i, /^\/\.aws/i,
  /^\/\.ssh/i, /^\/\.docker/i, /^\/\.kube/i, /^\/\.ds_store$/i,
  /^\/config\.(json|php|ya?ml|ini)/i, /^\/nginx_status/i, /^\/server-status/i,
  /^\/backup/i, /^\/db\.(php|sql|bak)/i, /^\/eval/i, /^\/phpinfo/i, /^\/php_info/i,
  /^\/info\.php/i, /^\/test\.php/i, /^\/setup\.cgi/i, /^\/www\.(zip|tar|rar)/i
];
// 扫描器常探测的可执行/备份后缀：本站只提供 .html/.js/.css 等，这些后缀必属探测
const SCAN_EXT_RE = /\.(php|php\d|asp|aspx|jsp|jspx|cgi|pl|do|action|war|sql|bak|old|orig|swp|env)$/i;

function isScannerProbe(p) {
  if (!p) return false;
  if (SCAN_EXT_RE.test(p)) return true;
  for (let i = 0; i < SCAN_PATH_RE.length; i++) {
    if (SCAN_PATH_RE[i].test(p)) return true;
  }
  return false;
}

// 朴素 404：与普通静态服务器默认页一致，不含任何本站特征
const BORING_404 = '<html>\r\n<head><title>404 Not Found</title></head>\r\n' +
  '<body>\r\n<center><h1>404 Not Found</h1></center>\r\n</body>\r\n</html>\r\n';

app.use((req, res, next) => {
  const p = req.path || '/';
  if (!isScannerProbe(p)) return next();
  // 记录一次（同一 IP 半小时内只记一条，避免扫描器刷爆日志表）
  try {
    const ip = clientIp(req);
    const now = Date.now();
    const key = 'scan:' + ip;
    if (now - (accessLastLog.get(key) || 0) > ACCESS_DEDUP_MS) {
      accessLastLog.set(key, now);
      logAccess({
        ip, region: '扫描探测', province: '', city: '', isp: '',
        allowed: 0, reason: '扫描特征路径，已伪装为普通 404',
        path: p, method: req.method
      });
    }
  } catch (_) { /* 日志失败不影响响应 */ }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  return res.status(404).send(BORING_404);
});

// 强制 HTTPS：访问明文 8080 自动跳到 8443（保留路径），让录音等安全 API 可用。
// 例外（不跳）：本机健康检查（127.0.0.1/::1）、socket.io 握手、非 GET/HEAD、已加密连接。
// 开关：FORCE_HTTPS=0 关闭；默认开启。
// 注意：GEO_TEST_IP 存在时本机请求会被伪装成该公网 IP，此时不按本机豁免（便于本地验证跳转）。
if (process.env.FORCE_HTTPS !== '0') {
  app.use((req, res, next) => {
    const isLocalReq = req.ip === '127.0.0.1' || req.ip === '::1' || req.ip === '::ffff:127.0.0.1';
    const isLocal = isLocalReq && !GEO_TEST_IP;
    const isSocket = req.path.indexOf('/socket.io') === 0;
    const isEncrypted = !!req.socket.encrypted;
    if (!isEncrypted && !isLocal && !isSocket && (req.method === 'GET' || req.method === 'HEAD')) {
      const host = (req.headers.host || '').replace(/:\d+$/, '') || HOST;
      return res.redirect(302, 'https://' + host + ':' + HTTPS_PORT + req.originalUrl);
    }
    next();
  });
}
app.use(geoGuard);
app.use((req, res, next) => {
  // 最高保密档：任何页面/接口都不允许被浏览器缓存，杜绝「刷新仍进」的缓存幻觉。
  // 语音消息需要麦克风：Permissions-Policy 必须放行给本站（self），
  // 否则浏览器直接拒绝 getUserMedia，录音功能永远不可用。
  // 封禁页/异常页（见 geoGuard 内两处）保持全禁 microphone=()，正常页面才需要。
  setBlockedHeaders(res, true);
  // HSTS 已移除：它是 host 级机制（作用于整个站点域名），会覆盖下面所有端口。
  // 一旦浏览器通过 8443 访问过、记住 HSTS，之后访问 http 8080 会被浏览器静默改写为
  // https://...:8080，导致「切不回 8080」。本服务 8080(明文) 与 8443(HTTPS) 并存，
  // HSTS 与「数字 IP + 自签证书」的组合会毒化整站访问，故不再下发。
  next();
});

function requireAuth(req, res, next) {
  const u = authFromHeaders(req.headers);
  if (!u) return res.status(401).json({ error: '请先登录' });
  req.user = u;
  next();
}

function requireAdmin(req, res, next) {
  const u = authFromHeaders(req.headers);
  if (!u) return res.status(401).json({ error: '请先登录' });
  if (u.role !== 'admin') return res.status(403).json({ error: '需要管理员权限' });
  req.user = u;
  next();
}

/* ---------- 会话 ---------- */

app.post('/api/login', async (req, res) => {
  const ip = req.clientIp || 'unknown';
  const ua = req.headers['user-agent'];
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  // 一律回字符串：调用方有多处直接把它塞进 SQLite（如 login_approvals 的 INSERT），
  // 而归属地查不到时 region 是个 {ok:false} 对象、province 会是 undefined，
  // node:sqlite 遇到 undefined 会抛「cannot be bound to SQLite parameter」，整个请求 500。
  const regionOf = (d) => {
    const r = (d && d.region) || null;
    return {
      province: (r && r.province) || '',
      city: (r && r.city) || '',
      isp: (r && r.isp) || ''
    };
  };
  const geoOf = regionOf(req.geoDecision);
  const pretty = geo.prettyRegion(req.geoDecision && req.geoDecision.region);

  if (!username || !password) {
    return res.status(400).json({ error: '请输入账号和密码' });
  }

  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  // ---- IP 级兜底限流：一分钟内失败过 20 次的 IP 先喘口气 ----
  // 注意这只是防无差别爆破的兜底，不针对具体账号，正常用户基本不会碰到。
  if (ipBlocked(ip)) {
    const r2 = db.prepare('SELECT * FROM login_bans WHERE user_id = ?').get(row && row.id);
    logLogin({
      user_id: row && row.id, username: username || null, ip,
      region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp, ua,
      result: 'locked', reason: 'IP 触发临时限流'
    });
    return res.status(429).json({ error: '尝试过于频繁，请 1 分钟后再试', code: 'IP_RL' });
  }

  // ---- 账号不存在：不暴露"用户不存在"，与密码错同样对待 ----
  if (!row) {
    noteIpFail(ip);
    logLogin({ username: username || null, ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp, ua, result: 'fail', reason: '账号或密码不正确' });
    setImmediate(() => logAccess({
      ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp,
      allowed: true, reason: '登录失败：账号或密码不正确',
      path: '/api/login', method: 'POST', username: username || null
    }));
    return res.status(401).json({ error: '账号或密码不正确' });
  }

  const isAdmin = row.role === 'admin';
  const lock = banLockFor(row.id, ua);

  // 已知 IP 段记忆（放行体验优化）：同一用户登录成功过的 IPv4 /24 段记入 users.known_ips，
  // 之后从同段新 IP 登录直接放行。出口 IP 常在段内浮动（同一网络/同一运营商），逐 IP 审批体验很差。
  // 存的是完整「网络段地址」如 127.0.0.0/24；取「前三段」比，段前缀一致就算同段
  const ipSeg = ip.indexOf(':') >= 0 ? '' : (ip.split('.').slice(0, 3).join('.') + '.0/24');
  const segPrefix = ip.indexOf(':') >= 0 ? '' : ip.split('.').slice(0, 3).join('.');
  const knownIps = new Set(String(row.known_ips || '').split(',').map(s => s.trim()).filter(Boolean));
  const sameSeg = segPrefix
    ? Array.from(knownIps).some(k => {
        try { return k.indexOf('/') > 0 && k.split('/')[0].replace(/\.0$/, '') === segPrefix; }
        catch (_) { return false; }
      })
    : false;

  // ---- 管理员：权限最大 → 校验最严。密码对还不够，必须同时满足：
  //      ① 来源在放行省份内 ② 归属地能识别 ③ 运营商能识别
  //      （仅在「拦截」模式下强制；紧急关闭/只记录模式下放宽，避免把自己锁死）
  const adminPassOk = isAdmin ? await bcrypt.compare(password, row.password_hash) : false;
  if (isAdmin && adminPassOk) {
    const gd = req.geoDecision || {};
    const strict = gd.mode === 'on';
    const geoBlocked = strict && !gd.allow;
    // 「归属地能识别」的口径要和访问规则保持一致：
    //   省开关开 → 需要省；市开关开 → 需要省+市。
    // 否则会出现「普通用户能进、管理员登录不了」的自锁。
    const provOn = geoConf.provOn && (geoConf.provinces || []).length > 0;
    const cityOn = geoConf.cityOn && (geoConf.cities || []).length > 0;
    const needCity = cityOn;
    const hasRegion = needCity
      ? !!(geoOf.province && geoOf.city)
      : provOn
        ? !!(geoOf.province)
        : !!(geoOf.province || geoOf.city);
    const hasIsp = !!(geoOf.isp && String(geoOf.isp).trim());
    if (geoBlocked || (strict && (!hasRegion || !hasIsp))) {
      const why = !hasRegion ? '归属地无法识别'
        : !hasIsp ? '运营商无法识别'
        : '当前所属地不在放行范围';
      noteIpFail(ip);
      logLogin({
        user_id: row.id, username: row.username, ip, region: pretty,
        province: geoOf.province, city: geoOf.city, isp: geoOf.isp, ua,
        result: 'geo_blocked', reason: '管理员登录被拒绝：' + why
      });
      logAccess({
        ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp,
        allowed: false, reason: '管理员登录被拒绝：' + why,
        path: '/api/login', method: 'POST', username: row.username
      });
      return res.status(403).json({
        error: '管理员账号仅允许在指定区域登录（' + why + '）',
        code: 'ADMIN_GEO_BLOCKED',
        region: pretty
      });
    }
    clearBan(row.id);
    clearIpFails(ip);
    const token = createSession(row.id, ua, ip);
    const now = Date.now();
    // 管理员同样记录已知 IP 段（放行优化：管理员切换出口 IP 时免审批）
    let kmnown = new Set(String(row.known_ips || '').split(',').map(s => s.trim()).filter(Boolean));
    if (ipSeg) {
      kmnown.add(ipSeg);
      if (kmnown.size > 20) { const arr = Array.from(kmnown); kmnown = new Set(arr.slice(arr.length - 20)); }
      db.prepare('UPDATE users SET known_ips = ? WHERE id = ?').run(Array.from(kmnown).join(','), row.id);
    }
    db.prepare('UPDATE users SET last_seen = ?, last_ip = ? WHERE id = ?').run(now, ip, row.id);
    logLogin({ user_id: row.id, username: row.username, ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp, ua, result: 'success', reason: '管理员登录成功（地域校验通过）' });
    logAccess({ ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp, allowed: true, reason: '管理员登录成功', path: '/api/login', method: 'POST', username: row.username });
    res.setHeader('Set-Cookie', cookieString(token, Math.floor(SESSION_TTL / 1000), isSecureReq(req)));
    return res.json({ user: publicUser(row) });
  }

  // ---- 普通账号：先看封禁状态（密码对了也要先看锁没锁） ----
  if (lock) {
    if (lock.permanent) {
      logLogin({ user_id: row.id, username: row.username, ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp, ua, result: 'banned', reason: '账号已永久封禁，等待管理员解封' });
      return res.status(423).json({
        error: '该账号因连续错误次数过多已被永久封禁，请联系管理员解封',
        code: 'BANNED_PERM', blocked: true
      });
    }
    const remain = banRemainMs(lock);
    logLogin({ user_id: row.id, username: row.username, ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp, ua, result: 'banned', reason: '账号处于封禁中（第 ' + lock.level + ' 档）' });
    return res.status(423).json({
      error: '尝试次数过多，请在 ' + Math.ceil(remain / 1000) + ' 秒后再试',
      code: 'BANNED_TEMP', until: lock.until, remainMs: remain, level: lock.level, blocked: true
    });
  }

  // ---- 密码比对（非管理员走到这里才有意义；账号不存在已在上面拦截） ----
  const passOk = await bcrypt.compare(password, row.password_hash);
  if (!passOk) {
    noteIpFail(ip);
    const r = noteLoginFail(row.id);
    let reason = '账号或密码不正确';
    let extra = {};
    if (r.permanent) {
      reason = '连续错误次数过多，账号已被永久封禁';
      extra = { code: 'BANNED_PERM', blocked: true, error: '该账号因连续错误次数过多已被永久封禁，请联系管理员解封' };
    } else if (r.until) {
      const durMin = r.durationMs ? Math.round(r.durationMs / 60000) : Math.round((r.until - Date.now()) / 60000);
      reason = '连续错误 5 次，账号封禁 ' + durMin + ' 分钟';
      extra = { code: 'BANNED_TEMP', until: r.until, remainMs: Math.max(0, r.until - Date.now()), level: r.level, durationMin: durMin, blocked: true };
    } else {
      extra = { code: 'FAIL', strike: r.strike, remaining: BAN_STRIKES_PER_LEVEL - r.strike };
    }
    logLogin({ user_id: row.id, username: row.username, ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp, ua, result: r.permanent ? 'banned' : 'fail', reason });
    setImmediate(() => logAccess({
      ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp,
      allowed: true, reason: '登录失败：' + reason,
      path: '/api/login', method: 'POST', username: row.username
    }));
    return res.status(401).json(Object.assign({ error: extra.error || '账号或密码不正确' }, extra));
  }

  // 到这里：密码正确，继续检查账号状态
  if (row.disabled) {
    logLogin({ user_id: row.id, username: row.username, ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp, ua, result: 'denied', reason: '账号已被停用' });
    return res.status(403).json({ error: '该账号已被停用' });
  }

  // ---- 陌生 IP 放行机制：IP 与上次登录 IP 不一致 → 挂起待审批（仅本次有效） ----
  // 优化（放行体验）：同一用户登录成功过的 IP 段（IPv4 /24）记入 users.known_ips，
  // 之后从同段新 IP 登录时直接放行，不再每次换 IP 都触发审批。
  // 出口 IP 经常在同一个段里小幅浮动，逐 IP 审批会烦死正常用户。
  const lastIp = row.last_ip || '';
  const firstLogin = !lastIp;
  const sameIp = lastIp === ip;

  // 管理员已经放行过这条审批，且还没被用过 → 直接从该 IP 放行，标记已用
  // （放行仅针对"本次登录"：一旦成功登录，该审批即作废，下次换 IP 需重新审批）
  const approvedRec = !sameIp ? db.prepare(
    "SELECT * FROM login_approvals WHERE user_id = ? AND status = 'approved' AND used = 0 AND ip = ? AND expires_at > ? ORDER BY id DESC LIMIT 1"
  ).get(row.id, ip, Date.now()) : null;

  if (!sameIp && !approvedRec && !sameSeg) {
    const created = Date.now();
    const expires = created + 30 * 60 * 1000; // 审批有效期 30 分钟
    const info = db.prepare(
      'INSERT INTO login_approvals (user_id, username, ip, region, province, city, isp, ua, status, expires_at, created_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(row.id, row.username, ip, pretty, geoOf.province, geoOf.city, geoOf.isp, String(ua || '').slice(0, 200), 'pending', expires, created);
    const approvalId = Number(info.lastInsertRowid);

    logLogin({ user_id: row.id, username: row.username, ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp, ua, result: 'pending', reason: firstLogin ? '首次登录，等待管理员放行' : '新 IP 登录，等待管理员放行（上次 IP：' + lastIp + '）' });
    setImmediate(() => notifyAdmins('approval', {
      id: approvalId, username: row.username, nickname: row.nickname,
      ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp,
      ua: String(ua || '').slice(0, 200), firstLogin,
      createdAt: created
    }));
    return res.status(202).json({
      error: firstLogin ? '首次登录，需管理员放行后才能进入' : '当前 IP 与上次登录不一致，需管理员放行后才能进入',
      code: 'NEED_APPROVAL', firstLogin,
      approval: { id: approvalId, ip, region: pretty, username: row.username }
    });
  }

  // ---- 正常放行 ----
  clearBan(row.id);
  clearIpFails(ip);
  // 成本因子升级：用旧参数存的老哈希，在登录成功时顺手升级到新参数
  try {
    if (bcrypt.getRounds(row.password_hash) < BCRYPT_ROUNDS) {
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
        .run(bcrypt.hashSync(password, BCRYPT_ROUNDS), row.id);
    }
  } catch (_) { /* 升级失败不影响正常登录 */ }

  const token = createSession(row.id, ua, ip);
  const now = Date.now();
  // 记住本次登录 IP：已知段免审批。最多记 20 个 IP 段（旧的不删，但同段去重）
  let known = new Set(String(row.known_ips || '').split(',').map(s => s.trim()).filter(Boolean));
  if (ipSeg) {
    // 存 /24 段而不是具体 IP：同段任何 IP 下次登录都免审批
    known.add(ipSeg);
    if (known.size > 20) {
      const arr = Array.from(known);
      known = new Set(arr.slice(arr.length - 20));
    }
    db.prepare('UPDATE users SET known_ips = ? WHERE id = ?')
      .run(Array.from(known).join(','), row.id);
  }
  db.prepare('UPDATE users SET last_seen = ?, last_ip = ? WHERE id = ?')
    .run(now, ip, row.id);
  // 已审批的本次登录：标记为已用（仅本次有效，下次换 IP 需要重新审批）；
  // 若有遗留的旧待审批记录（比如挂了审批没等直接换回老 IP），也一并作废
  if (approvedRec) {
    db.prepare('UPDATE login_approvals SET used = 1 WHERE id = ?').run(approvedRec.id);
  }
  db.prepare("UPDATE login_approvals SET used = 1 WHERE user_id = ? AND status IN ('pending','approved') AND used = 0 AND id != ?")
    .run(row.id, approvedRec ? approvedRec.id : 0);
  logLogin({ user_id: row.id, username: row.username, ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp, ua, result: 'success', reason: '登录成功' });
  logAccess({
    ip, region: pretty, province: geoOf.province, city: geoOf.city, isp: geoOf.isp,
    allowed: true, reason: '登录成功', path: '/api/login', method: 'POST', username: row.username
  });
  res.setHeader('Set-Cookie', cookieString(token, Math.floor(SESSION_TTL / 1000), isSecureReq(req)));
  res.json({ user: publicUser(row) });
});

app.post('/api/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[COOKIE_NAME];
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.setHeader('Set-Cookie', cookieString('', 0, isSecureReq(req)));
  res.json({ ok: true });
});

/* ---------- 登录设备管理（隐私增强） ----------
 * 用户能看到自己账号下所有已登录的会话（设备/位置/时间），
 * 并可以远程把陌生设备踢下线 —— 账号被别的设备登录过时，第一时间发现并处理。
 */
app.get('/api/sessions', requireAuth, (req, res) => {
  try {
    const rows = db.prepare(
      'SELECT token, created_at, expires_at, ua, ip FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 20'
    ).all(req.user.id);
    // 当前会话的 token：从 Cookie 里取，用于标记「本机」
    const cookies = parseCookies(req.headers.cookie);
    const current = cookies[COOKIE_NAME] || '';
    res.json({
      sessions: rows.map(r => ({
        token: r.token,
        current: r.token === current,
        createdAt: r.created_at,
        expiresAt: r.expires_at,
        ua: r.ua || '',
        device: deviceFromUA(r.ua),
        ip: r.ip || ''
      }))
    });
  } catch (e) {
    res.status(500).json({ error: '获取会话列表失败' });
  }
});

// 远程踢下线：删掉那条会话 token。不能踢自己（当前 token）。
app.post('/api/sessions/:token/revoke', requireAuth, (req, res) => {
  try {
    const token = String(req.params.token || '').slice(0, 128);
    const cookies = parseCookies(req.headers.cookie);
    const current = cookies[COOKIE_NAME] || '';
    if (!token || token === current) {
      return res.status(400).json({ error: '不能踢掉当前登录的设备' });
    }
    const r = db.prepare('DELETE FROM sessions WHERE token = ? AND user_id = ?').run(token, req.user.id);
    if (r.changes === 0) {
      return res.status(404).json({ error: '该会话不存在或已被移除' });
    }
    logAccess({
      ip: req.clientIp || '', region: '', province: '', city: '', isp: '',
      allowed: true, reason: '远程踢下线了一台登录设备', path: '/api/sessions/revoke',
      method: 'POST', username: req.user.username
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: '操作失败' });
  }
});

// 用户主动「退出所有其他设备」（微信的"退出所有设备"）：保留当前，其余全删
app.post('/api/sessions/revoke-others', requireAuth, (req, res) => {
  try {
    const cookies = parseCookies(req.headers.cookie);
    const current = cookies[COOKIE_NAME] || '';
    const r = db.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?').run(req.user.id, current);
    logAccess({
      ip: req.clientIp || '', region: '', province: '', city: '', isp: '',
      allowed: true, reason: '退出了所有其他登录设备（共 ' + r.changes + ' 台）',
      path: '/api/sessions/revoke-others', method: 'POST', username: req.user.username
    });
    res.json({ ok: true, revoked: r.changes });
  } catch (e) {
    res.status(500).json({ error: '操作失败' });
  }
});

app.get('/api/me', (req, res) => {
  const u = authFromHeaders(req.headers);
  if (!u) return res.json({ user: null });
  db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(Date.now(), u.id);
  res.json({ user: publicUser(u) });
});

// 可 @ 的成员列表（供输入框 @ 候选面板用）。只暴露昵称/账号/角色，不含任何敏感字段。
// 只统计"在线"用于给候选加绿点，不影响可达性（@ 提醒按 username 精确匹配）。
app.get('/api/members', requireAuth, (req, res) => {
  try {
    const rows = db.prepare(
      "SELECT id, username, nickname, role FROM users WHERE disabled = 0 ORDER BY role = 'admin' DESC, id ASC LIMIT 500"
    ).all();
    const online = new Set(onlineUsers.keys());
    res.json({
      members: rows.map(r => ({
        id: r.id, username: r.username, nickname: r.nickname,
        role: r.role, online: online.has(r.id)
      }))
    });
  } catch (e) {
    res.json({ members: [] });
  }
});

// 链路信息：把服务器出口带宽告诉前端，用来估算「下载大概要多久」。
// 带宽按服务器套餐实际值调整（或设 LINK_BANDWIDTH_MBPS 环境变量）。
// 上传耗时不用这个值——上传速度跟用户本身上行带宽关系更大，前端按实际进度实时测算。
app.get('/api/link', requireAuth, (req, res) => {
  res.json({ downMbps: LINK_BANDWIDTH_MBPS });
});

// 语音通话用：返回 ICE 服务器（STUN/TURN）与人数上限。
// 放在接口里而不是写死在前端，是为了以后加 TURN 时不用重新部署前端。
app.get('/api/call/config', requireAuth, (req, res) => {
  res.json({ iceServers: callIceServers(), max: CALL_MAX, state: callSnapshot() });
});

/* ---------- 消息 ---------- */

/**
 * 历史记录接口
 *   ?before=<id>  取该 id 之前的一页（向上翻历史）
 *   ?after=<id>   取该 id 之后的消息（断线重连补齐）
 *   ?q=<关键词>    在历史里检索
 * 返回体始终带 total（历史总条数）
 */
app.get('/api/messages', requireAuth, (req, res) => {
  const q = String(req.query.q || '').trim();
  const peer = Number(req.query.peer) || 0;   // 0=公共房间；>0=与该用户的私聊
  const total = countMessages(peer);

  if (q) {
    const messages = searchMessages(q, req.query.limit, req.user.id);
    const ridMap = readersFor(messages, req.user.id);
    if (Object.keys(ridMap).length) messages.forEach(m => { if (ridMap[m.id]) m.readers = ridMap[m.id]; });
    const vu = voiceUnreadIds(messages, req.user.id);
    if (vu.size) messages.forEach(m => { if (vu.has(m.id)) m.unreadVoice = true; });
    attachReactions(messages, req.user.id);
    return res.json({ messages, total, query: q, scanned: Math.min(total, SEARCH_SCAN_MAX) });
  }

  let messages;
  if (req.query.after) {
    messages = getMessagesAfter(req.query.after, req.query.limit, req.user.id, peer);
  } else {
    messages = getMessages(req.query.before, req.query.limit, req.user.id, peer);
  }
  const ridMap = readersFor(messages, req.user.id);
  if (Object.keys(ridMap).length) messages.forEach(m => { if (ridMap[m.id]) m.readers = ridMap[m.id]; });
  const vu = voiceUnreadIds(messages, req.user.id);
  if (vu.size) messages.forEach(m => { if (vu.has(m.id)) m.unreadVoice = true; });
  attachReactions(messages, req.user.id);
  res.json({ messages, total });
});

/** 给一批消息挂上 reactions（有的才挂，避免每条都塞一个空数组白占传输量） */
function attachReactions(messages, uid) {
  try {
    if (!messages || !messages.length) return;
    const rMap = reactionsFor(messages, uid);
    if (!Object.keys(rMap).length) return;
    messages.forEach(m => { if (rMap[m.id] && rMap[m.id].length) m.reactions = rMap[m.id]; });
  } catch (e) { /* 表情回应取不到不影响消息本身 */ }
}

/* ---------- 会话列表（私聊） ---------- */
app.get('/api/convs', requireAuth, (req, res) => {
  const me = req.user.id;
  // B1/B2 修复：排序与摘要只取「对当前用户可见」的最后一条。
  // 原来只排除 revoked，若最后一条被「我」本地删除（message_deletes），
  // 会话仍会按它排序、摘要也显示它 → 现在两处都排除。
  const rows = db.prepare(
    "SELECT CASE WHEN m.user_id = ? THEN m.peer_id ELSE m.user_id END AS other_id, MAX(m.id) AS last_id " +
    "FROM messages m " +
    "WHERE m.peer_id > 0 AND (m.user_id = ? OR m.peer_id = ?) " +
    "  AND m.revoked = 0 " +
    "  AND m.id NOT IN (SELECT message_id FROM message_deletes WHERE user_id = ?) " +
    "GROUP BY other_id ORDER BY last_id DESC LIMIT 100"
  ).all(me, me, me, me);
  const convs = [];
  for (const r of rows) {
    const other = db.prepare('SELECT id, username, nickname, role, disabled FROM users WHERE id = ?').get(r.other_id);
    if (!other || other.disabled) continue;
    const lastRow = db.prepare(MSG_SELECT + ' WHERE m.id = ?').get(r.last_id);
    // 未读数：同样排除撤回 + 我已删除的消息
    const unread = db.prepare(
      "SELECT COUNT(*) AS c FROM messages m WHERE m.user_id = ? AND m.peer_id = ? AND m.revoked = 0 " +
      "AND m.id NOT IN (SELECT message_id FROM message_reads WHERE user_id = ?) " +
      "AND m.id NOT IN (SELECT message_id FROM message_deletes WHERE user_id = ?)"
    ).get(r.other_id, me, me, me).c;
    // F2：置顶时间
    const pin = db.prepare('SELECT pinned_at FROM conversation_pins WHERE user_id = ? AND peer_id = ?').get(me, other.id);
    convs.push({
      peer: { id: other.id, username: other.username, nickname: other.nickname, role: other.role, online: onlineUsers.has(other.id) },
      last: lastRow ? serializeMessage(lastRow) : null,
      unread,
      pinnedAt: pin ? pin.pinned_at : 0
    });
  }
  // F2：置顶会话排最前（pinned_at 大的在前），下面按最后消息时间倒序
  convs.sort(function(a, b) {
    if (!!b.pinnedAt !== !!a.pinnedAt) return b.pinnedAt ? 1 : -1;
    if (a.pinnedAt && b.pinnedAt) return b.pinnedAt - a.pinnedAt;
    return (b.last ? b.last.createdAt : 0) - (a.last ? a.last.createdAt : 0);
  });
  // F1：会话预览 — 把最后一条的正文摘要算好（已可见性过滤），前端直接展示
  for (const c of convs) {
    if (c.last) c.preview = convPreview(c.last);
  }
  res.json({ convs });
});

// F2：置顶 / 取消置顶私聊会话
app.post('/api/convs/:peer/pin', requireAuth, (req, res) => {
  const peer = Number(req.params.peer);
  if (!Number.isInteger(peer) || peer <= 0) return res.status(400).json({ error: '参数不合法' });
  const other = db.prepare('SELECT id, disabled FROM users WHERE id = ?').get(peer);
  if (!other || other.disabled) return res.status(404).json({ error: '用户不存在' });
  const on = req.body && req.body.on;
  if (on === false || on === 'false' || on === 0) {
    db.prepare('DELETE FROM conversation_pins WHERE user_id = ? AND peer_id = ?').run(req.user.id, peer);
  } else {
    db.prepare('INSERT INTO conversation_pins (user_id, peer_id, pinned_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(user_id, peer_id) DO UPDATE SET pinned_at = excluded.pinned_at')
      .run(req.user.id, peer, Date.now());
  }
  res.json({ ok: true, pinned: !(on === false || on === 'false' || on === 0) });
});

// F3：把某个私聊会话（或公共房间）的所有未读消息标记为已读
app.post('/api/convs/read', requireAuth, (req, res) => {
  const me = req.user.id;
  const peer = Number((req.body && req.body.peer) || 0);
  const beforeId = Number((req.body && req.body.beforeId) || 0);
  const where = ['m.revoked = 0', 'm.user_id != ?', NOT_DELETED_BY];
  const args = [me, me];
  if (peer > 0) {
    where.push('((m.user_id = ? AND m.peer_id = ?) OR (m.user_id = ? AND m.peer_id = ?))');
    args.push.apply(args, [peer, me, me, peer]);
  } else {
    where.push('m.peer_id = 0');
  }
  if (beforeId > 0) { where.push('m.id <= ?'); args.push(beforeId); }
  const rows = db.prepare('SELECT id FROM messages m WHERE ' + where.join(' AND ')).all(...args);
  const now = Date.now();
  const ins = db.prepare('INSERT OR IGNORE INTO message_reads (message_id, user_id, read_at) VALUES (?, ?, ?)');
  const tx = db.prepare('BEGIN');
  tx.run();
  try {
    for (const r of rows) ins.run(r.id, me, now);
    db.prepare('COMMIT').run();
  } catch (e) {
    db.prepare('ROLLBACK').run();
    throw e;
  }
  res.json({ ok: true, marked: rows.length });
});

// F12：会话外观设置（当前只支持 wallpaper：聊天区背景图 URL / CSS 渐变值，空串=默认）。
// 设置按「用户 × 会话」存储，公共房间用 peer=0。
app.get('/api/convs/:peer/settings', requireAuth, (req, res) => {
  const peer = Number(req.params.peer);
  if (!Number.isInteger(peer) || peer < 0) return res.status(400).json({ error: '参数不合法' });
  const rows = db.prepare('SELECT key, value FROM conversation_settings WHERE user_id = ? AND peer_id = ?')
    .all(req.user.id, peer);
  const out = {};
  for (const r of rows) out[r.key] = r.value;
  res.json({ ok: true, settings: out });
});

app.put('/api/convs/:peer/settings', requireAuth, (req, res) => {
  const peer = Number(req.params.peer);
  if (!Number.isInteger(peer) || peer < 0) return res.status(400).json({ error: '参数不合法' });
  const allowed = new Set(['wallpaper']);
  const updates = (req.body && req.body.settings) || {};
  const keys = Object.keys(updates).filter((k) => allowed.has(k));
  if (!keys.length) return res.status(400).json({ error: '没有可保存的设置项' });
  const tx = db.prepare('BEGIN');
  tx.run();
  try {
    const up = db.prepare('INSERT INTO conversation_settings (user_id, peer_id, key, value) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT(user_id, peer_id, key) DO UPDATE SET value = excluded.value');
    for (const k of keys) {
      let v = String(updates[k] == null ? '' : updates[k]).slice(0, 1000);
      if (v.trim() === '') {
        db.prepare('DELETE FROM conversation_settings WHERE user_id = ? AND peer_id = ? AND key = ?')
          .run(req.user.id, peer, k);
      } else {
        up.run(req.user.id, peer, k, v);
      }
    }
    db.prepare('COMMIT').run();
  } catch (e) {
    db.prepare('ROLLBACK').run();
    return res.status(500).json({ error: '保存失败' });
  }
  const rows = db.prepare('SELECT key, value FROM conversation_settings WHERE user_id = ? AND peer_id = ?')
    .all(req.user.id, peer);
  const out = {};
  for (const r of rows) out[r.key] = r.value;
  res.json({ ok: true, settings: out });
});
function convPreview(m) {
  if (m.revoked) return '（该消息已撤回）';
  if (m.kind === 'file' && m.file) {
    if (/^audio\//.test(m.file.mime || '')) return '[语音]';
    if (/^image\//.test(m.file.mime || '')) return '[图片]';
    if (/^video\//.test(m.file.mime || '')) return '[视频]';
    return '[文件] ' + (m.file.name || '文件');
  }
  if (m.kind === 'call') {
    try {
      const o = JSON.parse(m.body);
      if (o.st === 'missed') return '[未接来电]';
      if (o.st === 'canceled') return '[已取消]';
      if (o.st === 'declined') return '[已拒绝]';
      return '[通话] ' + (o.dur ? formatDur(o.dur) : '');
    } catch (_) { return '[通话]'; }
  }
  return (m.body || '').slice(0, 40);
}

function formatDur(sec) {
  sec = Math.max(0, Math.round(Number(sec) || 0));
  const m = Math.floor(sec / 60), s = sec % 60;
  if (m >= 60) return Math.floor(m / 60) + ':' + String(m % 60).padStart(2, '0') + ':' + String(s).padStart(2, '0');
  return m + ':' + String(s).padStart(2, '0');
}

app.post('/api/messages', requireAuth, (req, res) => {
  if (!rateLimit('msg:' + req.user.id, 'msg')) {
    return res.status(429).json({ error: '发送太频繁，请稍后再试', code: 'MSG_RL' });
  }
  const text = String((req.body && req.body.body) || '').trim();
  if (!text) return res.status(400).json({ error: '消息内容不能为空' });
  // P0 修复：引用目标必须对发送者可见，否则静默降级为普通消息
  const replyTo = resolveReplyTo(db, req.user.id, req.body && req.body.replyTo);
  const msg = createMessage(req.user.id, 'text', text.slice(0, MAX_TEXT), null, replyTo);
  io.emit('chat:new', msg);
  // 与 WS chat:send 行为对齐：公共消息触发 @ 提醒（含离线落库）
  fireMentions(msg.body, msg);
  res.json({ ok: true, message: msg });
});

/**
 * 本地删除：只把这条消息从「我」的列表里抹掉，别人还能看到。
 * 和撤回的区别就是撤回是服务端置 revoked（所有人看不到），删除只写这张个人表。
 */
app.post('/api/messages/:id/delete', requireAuth, (req, res) => {
  const mid = Number(req.params.id);
  if (!Number.isInteger(mid) || mid <= 0) return res.status(400).json({ error: '参数不合法' });
  db.prepare('INSERT OR IGNORE INTO message_deletes (user_id, message_id, deleted_at) VALUES (?, ?, ?)')
    .run(req.user.id, mid, Date.now());
  res.json({ ok: true });
});

/* ---------- 文件上传（不限制大小，流式落盘） ---------- */

/**
 * 自定义存储引擎：上传流 → AES-256-GCM 加密 → 落盘
 * 全程流式，不占内存，因此文件大小依旧不受限制。
 * GCM 属流式模式，密文长度与明文一致，所以统计到的 size 就是原始大小。
 */
class EncryptedStorage {
  _handleFile(req, file, cb) {
    const iv = vault.newIv();
    const cipher = vault.createEncryptStream(iv);
    const storedName = Date.now().toString(36) + '-' + crypto.randomBytes(8).toString('hex') + '.enc';
    const abs = path.join(UPLOAD_DIR, storedName);
    const out = fs.createWriteStream(abs);

    let size = 0;
    const counter = new Transform({
      transform(chunk, enc, callback) {
        size += chunk.length;
        callback(null, chunk);
      }
    });

    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      fs.unlink(abs, () => cb(err || new Error('写入失败')));
    };

    file.stream.on('error', fail);
    counter.on('error', fail);
    cipher.on('error', fail);
    out.on('error', fail);
    out.on('finish', () => {
      if (settled) return;
      settled = true;
      cb(null, {
        storedName,
        iv: iv.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'),
        size
      });
    });

    file.stream.pipe(counter).pipe(cipher).pipe(out);
  }

  _removeFile(req, file, cb) {
    if (!file || !file.storedName) return cb(null);
    fs.unlink(path.join(UPLOAD_DIR, path.basename(file.storedName)), () => cb(null));
  }
}

const upload = multer({
  storage: new EncryptedStorage(),
  // P1 修复：限制单文件大小，防止无上限上传拖垮磁盘/带宽（超限由 multer 抛 LIMIT_FILE_SIZE）
  limits: { fileSize: UPLOAD_MAX_BYTES }
});

app.post('/api/upload', requireAuth, (req, res) => {
  if (!rateLimit('upload:' + req.user.id, 'upload')) {
    return res.status(429).json({ error: '上传太频繁，请稍后再试', code: 'UPLOAD_RL' });
  }
  upload.single('file')(req, res, (err) => {
    if (err) {
      // 超过 UPLOAD_MAX_MB：明确回 413，前端可据此提示（而非笼统的 500）
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: '文件不能超过 ' + UPLOAD_MAX_MB + 'MB', code: 'LIMIT_FILE_SIZE' });
      }
      return res.status(500).json({ error: '上传失败：' + (err.message || '未知错误') });
    }
    if (!req.file) {
      return res.status(400).json({ error: '没有收到文件' });
    }
    const orig = fixFilename(req.file.originalname) || 'file';
    const info = db.prepare(
      'INSERT INTO files (user_id, orig_name, stored_name, size, mime, created_at, encrypted, iv, tag) ' +
      'VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)'
    ).run(
      req.user.id, vault.encryptText(orig), req.file.storedName, req.file.size,
      req.file.mimetype || 'application/octet-stream', Date.now(),
      req.file.iv, req.file.tag
    );
    const caption = req.body && req.body.text ? String(req.body.text).trim().slice(0, MAX_TEXT) : null;
    // P0 修复：引用目标必须对发送者可见，否则静默降级
    const replyTo = resolveReplyTo(db, req.user.id, req.body && req.body.replyTo);
    // 私聊文件：peer 与文本消息同一套规则
    let peer = 0;
    if (req.body && req.body.peer) {
      const pv = Number(req.body.peer);
      if (Number.isInteger(pv) && pv > 0) {
        const pr = db.prepare('SELECT id, disabled FROM users WHERE id = ?').get(pv);
        if (pr && !pr.disabled && pv !== req.user.id) peer = pv;
      }
    }
    // 语音消息：前端把录音秒数带上来，存库后列表就能直接显示时长，不用等加载音频才知道
    const duration = req.body && req.body.duration ? Number(req.body.duration) : 0;
    // 语音消息可能因为浏览器差异带上更精确的 MIME（如 audio/webm;codecs=opus），
    // 若提供了就用它覆盖 multer 推测的类型，保证播放端能正确识别。
    const upMime = req.body && req.body.mime ? String(req.body.mime).trim().slice(0, 100) : '';
    if (upMime && /^audio\//i.test(upMime)) {
      db.prepare('UPDATE files SET mime = ? WHERE id = ?').run(upMime, Number(info.lastInsertRowid));
    }
    const msg = createMessage(req.user.id, 'file', caption || null, Number(info.lastInsertRowid), replyTo, duration, peer);
    if (peer > 0) {
      emitToUser(req.user.id, 'chat:new', msg);
      emitToUser(peer, 'chat:new', msg);
    } else {
      io.emit('chat:new', msg);
      // 与文本消息一致：文件说明（caption）里 @ 了谁同样触发提醒（私聊路径由内部早退跳过）
      fireMentions(msg.body, msg);
    }
    res.json({ ok: true, message: msg });
  });
});

app.get('/api/files/:id', requireAuth, (req, res) => {
  if (!rateLimit('file:' + req.user.id, 'file')) {
    return res.status(429).json({ error: '请求太频繁，请稍后再试', code: 'FILE_RL' });
  }
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: '参数不合法' });
  const f = db.prepare('SELECT * FROM files WHERE id = ?').get(id);
  if (!f) return res.status(404).json({ error: '文件不存在' });
  // P0 修复：越权下载拦截 —— 非属主/非会话参与方/非管理员一律按 404 处理（不暴露文件是否存在）
  if (!canAccessFile(db, f, req.user)) return res.status(404).json({ error: '文件不存在' });
  const abs = path.join(UPLOAD_DIR, path.basename(f.stored_name));

  let diskSize = 0;
  try { diskSize = fs.statSync(abs).size; } catch (_) { return res.status(404).json({ error: '文件已丢失' }); }
  // AES-256-GCM 是流式加密、authTag 另存数据库，所以磁盘上的密文长度 == 明文长度，
  // 这个前提让「按明文偏移读密文」和 Content-Length 都能算准。
  const total = Number(f.size) || diskSize;

  const mime = f.mime || 'application/octet-stream';
  // 只有图片/视频/音频允许内联预览，其余一律强制下载，避免 HTML/SVG 挂马
  const inline = /^(image\/(png|jpe?g|gif|webp|bmp|avif)|video\/|audio\/)/i.test(mime);
  const filename = safeDecrypt(f.orig_name, 'file');

  /* ---------- HTTP Range 支持（206）----------
   * 为什么必须做：浏览器的下载管理器中断后会带 Range 续传，<audio>/<video> 也用 Range 取数据。
   * 旧实现一律回 200 + 全量，续传会被判定失败 —— 浏览器直接报「网络错误」，
   * 而且同一页面内重试仍走续传、继续失败，只有刷新页面开一个全新下载才恢复。
   */
  let start = 0, end = Math.max(0, total - 1), partial = false;
  const rangeHdr = req.headers.range;
  if (rangeHdr && total > 0) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(String(rangeHdr).trim());
    if (m && (m[1] || m[2])) {
      if (!m[1]) {
        const n = Number(m[2]);                       // bytes=-N：末尾 N 字节
        if (n > 0) { start = Math.max(0, total - n); end = total - 1; partial = true; }
      } else {
        start = Number(m[1]);
        end = (m[2] === '') ? total - 1 : Math.min(Number(m[2]), total - 1);
        partial = true;
      }
      if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || start >= total) {
        res.setHeader('Content-Range', 'bytes */' + total);
        return res.status(416).end();
      }
    }
  }
  const len = Math.max(0, end - start + 1);

  res.setHeader('Accept-Ranges', 'bytes');
  // ETag / Last-Modified：浏览器判定"资源没变"才敢接着续传，缺了它们有些版本会直接放弃续传
  res.setHeader('ETag', 'W/"f' + f.id + '-' + total + (f.encrypted ? '-e' : '-p') + '"');
  if (f.created_at) res.setHeader('Last-Modified', new Date(f.created_at).toUTCString());
  res.setHeader('Content-Type', inline ? mime : 'application/octet-stream');
  res.setHeader('Content-Disposition',
    (inline ? 'inline' : 'attachment') + "; filename*=UTF-8''" + encodeURIComponent(filename));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'private, max-age=86400');
  if (total > 0) res.setHeader('Content-Length', String(len));
  if (partial) {
    res.status(206);
    res.setHeader('Content-Range', 'bytes ' + start + '-' + end + '/' + total);
  }

  const src = fs.createReadStream(abs);
  let decipher = null;
  let finished = false;
  let sentBytes = 0;
  const startedAt = Date.now();
  // 统计真正写出去的字节（仅用于中断诊断，不影响数据流）
  try {
    const rawWrite = res.write.bind(res);
    res.write = function (chunk, enc, cb) {
      if (chunk) {
        sentBytes += (typeof chunk === 'string')
          ? Buffer.byteLength(chunk, typeof enc === 'string' ? enc : 'utf8')
          : chunk.length;
      }
      return rawWrite(chunk, enc, cb);
    };
  } catch (_) { /* 忽略 */ }
  const release = () => {
    if (finished) return;
    finished = true;
    try { if (decipher) decipher.destroy(); } catch (_) { /* 忽略 */ }
    try { src.destroy(); } catch (_) { /* 忽略 */ }
  };
  // 客户端断开/取消下载时释放上游流：否则半开响应会一直占着连接，
  // 攒够若干个之后浏览器对该域名的并发名额被占满，之后所有下载都失败（也要靠刷新才能解）。
  res.on('close', () => {
    const done = res.writableFinished;
    release();
    // 出问题时最有力的证据：是"客户端把连接断了"，还是"服务端没发完"。
    // 正常完成的请求不打日志，避免刷屏。
    if (!done) {
      console.warn('[chat] 下载中断 id=' + id + ' 已发 ' + sentBytes + '/' + len +
        ' 字节 用时 ' + (Date.now() - startedAt) + 'ms');
    }
  });
  res.on('finish', () => { sentBytes = len; });
  src.on('error', () => { try { res.destroy(); } catch (_) { /* 忽略 */ } });

  // 加密过的文件：边读边解密再吐给浏览器；老数据（未加密）直接透传
  if (f.encrypted && f.iv && f.tag) {
    try { decipher = vault.createDecryptStream(f.iv, f.tag); } catch (_) {
      return res.status(500).end('解密失败');
    }
    decipher.on('error', () => { try { res.destroy(); } catch (_) { /* 忽略 */ } });

    if (!partial) { src.pipe(decipher).pipe(res); return; }

    // 带 Range 时必须从头解密（GCM 无法从中途偏移解密），丢弃前 start 字节，只写需要的窗口
    let skip = start;
    let written = 0;
    decipher.on('data', (chunk) => {
      if (finished || res.writableEnded) return;
      let buf = chunk;
      if (skip > 0) {
        if (buf.length <= skip) { skip -= buf.length; return; }
        buf = buf.subarray(skip);
        skip = 0;
      }
      if (written + buf.length > len) buf = buf.subarray(0, len - written);
      if (buf.length) { written += buf.length; res.write(buf); }
      if (written >= len) { release(); try { res.end(); } catch (_) { /* 忽略 */ } }
    });
    decipher.on('end', () => {
      if (finished || res.writableEnded) return;
      // 明文比声明的短：宁可断开让下载显式失败，也不要让浏览器一直等永远不来的字节
      if (written < len) { try { res.destroy(); } catch (_) { /* 忽略 */ } release(); return; }
      release();
      try { res.end(); } catch (_) { /* 忽略 */ }
    });
    src.pipe(decipher);
    return;
  }

  // 未加密（历史数据）：按需读取密文等价于明文
  if (partial) {
    release();
    const s2 = fs.createReadStream(abs, { start: start, end: end });
    s2.on('error', () => { try { res.destroy(); } catch (_) { /* 忽略 */ } });
    res.on('close', () => { try { s2.destroy(); } catch (_) { /* 忽略 */ } });
    s2.pipe(res);
    return;
  }
  src.pipe(res);
});

/* ---------- 后台管理 ---------- */

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.username, u.nickname, u.role, u.disabled, u.created_at, u.last_seen, u.created_by, u.last_ip, u.known_ips,
           r.province AS ip_province, r.city AS ip_city, r.isp AS ip_isp, r.src AS ip_src,
           (SELECT COUNT(*) FROM messages m WHERE m.user_id = u.id) AS msg_count,
           (SELECT COUNT(*) FROM files f WHERE f.user_id = u.id) AS file_count
    FROM users u
    LEFT JOIN ip_region r ON r.ip = u.last_ip
    ORDER BY u.id ASC
  `).all();
  res.json({
    users: rows.map(r => ({
      id: r.id,
      username: r.username,
      nickname: r.nickname,
      role: r.role,
      disabled: !!r.disabled,
      createdAt: r.created_at,
      lastSeen: r.last_seen,
      createdBy: r.created_by || null,
      msgCount: r.msg_count,
      fileCount: r.file_count,
      lastIp: r.last_ip || null,
      ipRegion: r.last_ip
        ? geo.prettyRegion({ province: r.ip_province, city: r.ip_city, src: r.ip_src, ok: !!r.ip_province })
        : null,
      ipIsp: r.ip_isp || null,
      knownIps: String(r.known_ips || '').split(',').map(s => s.trim()).filter(Boolean)
    }))
  });
});

/* ---------- 访问安全（地域准入） ---------- */

app.get('/api/admin/geo', requireAdmin, (req, res) => {
  res.json({
    conf: geoConf,
    killSwitch: geoKillSwitchOn(),
    lookupEnabled: process.env.GEO_LOOKUP !== '0',
    killFile: GEO_KILL_FILE,
    confFile: GEO_CONF_FILE,
    testIp: GEO_TEST_IP || null,
    apiBase: process.env.GEO_API_BASE || null,
    mode: geoKillSwitchOn() ? 'off' : geoConf.mode
  });
});

app.patch('/api/admin/geo', requireAdmin, (req, res) => {
  const b = req.body || {};
  const next = {};

  if (typeof b.mode === 'string') {
    if (['off', 'log', 'on'].indexOf(b.mode) < 0) {
      return res.status(400).json({ error: 'mode 只能是 off / log / on' });
    }
    next.mode = b.mode;
  }
  // 两级独立开关
  if (typeof b.provOn === 'boolean') next.provOn = b.provOn;
  if (typeof b.cityOn === 'boolean') next.cityOn = b.cityOn;
  if (Array.isArray(b.provinces)) {
    next.provinces = b.provinces.map(s => String(s).trim()).filter(Boolean).slice(0, 40);
  }
  if (Array.isArray(b.cities)) {
    next.cities = b.cities.map(s => String(s).trim()).filter(Boolean).slice(0, 60);
  }
  if (Array.isArray(b.allowIps)) {
    const bad = b.allowIps.filter(ip => ip && !/^(\d{1,3}\.){3}\d{1,3}$/.test(String(ip).trim()) && String(ip).indexOf(':') < 0);
    if (bad.length) return res.status(400).json({ error: '这几条不是合法 IP：' + bad.join('、') });
    next.allowIps = b.allowIps.map(s => String(s).trim()).filter(Boolean).slice(0, 200);
  }
  if (typeof b.failOpen === 'boolean') next.failOpen = b.failOpen;

  if (!Object.keys(next).length) return res.status(400).json({ error: '没有需要修改的内容' });

  saveGeoConf(next);
  logAccess({
    ip: req.clientIp, region: '管理后台', allowed: true,
    reason: '管理员 ' + req.user.username + ' 修改了地域规则：' + JSON.stringify(next),
    path: '/api/admin/geo', method: 'PATCH', username: req.user.username
  });
  audit(req.user, 'update_geo', '地域准入', JSON.stringify(next), req.clientIp);
  res.json({ ok: true, conf: geoConf });
});

// 手动查一个 IP 的归属地（后台用来核对、也方便用户报自己 IP 时先查一下）
app.get('/api/admin/geo/lookup', requireAdmin, async (req, res) => {
  const ip = geo.normalizeIp(req.query.ip);
  if (!ip) return res.status(400).json({ error: '请提供 ip 参数' });
  if (geo.isPrivateIp(ip)) {
    return res.json({ ip, region: '内网地址', province: '内网', city: '', isp: '', src: 'private', allowed: true });
  }
  const region = await geo.resolve(ip);
  const m = geo.matchRules(region, geoConf);
  res.json({
    ip,
    region: geo.prettyRegion(region),
    province: region.province || '',
    city: region.city || '',
    isp: region.isp || '',
    src: region.src || '',
    ok: !!region.ok,
    wouldAllow: m.hit,
    reason: m.reason
  });
});

app.get('/api/admin/access', requireAdmin, (req, res) => {
  const size = Math.min(Math.max(Number(req.query.size) || 20, 1), 200);
  const page = Math.max(Number(req.query.page) || 1, 1);
  const only = String(req.query.only || '');
  const where = [];
  const args = [];
  if (only === 'blocked') where.push('allowed = 0');
  else if (only === 'login') where.push("path = '/api/login'");
  const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
  const total = db.prepare('SELECT COUNT(*) AS c FROM access_log' + whereSql).get(...args).c;
  const rows = db.prepare(
    'SELECT * FROM access_log' + whereSql + ' ORDER BY id DESC LIMIT ? OFFSET ?'
  ).all(...args, size, (page - 1) * size);
  const agg = db.prepare(
    'SELECT COUNT(*) AS total, SUM(CASE WHEN allowed = 0 THEN 1 ELSE 0 END) AS blocked FROM access_log'
  ).get();

  res.json({
    total: agg.total || 0,
    blocked: agg.blocked || 0,
    page,
    size,
    pages: Math.max(1, Math.ceil(total / size)),
    logs: rows.map(r => ({
      id: r.id,
      ip: r.ip,
      region: r.region || '未知',
      province: r.province || '',
      city: r.city || '',
      isp: r.isp || '',
      allowed: !!r.allowed,
      reason: r.reason || '',
      path: r.path || '',
      method: r.method || '',
      username: r.username || '',
      createdAt: r.created_at
    }))
  });
});

// 清空访问日志
app.delete('/api/admin/access', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM access_log').run();
  accessLastLog.clear();
  res.json({ ok: true });
});

// 清掉某个 IP 的归属地缓存，强制下次重新查（接口换了数据源、或查错了时用）
app.delete('/api/admin/geo/cache', requireAdmin, (req, res) => {
  const ip = geo.normalizeIp(req.query.ip);
  if (ip) db.prepare('DELETE FROM ip_region WHERE ip = ?').run(ip);
  else db.prepare('DELETE FROM ip_region').run();
  res.json({ ok: true, cleared: ip || 'all' });
});

app.post('/api/admin/users', requireAdmin, (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const nickname = String((req.body && req.body.nickname) || '').trim() || username;
  const role = (req.body && req.body.role) === 'admin' ? 'admin' : 'member';

  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    return res.status(400).json({ error: '账号需为 3-32 位字母、数字或 _ . -' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: '密码至少 6 位' });
  }
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
    return res.status(409).json({ error: '该账号已存在' });
  }
  const info = db.prepare(
    'INSERT INTO users (username, password_hash, nickname, role, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(username, bcrypt.hashSync(password, BCRYPT_ROUNDS), nickname.slice(0, 32), role, Date.now(), req.user.username);
  audit(req.user, 'create_user', username, '角色：' + (role === 'admin' ? '管理员' : '普通成员'), req.clientIp);
  res.json({ ok: true, id: Number(info.lastInsertRowid) });
});

app.patch('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: '用户不存在' });

  const b = req.body || {};
  const sets = [];
  const vals = [];

  if (typeof b.nickname === 'string' && b.nickname.trim()) {
    sets.push('nickname = ?');
    vals.push(b.nickname.trim().slice(0, 32));
  }
  if (b.role === 'admin' || b.role === 'member') {
    if (target.id === req.user.id && b.role !== 'admin') {
      return res.status(400).json({ error: '不能取消自己的管理员身份' });
    }
    // 降级任何管理员前，确保启用状态的管理员至少还剩一名（防止互降导致零管理员）
    if (target.role === 'admin' && b.role !== 'admin') {
      const admins = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND disabled = 0").get();
      if (admins.c <= 1) {
        return res.status(400).json({ error: '至少要保留一名启用的管理员' });
      }
    }
    sets.push('role = ?');
    vals.push(b.role);
  }
  if (typeof b.disabled === 'boolean') {
    if (target.id === req.user.id && b.disabled) {
      return res.status(400).json({ error: '不能停用自己的账号' });
    }
    sets.push('disabled = ?');
    vals.push(b.disabled ? 1 : 0);
    if (b.disabled) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  }
  if (!sets.length) return res.status(400).json({ error: '没有需要修改的内容' });

  vals.push(id);
  db.prepare('UPDATE users SET ' + sets.join(', ') + ' WHERE id = ?').run(...vals);
  // 审计：记录改了哪些字段（昵称/角色/停用）
  const changed = [];
  if (sets.includes('nickname = ?')) changed.push('昵称');
  if (sets.includes('role = ?')) changed.push('角色 → ' + (b.role === 'admin' ? '管理员' : '普通成员'));
  if (sets.includes('disabled = ?')) changed.push(b.disabled ? '停用账号' : '恢复启用');
  audit(req.user, 'update_user', target.username, '修改：' + (changed.join('、') || '未知'), req.clientIp);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/password', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const pwd = String((req.body && req.body.password) || '');
  if (pwd.length < 6) return res.status(400).json({ error: '密码至少 6 位' });
  const target = db.prepare('SELECT id FROM users WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: '用户不存在' });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(pwd, BCRYPT_ROUNDS), id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id); // 强制该用户重新登录
  audit(req.user, 'reset_password', target.username, '重置密码，已强制该用户重新登录', req.clientIp);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: '用户不存在' });
  if (target.id === req.user.id) {
    return res.status(400).json({ error: '不能删除自己的账号' });
  }
  if (target.role === 'admin') {
    const admins = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND disabled = 0").get();
    if (admins.c <= 1) return res.status(400).json({ error: '至少要保留一名管理员' });
  }
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  // 历史消息保留，作者显示为“已注销用户”
  audit(req.user, 'delete_user', target.username, '删除账号（历史消息保留）', req.clientIp);
  res.json({ ok: true });
});

/* ---------- 登录安全：动态 / 审批 / 封禁 ---------- */

// 安全一览：待放行数、待处理封禁数、今日登录数等
app.get('/api/admin/security', requireAdmin, (req, res) => {
  const pending = db.prepare("SELECT COUNT(*) AS c FROM login_approvals WHERE status = 'pending' AND used = 0").get().c;
  const bannedUsers = db.prepare('SELECT COUNT(*) AS c FROM login_bans WHERE level >= 4').get().c;
  const bannedTemp = db.prepare('SELECT COUNT(*) AS c FROM login_bans WHERE level < 4 AND level > 0 AND banned_until > ?').get(Date.now()).c;
  const log24h = db.prepare('SELECT COUNT(*) AS c FROM login_log WHERE created_at > ?').get(Date.now() - 24 * 3600 * 1000).c;
  const ok24h = db.prepare("SELECT COUNT(*) AS c FROM login_log WHERE created_at > ? AND result = 'success'").get(Date.now() - 24 * 3600 * 1000).c;
  // HTTPS 状态：只有证书存在且本请求走 TLS 才认为「当前正使用加密通道」。
  // 注意：8443 一直开着，但用户若从 8080 访问，req.secure 是 false —— 这就是
  // 「明明启动了 HTTPS 却显示未启用」的真相：是访问入口不对，不是服务没起。
  const httpsEnabled = !!(httpsServer && req.secure);
  res.json({
    pending, bannedUsers, bannedTemp, log24h, ok24h,
    httpsEnabled,
    scheme: req.secure ? 'https' : 'http',
    channelHint: req.secure
      ? '当前通过 HTTPS 加密通道访问'
      : '当前通过 HTTP 明文访问，请改用 https://' + req.headers.host + ':' + HTTPS_PORT + '（若已配置 HTTPS）'
  });
});

// 登录动态日志（支持分页：page 从 1 开始，size 可选 10/20/30/50/100）
app.get('/api/admin/login-log', requireAdmin, (req, res) => {
  const size = Math.min(Math.max(Number(req.query.size) || 20, 1), 200);
  const page = Math.max(Number(req.query.page) || 1, 1);
  const only = String(req.query.only || '');
  const where = [];
  const args = [];
  if (only === 'fail') where.push("result IN ('fail','banned','locked','geo_blocked','denied')");
  else if (only === 'pending') where.push("result = 'pending'");
  else if (only === 'success') where.push("result = 'success'");
  const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
  const total = db.prepare('SELECT COUNT(*) AS c FROM login_log' + whereSql).get(...args).c;
  const rows = db.prepare(
    'SELECT * FROM login_log' + whereSql + ' ORDER BY id DESC LIMIT ? OFFSET ?'
  ).all(...args, size, (page - 1) * size);
  res.json({
    total,
    page,
    size,
    pages: Math.max(1, Math.ceil(total / size)),
    logs: rows.map(r => ({
      id: r.id, userId: r.user_id, username: r.username, ip: r.ip,
      region: r.region || '未知', province: r.province || '', city: r.city || '',
      isp: r.isp || '', ua: r.ua || '', device: deviceFromUA(r.ua),
      result: r.result, reason: r.reason || '',
      createdAt: r.created_at
    }))
  });
});

// 清空登录动态日志
app.delete('/api/admin/login-log', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM login_log').run();
  res.json({ ok: true });
});

// 待审批列表
app.get('/api/admin/approvals', requireAdmin, (req, res) => {
  const rows = db.prepare(
    "SELECT * FROM login_approvals WHERE status = 'pending' ORDER BY id DESC LIMIT 200"
  ).all();
  // 同段判定：该用户 known_ips 里有没有和本次 IP 同一 /24 段的（放行优化的记忆）
  // 已知段存的是「完整网络地址 + 掩码」如 127.0.0.0/24，只取前三段做比较。
  const segOf = (ip) => ip.indexOf(':') >= 0 ? '' : (ip.split('.').slice(0, 3).join('.'));
  res.json({
    approvals: rows.map(r => {
      const u = db.prepare('SELECT known_ips FROM users WHERE id = ?').get(r.user_id);
      const known = new Set(String(u && u.known_ips || '').split(',').map(s => s.trim()).filter(Boolean)
        .map(k => k.indexOf('/') > 0 ? k.split('/')[0].replace(/\.0$/, '') : ''));
      const seg = segOf(r.ip);
      const sameSeg = seg ? Array.from(known).indexOf(seg) >= 0 : false;
      return {
        id: r.id, userId: r.user_id, username: r.username, ip: r.ip,
        region: r.region || '未知', province: r.province || '', city: r.city || '',
        isp: r.isp || '', ua: r.ua || '', device: deviceFromUA(r.ua), createdAt: r.created_at,
        expiresAt: r.expires_at,
        firstLogin: !!(r.created_at && r.created_at === r.updated_at),
        sameSeg   // true = 用户常用 IP 段，大概率是本人换 IP/换网络，可放心放行
      };
    })
  });
});

function approvalExpired(r) {
  return r.expires_at && Date.now() > r.expires_at;
}

// 审批决定：放行 / 拒绝（仅本次登录有效）
app.post('/api/admin/approvals/:id/decide', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const decide = String((req.body && req.body.decide) || '');
  if (decide !== 'approve' && decide !== 'reject') {
    return res.status(400).json({ error: 'decide 只能是 approve 或 reject' });
  }
  const r = db.prepare('SELECT * FROM login_approvals WHERE id = ?').get(id);
  if (!r) return res.status(404).json({ error: '审批记录不存在' });
  if (r.status !== 'pending') return res.status(400).json({ error: '该记录已处理过' });
  if (approvalExpired(r)) {
    db.prepare("UPDATE login_approvals SET status = 'rejected', decided_by = ?, decided_at = ?, reason = '审批超时自动失效' WHERE id = ?")
      .run(req.user.username, Date.now(), id);
    return res.status(400).json({ error: '该审批已过期（30 分钟内未处理），请让用户重新发起登录' });
  }
  const approved = decide === 'approve';
  db.prepare('UPDATE login_approvals SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?')
    .run(approved ? 'approved' : 'rejected', req.user.username, Date.now(), id);
  logLogin({
    user_id: r.user_id, username: r.username, ip: r.ip,
    region: r.region, province: r.province, city: r.city, isp: r.isp, ua: r.ua,
    result: approved ? 'pending' : 'denied',
    reason: '管理员 ' + req.user.username + (approved ? ' 放行了该 IP 的本次登录' : ' 拒绝了该 IP 的本次登录')
  });
  logAccess({
    ip: req.clientIp, region: '管理后台', allowed: true,
    reason: '管理员 ' + req.user.username + (approved ? ' 放行' : ' 拒绝') + ' ' + r.username + ' 从 ' + r.ip + ' 的登录',
    path: '/api/admin/approvals/' + id + '/decide', method: 'POST', username: req.user.username
  });
  notifyAdmins('approval_handled', { id, decide: approved ? 'approve' : 'reject', by: req.user.username });
  audit(req.user, approved ? 'approve_login' : 'reject_login', r.username,
    (approved ? '放行' : '拒绝') + ' ' + r.username + ' 从 ' + (r.ip || '') + ' 的登录申请', req.clientIp);
  res.json({ ok: true, approved });
});

// 账号封禁列表（含解封入口）
app.get('/api/admin/bans', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT b.user_id, b.level, b.strike, b.banned_until, b.reason, b.updated_at,
           u.username, u.nickname
    FROM login_bans b
    JOIN users u ON u.id = b.user_id
    ORDER BY b.updated_at DESC
  `).all();
  res.json({
    bans: rows.map(r => ({
      userId: r.user_id, username: r.username, nickname: r.nickname,
      level: r.level, strike: r.strike, reason: r.reason || '',
      permanent: r.level >= 4, until: r.banned_until, updatedAt: r.updated_at
    }))
  });
});

// 解封账号（管理员手动）
app.post('/api/admin/bans/:userId/unban', requireAdmin, (req, res) => {
  const userId = Number(req.params.userId);
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!target) return res.status(404).json({ error: '用户不存在' });
  db.prepare('DELETE FROM login_bans WHERE user_id = ?').run(userId);
  const un = target.username;
  logLogin({ user_id: userId, username: un, ip: req.clientIp, region: '管理后台', result: 'success', reason: '管理员 ' + req.user.username + ' 解封了该账号' });
  logAccess({ ip: req.clientIp, region: '管理后台', allowed: true, reason: '管理员 ' + req.user.username + ' 解封了 ' + un, path: '/api/admin/bans/' + userId + '/unban', method: 'POST', username: req.user.username });
  audit(req.user, 'unban_user', un, '解除账号封禁', req.clientIp);
  notifyAdmins('ban_lifted', { userId, username: un, by: req.user.username });
  res.json({ ok: true });
});

// 管理操作审计日志（后台敏感操作可追溯）
app.get('/api/admin/audit', requireAdmin, (req, res) => {
  const size = Math.min(Math.max(Number(req.query.size) || 20, 1), 100);
  const page = Math.max(Number(req.query.page) || 1, 1);
  const only = String(req.query.only || '');
  const where = [];
  const args = [];
  if (only) {
    where.push('action LIKE ?');
    args.push('%' + only + '%');
  }
  const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
  const total = db.prepare('SELECT COUNT(*) AS c FROM admin_audit' + whereSql).get(...args).c;
  const rows = db.prepare(
    'SELECT * FROM admin_audit' + whereSql + ' ORDER BY id DESC LIMIT ? OFFSET ?'
  ).all(...args, size, (page - 1) * size);
  res.json({
    total,
    page,
    size,
    pages: Math.max(1, Math.ceil(total / size)),
    logs: rows.map(r => ({
      id: r.id,
      admin: r.admin_user || '',
      action: r.action || '',
      target: r.target || '',
      detail: r.detail || '',
      ip: r.ip || '',
      createdAt: r.created_at
    }))
  });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  const members = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'member'").get().c;
  const messages = db.prepare('SELECT COUNT(*) AS c FROM messages').get().c;
  const files = db.prepare('SELECT COUNT(*) AS c, COALESCE(SUM(size), 0) AS s FROM files').get();

  let dbSize = 0;
  for (const f of ['chat.db', 'chat.db-wal', 'chat.db-shm']) {
    try { dbSize += fs.statSync(path.join(DATA_DIR, f)).size; } catch (_) { /* 忽略 */ }
  }

  res.json({
    users, members, messages,
    files: files.c,
    fileBytes: Number(files.s),
    dbBytes: dbSize,
    online: onlineUsers.size,
    startedAt: STARTED_AT,
    uptimeSec: Math.floor((Date.now() - STARTED_AT) / 1000)
  });
});

/* ---------- F8 群公告 ---------- */

// 当前生效的公告（用户端拉取）
app.get('/api/announcement', requireAuth, (req, res) => {
  const a = db.prepare("SELECT * FROM announcements WHERE active = 1 ORDER BY updated_at DESC LIMIT 1").get();
  if (!a) return res.json({ announcement: null });
  res.json({
    announcement: {
      id: a.id, title: a.title || '', body: safeDecrypt(a.body, ''),
      createdAt: a.created_at, updatedAt: a.updated_at
    }
  });
});

// 管理端：设置 / 关闭公告
app.post('/api/admin/announcement', requireAdmin, (req, res) => {
  const body = String((req.body && req.body.body) || '').trim();
  const title = String((req.body && req.body.title) || '').trim().slice(0, 60);
  const now = Date.now();
  if (!body) {
    // 空正文 = 关闭当前公告
    db.prepare('UPDATE announcements SET active = 0 WHERE active = 1').run();
    audit(req.user, 'announcement_off', '群公告', '关闭公告', req.clientIp);
    // 通知前端收起横幅
    try { io.emit('announcement:update', null); } catch (_) {}
    return res.json({ ok: true, active: false });
  }
  const v = vault.encryptText(body.slice(0, 2000));
  db.prepare('UPDATE announcements SET active = 0 WHERE active = 1').run();
  db.prepare('INSERT INTO announcements (title, body, created_by, created_at, updated_at, active) VALUES (?, ?, ?, ?, ?, 1)')
    .run(title, v, req.user.id, now, now);
  audit(req.user, 'announcement_on', '群公告', '发布公告：' + (title || '（无标题）'), req.clientIp);
  const out = { id: db.prepare("SELECT id FROM announcements WHERE active = 1 LIMIT 1").get().id, title, body, updatedAt: now };
  try { io.emit('announcement:update', out); } catch (_) {}
  res.json({ ok: true, active: true });
});

/* ---------- F9 敏感词管理 ---------- */

app.get('/api/admin/sensitive-words', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT word, created_at FROM sensitive_words ORDER BY created_at DESC').all();
  res.json({ words: rows.map(r => r.word) });
});

app.post('/api/admin/sensitive-words', requireAdmin, (req, res) => {
  const raw = String((req.body && req.body.word) || '').trim();
  if (!raw) return res.status(400).json({ error: '敏感词不能为空' });
  const word = raw.slice(0, 50);
  db.prepare('INSERT OR IGNORE INTO sensitive_words (word, created_by, created_at) VALUES (?, ?, ?)')
    .run(word, req.user.id, Date.now());
  sensitiveWords = db.prepare('SELECT word FROM sensitive_words').all().map(r => r.word);
  audit(req.user, 'sensitive_add', '敏感词', '添加：' + word, req.clientIp);
  res.json({ ok: true, words: sensitiveWords });
});

app.delete('/api/admin/sensitive-words', requireAdmin, (req, res) => {
  const raw = String((req.body && req.body.word) || '').trim();
  if (!raw) return res.status(400).json({ error: '参数不合法' });
  db.prepare('DELETE FROM sensitive_words WHERE word = ?').run(raw);
  sensitiveWords = db.prepare('SELECT word FROM sensitive_words').all().map(r => r.word);
  audit(req.user, 'sensitive_del', '敏感词', '删除：' + raw, req.clientIp);
  res.json({ ok: true, words: sensitiveWords });
});

/* ---------- F10 一键清空聊天记录（软删，保留审计） ---------- */

app.post('/api/admin/clear-messages', requireAdmin, (req, res) => {
  const scope = String((req.body && req.body.scope) || 'all');   // all | public | dm
  const where = [];
  const args = [];
  if (scope === 'public') where.push('peer_id = 0');
  else if (scope === 'dm') where.push('peer_id > 0');
  const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
  const before = db.prepare('SELECT COUNT(*) AS c FROM messages' + whereSql).get(...args).c;
  // 软删：置 revoked，正文清空（保留用户/时间/类型，前端显示「已撤回」）
  db.prepare('UPDATE messages SET revoked = 1, body = NULL WHERE revoked = 0' + whereSql).run(...args);
  audit(req.user, 'clear_messages', scope,
    '清空聊天记录（' + (scope === 'public' ? '公共房间' : scope === 'dm' ? '全部私聊' : '全部') + '）：' + before + ' 条',
    req.clientIp);
  try { io.emit('chat:cleared', { scope, count: before }); } catch (_) {}
  res.json({ ok: true, cleared: before });
});

/* ---------- 页面 ---------- */

/* 静态文本预压缩：挂在这里（geoGuard 与通用安全头之后、express.static 之前）。
 * 为什么必须在这：express.static 内部用 createReadStream().pipe(res) 流式输出，
 * 上面的 res.send/res.end 补丁看不到内容，静态文件（含首页）压不动。
 * 本中间件在 static 之前直接接管「GET + 文本型静态资源」：读文件、压缩、end()。
 * 位置在 geoGuard 之后，确保地域拦截对静态资源同样生效，不存在绕过。
 * res.end 补丁看到已设 Content-Encoding 会跳过二次压缩，不会双压。
 */
// 压缩结果缓存。静态文件就那么几个，上限给得宽一些，超了直接整体清空重建
const staticCompCache = new Map();
const STATIC_COMP_CACHE_MAX = 64;
const STATIC_GZIP_EXT = {
  '.html': 'text/html; charset=utf-8', '.htm': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8', '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml; charset=utf-8', '.txt': 'text/plain; charset=utf-8'
};
app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  const accept = String(req.headers['accept-encoding'] || '');
  const enc = accept.indexOf('br') >= 0 ? 'br' : (accept.indexOf('gzip') >= 0 ? 'gzip' : null);
  if (!enc) return next();
  // 隐藏管理后台路径 → admin.html；其余按扩展名白名单接管
  let rel = null;
  if (req.path === ADMIN_PATH) rel = 'admin.html';
  else if (req.path === '/' || req.path === '/index.html') rel = 'index.html';
  else if (req.path.startsWith('/') && !req.path.startsWith('/api/') && !req.path.startsWith('/socket.io')) {
    try { rel = decodeURIComponent(req.path).replace(/^\/+/, ''); } catch (_) { return next(); }
    if (rel.indexOf('?') >= 0) rel = rel.split('?')[0];
    if (!STATIC_GZIP_EXT[path.extname(rel).toLowerCase()]) rel = null;
  }
  if (!rel) return next();
  const abs = path.join(PUBLIC_DIR, rel);
  // 防目录穿越：目标必须落在 PUBLIC_DIR 内
  if (abs !== PUBLIC_DIR && !abs.startsWith(PUBLIC_DIR + path.sep)) return next();
  let buf;
  try { buf = fs.readFileSync(abs); } catch (_) { return next(); } // 文件不存在 → 交给 static/404
  // 缓存优化：
  //  - 所有文本资源都发 ETag（内容 sha1），浏览器带 If-None-Match 回来时命中就 304，
  //    首次之后刷新不再全量重传（首页 272KB → gzip ~50KB → 304 0 字节）。
  //  - Cache-Control：/vendor/* 与 /sounds/* 等不易变资源给长缓存；index/admin 用 no-cache
  //    （no-cache 仍会带 ETag 走 304，兼顾「改动立即生效」与「不重复下载」）。
  const etag = '"' + crypto.createHash('sha1').update(buf).digest('hex').slice(0, 16) + '"';
  const inm = String(req.headers['if-none-match'] || '');
  res.setHeader('Content-Type', STATIC_GZIP_EXT[path.extname(rel).toLowerCase()] || 'text/plain; charset=utf-8');
  res.setHeader('ETag', etag);
  const longCache = /^vendor\//.test(rel) || /^sounds\//.test(rel);
  res.setHeader('Cache-Control', longCache
    ? 'public, max-age=31536000, immutable'
    : (rel === 'index.html' || rel === 'admin.html' ? 'no-cache' : 'public, max-age=3600'));
  if (inm === etag) {
    res.status(304);
    res.removeHeader('Content-Length');
    return res.end();
  }
  // 压缩结果缓存：brotli 压 272KB 首页要好几十毫秒，而且是**同步**调用，
  // 会整段阻塞事件循环。每次请求都重压的话，并发一上来所有请求一起卡。
  // key 里带 etag（内容 sha1），文件内容一变就自动失效，不需要额外的失效机制。
  const ck = rel + '|' + enc + '|' + etag;
  let out = staticCompCache.get(ck);
  if (!out) {
    out = enc === 'br' ? zlib.brotliCompressSync(buf) : zlib.gzipSync(buf);
    if (staticCompCache.size > STATIC_COMP_CACHE_MAX) staticCompCache.clear();
    staticCompCache.set(ck, out);
  }
  res.setHeader('Content-Encoding', enc);
  res.setHeader('Content-Length', out.length);
  return res.end(out);
});

// 管理后台：隐藏入口，使用不易被猜测的路径，旧 /admin 一律 404。
// 安装时可用 ADMIN_PATH 环境变量指定（如 ADMIN_PATH=/my-secret-admin），
// 未指定则每次启动自动生成随机路径，保证不同实例入口互不相同、无法枚举。
const ADMIN_PATH = (function () {
  const env = String(process.env.ADMIN_PATH || '').trim();
  if (env) return env.startsWith('/') ? env : '/' + env;
  const charset = 'abcdefghijkmnpqrstuvwxyz23456789';
  let s = '';
  for (let i = 0; i < 8; i++) s += charset[Math.floor(Math.random() * charset.length)];
  return '/' + s;
})();
app.get(ADMIN_PATH, (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));
app.get('/admin', (req, res) => res.status(404).send('Not Found'));
app.get('/admin.html', (req, res) => res.status(404).send('Not Found'));
// 把当前实例的管理后台路径暴露给前端（仅登录用户可查，未登录返回 401）
app.get('/api/admin-path', requireAuth, (req, res) => {
  res.json({ path: ADMIN_PATH });
});
// 静态回退：不压缩的浏览器走这里。vendor/sounds 长缓存（内容不变），其余不缓存。
app.use(express.static(PUBLIC_DIR, {
  index: 'index.html',
  maxAge: 0,
  setHeaders(res, filePath) {
    if (/[\\/](vendor|sounds)[\\/]/.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
  }
}));

app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: '接口不存在' });
  res.status(404).sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

/* ==================== HTTP + WebSocket ==================== */

// 大文件上传可能持续很久，关闭请求超时，避免传到一半被服务端掐断
function tuneServer(s) {
  s.requestTimeout = 0;
  s.headersTimeout = 0;
  s.keepAliveTimeout = 120000;
  return s;
}

const server = tuneServer(http.createServer(app));

// 只要 certs/ 下有证书，就额外开一个 HTTPS 端口；没有就只跑 HTTP
let httpsServer = null;
try {
  const crtFile = path.join(CERT_DIR, 'server.crt');
  const keyFile = path.join(CERT_DIR, 'server.key');
  if (fs.existsSync(crtFile) && fs.existsSync(keyFile)) {
    httpsServer = tuneServer(https.createServer({
      key: fs.readFileSync(keyFile),
      cert: fs.readFileSync(crtFile)
    }, app));
  }
} catch (e) {
  console.error('[chat] HTTPS 初始化失败，本次仅提供 HTTP：', e.message);
}

const io = new Server({
  maxHttpBufferSize: 1e6,
  pingInterval: 25000,
  pingTimeout: 60000
});
io.attach(server);
if (httpsServer) io.attach(httpsServer);

// engine.io 中间件：HTTP 握手请求（polling/websocket upgrade）在 engine.io 层就被
// express 之外的处理器接管，io.use() 拦不到「裸握手」。这里在更前面拦一道，
// 避免用 curl 直接打 /socket.io/?EIO=4&transport=polling 就能绕过地域拦截。
io.engine.use((req, res, next) => {
  const rawAddr = req.socket && req.socket.remoteAddress;
  let ip = geo.normalizeIp(rawAddr);
  if (GEO_TEST_IP && geo.isPrivateIp(ip)) ip = GEO_TEST_IP;
  geoDecide(ip).then(function (d) {
    const blocked = !d.allow && d.mode === 'on';
    if (blocked) {
      logAccess({
        ip, region: geo.prettyRegion(d.region),
        province: d.region && d.region.province, city: d.region && d.region.city, isp: d.region && d.region.isp,
        allowed: false, reason: '实时连接被地域规则拦截：' + d.reason, path: '/socket.io', method: 'WS'
      });
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: '当前网络所在地不在允许范围内', detail: d.reason }));
    }
    next();
  }).catch(function (err) {
    // 判定异常：fail-closed —— 地域是管理员登录+实时连接的核心防线，
    // 出异常时宁可拒绝连接并留痕，也不要静默放行让防线整体失效。
    try {
      logAccess({
        ip, region: '', province: '', city: '', isp: '',
        allowed: false, reason: '地域判定异常，实时连接拒绝：' + (err && err.message || err),
        path: '/socket.io', method: 'WS'
      });
    } catch (_) { /* 审计写失败不影响阻断 */ }
    res.writeHead(503, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: '服务暂时不可用，请稍后重试', code: 'GEO_ERROR' }));
  });
});

const onlineUsers = new Map(); // userId -> Set<socketId>
const onlineByUsername = new Map(); // username -> Set<socketId>（@提醒用）

/** 解析消息里的 @提及：
 *  - 在线用户实时推送 chat:mention；
 *  - 无论在线与否都写入 mentions 表（离线 @ 不丢，连接时补推，P2-1）。
 *  精确匹配 username，其次昵称。 */
function fireMentions(text, msg) {
  if (!text || !msg) return;
  if (Number(msg.peer || 0) > 0) return;   // 私聊不做 @ 提醒（也不该有 @所有人）
  const msgId = Number(msg.id);
  const now = Date.now();
  const push = (uid, sid, payload) => io.to(sid).emit('chat:mention', payload);
  const persist = (uid) => {
    try {
      db.prepare('INSERT INTO mentions (message_id, user_id, created_at) VALUES (?, ?, ?)')
        .run(msgId, uid, now);
    } catch (_) { /* 落库失败不影响实时推送 */ }
  };

  // @所有人：发给除发送者以外的每一个在线用户（不走昵称匹配）
  if (/@所有人/.test(text)) {
    const payload = {
      id: msg.id,
      from: { id: msg.user.id, nickname: msg.user.nickname, username: msg.user.username },
      text: (msg.body || '').slice(0, 140),
      all: true
    };
    for (const [uid, set] of onlineUsers) {
      if (uid === msg.user.id) continue;      // 自己 @所有人 不提醒自己
      for (const sid of set) push(uid, sid, payload);
    }
    // @所有人也落库给所有成员（除自己），离线者登录后可查未读
    try {
      db.prepare(
        'INSERT INTO mentions (message_id, user_id, created_at) ' +
        'SELECT ?, id, ? FROM users WHERE role = ? AND id != ?'
      ).run(msgId, now, 'member', msg.user.id);
    } catch (_) { /* 忽略 */ }
  }

  const names = new Set();
  const re = /@([\w\u4e00-\u9fa5·.]{1,24})/g;
  let m;
  while ((m = re.exec(text))) names.add(m[1]);
  if (!names.size) return;
  for (const name of names) {
    // 先按 username 匹配；找不到再按昵称匹配 —— 两者都要落库 + 实时推
    let row = db.prepare('SELECT id, username FROM users WHERE username = ?').get(name);
    if (!row) row = db.prepare('SELECT id, username FROM users WHERE nickname = ?').get(name);
    if (!row) continue;
    const uid = Number(row.id);
    if (uid === Number(msg.user.id)) continue;   // @自己 不提醒自己
    persist(uid);
    const targets = onlineByUsername.get(row.username);
    if (targets && targets.size) {
      const payload = {
        id: msg.id,
        from: { id: msg.user.id, nickname: msg.user.nickname, username: msg.user.username },
        text: (msg.body || '').slice(0, 140)
      };
      for (const sid of targets) push(uid, sid, payload);
    }
  }
}

/** 用户建立实时连接时，把离线期间攒下的 @ 提醒补推给他（一次性拉取未读，推送后标记已读） */
function flushPendingMentions(uid, socket) {
  try {
    const rows = db.prepare(
      'SELECT message_id, created_at FROM mentions WHERE user_id = ? AND read_at IS NULL ORDER BY id ASC LIMIT 50'
    ).all(uid);
    if (!rows.length) return;
    const ids = rows.map(r => r.message_id);
    const qmarks = ids.map(() => '?').join(',');
    const stmt = db.prepare(MSG_SELECT + ' WHERE m.id IN (' + qmarks + ') ORDER BY m.id ASC');
    const msgs = stmt.all.apply(stmt, ids);
    const byId = new Map(msgs.map(sm => [sm.id, sm]));
    for (const r of rows) {
      const sm = byId.get(r.message_id);
      if (!sm) continue;
      const ser = serializeMessage(sm);
      socket.emit('chat:mention', {
        id: ser.id,
        from: { id: ser.user.id, nickname: ser.user.nickname, username: ser.user.username },
        text: (ser.body || '').slice(0, 140),
        offline: true
      });
    }
    // 全部 emit 完再统一标记已读：若中途连接断开（emit 本身不报错，但数据已进传输队列，
    // 标了已读这条提醒就永久丢了），应让未送出的提醒保留下来，下次重连再补。
    // Socket.IO 是队列式发送，断开瞬间仍在队列里的包也会跟着连接一起丢弃。
    // 所以先全部入队、再统一标记 —— 队列丢弃发生在断开那一刹，已标记的并不保证送达，
    // 这里改为：标记动作延后一拍（setImmediate），让本轮 emit 先走完。
    setImmediate(() => {
      try {
        const now2 = Date.now();
        for (const r of rows) {
          db.prepare('UPDATE mentions SET read_at = ? WHERE user_id = ? AND message_id = ? AND read_at IS NULL')
            .run(now2, uid, r.message_id);
        }
      } catch (_) { /* 标记失败下次连接会再补一次（无害） */ }
    });
  } catch (_) { /* 补推失败不影响连接 */ }
}

function broadcastPresence() {
  io.emit('presence', { online: onlineUsers.size });
}

/* ==================== 群组语音通话（WebRTC 信令中转） ====================
 * 本服务只做「信令转发」，音频走 WebRTC 点对点直连，服务器不听也不存任何声音。
 * 组网方式：mesh（两两直连）。因此人数上限默认 6，人多时上行带宽会线性增长。
 * 谁发 offer：新加入者向「已在通话里的每个人」发 offer；已在线的只负责应答，
 * 这样不会有 glare（双方同时发 offer 撞车）。
 */
const CALL_MAX = Math.max(2, Number(process.env.CALL_MAX || 6));
const callState = {
  startedAt: 0,
  startedBy: null,
  private: false,       // 一对一通话：只允许被呼叫的那个人加入，别人进不来
  members: new Map(),   // userId -> { nickname, username, joinedAt, muted }
  invited: new Map(),   // userId -> { by, nickname, username, at }  被点名呼叫、还没回应
  declined: new Set(),   // 本次通话里已明确拒绝的人（不再重复弹来电）
  noAnswerTimer: null   // 1v1 呼叫 60 秒无人接 → 自动挂断留痕（防止双方都断线时无痕）
};

function callSnapshot() {
  return {
    active: callState.members.size > 0,
    startedAt: callState.startedAt,
    startedBy: callState.startedBy,
    max: CALL_MAX,
    members: Array.from(callState.members.entries()).map(function (e) {
      return { id: e[0], nickname: e[1].nickname, username: e[1].username, joinedAt: e[1].joinedAt, muted: !!e[1].muted };
    }),
    invited: Array.from(callState.invited.entries()).map(function (e) {
      return { id: e[0], nickname: e[1].nickname, username: e[1].username, by: e[1].by };
    }),
    declined: Array.from(callState.declined)
  };
}
function broadcastCall() {
  try { io.emit('call:state', callSnapshot()); } catch (_) { /* 忽略 */ }
}
function callReset() {
  callState.startedAt = 0;
  callState.startedBy = null;
  callState.private = false;   // 通话结束，解除一对一限制
  callState.invited.clear();
  callState.declined.clear();
  if (callState.noAnswerTimer) { clearTimeout(callState.noAnswerTimer); callState.noAnswerTimer = null; }
}
function callLeave(userId) {
  if (!callState.members.has(userId)) return false;
  callState.members.delete(userId);
  callState.invited.delete(userId);
  callState.declined.delete(userId);
  if (!callState.members.size) callReset();      // 最后一个人走了，整场通话结束
  // 通知其余成员：这个人走了（前端据此关掉对应的 PeerConnection 和音频）
  io.emit('call:peer-left', { id: userId });
  broadcastCall();
  return true;
}

/** 通话留痕：前端在通话结束的精确时刻上报一次（幂等：noteDone 防重）。
 *  st: 'ended'(接通并结束) | 'canceled'(主叫未接通自行挂断) | 'declined'(被拒) | 'missed'(无人接听)
 *  私聊(peerId>0) 只推给双方；群聊广播到公共房间。
 */
function callNote(actorId, st, durSec, peerId) {
  try {
    const body = JSON.stringify({ st: String(st || 'ended'), dur: Math.max(0, Math.round(durSec || 0)) });
    const msg = createCallNote(actorId, String(st || 'ended'), durSec, peerId);
    if (!msg) return null;
    if (peerId && Number(peerId) > 0) {
      try {
        emitToUser(actorId, 'chat:new', msg);
        emitToUser(Number(peerId), 'chat:new', msg);
      } catch (_e) { /* 忽略 */ }
    } else {
      try { io.emit('chat:new', msg); } catch (_e) { /* 忽略 */ }
    }
    return msg;
  } catch (_e) {
    return null;
  }
}

/** 通话用 ICE 服务器配置：默认给几个公共 STUN；如需穿透对称 NAT，用 CALL_ICE_SERVERS 传 JSON 配 TURN。 */
function callIceServers() {
  const raw = process.env.CALL_ICE_SERVERS;
  if (raw) {
    try {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr) && arr.length) return arr;
    } catch (_) { /* 配错了就退回默认 */ }
  }
  return [
    { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] },
    { urls: ['stun:stun.qq.com:3478'] }
  ];
}

/** 向所有在线的管理员推送安全事件（登录动态、待审批、封禁等） */
function notifyAdmins(kind, data) {
  try {
    io.to('admins').emit('security:' + kind, data);
  } catch (_) { /* 通知失败不影响主流程 */ }
}

/** 管理操作审计：管理员每次敏感操作都落一条，后台可查可追溯 */
function audit(adminUser, action, target, detail, ip) {
  try {
    db.prepare(
      'INSERT INTO admin_audit (admin_id, admin_user, action, target, detail, ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(adminUser && adminUser.id || null, adminUser && adminUser.username || adminUser || '',
      String(action).slice(0, 40), String(target || '').slice(0, 120),
      String(detail || '').slice(0, 400), String(ip || '').slice(0, 64), Date.now());
    // 只保留最近 5000 条，防止后台越堆越大
    db.prepare('DELETE FROM admin_audit WHERE id IN (SELECT id FROM admin_audit ORDER BY id DESC LIMIT -1 OFFSET 5000)').run();
  } catch (_) { /* 审计写失败不影响业务 */ }
}

// Socket.IO 不走 Express 中间件（它在更前面就接管了 /socket.io 请求），
// 所以地域拦截要在握手阶段单独判一次，否则可以绕过页面直接连实时通道。
io.use(async (socket, next) => {
  // 与 clientIp() 保持一致：握手来源 IP 也套用 GEO_TEST_IP 伪装规则（仅本机验证用）
  const rawAddr = socket.handshake.address || '';
  let ip = geo.normalizeIp(rawAddr);
  if (GEO_TEST_IP && geo.isPrivateIp(ip)) ip = GEO_TEST_IP;
  try {
    const d = await geoDecide(ip);
    if (!d.allow && d.mode === 'on') {
      logAccess({
        ip, region: geo.prettyRegion(d.region),
        province: d.region && d.region.province, city: d.region && d.region.city, isp: d.region && d.region.isp,
        allowed: false, reason: '实时连接被地域规则拦截：' + d.reason, path: '/socket.io', method: 'WS'
      });
      return next(new Error('region_blocked'));
    }
    socket.data.ip = ip;
    socket.data.geoDecision = d;
  } catch (e) {
    // fail-closed：判定异常不放行。静默放行会让地域防线整体失效且无任何告警。
    try {
      logAccess({
        ip, region: '', province: '', city: '', isp: '',
        allowed: false, reason: '地域判定异常，实时连接拒绝：' + (e && e.message || e), path: '/socket.io', method: 'WS'
      });
    } catch (_) { /* 审计写失败不影响阻断 */ }
    return next(new Error('geo_error'));
  }

  const u = authFromHeaders(socket.handshake.headers);
  if (!u) return next(new Error('unauthorized'));
  socket.data.user = u;
  if (u.role === 'admin') socket.join('admins'); // 管理员进入专属房间，收安全通知
  next();
});

io.on('connection', (socket) => {
  const u = socket.data.user;
  if (!onlineUsers.has(u.id)) onlineUsers.set(u.id, new Set());
  onlineUsers.get(u.id).add(socket.id);
  if (!onlineByUsername.has(u.username)) onlineByUsername.set(u.username, new Set());
  onlineByUsername.get(u.username).add(socket.id);
  broadcastPresence();
  // P2-1：补推离线期间攒下的 @ 提醒
  flushPendingMentions(u.id, socket);

  socket.on('chat:send', (payload, ack) => {
    if (!rateLimit('msg:' + u.id, 'msg')) {
      if (typeof ack === 'function') ack({ ok: false, error: '发送太频繁，请稍后再试', code: 'MSG_RL' });
      return;
    }
    const text = String((payload && payload.body) || '').trim();
    if (!text) {
      if (typeof ack === 'function') ack({ ok: false, error: '内容为空' });
      return;
    }
    // 私聊目标：0 = 公共房间；>0 = 与该用户私聊
    let peer = 0;
    if (payload && payload.peer) {
      const p = Number(payload.peer);
      if (Number.isInteger(p) && p > 0) {
        const pr = db.prepare('SELECT id, disabled FROM users WHERE id = ?').get(p);
        if (!pr || pr.disabled || p === u.id) {
          if (typeof ack === 'function') ack({ ok: false, error: '无法与该用户私聊' });
          return;
        }
        peer = p;
      }
    }
    try {
      // P0 修复：引用目标必须对发送者可见，否则静默降级为普通消息
      const replyTo = resolveReplyTo(db, u.id, payload && payload.replyTo);
      const msg = createMessage(u.id, 'text', text.slice(0, MAX_TEXT), null, replyTo, null, peer);
      // clientToken 是发送方自己生成的随机串，原样带回去，
      // 好让发送方把「发送中的临时气泡」换成服务端确认后的正式消息。
      // 别人收到这串也没用，匹配不上自己的待发列表。
      const token = payload && typeof payload.clientToken === 'string'
        ? payload.clientToken.slice(0, 64) : null;
      if (token) msg.clientToken = token;
      if (peer > 0) {
        // 私聊：只发给聊天双方，绝不进公共房间
        emitToUser(u.id, 'chat:new', msg);
        emitToUser(peer, 'chat:new', msg);
      } else {
        io.emit('chat:new', msg);
        fireMentions(msg.body, msg);
      }
      if (typeof ack === 'function') ack({ ok: true, id: msg.id });
    } catch (e) {
      if (typeof ack === 'function') ack({ ok: false, error: '发送失败' });
    }
  });

  // 转发（微信式）：把一条已有消息复制到若干会话里。
  // 转发文件/图片时复用同一个 file_id，不重复占磁盘；正文原样带过去。
  // 目标可以是「公共房间」或若干私聊对象，一次转发可以投多处。
  socket.on('chat:forward', (payload, ack) => {
    try {
      const srcId = Number(payload && payload.id);
      if (!Number.isInteger(srcId) || srcId <= 0) {
        if (typeof ack === 'function') ack({ ok: false, error: '参数不合法' }); return;
      }
      const src = db.prepare(MSG_SELECT + ' WHERE m.id = ?').get(srcId);
      if (!src || src.revoked) {
        if (typeof ack === 'function') ack({ ok: false, error: '消息不存在或已撤回' }); return;
      }
      // 可见性：只能转发我看得见的（公共消息，或与我相关的私聊）
      if (src.peer_id !== 0 && src.peer_id !== u.id && src.user_id !== u.id) {
        if (typeof ack === 'function') ack({ ok: false, error: '无权转发这条消息' }); return;
      }
      // 目标：数组，0 表示公共房间，其余为用户 id；去重、去自己、最多 20 个
      const rawTargets = Array.isArray(payload && payload.targets) ? payload.targets : [];
      const targets = [];
      for (const t of rawTargets) {
        const v = Number(t);
        if (!Number.isInteger(v) || v < 0) continue;
        if (v === 0) { if (targets.indexOf(0) < 0) targets.push(0); continue; }
        if (v === u.id) continue;                       // 不发给自己
        const ur = db.prepare('SELECT id, disabled FROM users WHERE id = ?').get(v);
        if (!ur || ur.disabled) continue;
        if (targets.indexOf(v) < 0) targets.push(v);
      }
      if (!targets.length) {
        if (typeof ack === 'function') ack({ ok: false, error: '没有选择转发目标' }); return;
      }
      if (targets.length > 20) targets.length = 20;
      // 转发的正文：过一遍敏感词（createMessage 只对 kind==='text' 生效，这边保持一致）
      const extra = String((payload && payload.text) || '').slice(0, 200).trim();
      const created = [];
      for (const target of targets) {
        if (!rateLimit('msg:' + u.id, 'msg')) break;     // 超出发言配额就停手，避免一次刷爆
        const msg = createMessage(
          u.id,
          src.kind,
          src.kind === 'call' || src.kind === 'pat' ? null : (extra || srcBodyOf(src)),
          src.file_id || null,
          0,
          src.duration || null,
          target
        );
        if (!msg) continue;
        msg.forwardedFrom = src.user_id;                // 前端据此显示「转发自 …」
        if (target > 0) {
          emitToUser(u.id, 'chat:new', msg);
          emitToUser(target, 'chat:new', msg);
        } else {
          io.emit('chat:new', msg);
          // 与 chat:send /api/messages 对齐：转发到公共房间同样触发 @ 提醒（含离线落库）；
          // 私聊路径由 fireMentions 内部 peer>0 早退天然跳过
          fireMentions(msg.body, msg);
        }
        created.push(msg.id);
      }
      if (typeof ack === 'function') ack({ ok: created.length > 0, ids: created, count: created.length });
    } catch (e) {
      if (typeof ack === 'function') ack({ ok: false, error: '转发失败' });
    }
  });

  // 拍一拍（微信标志性互动）：双击对方头像触发，生成一条系统提示。
  // 落在哪个上下文里取决于当前会话——私聊里拍就是私聊消息，公共房间里拍就是公共提示。
  // 限流是必须的：不加的话双击一次浏览器可能连发，对方那边就是一串刷屏。
  socket.on('chat:pat', (payload, ack) => {
    try {
      if (!rateLimit('pat:' + u.id, 'pat')) {
        if (typeof ack === 'function') ack({ ok: false, error: '拍得太快了，歇一下' });
        return;
      }
      const target = Number(payload && payload.target);
      if (!Number.isInteger(target) || target <= 0) { if (typeof ack === 'function') ack({ ok: false }); return; }
      if (target === u.id) { if (typeof ack === 'function') ack({ ok: false, error: '不能拍自己' }); return; }
      const tr = db.prepare('SELECT id, nickname, username, disabled FROM users WHERE id = ?').get(target);
      if (!tr || tr.disabled) { if (typeof ack === 'function') ack({ ok: false, error: '用户不存在' }); return; }
      let peer = 0;
      if (payload && payload.peer) {
        const p = Number(payload.peer);
        if (Number.isInteger(p) && p > 0 && p !== u.id) peer = p;
      }
      // 名字存快照：昵称后来改了，历史里的「谁拍了谁」也还是当时看到的那句话
      const body = JSON.stringify({
        tid: tr.id,
        tname: tr.nickname || tr.username,
        aname: u.nickname || u.username
      });
      const msg = createMessage(u.id, 'pat', body, null, 0, null, peer);
      if (peer > 0) {
        emitToUser(u.id, 'chat:new', msg);
        emitToUser(peer, 'chat:new', msg);
      } else {
        io.emit('chat:new', msg);
      }
      if (typeof ack === 'function') ack({ ok: true, id: msg.id });
    } catch (e) {
      if (typeof ack === 'function') ack({ ok: false, error: '操作失败' });
    }
  });

  // 表情回应（微信式 reactions）：对一条消息点表情，再点一次同一个即取消。
  // 限制：① emoji 长度上限（防客户端塞一大串字符进来）② 目标消息必须存在且可见。
  // 广播给所有人（含发起者），让所有人的界面同时更新计数。
  socket.on('chat:react', (payload, ack) => {
    try {
      const mid = payload && Number(payload.id);
      const emoji = String((payload && payload.emoji) || '').trim();
      if (!Number.isInteger(mid) || mid <= 0) { if (typeof ack === 'function') ack({ ok: false }); return; }
      if (!emoji || emoji.length > 8) { if (typeof ack === 'function') ack({ ok: false, error: '表情不合法' }); return; }
      const row = db.prepare('SELECT id, user_id, peer_id, revoked FROM messages WHERE id = ?').get(mid);
      if (!row) { if (typeof ack === 'function') ack({ ok: false, error: '消息不存在' }); return; }
      if (row.revoked) { if (typeof ack === 'function') ack({ ok: false, error: '消息已撤回' }); return; }
      // 可见性：公共消息，或与我相关的私聊（别人的私聊我看不见，自然也不能回应）
      if (row.peer_id !== 0 && row.peer_id !== u.id && row.user_id !== u.id) {
        if (typeof ack === 'function') ack({ ok: false, error: '无权操作' }); return;
      }
      const exist = db.prepare(
        'SELECT user_id FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?'
      ).get(mid, u.id, emoji);
      if (exist) {
        db.prepare('DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?')
          .run(mid, u.id, emoji);
      } else {
        db.prepare('INSERT OR IGNORE INTO message_reactions (message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?)')
          .run(mid, u.id, emoji, Date.now());
      }
      const list = reactionsOf(mid, 0);
      io.emit('chat:reaction', { id: mid, reactions: list });
      if (typeof ack === 'function') ack({ ok: true, reactions: list });
    } catch (e) {
      if (typeof ack === 'function') ack({ ok: false, error: '操作失败' });
    }
  });

  // 「正在输入…」：只转发给除自己以外的所有在线用户，带 2 秒节流上限
  socket.on('chat:typing', () => {
    socket.broadcast.emit('chat:typing', {
      user: { id: u.id, nickname: u.nickname, username: u.username }
    });
  });

  // 已读回执：收到别人发的消息时，前端会 emit 这条，服务端记录「谁读了哪条」，
  // 再广播给原作者，原作者界面上就能看到「已读：张三、李四」。
  // 自己的消息不能标记已读；重复标记用 INSERT OR IGNORE 去重。
  socket.on('chat:read', (payload, ack) => {
    try {
      const mid = payload && Number(payload.id);
      if (!Number.isInteger(mid) || mid <= 0) return;
      const row = db.prepare('SELECT id, user_id, peer_id FROM messages WHERE id = ?').get(mid);
      if (!row) return;
      if (row.user_id === u.id) return; // 不能读自己的消息
      // 可见性：公共消息，或与我相关的私聊（别人的私聊不能拿来刷已读）
      if (row.peer_id !== 0 && row.peer_id !== u.id && row.user_id !== u.id) return;
      db.prepare('INSERT OR IGNORE INTO message_reads (message_id, user_id, read_at) VALUES (?, ?, ?)')
        .run(mid, u.id, Date.now());
      io.emit('chat:readUpdate', { id: mid, reader: { id: u.id, nickname: u.nickname } });
      if (typeof ack === 'function') ack({ ok: true });
    } catch (e) {
      if (typeof ack === 'function') ack({ ok: false });
    }
  });

  // 撤回：只允许撤回自己的消息（管理员可撤任何人的），撤回后广播给所有人
  socket.on('chat:revoke', (payload, ack) => {
    try {
      const mid = payload && Number(payload.id);
      if (!Number.isInteger(mid) || mid <= 0) {
        if (typeof ack === 'function') ack({ ok: false, error: '参数不合法' });
        return;
      }
      const row = db.prepare('SELECT id, user_id, revoked FROM messages WHERE id = ?').get(mid);
      if (!row) {
        if (typeof ack === 'function') ack({ ok: false, error: '消息不存在' });
        return;
      }
      // 已经撤回过的不能再撤：否则每点一次就广播一轮，别人界面上会反复闪撤回提示条
      if (row.revoked) {
        if (typeof ack === 'function') ack({ ok: false, error: '这条消息已经撤回过了' });
        return;
      }
      if (row.user_id !== u.id && u.role !== 'admin') {
        if (typeof ack === 'function') ack({ ok: false, error: '只能撤回自己的消息' });
        return;
      }
      db.prepare('UPDATE messages SET revoked = 1, body = NULL WHERE id = ?').run(mid);
      // 带上操作者：前端要区分「你撤回了一条消息」和「XX 撤回了一条消息」，
      // 前者还要给一句「重新编辑」（微信行为，2 分钟内可把原文填回输入框）。
      const author = db.prepare('SELECT nickname, username FROM users WHERE id = ?').get(row.user_id);
      io.emit('chat:revoked', {
        id: mid,
        by: u.id,
        authorId: row.user_id,
        authorName: author ? (author.nickname || author.username) : ''
      });
      if (typeof ack === 'function') ack({ ok: true });
    } catch (e) {
      if (typeof ack === 'function') ack({ ok: false, error: '撤回失败' });
    }
  });

  /* ---------- 群组语音通话信令 ---------- */

  // 加入通话：返回「已在通话里的成员」列表，新加入者负责向这些人发 offer
  socket.on('call:join', (payload, ack) => {
    try {
      // 私聊（一对一）通话：只允许通话双方加入，公共房间里的其他人进不来
      if (callState.private && !callState.members.has(u.id) && !callState.invited.has(u.id)) {
        if (typeof ack === 'function') ack({ ok: false, error: '这是一对一通话，不能加入' });
        return;
      }
      if (!callState.members.has(u.id) && callState.members.size >= CALL_MAX) {
        if (typeof ack === 'function') ack({ ok: false, error: '通话人数已满（上限 ' + CALL_MAX + ' 人）' });
        return;
      }
      const existing = Array.from(callState.members.keys()).filter(function (id) { return id !== u.id; });
      if (!callState.members.size) { callState.startedAt = Date.now(); callState.startedBy = u.id; }
      callState.invited.delete(u.id);          // 自己进来了，清掉对我的呼叫
      callState.declined.delete(u.id);
      callState.members.set(u.id, {
        nickname: u.nickname, username: u.username,
        joinedAt: Date.now(), muted: !!(payload && payload.muted)
      });
      // 有人接听 → 1v1 noAnswer 定时器作废
      if (callState.noAnswerTimer) { clearTimeout(callState.noAnswerTimer); callState.noAnswerTimer = null; }
      broadcastCall();
      if (typeof ack === 'function') ack({ ok: true, peers: existing, state: callSnapshot() });
    } catch (e) {
      if (typeof ack === 'function') ack({ ok: false, error: '加入通话失败' });
    }
  });

  // 定向呼叫：发起人加入通话，并把 invite 名单里的人「点名」叫一遍（定向推来电）
  socket.on('call:start', (payload, ack) => {
    try {
      const raw = (payload && Array.isArray(payload.invite)) ? payload.invite : [];
      const ids = raw.map(Number).filter(function (n) {
        return Number.isInteger(n) && n > 0 && n !== u.id;
      }).slice(0, CALL_MAX * 4);
      callState.private = (ids.length === 1);   // 只点一个人 = 一对一通话，外人禁止加入
      if (!callState.members.has(u.id) && callState.members.size >= CALL_MAX) {
        if (typeof ack === 'function') ack({ ok: false, error: '通话人数已满（上限 ' + CALL_MAX + ' 人）' });
        return;
      }
      const existing = Array.from(callState.members.keys()).filter(function (id) { return id !== u.id; });
      if (!callState.members.size) { callState.startedAt = Date.now(); callState.startedBy = u.id; }
      callState.invited.delete(u.id);
      callState.declined.delete(u.id);
      callState.members.set(u.id, {
        nickname: u.nickname, username: u.username,
        joinedAt: Date.now(), muted: !!(payload && payload.muted)
      });
      // 点名：只叫还不在通话里的人
      let rang = 0;
      ids.forEach(function (id) {
        if (callState.members.has(id)) return;
        callState.declined.delete(id);
        callState.invited.set(id, { by: u.id, nickname: u.nickname, username: u.username, at: Date.now() });
        rang++;
        const set = onlineUsers.get(id);
        if (set) {
          for (const sid of set) {
            io.to(sid).emit('call:invite', {
              from: { id: u.id, nickname: u.nickname, username: u.username },
              state: callSnapshot()
            });
          }
        }
      });
      // 1v1 呼叫：60 秒无人接听 → 自动挂断并把「未接听」留痕给双方（微信规则）
      if (callState.private && ids.length === 1) {
        if (callState.noAnswerTimer) clearTimeout(callState.noAnswerTimer);
        callState.noAnswerTimer = setTimeout(function () {
          callState.noAnswerTimer = null;
          // 被叫既没加入、也没明确拒绝 → 视为无人接听
          const calleeId = ids[0];
          if (callState.members.size === 1 && callState.members.has(u.id) &&
              !callState.members.has(calleeId) && !callState.declined.has(calleeId)) {
            callNote(u.id, 'missed', 0, calleeId);        // 主叫视角：未接听
            callState.members.delete(u.id);
            callState.invited.delete(u.id);
            callState.declined.delete(u.id);
            io.emit('call:peer-left', { id: u.id });
            callReset();
            broadcastCall();
          }
        }, 60 * 1000);
      } else if (callState.noAnswerTimer) {
        clearTimeout(callState.noAnswerTimer);
        callState.noAnswerTimer = null;
      }
      broadcastCall();
      if (typeof ack === 'function') ack({ ok: true, peers: existing, rang: rang, state: callSnapshot() });
    } catch (e) {
      if (typeof ack === 'function') ack({ ok: false, error: '发起通话失败' });
    }
  });

  // 拒绝来电：记入 declined，本次通话不再重复叫他；并给主叫方留一条「已拒绝」记录
  socket.on('call:reject', (payload, ack) => {
    if (callState.members.has(u.id)) {
      if (typeof ack === 'function') ack({ ok: false });
      return;     // 已经在通话里就不算拒绝
    }
    callState.invited.delete(u.id);
    if (callState.members.size) callState.declined.add(u.id);
    // 一对一通话被拒 → 整场通话直接结束（微信规则：对方拒绝，主叫也收线）
    const callerId = (callState.members.size === 1) ? Array.from(callState.members.keys())[0] : null;
    if (callerId && Number(callerId) !== u.id) {
      callNote(callerId, 'declined', 0, u.id);   // 主叫方视角：对方已拒绝
      callState.members.delete(callerId);
      callState.invited.delete(callerId);
      callState.declined.delete(callerId);
      callReset();
      io.emit('call:peer-left', { id: callerId });
      broadcastCall();
      if (typeof ack === 'function') ack({ ok: true, ended: true });
      return;
    }
    broadcastCall();
    if (typeof ack === 'function') ack({ ok: true, by: callerId });
  });

  socket.on('call:leave', () => { callLeave(u.id); });

  // 通话结束留痕上报（微信式）：前端在通话结束的精确时刻发一次。
  // 服务端落一条 kind='call' 的消息到相应会话，聊天窗口里就有一条
  // 「通话 00:35 / 未接通」之类的系统说明。
  socket.on('call:note', (payload) => {
    try {
      if (!payload) return;
      const st = String(payload.st || '').slice(0, 16);
      if (['ended', 'canceled', 'declined', 'missed'].indexOf(st) < 0) return;
      const dur = Math.max(0, Math.floor(Number(payload.dur) || 0));
      const peer = Number(payload.peer) > 0 ? Number(payload.peer) : 0;
      callNote(u.id, st, dur, peer);
    } catch (_e) { /* 留痕失败不影响通话 */ }
  });

  // 静音状态：仅用于让其他人的界面上显示「已静音」，不涉及音频流
  socket.on('call:mute', (payload) => {
    const m = callState.members.get(u.id);
    if (!m) return;
    m.muted = !!(payload && payload.muted);
    broadcastCall();
  });

  // 信令转发：SDP / ICE 一律点对点转给指定成员，服务端不解析内容
  socket.on('call:signal', (payload) => {
    const to = Number(payload && payload.to);
    const data = payload && payload.data;
    if (!Number.isInteger(to) || to <= 0 || to === u.id || !data) return;
    if (!callState.members.has(u.id)) return;          // 不在通话里的人不能发信令
    if (!callState.members.has(to)) return;            // 目标已不在通话里，丢弃
    const set = onlineUsers.get(to);
    if (!set) return;
    for (const sid of set) {
      io.to(sid).emit('call:signal', { from: u.id, fromName: u.nickname, data });
    }
  });

  socket.on('disconnect', () => {
    callLeave(u.id);
    const set = onlineUsers.get(u.id);
    if (set) {
      set.delete(socket.id);
      if (!set.size) onlineUsers.delete(u.id);
    }
    const uset = onlineByUsername.get(u.username);
    if (uset) {
      uset.delete(socket.id);
      if (!uset.size) onlineByUsername.delete(u.username);
    }
    broadcastPresence();
  });
});

/* ==================== 首次启动：内置管理员 ==================== */

const STARTED_AT = Date.now();

function ensureAdmin() {
  const exists = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").get().c;
  if (exists > 0) return;
  const pwd = process.env.ADMIN_PASSWORD ||
    crypto.randomBytes(9).toString('base64').replace(/[+/=]/g, '').slice(0, 10);
  db.prepare(
    'INSERT INTO users (username, password_hash, nickname, role, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)'
  ).run('admin', bcrypt.hashSync(pwd, BCRYPT_ROUNDS), '管理员', 'admin', Date.now(), 'system');

  const note = [
    '初始管理员账号（请登录后立即在后台修改密码）',
    '账号: admin',
    '密码: ' + pwd,
    '生成时间: ' + new Date().toISOString(),
    ''
  ].join('\n');
  try {
    fs.writeFileSync(path.join(DATA_DIR, 'INITIAL_ADMIN.txt'), note, { mode: 0o600 });
  } catch (_) { /* 忽略 */ }

  console.log('==================================================');
  console.log('  已创建初始管理员账号');
  console.log('  账号: admin');
  console.log('  密码: ' + pwd);
  console.log('==================================================');
}

// 私聊迁移：老库没有 peer_id 列就补上（0 = 公共房间）
(function migratePeerColumn() {
  try {
    const cols = db.prepare('PRAGMA table_info(messages)').all().map(c => c.name);
    if (!cols.includes('peer_id')) {
      db.exec('ALTER TABLE messages ADD COLUMN peer_id INTEGER NOT NULL DEFAULT 0');
      db.exec('CREATE INDEX IF NOT EXISTS idx_msg_peer ON messages(peer_id)');
      console.log('[chat] 已为 messages 补充 peer_id 列（支持私聊）');
    }
  } catch (e) {
    console.error('[chat] peer_id 迁移失败：', e.message);
  }
})();

// 已知 IP 段记忆迁移：老库 users 没有 known_ips 列就补上（放行优化用）
(function migrateKnownIpsColumn() {
  try {
    const cols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
    if (!cols.includes('known_ips')) {
      db.exec('ALTER TABLE users ADD COLUMN known_ips TEXT');
      console.log('[chat] 已为 users 补充 known_ips 列（已知 IP 段免审批）');
    }
  } catch (e) {
    console.error('[chat] users.known_ips 迁移失败：', e.message);
  }
})();

// 设备会话迁移：老库 sessions 没有 ip 列就补上（设备管理「登录位置」用）
(function migrateSessionIpColumn() {
  try {
    const cols = db.prepare('PRAGMA table_info(sessions)').all().map(c => c.name);
    if (!cols.includes('ip')) {
      db.exec('ALTER TABLE sessions ADD COLUMN ip TEXT');
      console.log('[chat] 已为 sessions 补充 ip 列（设备会话管理）');
    }
  } catch (e) {
    console.error('[chat] sessions.ip 迁移失败：', e.message);
  }
})();

ensureAdmin();

// 清理过期会话
const timer = setInterval(() => {
  try {
    db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
  } catch (_) { /* 忽略 */ }
}, 6 * 3600 * 1000);
timer.unref();

server.listen(PORT, HOST, () => {
  console.log('[chat] 服务已启动 http://' + HOST + ':' + PORT);
  console.log('[chat] 数据目录 ' + DATA_DIR);
  console.log('[chat] 加密密钥来源 ' + KEY_SOURCE + '（指纹 ' + vault.keyFingerprint() + '）');
  const gm = geoKillSwitchOn() ? 'off（紧急开关已打开）' : geoConf.mode;
  const modeText = gm === 'on' ? '拦截中' : gm === 'log' ? '只记录不拦截' : '已关闭';
  const ruleText = [
    geoConf.provOn && geoConf.provinces.length ? '省:' + geoConf.provinces.join('、') : null,
    geoConf.cityOn && geoConf.cities.length ? '市:' + geoConf.cities.join('、') : null
  ].filter(Boolean).join(' / ') || '不限';
  console.log('[chat] 地域准入 ' + modeText +
    ' · 放行 ' + ruleText +
    (geoConf.allowIps.length ? ' · IP 白名单 ' + geoConf.allowIps.length + ' 条' : '') +
    (geoConf.failOpen ? ' · 查不到归属地时放行' : ' · 查不到归属地时拦截'));
  if (GEO_TEST_IP) {
    console.warn('[chat] ⚠ GEO_TEST_IP=' + GEO_TEST_IP + ' 已启用：本机来访问都会被当作来自这个 IP，仅用于验证规则，线上请勿设置');
  }
  if (!httpsServer) {
    console.log('[chat] 未发现 certs/server.crt，本次仅提供 HTTP');
  }
});

if (httpsServer) {
  httpsServer.listen(HTTPS_PORT, HOST, () => {
    console.log('[chat] 加密通道已启动 https://' + HOST + ':' + HTTPS_PORT);
  });
}

process.on('SIGTERM', () => {
  try { server.close(); } catch (_) {}
  try { if (httpsServer) httpsServer.close(); } catch (_) {}
  process.exit(0);
});
