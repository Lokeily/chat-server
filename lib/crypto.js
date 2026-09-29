'use strict';

/**
 * 加解密模块（AES-256-GCM）
 *
 * 用途：
 *   - 消息文本加密后入库
 *   - 上传文件名加密后入库
 *   - 上传文件实体加密后落盘
 *
 * 密钥来源（按优先级）：
 *   1. 环境变量 CHAT_SECRET（任意字符串，内部用 SHA-256 归一化成 32 字节）
 *   2. data/secret.key（首次启动自动生成，base64 存储，权限 600）
 *
 * 注意：密钥丢了，已加密的数据就永久解不开了。请务必备份 secret.key。
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;
const PREFIX = 'enc:v1:';

let KEY = null;
let KEY_SOURCE = '';

function initKey(dataDir) {
  const envSecret = process.env.CHAT_SECRET;
  if (envSecret && envSecret.trim()) {
    KEY = crypto.createHash('sha256').update(envSecret.trim(), 'utf8').digest();
    KEY_SOURCE = '环境变量 CHAT_SECRET';
    return KEY_SOURCE;
  }

  const keyFile = path.join(dataDir, 'secret.key');
  if (fs.existsSync(keyFile)) {
    const raw = fs.readFileSync(keyFile, 'utf8').trim();
    const buf = Buffer.from(raw, 'base64');
    if (buf.length !== 32) {
      throw new Error('secret.key 内容不合法（应为 32 字节的 base64），请检查该文件');
    }
    KEY = buf;
    KEY_SOURCE = keyFile;
    return KEY_SOURCE;
  }

  const buf = crypto.randomBytes(32);
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(keyFile, buf.toString('base64') + '\n', { mode: 0o600 });
  KEY = buf;
  KEY_SOURCE = keyFile + '（本次自动生成）';
  return KEY_SOURCE;
}

function assertReady() {
  if (!KEY) throw new Error('加密密钥尚未初始化，请先调用 initKey()');
}

/* ---------------- 文本 ---------------- */

function encryptText(plain) {
  if (plain === null || plain === undefined) return plain;
  assertReady();
  const iv = crypto.randomBytes(IV_LEN);
  const c = crypto.createCipheriv(ALGO, KEY, iv);
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  const tag = c.getAuthTag();
  return PREFIX +
    iv.toString('base64') + ':' +
    tag.toString('base64') + ':' +
    ct.toString('base64');
}

function isEncrypted(v) {
  return typeof v === 'string' && v.startsWith(PREFIX);
}

function decryptText(stored) {
  if (stored === null || stored === undefined) return stored;
  const s = String(stored);
  // 兼容历史明文数据：没有前缀就原样返回
  if (!s.startsWith(PREFIX)) return s;
  assertReady();
  const parts = s.slice(PREFIX.length).split(':');
  if (parts.length !== 3) return s;
  const iv = Buffer.from(parts[0], 'base64');
  const tag = Buffer.from(parts[1], 'base64');
  const ct = Buffer.from(parts[2], 'base64');
  const d = crypto.createDecipheriv(ALGO, KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

/* ---------------- 流（用于大文件，不占内存） ---------------- */

function newIv() {
  return crypto.randomBytes(IV_LEN);
}

function createEncryptStream(iv) {
  assertReady();
  return crypto.createCipheriv(ALGO, KEY, iv);
}

function createDecryptStream(ivB64, tagB64) {
  assertReady();
  const d = crypto.createDecipheriv(ALGO, KEY, Buffer.from(ivB64, 'base64'));
  d.setAuthTag(Buffer.from(tagB64, 'base64'));
  return d;
}

/* ---------------- 密钥指纹（用于自检，不泄露密钥本身） ---------------- */

function keyFingerprint() {
  assertReady();
  return crypto.createHash('sha256').update(KEY).digest('hex').slice(0, 12);
}

module.exports = {
  PREFIX,
  IV_LEN,
  TAG_LEN,
  initKey,
  isEncrypted,
  encryptText,
  decryptText,
  newIv,
  createEncryptStream,
  createDecryptStream,
  keyFingerprint,
  get keySource() { return KEY_SOURCE; }
};
