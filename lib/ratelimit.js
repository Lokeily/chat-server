'use strict';

/**
 * 轻量速率限制（P1 加固）
 * 内存 token bucket，按 (key, 窗口) 计数，窗口滑动即清空。
 * 无持久化、无外部依赖；阈值取「人手操作的宽松上限」，正常用户永远碰不到。
 * 用途：防单用户刷屏灌库、无限上传、枚举文件 id。
 */
const RATE_LIMITS = {
  msg:    { window: 60000,   max: 60 },   // 消息：60 条/分钟/用户（HTTP + WS 共用）
  upload: { window: 3600000, max: 30 },   // 上传：30 次/小时/用户
  file:   { window: 60000,   max: 120 },  // 文件下载：120 次/分钟/用户（图片预览会连续取）
  // 拍一拍单独一档：它是「双击一下」的轻量互动，触发成本极低，
  // 沿用 msg 的 60/分钟会让人连点着刷屏（对方那边就是一串"拍了拍"）。
  pat:    { window: 10000,   max: 3 }     // 拍一拍：10 秒内最多 3 次
};
const rateBuckets = new Map(); // key -> { start, count }

/**
 * 尝试消耗一次配额。
 * @param {string} key  限流维度，如 'msg:3'（用户 3）
 * @param {string} kind RATE_LIMITS 的键名
 * @returns {boolean} true=放行；false=超限应拒绝
 */
function rateLimit(key, kind) {
  const cfg = RATE_LIMITS[kind];
  if (!cfg) return true;
  const now = Date.now();
  let b = rateBuckets.get(key);
  if (!b || now - b.start >= cfg.window) {
    rateBuckets.set(key, { start: now, count: 1 });
    // 简单防泄漏：超过 5000 个 key 时全量清空一次（代价可忽略）
    if (rateBuckets.size > 5000) rateBuckets.clear();
    return true;
  }
  b.count += 1;
  return b.count <= cfg.max;
}

module.exports = { rateLimit, RATE_LIMITS };
