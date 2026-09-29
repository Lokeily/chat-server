'use strict';

/**
 * 访问控制辅助（P0 安全修复的可见性判定）
 * 两个函数都依赖 db 实例，用工厂注入，避免模块间循环引用。
 */

/**
 * 文件可见性判定：文件只能被「与该文件存在可见关系」的用户下载，
 * 防止枚举文件 id 越权拉取他人私聊文件。
 * 放行条件（满足其一）：
 *   ① 文件属主本人；② 关联消息是公共消息（peer_id = 0）；
 *   ③ 关联消息是私聊且当前用户是收发双方之一；④ 管理员。
 * @param {object} db    node:sqlite DatabaseSync 实例
 * @param {object} fileRow files 表行
 * @param {object} user   当前登录用户（含 id / role）
 */
function canAccessFile(db, fileRow, user) {
  if (!fileRow || !user) return false;
  if (user.role === 'admin') return true;
  if (Number(fileRow.user_id) === Number(user.id)) return true;
  try {
    const m = db.prepare(
      'SELECT user_id, peer_id FROM messages WHERE file_id = ? AND revoked = 0 ORDER BY id DESC LIMIT 1'
    ).get(fileRow.id);
    if (!m) return false;                       // 没有关联消息：只允许属主
    if (Number(m.peer_id) === 0) return true;    // 公共消息：所有人可见
    // 私聊：必须是收发双方之一
    return Number(m.user_id) === Number(user.id) || Number(m.peer_id) === Number(user.id);
  } catch (_) {
    return false;                               // 判定异常：拒绝而非放行
  }
}

/**
 * 引用回复可见性校验：只允许引用「当前用户可见的消息」——
 * 公共消息或与当前用户相关的私聊，防止把别人私聊内容以引用摘要形式搬运到公共频道。
 * 非法引用返回 0（静默降级为普通消息），避免给出可试探的报错。
 * @param {object} db      node:sqlite DatabaseSync 实例
 * @param {number} actorId 当前用户 id
 * @param {*}      replyTo 客户端提交的 replyTo
 * @returns {number} 合法的引用消息 id，否则 0
 */
function resolveReplyTo(db, actorId, replyTo) {
  const rt = Number(replyTo);
  if (!Number.isInteger(rt) || rt <= 0) return 0;
  try {
    const m = db.prepare(
      'SELECT id, user_id, peer_id, revoked FROM messages WHERE id = ?'
    ).get(rt);
    if (!m || m.revoked) return 0;                        // 不存在或已撤回：不可引用
    if (Number(m.peer_id) === 0) return rt;               // 公共消息：人人可引用
    // 私聊：必须是收发双方之一才能引用
    if (Number(m.user_id) === Number(actorId) || Number(m.peer_id) === Number(actorId)) return rt;
    return 0;                                             // 他人私聊：不可引用
  } catch (_) {
    return 0;                                             // 判定异常：拒绝而非放行
  }
}

module.exports = { canAccessFile, resolveReplyTo };
