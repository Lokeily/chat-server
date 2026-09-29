'use strict';

/**
 * IP 归属地解析 + 地域准入判定
 *
 * 数据源（都免 key）：
 *   1. ip-api.com     —— 准确度高，返回中文省/市；免费额度 45 次/分钟
 *   2. whois.pconline —— 国内接口，GBK 编码，作为备用
 *
 * 为什么不用离线库：ip2region / 纯真库都是 10MB 级别的二进制文件，
 * 而当前这套部署是通过文本中转下发的，塞不下。改走在线接口 + 本地缓存。
 *
 * 缓存策略：
 *   - 内存 Map（进程内，6 小时）
 *   - 外部 store（落 SQLite，重启后仍有效，默认 30 天）
 *   - 同一 IP 的并发查询会合并成一次请求（inflight 去重）
 */

const DEFAULT_BASE = 'http://ip-api.com/json/';
const DEFAULT_TIMEOUT = 2500;
const DEFAULT_TOTAL_TIMEOUT = 4000;
const MEM_TTL = 6 * 3600 * 1000;
const PREFIX = 'pconline:';

let cfg = {
  base: DEFAULT_BASE,
  timeout: DEFAULT_TIMEOUT,
  // 整次查询的总时限（含主源 + 备用源两次尝试）。
  // 没有它时：主源 2.5s 超时 + 备用源 2.5s，接口半死不活的情况下每个请求要挂 5 秒才返回，
  // 页面表现就是「一直转圈」。加上总闸后最多挂 4 秒，之后按「查不到」处理，由调用方决定放行还是拦截。
  totalTimeout: DEFAULT_TOTAL_TIMEOUT,
  store: null,          // { get(ip) -> rec|null, put(ip, rec) }
  enabled: true
};

const mem = new Map();     // ip -> rec
const inflight = new Map(); // ip -> Promise

function configure(next) {
  // 过滤掉 undefined：Object.assign 会把 {timeout: undefined} 覆盖掉默认值，
  // 导致 setTimeout(abort, undefined) 立即中止 fetch（这是线上查不到归属地的根因）。
  const clean = {};
  for (const k of Object.keys(next || {})) {
    if (next[k] !== undefined) clean[k] = next[k];
  }
  cfg = Object.assign({}, cfg, clean);
  if (!cfg.base) cfg.base = DEFAULT_BASE;
  if (!(cfg.timeout > 0)) cfg.timeout = DEFAULT_TIMEOUT;
  if (!(cfg.totalTimeout > 0)) cfg.totalTimeout = DEFAULT_TOTAL_TIMEOUT;
  if (typeof cfg.enabled !== 'boolean') cfg.enabled = true;
}

/* ---------------- IP 规整 ---------------- */

function normalizeIp(raw) {
  let ip = String(raw || '').trim();
  if (!ip) return '';
  // ::ffff:1.2.3.4 —— IPv4-mapped IPv6
  if (ip.slice(0, 7).toLowerCase() === '::ffff:') ip = ip.slice(7);
  // 去掉 IPv6 的 zone id，如 fe80::1%en0
  const z = ip.indexOf('%');
  if (z >= 0) ip = ip.slice(0, z);
  if (ip === '::1') return '127.0.0.1';
  return ip;
}

function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip === '127.0.0.1' || ip === 'localhost') return true;
  if (ip.indexOf(':') >= 0) {
    // IPv6：本机 / 链路本地 / 唯一本地地址一律视作内网
    const l = ip.toLowerCase();
    return l === '::1' || l.slice(0, 2) === 'fe' || l.slice(0, 2) === 'fc' || l.slice(0, 2) === 'fd';
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true; // 非法就当内网放行
  if (p[0] === 10) return true;
  if (p[0] === 127) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
  if (p[0] >= 224) return true;                                // 组播/保留
  return false;
}

/* ---------------- 归一化省/市名 ---------------- */

// 「云南省」→「云南」，「昆明市」→「昆明」，「北京市」→「北京」
function normRegion(s) {
  return String(s || '').replace(/[省市区县自治州地区盟]+$/g, '').trim();
}

/* ---------------- 远程查询 ---------------- */

async function fetchWithTimeout(url, ms, decode) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), ms);
  try {
    const res = await fetch(url, { signal: ac.signal });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    if (decode === 'gbk') {
      const buf = Buffer.from(await res.arrayBuffer());
      return JSON.parse(new TextDecoder('gbk').decode(buf).match(/\{[\s\S]*\}/)[0]);
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function viaIpApi(ip) {
  const url = cfg.base + encodeURIComponent(ip) +
    '?lang=zh-CN&fields=status,message,country,regionName,city,isp';
  const j = await fetchWithTimeout(url, cfg.timeout);
  if (!j || j.status !== 'success') throw new Error((j && j.message) || 'ip-api 无结果');
  return {
    country: j.country || '',
    province: j.regionName || '',
    city: j.city || '',
    isp: j.isp || '',
    src: 'ip-api'
  };
}

async function viaPconline(ip) {
  const url = 'https://whois.pconline.com.cn/ipJson.jsp?ip=' + encodeURIComponent(ip) + '&json=true';
  const j = await fetchWithTimeout(url, cfg.timeout, 'gbk');
  if (!j || j.err) throw new Error((j && j.err) || 'pconline 无结果');
  // 关键校验：pconline 碰到自己解析不了的地址（典型是 IPv6），会「退而求其次」返回
  // **发起查询那台机器自己**的归属地，而且 err 为空、看起来完全正常。
  // 那台机器就是我们的服务器 —— 用它去判定等于给所有查不到的人发放行通行证。
  // 所以返回的 ip 必须和查询的 ip 一致，对不上就当没查到。
  if (j.ip && String(j.ip) !== ip) {
    throw new Error('pconline 返回的是查询方自身归属地（' + j.ip + '），结果不可用');
  }
  if (!j.pro && !j.city) throw new Error('pconline 返回为空');
  return {
    country: '中国',
    province: j.pro || '',
    city: j.city || '',
    isp: (j.addr || '').replace(/^\S+?\s+/, ''),
    src: 'pconline'
  };
}

/** 给 promise 套一个总时限：超时直接 reject，避免慢接口把 HTTP 请求拖成「永远转圈」 */
function withTotalCap(promise, ms) {
  let timer = null;
  const cap = new Promise(function (_, reject) {
    timer = setTimeout(function () { reject(new Error('归属地查询超时（>' + ms + 'ms）')); }, ms);
  });
  return Promise.race([promise, cap]).finally(function () { clearTimeout(timer); });
}

/* ---------------- 对外入口 ---------------- */

/**
 * 解析 IP 归属地。
 * 返回 { ok, country, province, city, isp, src, cached }
 * ok=false 表示查不到（网络不通、接口挂了、或本身就是查不到的地址）。
 * 不会抛异常 —— 查不到是正常情况，由调用方决定放行还是拦截。
 */
async function resolve(ip) {
  const key = normalizeIp(ip);

  if (!key) return { ok: false, src: 'none', reason: '没有 IP' };
  if (isPrivateIp(key)) {
    return { ok: true, country: '内网', province: '内网', city: '内网', isp: '', src: 'private', cached: true };
  }

  // 两个数据源都是 IPv4 定位服务：纯 IPv6 地址送过去只会拿到不可信的结果
  // （实测会对无效 IPv6 返回默认省级值，拿假数据去判定会造成误放行）。
  // 另外公开的 IPv6 归属地源对中国运营商 IPv6 的省级判定普遍不可靠，
  // 拿这种数据做准入既会误伤自己人，也会放进外省人，比不查更糟。
  // 所以 IPv6 一律返回「查不到」，由调用方按策略处理（默认拦截 + 跳转拒绝页）。
  if (key.indexOf(':') >= 0) {
    return { ok: false, src: 'none', reason: 'IPv6 地址查不到可信归属地' };
  }

  const now = Date.now();
  const m = mem.get(key);
  if (m && now - m.at < MEM_TTL) return Object.assign({}, m, { cached: true });

  if (cfg.store) {
    try {
      const s = cfg.store.get(key);
      if (s && now - s.at < (s.ok ? 30 * 86400000 : 10 * 60000)) {
        mem.set(key, s);
        return Object.assign({}, s, { cached: true });
      }
    } catch (_) { /* 缓存读失败不影响主流程 */ }
  }

  if (!cfg.enabled) return { ok: false, src: 'disabled', reason: '归属地查询已关闭' };

  if (inflight.has(key)) return inflight.get(key);

  const task = (async () => {
    let rec;
    try {
      rec = await withTotalCap((async function () {
        try {
          return await viaIpApi(key);
        } catch (e1) {
          return await viaPconline(key);
        }
      })(), cfg.totalTimeout);
    } catch (e) {
      rec = { ok: false, src: 'none', reason: (e && e.message) || '查询失败' };
    }
    if (rec.ok !== false) rec.ok = !!(rec.province || rec.city);
    rec.at = Date.now();
    mem.set(key, rec);
    if (cfg.store) { try { cfg.store.put(key, rec); } catch (_) { /* 忽略 */ } }
    inflight.delete(key);
    return rec;
  })();

  inflight.set(key, task);
  return task;
}

/**
 * 判定归属地是否命中放行规则（两级独立开关）。
 *
 * 规则结构（来自后台配置）：
 *   {
 *     provOn:  false,  provinces: ['云南'],   // 省开关 + 放行省列表
 *     cityOn:  false,  cities:     ['昆明'],   // 市开关 + 放行市列表
 *     allowIps:[],      failOpen:   false
 *   }
 *
 * 两个开关相互独立，可同时开启：
 *   - 只开省 → 命中放行省份即放行（不管市）
 *   - 只开市 → 命中放行城市即放行（不管省）
 *   - 同时开省+市 → 必须命中省份 AND 城市才放行
 *
 * 每个开关只有在「开启且列表非空」时才参与判定，避免开了开关但列表为空
 * 导致所有人被误拦（防空列表 = 不限制）。
 *
 * 归属地数据只到「市」一级（免费 IP 库不提供可靠区县），因此不做区级限制。
 * 返回 { hit: true|false|null, reason }
 *   hit=true  放行；hit=false  明确不命中；hit=null  归属地未知（查不到）
 */
function matchRules(region, rules) {
  if (!region || !region.ok) {
    return { hit: null, reason: '归属地未知（' + ((region && region.reason) || '查询失败') + '）' };
  }
  const prov = normRegion(region.province);
  const city = normRegion(region.city);

  const provOn = !!rules.provOn;
  const cityOn = !!rules.cityOn;

  const provinces = (rules.provinces || []).map(normRegion).filter(Boolean);
  const cities = (rules.cities || []).map(normRegion).filter(Boolean);

  // 省开关：开启且有列表时才判定
  if (provOn && provinces.length) {
    if (provinces.indexOf(prov) < 0) {
      return { hit: false, reason: '省份「' + (region.province || '未知') + '」不在放行范围' };
    }
  }
  // 市开关：开启且有列表时才判定
  if (cityOn && cities.length) {
    if (cities.indexOf(city) < 0) {
      return { hit: false, reason: '城市「' + (region.city || '未知') + '」不在放行范围' };
    }
  }
  return { hit: true, reason: '归属地 ' + (region.province || '') + (region.city || '') + ' 命中放行规则' };
}

/** 把配置里的省市名补上行政后缀，方便显示 */
function prettyRegion(region) {
  if (!region) return '未知';
  if (region.src === 'private') return '内网';
  const p = region.province || '';
  const c = region.city || '';
  if (!p && !c) return '未知';
  if (p && c && c.indexOf(p) === 0) return c;   // 「云南」「昆明」→「云南昆明」
  return (p + c) || p || c;
}

module.exports = {
  configure,
  resolve,
  matchRules,
  isPrivateIp,
  normalizeIp,
  normRegion,
  prettyRegion
};
