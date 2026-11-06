/**
 * Cloudflare Snippets 多上游 DoH 转发
 *
 *   /                 首页（选择提供商、复制链接、在线测试）
 *   /<id>             DoH 端点，例如 /google、/cloudflare
 *   /dns-query        等同 /cloudflare
 *
 * 每个端点同时支持：
 *   RFC 8484   GET ?dns=<base64url>  /  POST application/dns-message
 *   JSON       GET ?name=example.com&type=A
 * 原生支持 JSON 的上游直接转发 JSON；其余上游由本脚本完成 JSON <-> DNS 报文转换。
 * 自动把客户端 IP 网段作为 ECS 发给上游（IPv4 /24，IPv6 /56）；客户端自带 ECS 时保留客户端的。
 */

// json: 原生 JSON 接口；ecs: 原生 JSON 接口支持 edns_client_subnet 参数
const PROVIDERS = [
  { id: 'cloudflare', name: 'Cloudflare', doh: 'https://cloudflare-dns.com/dns-query', json: 'https://cloudflare-dns.com/dns-query' },
  { id: 'ali', name: '阿里 AliDNS', doh: 'https://dns.alidns.com/dns-query', json: 'https://dns.alidns.com/resolve', ecs: 1 },
  { id: 'tencent', name: '腾讯 DNSPod', doh: 'https://sm2.doh.pub/dns-query', json: 'https://sm2.doh.pub/resolve', ecs: 1 },
  { id: '360', name: '360 安全DNS', doh: 'https://doh.360.cn/dns-query', json: 'https://doh.360.cn/resolve', ecs: 1 },
  { id: 'google', name: 'Google', doh: 'https://dns.google/dns-query', json: 'https://dns.google/resolve', ecs: 1 },
  { id: 'adguard', name: 'AdGuard', doh: 'https://dns.adguard-dns.com/dns-query', json: 'https://dns.adguard-dns.com/resolve' },
  { id: 'dnssb', name: 'DNS.SB', doh: 'https://doh.dns.sb/dns-query' },
  { id: 'nextdns', name: 'NextDNS', doh: 'https://dns.nextdns.io/' },
  { id: 'rethink', name: 'RethinkDNS', doh: 'https://basic.rethinkdns.com/' },
  { id: 'vrecipes', name: 'v.recipes', doh: 'https://v.recipes/dns-query' },
  { id: 'appliedprivacy', name: 'Applied Privacy', doh: 'https://doh.applied-privacy.net/query' },
  { id: 'cznic', name: 'CZ.NIC ODVR', doh: 'https://odvr.nic.cz/doh' },
  { id: 'onedns', name: 'OneDNS', doh: 'https://doh.onedns.net/dns-query' },
];
const DEFAULT_ID = 'cloudflare';
const ECS_V4 = 24;
const ECS_V6 = 56;

const MAP = Object.fromEntries(PROVIDERS.map((p) => [p.id, p]));
const CT_MSG = 'application/dns-message';
const CT_JSON = 'application/dns-json';
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type, accept',
};

class HttpError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (path === '/') {
      if (request.method !== 'GET' && request.method !== 'HEAD') return text('Method Not Allowed', 405);
      return new Response(request.method === 'HEAD' ? null : page(), {
        headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=600' },
      });
    }
    const p = MAP[path === '/dns-query' ? DEFAULT_ID : path.slice(1).toLowerCase()];
    if (!p) return text('Not Found', 404);
    try {
      return await handle(request, url, p);
    } catch (e) {
      return text(e.message || 'Error', e.status || 502);
    }
  },
};

async function handle(req, url, p) {
  const ecs = ecsFromIp(req.headers.get('cf-connecting-ip'));
  if (req.method === 'POST') {
    const ct = (req.headers.get('content-type') || '').toLowerCase();
    if (!ct.startsWith(CT_MSG)) throw new HttpError(415, 'Content-Type must be ' + CT_MSG);
    return wire(p, new Uint8Array(await req.arrayBuffer()), ecs);
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method Not Allowed');
  const q = url.searchParams;
  if (q.has('dns')) return wire(p, b64uDecode(q.get('dns')), ecs);
  if (q.has('name')) return json(p, q, ecs);
  throw new HttpError(400, 'Missing "dns" or "name" parameter');
}

// ---------- 转发 ----------

function upstream(p, msg) {
  return fetch(p.doh, { method: 'POST', headers: { 'content-type': CT_MSG, accept: CT_MSG }, body: msg });
}

async function wire(p, msg, ecs) {
  if (msg.length < 12) throw new HttpError(400, 'Invalid DNS message');
  if (ecs) {
    try { msg = addEcs(msg, ecs); } catch { /* 解析失败则原样转发 */ }
  }
  const r = await upstream(p, msg);
  const h = new Headers(CORS);
  h.set('content-type', r.headers.get('content-type') || CT_MSG);
  const cc = r.headers.get('cache-control');
  if (cc) h.set('cache-control', cc);
  return new Response(r.body, { status: r.status, headers: h });
}

// 国际化域名转 punycode
function toAscii(name) {
  name = String(name).trim();
  if (!/[^\x00-\x7f]/.test(name)) return name;
  try {
    return new URL('http://' + name.replace(/\.$/, '')).hostname + (name.endsWith('.') ? '.' : '');
  } catch {
    throw new HttpError(400, 'Invalid name');
  }
}

async function json(p, q, ecs) {
  const name = toAscii(q.get('name'));
  if (p.json) {
    const u = new URL(p.json);
    for (const [k, v] of q) u.searchParams.append(k, k === 'name' ? name : v);
    if (p.ecs && ecs && !q.has('edns_client_subnet')) u.searchParams.set('edns_client_subnet', ecsText(ecs));
    const r = await fetch(u, { headers: { accept: CT_JSON } });
    const h = new Headers(CORS);
    h.set('content-type', r.headers.get('content-type') || CT_JSON);
    const cc = r.headers.get('cache-control');
    if (cc) h.set('cache-control', cc);
    return new Response(r.body, { status: r.status, headers: h });
  }
  const type = typeNum(q.get('type') || 'A');
  if (type == null) throw new HttpError(400, 'Invalid type');
  const ov = q.get('edns_client_subnet');
  if (ov) {
    ecs = parseEcs(ov);
    if (!ecs) throw new HttpError(400, 'Invalid edns_client_subnet');
  }
  const msg = buildQuery(name, type, flag(q.get('cd')), flag(q.get('do')), ecs);
  const r = await upstream(p, msg);
  if (!r.ok) throw new HttpError(502, 'Upstream HTTP ' + r.status);
  let obj;
  try { obj = toJson(new Uint8Array(await r.arrayBuffer())); } catch { throw new HttpError(502, 'Invalid upstream response'); }
  const ttls = [...(obj.Answer || []), ...(obj.Authority || [])].map((x) => x.TTL);
  const h = new Headers(CORS);
  h.set('content-type', CT_JSON + '; charset=utf-8');
  h.set('cache-control', 'max-age=' + (ttls.length ? Math.min(...ttls) : 0));
  return new Response(JSON.stringify(obj), { headers: h });
}

function text(s, status) {
  return new Response(s + '\n', { status, headers: { ...CORS, 'content-type': 'text/plain; charset=utf-8' } });
}

const flag = (v) => v === '1' || v === 'true';

function b64uDecode(s) {
  try {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    const b = atob(s + '==='.slice((s.length + 3) % 4));
    return Uint8Array.from(b, (c) => c.charCodeAt(0));
  } catch {
    throw new HttpError(400, 'Invalid dns parameter');
  }
}

const b64 = (u8) => btoa(String.fromCharCode(...u8));
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();

// ---------- IP / ECS ----------

function v4bytes(s) {
  const a = s.split('.');
  if (a.length !== 4 || !a.every((x) => /^\d{1,3}$/.test(x) && +x < 256)) return null;
  return Uint8Array.from(a, Number);
}

function v6bytes(s) {
  const halves = s.split('%')[0].split('::');
  if (halves.length > 2) return null;
  const conv = (h) => {
    const out = [];
    for (const x of h ? h.split(':') : []) {
      if (x.includes('.')) {
        const v = v4bytes(x);
        if (!v) return null;
        out.push((v[0] << 8) | v[1], (v[2] << 8) | v[3]);
      } else if (/^[0-9a-f]{1,4}$/i.test(x)) out.push(parseInt(x, 16));
      else return null;
    }
    return out;
  };
  const a = conv(halves[0]);
  const b = conv(halves[1]);
  if (!a || !b) return null;
  const fill = 8 - a.length - b.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return null;
  const w = [...a, ...new Array(fill).fill(0), ...b];
  const out = new Uint8Array(16);
  w.forEach((x, i) => { out[i * 2] = x >> 8; out[i * 2 + 1] = x & 255; });
  return out;
}

function ipBytes(s) {
  return s.includes(':') ? v6bytes(s) : v4bytes(s);
}

function ipStr(u8) {
  if (u8.length === 4) return u8.join('.');
  const w = [];
  for (let i = 0; i < 16; i += 2) w.push((u8[i] << 8) | u8[i + 1]);
  let bs = -1, bl = 0;
  for (let i = 0; i < 8;) {
    if (w[i]) { i++; continue; }
    let j = i;
    while (j < 8 && !w[j]) j++;
    if (j - i > bl && j - i > 1) { bs = i; bl = j - i; }
    i = j;
  }
  const h = (a) => a.map((x) => x.toString(16)).join(':');
  return bs < 0 ? h(w) : h(w.slice(0, bs)) + '::' + h(w.slice(bs + bl));
}

function maskEcs(addr, prefix) {
  const fam = addr.length === 4 ? 1 : 2;
  const n = Math.ceil(prefix / 8);
  const a = addr.slice(0, n);
  if (n && prefix % 8) a[n - 1] &= 0xff << (8 - (prefix % 8));
  return { fam, prefix, addr: a };
}

function ecsFromIp(ip) {
  const b = ip && ipBytes(ip.trim());
  return b ? maskEcs(b, b.length === 4 ? ECS_V4 : ECS_V6) : null;
}

function parseEcs(s) {
  const [ip, pre] = s.split('/');
  const b = ipBytes(ip);
  if (!b) return null;
  const max = b.length * 8;
  const n = pre === undefined ? Math.min(max, b.length === 4 ? ECS_V4 : ECS_V6) : Number(pre);
  if (!Number.isInteger(n) || n < 0 || n > max) return null;
  return maskEcs(b, n);
}

function ecsText(e) {
  const full = new Uint8Array(e.fam === 1 ? 4 : 16);
  full.set(e.addr);
  return ipStr(full) + '/' + e.prefix;
}

function ecsOption(e) {
  const o = new Uint8Array(8 + e.addr.length);
  const v = new DataView(o.buffer);
  v.setUint16(0, 8); // OPTION-CODE: ECS
  v.setUint16(2, 4 + e.addr.length);
  v.setUint16(4, e.fam);
  o[6] = e.prefix;
  o[7] = 0;
  o.set(e.addr, 8);
  return o;
}

// ---------- DNS 报文 ----------

const view = (m) => new DataView(m.buffer, m.byteOffset, m.byteLength);

function skipName(m, o) {
  for (;;) {
    if (o >= m.length) throw new Error('truncated');
    const l = m[o];
    if (l === 0) return o + 1;
    if ((l & 0xc0) === 0xc0) return o + 2;
    if (l & 0xc0) throw new Error('bad label');
    o += l + 1;
  }
}

function skipRR(m, o) {
  const n = skipName(m, o);
  if (n + 10 > m.length) throw new Error('truncated');
  return n + 10 + ((m[n + 8] << 8) | m[n + 9]);
}

// 向查询报文注入 ECS（已有 ECS 时保持不变）
function addEcs(m, e) {
  const v = view(m);
  const qd = v.getUint16(4), an = v.getUint16(6), ns = v.getUint16(8), ar = v.getUint16(10);
  let o = 12;
  for (let i = 0; i < qd; i++) o = skipName(m, o) + 4;
  for (let i = 0; i < an + ns; i++) o = skipRR(m, o);
  const opt = ecsOption(e);
  for (let i = 0; i < ar; i++) {
    const n = skipName(m, o);
    const rd = n + 10;
    const end = rd + v.getUint16(n + 8);
    if (end > m.length) throw new Error('truncated');
    if (v.getUint16(n) === 41) {
      for (let p = rd; p + 4 <= end; p += 4 + v.getUint16(p + 2)) if (v.getUint16(p) === 8) return m;
      const out = new Uint8Array(m.length + opt.length);
      out.set(m.subarray(0, end));
      out.set(opt, end);
      out.set(m.subarray(end), end + opt.length);
      view(out).setUint16(n + 8, end - rd + opt.length);
      return out;
    }
    o = end;
  }
  if (o > m.length) throw new Error('truncated');
  const out = new Uint8Array(o + 11 + opt.length);
  out.set(m.subarray(0, o));
  const w = view(out);
  w.setUint16(10, ar + 1);
  out[o] = 0;
  w.setUint16(o + 1, 41);
  w.setUint16(o + 3, 4096);
  w.setUint32(o + 5, 0);
  w.setUint16(o + 9, opt.length);
  out.set(opt, o + 11);
  return out;
}

const TYPES = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, HINFO: 13, MX: 15, TXT: 16, AAAA: 28, SRV: 33, NAPTR: 35,
  DNAME: 39, DS: 43, SSHFP: 44, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50, TLSA: 52, SVCB: 64,
  HTTPS: 65, SPF: 99, ANY: 255, CAA: 257,
};

function typeNum(t) {
  t = String(t).trim().toUpperCase();
  const m = /^(?:TYPE)?(\d+)$/.exec(t);
  if (m) return +m[1] > 0 && +m[1] < 65536 ? +m[1] : null;
  return TYPES[t] ?? null;
}

function buildQuery(name, type, cd, dnssec, ecs) {
  const labels = name === '.' || name === '' ? [] : name.replace(/\.$/, '').split('.');
  const enc = new TextEncoder();
  const parts = [];
  let len = 1;
  for (const l of labels) {
    const b = enc.encode(l);
    if (!b.length || b.length > 63) throw new HttpError(400, 'Invalid name');
    parts.push(b);
    len += b.length + 1;
  }
  if (len > 255) throw new HttpError(400, 'Name too long');
  const opt = ecs ? ecsOption(ecs) : new Uint8Array(0);
  const m = new Uint8Array(12 + len + 4 + 11 + opt.length);
  const v = view(m);
  v.setUint16(2, 0x0100 | (cd ? 0x10 : 0)); // RD, CD
  v.setUint16(4, 1);
  v.setUint16(10, 1);
  let o = 12;
  for (const b of parts) { m[o++] = b.length; m.set(b, o); o += b.length; }
  m[o++] = 0;
  v.setUint16(o, type);
  v.setUint16(o + 2, 1);
  o += 4;
  m[o] = 0;
  v.setUint16(o + 1, 41);
  v.setUint16(o + 3, 4096);
  v.setUint32(o + 5, dnssec ? 0x8000 : 0); // DO
  v.setUint16(o + 9, opt.length);
  m.set(opt, o + 11);
  return m;
}

function readName(m, o) {
  const labels = [];
  let end = -1;
  for (let jumps = 0; ;) {
    if (o >= m.length) throw new Error('truncated');
    const l = m[o];
    if (l === 0) { o++; break; }
    if ((l & 0xc0) === 0xc0) {
      if (++jumps > 64) throw new Error('loop');
      if (end < 0) end = o + 2;
      o = ((l & 0x3f) << 8) | m[o + 1];
      continue;
    }
    if (o + 1 + l > m.length) throw new Error('truncated');
    let s = '';
    for (const c of m.subarray(o + 1, o + 1 + l)) {
      s += c === 0x2e || c === 0x5c ? '\\' + String.fromCharCode(c)
        : c > 0x20 && c < 0x7f ? String.fromCharCode(c) : '\\' + String(c).padStart(3, '0');
    }
    labels.push(s);
    o += 1 + l;
  }
  return [labels.length ? labels.join('.') + '.' : '.', end < 0 ? o : end];
}

function charStrings(m, o, end) {
  const dec = new TextDecoder();
  const out = [];
  while (o < end) {
    const l = m[o];
    out.push('"' + dec.decode(m.subarray(o + 1, o + 1 + l)).replace(/["\\]/g, '\\$&') + '"');
    o += 1 + l;
  }
  return out;
}

const SVC_KEYS = ['mandatory', 'alpn', 'no-default-alpn', 'port', 'ipv4hint', 'ech', 'ipv6hint'];

function svcb(m, v, o, end) {
  const [target, p0] = readName(m, o + 2);
  const out = [v.getUint16(o), target];
  for (let p = p0; p + 4 <= end;) {
    const k = v.getUint16(p), l = v.getUint16(p + 2), d = m.subarray(p + 4, p + 4 + l);
    const key = SVC_KEYS[k] || 'key' + k;
    let val;
    if (k === 0) val = Array.from({ length: l / 2 }, (_, i) => SVC_KEYS[v.getUint16(p + 4 + i * 2)] || 'key' + v.getUint16(p + 4 + i * 2)).join(',');
    else if (k === 1) val = charStrings(m, p + 4, p + 4 + l).map((s) => s.slice(1, -1)).join(',');
    else if (k === 3) val = v.getUint16(p + 4);
    else if (k === 4 || k === 6) {
      const n = k === 4 ? 4 : 16;
      val = Array.from({ length: l / n }, (_, i) => ipStr(d.subarray(i * n, i * n + n))).join(',');
    } else if (k === 5) val = b64(d);
    else if (l) val = hex(d);
    out.push(val === undefined ? key : key + '=' + val);
    p += 4 + l;
  }
  return out.join(' ');
}

function rdata(m, v, type, o, len) {
  const end = o + len;
  const name = (x) => readName(m, x)[0];
  switch (type) {
    case 1: if (len === 4) return ipStr(m.subarray(o, end)); break;
    case 28: if (len === 16) return ipStr(m.subarray(o, end)); break;
    case 2: case 5: case 12: case 39: return name(o);
    case 15: return v.getUint16(o) + ' ' + name(o + 2);
    case 16: case 99: return charStrings(m, o, end).join(' ');
    case 6: {
      const [mn, o1] = readName(m, o);
      const [rn, o2] = readName(m, o1);
      return [mn, rn, ...[0, 4, 8, 12, 16].map((i) => v.getUint32(o2 + i))].join(' ');
    }
    case 33: return [v.getUint16(o), v.getUint16(o + 2), v.getUint16(o + 4), name(o + 6)].join(' ');
    case 257: {
      const tl = m[o + 1];
      const tag = String.fromCharCode(...m.subarray(o + 2, o + 2 + tl));
      const val = new TextDecoder().decode(m.subarray(o + 2 + tl, end)).replace(/["\\]/g, '\\$&');
      return m[o] + ' ' + tag + ' "' + val + '"';
    }
    case 43: return [v.getUint16(o), m[o + 2], m[o + 3], hex(m.subarray(o + 4, end))].join(' ');
    case 48: return [v.getUint16(o), m[o + 2], m[o + 3], b64(m.subarray(o + 4, end))].join(' ');
    case 64: case 65: return svcb(m, v, o, end);
  }
  return '\\# ' + len + (len ? ' ' + hex(m.subarray(o, end)) : '');
}

function toJson(m) {
  const v = view(m);
  const f = v.getUint16(2);
  const res = {
    Status: f & 15, TC: !!(f & 0x200), RD: !!(f & 0x100), RA: !!(f & 0x80),
    AD: !!(f & 0x20), CD: !!(f & 0x10), Question: [],
  };
  let o = 12;
  for (let i = v.getUint16(4); i > 0; i--) {
    const [name, n] = readName(m, o);
    res.Question.push({ name, type: v.getUint16(n) });
    o = n + 4;
  }
  const section = (count, key) => {
    for (let i = 0; i < count; i++) {
      const [name, n] = readName(m, o);
      const type = v.getUint16(n), ttl = v.getUint32(n + 4), len = v.getUint16(n + 8), rd = n + 10;
      if (rd + len > m.length) throw new Error('truncated');
      o = rd + len;
      if (type === 41) {
        res.Status |= (ttl >>> 24) << 4;
        for (let p = rd; p + 4 <= o; p += 4 + v.getUint16(p + 2)) {
          if (v.getUint16(p) !== 8) continue;
          const fam = v.getUint16(p + 4), full = new Uint8Array(fam === 1 ? 4 : 16);
          full.set(m.subarray(p + 8, p + 4 + v.getUint16(p + 2)).slice(0, full.length));
          res.edns_client_subnet = ipStr(full) + '/' + m[p + 6];
        }
        continue;
      }
      (res[key] ||= []).push({ name, type, TTL: ttl, data: rdata(m, v, type, rd, len) });
    }
  };
  section(v.getUint16(6), 'Answer');
  section(v.getUint16(8), 'Authority');
  section(v.getUint16(10), 'Additional');
  return res;
}

// ---------- 首页 ----------

function page() {
  const list = JSON.stringify(PROVIDERS.map((p) => ({ id: p.id, name: p.name, up: p.doh.replace(/^https:\/\//, '') })));
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DoH 解析服务</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;font:15px/1.6 system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);color:#1f2937;display:flex;justify-content:center;padding:32px 14px}
.card{width:100%;max-width:760px;background:rgba(255,255,255,.96);border-radius:18px;box-shadow:0 20px 50px rgba(0,0,0,.25);padding:28px 28px 20px}
h1{margin:0;font-size:26px;text-align:center;background:linear-gradient(135deg,#667eea,#764ba2);-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{text-align:center;color:#6b7280;margin:4px 0 22px}h2{font-size:16px;margin:22px 0 10px;border-left:4px solid #667eea;padding-left:8px}
label{display:block;font-weight:600;margin:12px 0 6px}select,input{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:10px;font:inherit;background:#fff}
select:focus,input:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.2)}
.row{display:flex;gap:8px}.row>*{flex:1}.row .sm{flex:0 0 120px}
.url{display:flex;gap:8px;align-items:stretch}.url code{flex:1;padding:10px 12px;background:#f3f4f6;border-radius:10px;word-break:break-all;font:14px ui-monospace,Consolas,monospace}
button{border:0;border-radius:10px;padding:10px 18px;font:inherit;font-weight:600;color:#fff;background:linear-gradient(135deg,#667eea,#764ba2);cursor:pointer;white-space:nowrap}button:hover{opacity:.9}
.hint{color:#6b7280;font-size:13px;margin-top:6px}table{width:100%;border-collapse:collapse;margin-top:10px;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e5e7eb;word-break:break-all}th{background:#f9fafb}
pre{background:#111827;color:#e5e7eb;border-radius:10px;padding:12px;overflow:auto;font-size:12.5px;max-height:360px}
#st{margin-top:10px;font-weight:600}.ok{color:#059669}.err{color:#dc2626}footer{text-align:center;color:#9ca3af;font-size:12px;margin-top:22px}
@media(prefers-color-scheme:dark){.card{background:rgba(17,24,39,.96);color:#e5e7eb}select,input{background:#1f2937;color:#e5e7eb;border-color:#374151}.url code{background:#1f2937}th{background:#1f2937}th,td{border-color:#374151}}
</style></head><body><div class="card">
<h1>DNS over HTTPS</h1><div class="sub">多上游 DoH 转发 · 支持 RFC 8484 与 JSON 查询</div>
<label for="p">选择提供商</label><select id="p"></select>
<label>DoH 地址</label><div class="url"><code id="u"></code><button id="c">复制</button></div>
<div class="hint" id="h"></div>
<h2>在线测试</h2>
<div class="row"><input id="n" value="www.google.com" placeholder="域名"><select id="t" class="sm"></select><button id="q" class="sm">查询</button></div>
<div id="st"></div><div id="r"></div>
<h2>使用示例</h2><pre id="ex"></pre>
<footer>Powered by Cloudflare Snippets</footer></div>
<script>
var P=${list},D=${JSON.stringify(DEFAULT_ID)},$=function(i){return document.getElementById(i)},base=location.origin;
var T=['A','AAAA','CNAME','MX','TXT','NS','HTTPS','SOA','CAA','SRV','PTR'];
P.forEach(function(p){var o=document.createElement('option');o.value=p.id;o.textContent=p.name+'  (/'+p.id+')';$('p').appendChild(o)});
T.forEach(function(t){var o=document.createElement('option');o.textContent=t;$('t').appendChild(o)});
var s=new URLSearchParams(location.search).get('p')||localStorage.getItem('doh-p');if(s&&P.some(function(p){return p.id===s}))$('p').value=s;
function cur(){var id=$('p').value;return P.filter(function(p){return p.id===id})[0]}
function upd(){var p=cur(),u=base+'/'+p.id;$('u').textContent=u;localStorage.setItem('doh-p',p.id);
$('h').textContent='上游：'+p.up+(p.id===D?'　｜　'+base+'/dns-query 同样指向 '+p.name:'');
$('ex').textContent='# JSON 查询\\ncurl -H "accept: application/dns-json" "'+u+'?name=example.com&type=A"\\n\\n# RFC 8484 查询 (example.com A)\\ncurl -s -H "accept: application/dns-message" "'+u+'?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE" | xxd\\n\\n# 浏览器 / 系统 / 路由器的 DoH 设置中填写\\n'+u}
$('p').onchange=upd;upd();
$('c').onclick=function(){var t=$('u').textContent,b=$('c');(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){b.textContent='已复制'},function(){prompt('复制地址',t)});setTimeout(function(){b.textContent='复制'},1500)};
function cell(tr,v,h){var e=document.createElement(h?'th':'td');e.textContent=v;tr.appendChild(e)}
function q(){var n=$('n').value.trim();if(!n)return;var p=cur(),st=$('st'),r=$('r'),t0=performance.now();st.className='';st.textContent='查询中…';r.innerHTML='';
fetch('/'+p.id+'?name='+encodeURIComponent(n)+'&type='+$('t').value,{headers:{accept:'application/dns-json'}}).then(function(x){if(!x.ok)return x.text().then(function(m){throw new Error('HTTP '+x.status+' '+m)});return x.json()}).then(function(j){
var ms=Math.round(performance.now()-t0),a=j.Answer||[];st.className=j.Status===0?'ok':'err';st.textContent=p.name+' · '+ms+' ms · Status '+j.Status+(j.Status===3?' (NXDOMAIN)':'')+' · '+a.length+' 条记录';
if(a.length){var tb=document.createElement('table'),tr=document.createElement('tr');['名称','类型','TTL','数据'].forEach(function(h){cell(tr,h,1)});tb.appendChild(tr);
a.forEach(function(x){var tr=document.createElement('tr');cell(tr,x.name);cell(tr,T.filter(function(k){return{A:1,AAAA:28,CNAME:5,MX:15,TXT:16,NS:2,HTTPS:65,SOA:6,CAA:257,SRV:33,PTR:12}[k]===x.type})[0]||x.type);cell(tr,x.TTL);cell(tr,x.data);tb.appendChild(tr)});r.appendChild(tb)}
var d=document.createElement('details'),sm=document.createElement('summary'),pr=document.createElement('pre');sm.textContent='原始 JSON';pr.textContent=JSON.stringify(j,null,2);d.appendChild(sm);d.appendChild(pr);r.appendChild(d)
}).catch(function(e){st.className='err';st.textContent='查询失败：'+e.message})}
$('q').onclick=q;$('n').onkeydown=function(e){if(e.key==='Enter')q()};
</script></body></html>`;
}
