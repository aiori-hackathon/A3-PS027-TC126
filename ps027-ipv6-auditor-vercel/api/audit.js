// SixCheck backend: GET /api/audit?domain=example.org
const dnsMod = require('node:dns');
const net = require('node:net');
const tls = require('node:tls');
dnsMod.setServers(['1.1.1.1', '8.8.8.8']);
const dns = dnsMod.promises;

const T = (p, ms) => Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error('timeout')), ms))]);
const list = async (fn, ...a) => { try { return await T(fn(...a), 4000); } catch { return []; } };
const r6 = (h) => list(dns.resolve6, h);
const r4 = (h) => list(dns.resolve4, h);

function cleanDomain(v) {
  v = String(v || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/[\/?#].*$/, '').replace(/:\d+$/, '').replace(/^www\./, '');
  if (/\.(local|localhost|internal|lan|home|arpa)$/.test(v)) return null;
  return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(v) ? v : null;
}

// Block private, loopback and link-local targets (SSRF protection)
function priv4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
}
function priv(ip) {
  if (net.isIPv4(ip)) return priv4(ip);
  const x = ip.toLowerCase();
  if (x === '::1' || x === '::') return true;
  if (x.startsWith('::ffff:')) return x.includes('.') ? priv4(x.slice(7)) : true;
  return /^f[cd]/.test(x) || /^fe[89ab]/.test(x) || x.startsWith('2001:db8');
}

function egress() { // does this server have outbound IPv6?
  return new Promise((res) => {
    const s = net.connect({ host: '2606:4700:4700::1111', port: 53, family: 6, timeout: 3000 });
    const f = () => { s.destroy(); res(false); };
    s.once('connect', () => { s.destroy(); res(true); });
    s.once('error', f); s.once('timeout', f);
  });
}

function probe(ip, servername) {
  return new Promise((res) => {
    const s = tls.connect({ host: ip, port: 443, servername, family: 6, rejectUnauthorized: false, timeout: 6000 });
    const done = (o) => { s.destroy(); res(o); };
    s.once('secureConnect', () => {
      const c = s.getPeerCertificate();
      done({ ok: true, authorized: s.authorized, err: s.authorizationError, validTo: c && c.valid_to ? new Date(c.valid_to) : null });
    });
    s.once('timeout', () => done({ ok: false, code: 'ETIMEDOUT' }));
    s.once('error', (e) => done({ ok: false, code: e.code || e.message }));
  });
}

async function readCapped(r, max = 500000) {
  const rd = r.body.getReader(); const out = []; let n = 0;
  while (n < max) { const { done, value } = await rd.read(); if (done) break; out.push(value); n += value.length; }
  rd.cancel().catch(() => {});
  return Buffer.concat(out).toString('utf8');
}

async function fetchHome(domain) {
  let url = 'https://' + domain + '/';
  for (let i = 0; i < 4; i++) {
    const u = new URL(url);
    const ips = [...await r4(u.hostname), ...await r6(u.hostname)];
    if (!ips.length || ips.some(priv)) throw new Error('blocked');
    const r = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(7000), headers: { 'user-agent': 'SixCheck/1.0 (IPv6 readiness audit)', accept: 'text/html' } });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) {
      url = new URL(loc, url).href;
      if (!url.startsWith('https:')) throw new Error('non-https redirect');
      continue;
    }
    if (!r.ok) throw new Error('http ' + r.status);
    return { html: await readCapped(r), base: url };
  }
  throw new Error('too many redirects');
}

function extract(html, base, domain) {
  const hosts = new Set(); const lit = [];
  const re = /<(?:script|link|img|iframe|source|video|audio)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html))) {
    try {
      const u = new URL(m[1].replace(/^\/\//, 'https://'), base);
      if (!/^https?:$/.test(u.protocol)) continue;
      if (net.isIPv4(u.hostname)) lit.push(u.hostname);
      else if (u.hostname !== domain && !u.hostname.endsWith('.' + domain)) hosts.add(u.hostname);
    } catch { /* ignore bad URLs */ }
  }
  return { hosts: [...hosts].slice(0, 20), lit };
}

const verdictOf = (s) => (s >= 85 ? 'IPv6 ready' : s >= 60 ? 'Partly ready' : 'Not ready for IPv6 users');

async function run(domain) {
  const [apex6, apex4, www6, www4, ns, mx, hasV6, home] = await Promise.all([
    r6(domain), r4(domain), r6('www.' + domain), r4('www.' + domain),
    list(dns.resolveNs, domain), list(dns.resolveMx, domain), egress(), fetchHome(domain).catch(() => null),
  ]);
  const nsV6 = (await Promise.all(ns.map(r6))).filter((a) => a.length).length;
  const mxList = mx.sort((a, b) => a.priority - b.priority).slice(0, 5);
  const mxV6 = (await Promise.all(mxList.map((m) => r6(m.exchange)))).filter((a) => a.length).length;

  let deps = []; let lit = [];
  if (home) {
    const x = extract(home.html, home.base, domain); lit = x.lit;
    deps = await Promise.all(x.hosts.map(async (h) => { const [a6, a4] = await Promise.all([r6(h), r4(h)]); return { host: h, v6: a6.length > 0, v4: a4.length > 0 }; }));
  }
  const live = deps.filter((d) => d.v4 || d.v6);
  const bad = live.filter((d) => d.v4 && !d.v6).length;

  const C = [];
  const add = (k, w, status, detail, fix) => C.push({ k, w, status, detail, fix: status === 'pass' || status === 'info' ? '' : fix });
  add('Apex AAAA', 15, apex6.length ? 'pass' : 'fail', apex6.length ? 'AAAA: ' + apex6.slice(0, 2).join(', ') : 'No AAAA record for ' + domain, 'Add an AAAA record for the root domain.');
  add('www AAAA', 10, www6.length ? 'pass' : www4.length ? 'fail' : 'info', www6.length ? 'AAAA: ' + www6[0] : www4.length ? 'www has an A record but no AAAA' : 'No www host found', 'Add an AAAA record for www or point it to a dual-stack CNAME.');
  add('Nameservers', 15, !ns.length ? 'fail' : nsV6 >= 2 ? 'pass' : nsV6 === 1 ? 'warn' : 'fail', ns.length ? nsV6 + ' of ' + ns.length + ' nameservers have AAAA records' : 'No NS records returned', 'Enable IPv6 on at least two authoritative nameservers.');
  add('Mail (MX)', 5, !mxList.length ? 'info' : mxV6 === mxList.length ? 'pass' : mxV6 ? 'warn' : 'fail', mxList.length ? mxV6 + ' of ' + mxList.length + ' mail hosts have AAAA records' : 'No MX records (mail not used)', 'Give each MX host an AAAA record and listener.');

  const ip = [...apex6, ...www6].find((a) => !priv(a));
  const name = apex6.length ? domain : 'www.' + domain;
  let p = null;
  if (hasV6 && ip) p = await probe(ip, name);
  if (!hasV6) add('HTTPS on IPv6', 20, 'info', 'Not testable: this server has no outbound IPv6', '');
  else if (!ip) add('HTTPS on IPv6', 20, 'fail', 'No public IPv6 address to connect to', 'Publish a public AAAA record and listen on it.');
  else add('HTTPS on IPv6', 20, p.ok ? 'pass' : 'fail', p.ok ? 'Connected to [' + ip + ']:443' : 'Connection to [' + ip + ']:443 failed (' + p.code + ')', 'Bind the web server and firewall rules to the IPv6 address.');
  if (!p || !p.ok) add('TLS on IPv6', 10, 'info', 'Skipped: no IPv6 connection to inspect', '');
  else {
    const days = p.validTo ? Math.floor((p.validTo - Date.now()) / 864e5) : null;
    const st = !p.authorized ? 'fail' : days !== null && days < 0 ? 'fail' : days !== null && days < 14 ? 'warn' : 'pass';
    add('TLS on IPv6', 10, st, !p.authorized ? 'Certificate problem: ' + p.err : 'Valid certificate' + (days !== null ? ', expires in ' + days + ' days' : ''), 'Serve a valid certificate for this hostname on the IPv6 address.');
  }
  add('Dependencies', 15, !home ? 'info' : bad === 0 ? 'pass' : bad <= 2 ? 'warn' : 'fail', !home ? 'Home page could not be fetched' : live.length ? bad + ' of ' + live.length + ' third-party hosts are IPv4 only' : 'No third-party hosts found', 'Replace or proxy IPv4-only third-party hosts.');
  add('IPv6-only test', 10, !apex6.length ? 'fail' : lit.length ? 'fail' : !home ? 'info' : bad ? 'warn' : 'pass',
    !apex6.length ? 'Main host has no IPv6, so it fails on IPv6-only networks' : lit.length ? 'IPv4 literals in page: ' + lit.slice(0, 3).join(', ') : !home ? 'Page could not be analysed' : bad ? bad + ' dependencies would need NAT64 to load' : 'Page and dependencies resolve over IPv6 (static analysis)',
    'Remove hard-coded IPv4 literals and IPv4-only hosts.');

  let s = 0; let t = 0;
  C.forEach((c) => { if (c.status === 'info') return; t += c.w; s += c.w * (c.status === 'pass' ? 1 : c.status === 'warn' ? 0.5 : 0); });
  const score = t ? Math.round((s / t) * 100) : 0;
  return { domain, mode: 'live', generatedAt: new Date().toISOString(), ipv6Egress: hasV6, score, verdict: verdictOf(score), checks: C, deps };
}

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  const domain = cleanDomain(new URL(req.url, 'http://x').searchParams.get('domain'));
  if (!domain) return res.status(400).json({ error: 'Enter a valid public domain, for example example.org' });
  try {
    const out = await run(domain);
    res.setHeader('Cache-Control', 's-maxage=120, stale-while-revalidate=300');
    return res.status(200).json(out);
  } catch (e) {
    return res.status(500).json({ error: 'Audit failed. Please try again.' });
  }
};
