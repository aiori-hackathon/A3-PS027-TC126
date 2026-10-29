// Standalone server for a VPS with IPv6: serves public/ and the /api/audit backend.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const audit = require('./api/audit.js');

const PORT = process.env.PORT || 3000;
const PUB = path.join(__dirname, 'public');
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.png': 'image/png' };

// Simple in-memory rate limit: 20 audits per minute per client
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const a = (hits.get(ip) || []).filter((t) => now - t < 60000);
  a.push(now); hits.set(ip, a);
  return a.length > 20;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some((t) => now - t < 60000)) hits.delete(k); }, 60000).unref();

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/api/audit') {
    const fwd = process.env.TRUST_PROXY ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() : '';
    if (limited(fwd || req.socket.remoteAddress)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      return res.end('{"error":"Too many requests. Try again in a minute."}');
    }
    res.status = (c) => { res.statusCode = c; return res; };
    res.json = (o) => res.end(JSON.stringify(o));
    return audit(req, res);
  }
  const f = path.normalize(path.join(PUB, u.pathname === '/' ? 'index.html' : u.pathname));
  if (!f.startsWith(PUB + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(f, (e, d) => {
    if (e) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(f)] || 'application/octet-stream' });
    res.end(d);
  });
});

// Listen on IPv6 (also accepts IPv4); fall back to IPv4 only if the host has IPv6 disabled
let v4only = false;
server.on('error', (e) => {
  if (e.code === 'EAFNOSUPPORT' && !v4only) { v4only = true; server.listen(PORT, '0.0.0.0'); } else throw e;
});
server.on('listening', () => console.log('SixCheck listening on port ' + PORT + (v4only ? ' (IPv4 only)' : ' (IPv6 and IPv4)')));
server.listen(PORT, '::');
