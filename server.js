const express = require('express');
const { createClient } = require('@libsql/client');
const crypto = require('crypto');
const path = require('path');

const PASSWORD = process.env.INBOX_PASSWORD || 'changeme';
const PORT = process.env.PORT || 3000;

const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public'))); // local dev; Vercel serves /public itself

// Turso in production, a local file when running on your PC
const db = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:messages.db',
  authToken: process.env.TURSO_AUTH_TOKEN,
});

const ready = db.execute(`CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  text TEXT, ip TEXT, ua TEXT, device TEXT, lang TEXT, screen TEXT, tz TEXT, tag TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);
ready.catch(e => console.error('DB init failed:', e.message));

// ---------- helpers ----------
function parseUA(ua = '') {
  let os = 'Unknown';
  let model = '';
  const android = ua.match(/Android ([\d.]+); ([^;)]+)/);
  if (android) {
    os = 'Android ' + android[1];
    if (android[2].trim().length > 1) model = android[2].trim(); // modern Chrome hides it as "K"
  } else if (/iPhone/.test(ua)) os = 'iPhone (iOS)';
  else if (/iPad/.test(ua)) os = 'iPad (iOS)';
  else if (/Windows/.test(ua)) os = 'Windows';
  else if (/Mac OS X/.test(ua)) os = 'macOS';
  else if (/Linux/.test(ua)) os = 'Linux';

  let browser = 'Unknown browser';
  if (/Instagram/.test(ua)) browser = 'Instagram in-app browser';
  else if (/FBAN|FBAV/.test(ua)) browser = 'Facebook in-app browser';
  else if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/Chrome\//.test(ua)) browser = 'Chrome';
  else if (/Safari\//.test(ua)) browser = 'Safari';
  else if (/Firefox\//.test(ua)) browser = 'Firefox';

  return [model, os, browser].filter(Boolean).join(' / ');
}

const cleanIp = (ip = '') => ip.replace('::ffff:', '');

const esc = (s = '') =>
  String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, encoded] = header.split(' ');
  if (scheme === 'Basic' && encoded) {
    const pass = Buffer.from(encoded, 'base64').toString().split(':').slice(1).join(':');
    const a = Buffer.from(pass);
    const b = Buffer.from(PASSWORD);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Inbox"').status(401).send('Login required');
}

// ---------- routes ----------
app.post(['/send', '/api/send'], async (req, res) => {
  try {
    await ready;
    const ip = cleanIp(req.ip);

    // rate limit: max 5 messages per minute per IP (stored in the DB, so it works on serverless)
    const recent = await db.execute({
      sql: `SELECT COUNT(*) AS n FROM messages WHERE ip = ? AND created_at > datetime('now','-1 minute')`,
      args: [ip],
    });
    if (Number(recent.rows[0].n) >= 5) return res.status(429).json({ error: 'Too many messages, slow down.' });

    const text = String(req.body.text || '').trim().slice(0, 1000);
    if (!text) return res.status(400).json({ error: 'Write something first.' });

    const ua = req.headers['user-agent'] || '';
    const lang = String(req.body.lang || req.headers['accept-language'] || '').slice(0, 40);
    const screen = String(req.body.screen || '').slice(0, 20);
    const tz = String(req.body.tz || '').slice(0, 40);

    // "Sender ID": same IP + device + screen + timezone + language => same tag
    const tag = crypto.createHash('sha256').update([ip, ua, screen, tz, lang].join('|')).digest('hex').slice(0, 6);

    await db.execute({
      sql: `INSERT INTO messages (text, ip, ua, device, lang, screen, tz, tag) VALUES (?,?,?,?,?,?,?,?)`,
      args: [text, ip, ua, parseUA(ua), lang, screen, tz, tag],
    });

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error, try again.' });
  }
});

app.get(['/inbox', '/api/inbox'], auth, async (req, res) => {
  try {
    await ready;
    const rows = (await db.execute('SELECT * FROM messages ORDER BY id DESC')).rows;
    const counts = {};
    rows.forEach(r => (counts[r.tag] = (counts[r.tag] || 0) + 1));

    const cards = rows.map(r => `
    <div class="card">
      <p class="msg">${esc(r.text)}</p>
      <div class="meta">
        <span class="tag">Sender #${esc(r.tag)}${counts[r.tag] > 1 ? ` &middot; ${counts[r.tag]} messages` : ''}</span>
        <span>${esc(r.device)}</span>
        <span>IP: ${esc(r.ip)}</span>
        <span>Screen: ${esc(r.screen || '?')} &middot; TZ: ${esc(r.tz || '?')} &middot; Lang: ${esc(r.lang || '?')}</span>
        <span>${esc(r.created_at)} UTC</span>
      </div>
    </div>`).join('');

    res.send(`<!doctype html><html><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1"><title>Inbox</title>
  <style>
    body{font-family:system-ui,sans-serif;background:#111;color:#eee;max-width:640px;margin:0 auto;padding:16px}
    .card{background:#1e1e1e;border-radius:12px;padding:14px;margin:12px 0}
    .msg{font-size:18px;margin:0 0 10px;white-space:pre-wrap;word-break:break-word}
    .meta{display:flex;flex-direction:column;gap:2px;font-size:12px;color:#999}
    .tag{color:#ff6b9d;font-weight:600}
  </style></head><body>
  <h1>Inbox (${rows.length})</h1>${cards || '<p>No messages yet.</p>'}</body></html>`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Could not load messages.');
  }
});

// run a normal server locally; on Vercel the app is exported instead
if (require.main === module) {
  app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}  (inbox: /inbox)`));
}

module.exports = app;
