'use strict';
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const QRCode = require('qrcode');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const TZ = process.env.FESTIVAL_TZ || 'Asia/Kolkata';
const CATEGORIES = ['VVIP', 'VIP', 'GUEST'];
const ID_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
const MAX_PERSONS = 20;

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- keys ----------
function loadKeys() {
  const file = path.join(DATA_DIR, 'keys.json');
  if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const keys = {
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicJwk: publicKey.export({ format: 'jwk' }),
    sessionSecret: crypto.randomBytes(32).toString('hex'),
  };
  fs.writeFileSync(file, JSON.stringify(keys, null, 2));
  return keys;
}
const KEYS = loadKeys();
const PRIVATE_KEY = crypto.createPrivateKey(KEYS.privateKey);

// ---------- database ----------
const db = new DatabaseSync(path.join(DATA_DIR, 'gateway.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    quota INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS passes(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,
    persons INTEGER NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    issued_by INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    rev INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS passes_rev ON passes(rev);
  CREATE INDEX IF NOT EXISTS passes_issuer ON passes(issued_by);
  CREATE TABLE IF NOT EXISTS entries(
    id INTEGER PRIMARY KEY,
    uuid TEXT UNIQUE NOT NULL,
    pass_id TEXT NOT NULL,
    day TEXT NOT NULL,
    scanned_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    scanner_id INTEGER NOT NULL,
    persons INTEGER NOT NULL,
    offline INTEGER NOT NULL DEFAULT 0,
    flag TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS entries_pass_day ON entries(pass_id, day);
  CREATE INDEX IF NOT EXISTS entries_day ON entries(day);
  CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);

const stmts = new Map();
const sql = (text) => {
  if (!stmts.has(text)) stmts.set(text, db.prepare(text));
  return stmts.get(text);
};
function tx(fn) {
  db.exec('BEGIN');
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

// rev is a strictly increasing change counter that scanners use as a sync cursor
let rev = sql('SELECT COALESCE(MAX(rev), 0) AS r FROM passes').get().r;

// ---------- helpers ----------
const dayOf = (ms) => new Intl.DateTimeFormat('en-CA', { timeZone: TZ }).format(new Date(ms));
const today = () => dayOf(Date.now());
const isDay = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s));
const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const cleanId = (s) => String(s || '').toUpperCase().replace(/[^0-9A-Z]/g, '');
const prettyId = (id) => `${id.slice(0, 5)}-${id.slice(5)}`;
const prettyDay = (d) => d.split('-').reverse().join('/');

function newPassId() {
  const bytes = crypto.randomBytes(10);
  let id = '';
  for (const b of bytes) id += ID_ALPHABET[b % 32];
  return id;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  return `${salt.toString('hex')}:${crypto.scryptSync(password, salt, 32).toString('hex')}`;
}
function checkPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const actual = crypto.scryptSync(password, Buffer.from(salt, 'hex'), 32);
  return crypto.timingSafeEqual(actual, Buffer.from(hash, 'hex'));
}

function getSettings() {
  const out = { festival_name: 'Temple Festival', start_date: today(), end_date: dayOf(Date.now() + 9 * 864e5) };
  for (const row of sql('SELECT key, value FROM settings').all()) out[row.key] = row.value;
  return out;
}

// The QR carries the pass details plus a signature, so a scanner can verify it with no network.
function signToken(p) {
  const name = Array.from(p.name).slice(0, 40).join('');
  const payload = Buffer.from(JSON.stringify([p.id, name, p.persons, p.category, p.valid_from, p.valid_to])).toString('base64url');
  const sig = crypto.sign('sha256', Buffer.from(payload), { key: PRIVATE_KEY, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  return `TP1.${payload}.${sig}`;
}

// ---------- sessions ----------
const hmac = (s) => crypto.createHmac('sha256', KEYS.sessionSecret).update(s).digest('base64url');
function makeSession(uid, hours) {
  const body = Buffer.from(JSON.stringify({ u: uid, e: Date.now() + hours * 3600e3 })).toString('base64url');
  return `${body}.${hmac(body)}`;
}
function readSession(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [body, mac] = m[1].split('.');
  if (!body || !mac) return null;
  const expected = hmac(body);
  if (mac.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return null;
  try {
    const { u, e } = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (e < Date.now()) return null;
    const user = sql('SELECT * FROM users WHERE id = ?').get(u);
    return user && user.active ? user : null;
  } catch {
    return null;
  }
}
const auth = (...roles) => (req, res, next) => {
  const user = readSession(req);
  if (!user) return res.status(401).json({ error: 'Please log in' });
  if (roles.length && !roles.includes(user.role)) return res.status(403).json({ error: 'Not allowed' });
  req.user = user;
  next();
};
const publicUser = (u) => ({ id: u.id, username: u.username, name: u.name, role: u.role, quota: u.quota, active: u.active });

// ---------- first run ----------
if (!sql('SELECT 1 AS x FROM users LIMIT 1').get()) {
  const password = process.env.ADMIN_PASSWORD || crypto.randomBytes(6).toString('base64url');
  sql('INSERT INTO users(username, name, role, pass_hash, created_at) VALUES (?,?,?,?,?)').run(
    'admin', 'Administrator', 'admin', hashPassword(password), Date.now());
  const file = path.join(DATA_DIR, 'admin-login.txt');
  fs.writeFileSync(file, `username: admin\npassword: ${password}\n\nChange this password after first login, then delete this file.\n`);
  console.log(`First run: admin login written to ${file}`);
}

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '4mb' }));

const loginFails = new Map();
app.post('/api/login', (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const key = `${req.ip}|${username}`;
  const fail = loginFails.get(key);
  if (fail && fail.count >= 10 && Date.now() - fail.at < 15 * 60e3) {
    return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  }
  const user = sql('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !user.active || !checkPassword(password, user.pass_hash)) {
    loginFails.set(key, { count: (fail && Date.now() - fail.at < 15 * 60e3 ? fail.count : 0) + 1, at: Date.now() });
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  loginFails.delete(key);
  // gate devices stay logged in for the whole festival; office logins expire in a day
  const hours = user.role === 'scanner' ? 24 * 30 : 24;
  const secure = req.secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `sid=${makeSession(user.id, hours)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${hours * 3600}${secure}`);
  res.json({ user: publicUser(user) });
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', auth(), (req, res) => {
  res.json({ user: publicUser(req.user), settings: getSettings(), categories: CATEGORIES, today: today() });
});

app.put('/api/settings', auth('admin'), (req, res) => {
  const name = String(req.body.festival_name || '').trim().slice(0, 80);
  const { start_date, end_date } = req.body;
  if (!name) return res.status(400).json({ error: 'Festival name is required' });
  if (!isDay(start_date) || !isDay(end_date) || start_date > end_date) return res.status(400).json({ error: 'Check the festival dates' });
  const put = sql('INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  tx(() => {
    put.run('festival_name', name);
    put.run('start_date', start_date);
    put.run('end_date', end_date);
  });
  res.json({ settings: getSettings() });
});

// ---------- passes ----------
function quotaUsed(userId) {
  return sql('SELECT COALESCE(SUM(persons), 0) AS n FROM passes WHERE issued_by = ? AND revoked = 0').get(userId).n;
}

function parsePass(input, settings) {
  const name = String(input.name || '').trim().replace(/\s+/g, ' ').slice(0, 80);
  if (!name) return { error: 'Name is required' };
  const phone = String(input.phone || '').replace(/\D/g, '');
  if (phone && (phone.length < 10 || phone.length > 13)) return { error: 'Phone number should have 10 digits' };
  const category = String(input.category || 'GUEST').trim().toUpperCase();
  if (!CATEGORIES.includes(category)) return { error: `Category must be one of ${CATEGORIES.join(', ')}` };
  const persons = Number(input.persons || 1);
  if (!Number.isInteger(persons) || persons < 1 || persons > MAX_PERSONS) return { error: `Persons must be 1 to ${MAX_PERSONS}` };
  const valid_from = input.valid_from || settings.start_date;
  const valid_to = input.valid_to || settings.end_date;
  if (!isDay(valid_from) || !isDay(valid_to) || valid_from > valid_to) return { error: 'Check the valid dates' };
  const note = String(input.note || '').trim().slice(0, 200);
  return { pass: { name, phone, category, persons, valid_from, valid_to, note } };
}

function insertPass(p, userId) {
  const id = newPassId();
  sql(`INSERT INTO passes(id, name, phone, category, persons, valid_from, valid_to, note, issued_by, created_at, rev)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
    id, p.name, p.phone, p.category, p.persons, p.valid_from, p.valid_to, p.note, userId, Date.now(), ++rev);
  return id;
}

const PASS_SELECT = `
  SELECT p.*, u.name AS issuer,
    (SELECT COUNT(*) FROM entries e WHERE e.pass_id = p.id AND e.flag = '') AS entered
  FROM passes p JOIN users u ON u.id = p.issued_by`;

app.post('/api/passes', auth('admin', 'issuer'), (req, res) => {
  const { pass, error } = parsePass(req.body, getSettings());
  if (error) return res.status(400).json({ error });
  if (req.user.role === 'issuer') {
    const left = req.user.quota - quotaUsed(req.user.id);
    if (pass.persons > left) return res.status(400).json({ error: `Quota exceeded. You can add ${Math.max(left, 0)} more person(s).` });
  }
  const id = insertPass(pass, req.user.id);
  res.json({ pass: sql(`${PASS_SELECT} WHERE p.id = ?`).get(id) });
});

app.post('/api/passes/bulk', auth('admin', 'issuer'), (req, res) => {
  const rows = Array.isArray(req.body.rows) ? req.body.rows.slice(0, 5000) : [];
  const settings = getSettings();
  let left = req.user.role === 'issuer' ? req.user.quota - quotaUsed(req.user.id) : Infinity;
  const errors = [];
  let created = 0;
  tx(() => {
    rows.forEach((row, i) => {
      const { pass, error } = parsePass(row, settings);
      if (error) return errors.push({ line: i + 1, error });
      if (pass.persons > left) return errors.push({ line: i + 1, error: 'Quota exceeded' });
      left -= pass.persons;
      insertPass(pass, req.user.id);
      created++;
    });
  });
  res.json({ created, errors });
});

app.get('/api/passes', auth('admin', 'issuer'), (req, res) => {
  const q = String(req.query.q || '').trim();
  const page = Math.max(0, Number(req.query.page) || 0);
  const where = [];
  const args = [];
  if (req.user.role === 'issuer') {
    where.push('p.issued_by = ?');
    args.push(req.user.id);
  }
  if (q) {
    where.push('(p.name LIKE ? OR p.phone LIKE ? OR p.id LIKE ?)');
    args.push(`%${q}%`, `%${q.replace(/\D/g, '') || q}%`, `${cleanId(q)}%`);
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const total = sql(`SELECT COUNT(*) AS n FROM passes p ${clause}`).get(...args).n;
  const passes = sql(`${PASS_SELECT} ${clause} ORDER BY p.created_at DESC, p.rev DESC LIMIT 50 OFFSET ?`).all(...args, page * 50);
  res.json({ passes, total, page });
});

app.post('/api/passes/:id/:action(revoke|restore)', auth('admin', 'issuer'), (req, res) => {
  const pass = sql('SELECT * FROM passes WHERE id = ?').get(cleanId(req.params.id));
  if (!pass || (req.user.role === 'issuer' && pass.issued_by !== req.user.id)) return res.status(404).json({ error: 'Pass not found' });
  const revoked = req.params.action === 'revoke' ? 1 : 0;
  if (!revoked && req.user.role === 'issuer' && pass.revoked) {
    const left = req.user.quota - quotaUsed(req.user.id);
    if (pass.persons > left) return res.status(400).json({ error: 'Quota exceeded' });
  }
  sql('UPDATE passes SET revoked = ?, rev = ? WHERE id = ?').run(revoked, ++rev, pass.id);
  res.json({ pass: sql(`${PASS_SELECT} WHERE p.id = ?`).get(pass.id) });
});

app.get('/api/stats', auth('admin', 'issuer'), (req, res) => {
  const mine = req.user.role === 'issuer';
  const issued = sql(`SELECT category, COUNT(*) AS passes, SUM(persons) AS persons FROM passes
                      WHERE revoked = 0 ${mine ? 'AND issued_by = ?' : ''} GROUP BY category`).all(...(mine ? [req.user.id] : []));
  const out = { issued, quota: mine ? { total: req.user.quota, used: quotaUsed(req.user.id) } : null };
  if (!mine) {
    out.days = sql(`SELECT day, COUNT(*) AS passes, SUM(persons) AS persons FROM entries WHERE flag = '' GROUP BY day ORDER BY day`).all();
    out.flagged = sql(`SELECT COUNT(*) AS n FROM entries WHERE flag != ''`).get().n;
    out.today = today();
  }
  res.json(out);
});

app.get('/api/entries', auth('admin'), (req, res) => {
  const day = isDay(req.query.day) ? req.query.day : today();
  const entries = sql(`
    SELECT e.id, e.pass_id, e.scanned_at, e.persons, e.offline, e.flag, p.name, p.category, u.name AS scanner
    FROM entries e LEFT JOIN passes p ON p.id = e.pass_id JOIN users u ON u.id = e.scanner_id
    WHERE e.day = ? ORDER BY e.scanned_at DESC LIMIT 1000`).all(day);
  res.json({ day, entries });
});

// ---------- users ----------
app.get('/api/users', auth('admin'), (req, res) => {
  const users = sql('SELECT * FROM users ORDER BY role, name').all().map((u) => ({ ...publicUser(u), used: quotaUsed(u.id) }));
  res.json({ users });
});

app.post('/api/users', auth('admin'), (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const name = String(req.body.name || '').trim().slice(0, 60);
  const role = String(req.body.role || '');
  const password = String(req.body.password || '');
  const quota = Math.max(0, Math.floor(Number(req.body.quota) || 0));
  if (!/^[a-z0-9_.-]{3,30}$/.test(username)) return res.status(400).json({ error: 'Username: 3-30 letters or numbers, no spaces' });
  if (!name) return res.status(400).json({ error: 'Name is required' });
  if (!['admin', 'issuer', 'scanner'].includes(role)) return res.status(400).json({ error: 'Choose a role' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (sql('SELECT 1 AS x FROM users WHERE username = ?').get(username)) return res.status(400).json({ error: 'Username already taken' });
  sql('INSERT INTO users(username, name, role, pass_hash, quota, created_at) VALUES (?,?,?,?,?,?)').run(
    username, name, role, hashPassword(password), quota, Date.now());
  res.json({ ok: true });
});

app.patch('/api/users/:id', auth('admin'), (req, res) => {
  const user = sql('SELECT * FROM users WHERE id = ?').get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });
  if ('active' in req.body) {
    if (user.id === req.user.id) return res.status(400).json({ error: 'You cannot disable your own login' });
    sql('UPDATE users SET active = ? WHERE id = ?').run(req.body.active ? 1 : 0, user.id);
  }
  if ('quota' in req.body) sql('UPDATE users SET quota = ? WHERE id = ?').run(Math.max(0, Math.floor(Number(req.body.quota) || 0)), user.id);
  if ('password' in req.body) {
    if (String(req.body.password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    sql('UPDATE users SET pass_hash = ? WHERE id = ?').run(hashPassword(String(req.body.password)), user.id);
  }
  res.json({ ok: true });
});

// ---------- gate scanner ----------
app.get('/api/scan/bootstrap', auth('scanner', 'admin'), (req, res) => {
  res.json({ user: publicUser(req.user), publicJwk: KEYS.publicJwk, settings: getSettings(), tz: TZ });
});

app.get('/api/scan/sync', auth('scanner', 'admin'), (req, res) => {
  const passes = sql('SELECT id, name, phone, persons, category, valid_from, valid_to, revoked, rev FROM passes WHERE rev > ? ORDER BY rev LIMIT 5000')
    .all(Number(req.query.rev) || 0)
    .map((p) => [p.id, p.name, p.phone, p.persons, p.category, p.valid_from, p.valid_to, p.revoked, p.rev]);
  const entries = sql(`SELECT e.id, e.pass_id, e.day, e.scanned_at, e.uuid, u.name AS scanner FROM entries e
                       JOIN users u ON u.id = e.scanner_id WHERE e.id > ? ORDER BY e.id LIMIT 5000`)
    .all(Number(req.query.entry) || 0)
    .map((e) => [e.id, e.pass_id, e.day, e.scanned_at, e.uuid, e.scanner]);
  res.json({ passes, entries, settings: getSettings() });
});

// live: the device is online and asks the server to decide. Otherwise the device already
// let the person in while offline, so the entry is always recorded and only flagged.
app.post('/api/scan/entries', auth('scanner', 'admin'), (req, res) => {
  const live = !!req.body.live;
  const list = Array.isArray(req.body.entries) ? req.body.entries.slice(0, 500) : [];
  const firstEntry = sql(`SELECT e.scanned_at, u.name AS scanner FROM entries e JOIN users u ON u.id = e.scanner_id
                          WHERE e.pass_id = ? AND e.day = ? ORDER BY e.scanned_at LIMIT 1`);
  const insert = sql('INSERT INTO entries(uuid, pass_id, day, scanned_at, received_at, scanner_id, persons, offline, flag) VALUES (?,?,?,?,?,?,?,?,?)');
  const results = tx(() => list.map((e) => {
    const uuid = String(e.uuid || '');
    const passId = cleanId(e.pass_id);
    const now = Date.now();
    const scannedAt = live ? now : Math.min(Number(e.scanned_at) || now, now);
    if (uuid.length < 8 || !passId) return { uuid, status: 'bad_request' };
    const known = sql('SELECT flag FROM entries WHERE uuid = ?').get(uuid);
    if (known) return { uuid, status: known.flag || 'ok' };
    const day = dayOf(scannedAt);
    const pass = sql('SELECT * FROM passes WHERE id = ?').get(passId);
    const first = firstEntry.get(passId, day);
    let flag = '';
    if (!pass) flag = 'unknown';
    else if (pass.revoked) flag = 'revoked';
    else if (day < pass.valid_from || day > pass.valid_to) flag = 'invalid_day';
    else if (first) flag = 'duplicate';
    if (live && flag) return { uuid, status: flag, first: first ? { scanned_at: first.scanned_at, by: first.scanner } : null };
    insert.run(uuid, passId, day, scannedAt, now, req.user.id, pass ? pass.persons : 0, live ? 0 : 1, flag);
    return { uuid, status: flag || 'ok' };
  }));
  res.json({ results });
});

// ---------- pages ----------
app.get('/p/:id', async (req, res) => {
  const pass = sql('SELECT * FROM passes WHERE id = ?').get(cleanId(req.params.id));
  const settings = getSettings();
  res.setHeader('Cache-Control', 'no-store');
  if (!pass) return res.status(404).send(passPage(settings, '<h2>Pass not found</h2><p>Please check the link you received.</p>'));
  const head = `
    <div class="cat cat-${esc(pass.category)}">${esc(pass.category)} PASS</div>
    <h2>${esc(pass.name)}</h2>
    <div class="persons">${pass.persons === 1 ? 'Admit 1 person' : `Family pass &middot; admit ${pass.persons} persons`}</div>`;
  if (pass.revoked) return res.send(passPage(settings, `${head}<div class="cancelled">THIS PASS IS CANCELLED</div>`));
  const qr = await QRCode.toString(signToken(pass), { type: 'svg', errorCorrectionLevel: 'M', margin: 2 });
  const dates = pass.valid_from === pass.valid_to ? prettyDay(pass.valid_from) : `${prettyDay(pass.valid_from)} to ${prettyDay(pass.valid_to)}`;
  res.send(passPage(settings, `${head}
    <div class="qr">${qr}</div>
    <div class="code">${prettyId(pass.id)}</div>
    <div class="dates">Valid: ${dates}</div>
    <ul>
      <li>Show this QR code at the special entry gate.</li>
      <li>One entry per day. All members must enter together.</li>
      <li>Do not share this pass. It stops working once it is scanned.</li>
      <li>Keep your screen brightness high while scanning.</li>
    </ul>`));
});

function passPage(settings, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>${esc(settings.festival_name)} - Entry Pass</title>
<style>
  body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f4efe6;color:#2b2118}
  .card{max-width:420px;margin:16px auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.12);text-align:center}
  .top{background:#8a1c1c;color:#fff;padding:14px 16px;font-size:18px;font-weight:700}
  .in{padding:16px 20px 20px}
  .cat{display:inline-block;padding:4px 14px;border-radius:99px;font-weight:700;font-size:14px;letter-spacing:.5px;color:#fff;background:#3d6b3d}
  .cat-VVIP{background:#b8860b}.cat-VIP{background:#8a1c1c}
  h2{margin:12px 0 4px;font-size:24px}
  .persons{font-size:17px;font-weight:600}
  .qr{max-width:300px;margin:12px auto 4px}.qr svg{width:100%;height:auto;display:block}
  .code{font-family:ui-monospace,Consolas,monospace;font-size:20px;letter-spacing:2px;font-weight:700}
  .dates{margin-top:6px;font-size:15px}
  .cancelled{margin:24px 0;padding:16px;background:#c62828;color:#fff;font-weight:700;font-size:20px;border-radius:10px}
  ul{text-align:left;font-size:14px;color:#5a4c40;padding-left:20px;margin:16px 0 0}
  @media print{body{background:#fff}.card{box-shadow:none;border:1px solid #999}}
</style></head><body><div class="card"><div class="top">${esc(settings.festival_name)}</div><div class="in">${body}</div></div></body></html>`;
}

const page = (file) => (req, res) => res.sendFile(path.join(__dirname, 'public', file));
app.get('/', (req, res) => res.redirect('/admin'));
app.get('/admin', page('admin.html'));
app.get('/scan', page('scan.html'));
app.get('/vendor/jsQR.js', (req, res) => res.sendFile(path.join(__dirname, 'node_modules', 'jsqr', 'dist', 'jsQR.js')));
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

app.listen(PORT, () => console.log(`Entrance gateway running on http://localhost:${PORT}  (admin: /admin, gate: /scan)`));
