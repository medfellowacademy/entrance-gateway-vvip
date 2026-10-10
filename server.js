'use strict';
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');
const { connect } = require('./db');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const TZ = process.env.FESTIVAL_TZ || 'Asia/Kolkata';
const CATEGORIES = ['VVIP', 'VIP', 'GUEST'];
const ID_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
const MAX_PERSONS = 20;
const PASS_LOCK = 727001;       // advisory lock: pass changes commit in rev order, so scanners never skip one
const ENTRY_SETTLE_MS = 3000;   // entries younger than this are held back from sync until surely committed

const configError = (message) => Object.assign(new Error(message), { config: true });

// ---------- startup (once per server instance) ----------
let db, q, one, KEYS;
let ready;
function init() {
  ready ||= (async () => {
    db = await connect(DATA_DIR);
    q = db.query;
    one = (text, params) => q(text, params).then((rows) => rows[0]);
    KEYS = await loadKeys();
    await ensureAdmin();
  })().catch((err) => {
    ready = null;
    throw err;
  });
  return ready;
}

// The signing key is created once and kept in the database, so every server instance signs alike.
async function loadKeys() {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  await q(`INSERT INTO gateway.secrets(key, value) VALUES ('signing_key', $1), ('session_secret', $2) ON CONFLICT (key) DO NOTHING`,
    [privateKey.export({ type: 'pkcs8', format: 'pem' }), crypto.randomBytes(32).toString('hex')]);
  const rows = await q('SELECT key, value FROM gateway.secrets');
  const get = (key) => rows.find((r) => r.key === key).value;
  const signingKey = crypto.createPrivateKey(get('signing_key'));
  return {
    signingKey,
    publicJwk: crypto.createPublicKey(signingKey).export({ format: 'jwk' }),
    sessionSecret: get('session_secret'),
  };
}

async function ensureAdmin() {
  if (await one('SELECT 1 AS x FROM gateway.users LIMIT 1')) return;
  let password = process.env.ADMIN_PASSWORD;
  if (!password) {
    if (process.env.VERCEL) throw configError('ADMIN_PASSWORD is not set. Add it in the Vercel project settings to create the first admin login.');
    password = crypto.randomBytes(6).toString('base64url');
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const file = path.join(DATA_DIR, 'admin-login.txt');
    fs.writeFileSync(file, `username: admin\npassword: ${password}\n\nChange this password after first login, then delete this file.\n`);
    console.log(`First run: admin login written to ${file}`);
  }
  await q(`INSERT INTO gateway.users(username, name, role, pass_hash, created_at) VALUES ('admin', 'Administrator', 'admin', $1, $2)
           ON CONFLICT (username) DO NOTHING`, [hashPassword(password), Date.now()]);
}

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

async function getSettings() {
  const out = { festival_name: 'Temple Festival', start_date: today(), end_date: dayOf(Date.now() + 9 * 864e5) };
  for (const row of await q(`SELECT key, value FROM gateway.settings WHERE key != 'schema_version'`)) out[row.key] = row.value;
  return out;
}

// The QR carries the pass details plus a signature, so a scanner can verify it with no network.
function signToken(p) {
  const name = Array.from(p.name).slice(0, 40).join('');
  const payload = Buffer.from(JSON.stringify([p.id, name, p.persons, p.category, p.valid_from, p.valid_to])).toString('base64url');
  const sig = crypto.sign('sha256', Buffer.from(payload), { key: KEYS.signingKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  return `TP1.${payload}.${sig}`;
}

// ---------- sessions ----------
const hmac = (s) => crypto.createHmac('sha256', KEYS.sessionSecret).update(s).digest('base64url');
function makeSession(uid, hours) {
  const body = Buffer.from(JSON.stringify({ u: uid, e: Date.now() + hours * 3600e3 })).toString('base64url');
  return `${body}.${hmac(body)}`;
}
async function readSession(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [body, mac] = m[1].split('.');
  if (!body || !mac) return null;
  const expected = hmac(body);
  if (mac.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return null;
  let session;
  try {
    session = JSON.parse(Buffer.from(body, 'base64url').toString());
  } catch {
    return null;
  }
  if (!(session.e > Date.now())) return null;
  const user = await one('SELECT * FROM gateway.users WHERE id = $1', [session.u]);
  return user && user.active ? user : null;
}
const h = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const auth = (...roles) => h(async (req, res, next) => {
  const user = await readSession(req);
  if (!user) return res.status(401).json({ error: 'Please log in' });
  if (roles.length && !roles.includes(user.role)) return res.status(403).json({ error: 'Not allowed' });
  req.user = user;
  next();
});
const publicUser = (u) => ({ id: u.id, username: u.username, name: u.name, role: u.role, quota: u.quota, active: u.active });

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '4mb' }));
app.use(['/api', '/p'], h(async (req, res, next) => {
  await init();
  next();
}));

const FAIL_WINDOW = 15 * 60e3;
app.post('/api/login', h(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const key = `${req.ip}|${username}`;
  const fail = await one('SELECT count FROM gateway.login_fails WHERE key = $1 AND at > $2', [key, Date.now() - FAIL_WINDOW]);
  if (fail && fail.count >= 10) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const user = await one('SELECT * FROM gateway.users WHERE username = $1', [username]);
  if (!user || !user.active || !checkPassword(password, user.pass_hash)) {
    await q(`INSERT INTO gateway.login_fails(key, count, at) VALUES ($1, 1, $2)
             ON CONFLICT (key) DO UPDATE SET count = CASE WHEN gateway.login_fails.at > $3 THEN gateway.login_fails.count + 1 ELSE 1 END, at = $2`,
      [key, Date.now(), Date.now() - FAIL_WINDOW]);
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  await q('DELETE FROM gateway.login_fails WHERE key = $1', [key]);
  // gate devices stay logged in for the whole festival; office logins expire in a day
  const hours = user.role === 'scanner' ? 24 * 30 : 24;
  const secure = req.secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `sid=${makeSession(user.id, hours)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${hours * 3600}${secure}`);
  res.json({ user: publicUser(user) });
}));

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', auth(), h(async (req, res) => {
  res.json({ user: publicUser(req.user), settings: await getSettings(), categories: CATEGORIES, today: today() });
}));

app.put('/api/settings', auth('admin'), h(async (req, res) => {
  const name = String(req.body.festival_name || '').trim().slice(0, 80);
  const { start_date, end_date } = req.body;
  if (!name) return res.status(400).json({ error: 'Festival name is required' });
  if (!isDay(start_date) || !isDay(end_date) || start_date > end_date) return res.status(400).json({ error: 'Check the festival dates' });
  await q(`INSERT INTO gateway.settings(key, value) VALUES ('festival_name', $1), ('start_date', $2), ('end_date', $3)
           ON CONFLICT (key) DO UPDATE SET value = excluded.value`, [name, start_date, end_date]);
  res.json({ settings: await getSettings() });
}));

// ---------- passes ----------
const quotaUsed = (userId) =>
  one('SELECT COALESCE(SUM(persons), 0) AS n FROM gateway.passes WHERE issued_by = $1 AND revoked = 0', [userId]).then((r) => r.n);

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

// One statement however many passes: a bulk upload must not make thousands of database round trips.
async function insertPasses(passes, userId) {
  const rows = passes.map((p) => ({ ...p, id: newPassId() }));
  await db.tx(async (t) => {
    await t('SELECT pg_advisory_xact_lock($1)', [PASS_LOCK]);
    await t(`INSERT INTO gateway.passes(id, name, phone, category, persons, valid_from, valid_to, note, issued_by, created_at, rev)
             SELECT r.id, r.name, r.phone, r.category, r.persons, r.valid_from, r.valid_to, r.note, $2, $3, nextval('gateway.pass_rev')
             FROM jsonb_to_recordset($1::jsonb)
               AS r(id text, name text, phone text, category text, persons int, valid_from text, valid_to text, note text)`,
      [JSON.stringify(rows), userId, Date.now()]);
  });
  return rows;
}

const PASS_SELECT = `
  SELECT p.*, u.name AS issuer,
    (SELECT COUNT(*) FROM gateway.entries e WHERE e.pass_id = p.id AND e.flag = '') AS entered
  FROM gateway.passes p JOIN gateway.users u ON u.id = p.issued_by`;

app.post('/api/passes', auth('admin', 'issuer'), h(async (req, res) => {
  const { pass, error } = parsePass(req.body, await getSettings());
  if (error) return res.status(400).json({ error });
  if (req.user.role === 'issuer') {
    const left = req.user.quota - await quotaUsed(req.user.id);
    if (pass.persons > left) return res.status(400).json({ error: `Quota exceeded. You can add ${Math.max(left, 0)} more person(s).` });
  }
  const [{ id }] = await insertPasses([pass], req.user.id);
  res.json({ pass: await one(`${PASS_SELECT} WHERE p.id = $1`, [id]) });
}));

app.post('/api/passes/bulk', auth('admin', 'issuer'), h(async (req, res) => {
  const rows = Array.isArray(req.body.rows) ? req.body.rows.slice(0, 5000) : [];
  const settings = await getSettings();
  let left = req.user.role === 'issuer' ? req.user.quota - await quotaUsed(req.user.id) : Infinity;
  const errors = [];
  const good = [];
  rows.forEach((row, i) => {
    const { pass, error } = parsePass(row || {}, settings);
    if (error) return errors.push({ line: i + 1, error });
    if (pass.persons > left) return errors.push({ line: i + 1, error: 'Quota exceeded' });
    left -= pass.persons;
    good.push(pass);
  });
  if (good.length) await insertPasses(good, req.user.id);
  res.json({ created: good.length, errors });
}));

app.get('/api/passes', auth('admin', 'issuer'), h(async (req, res) => {
  const search = String(req.query.q || '').trim();
  const page = Math.max(0, Number(req.query.page) || 0);
  const where = [];
  const args = [];
  if (req.user.role === 'issuer') {
    args.push(req.user.id);
    where.push(`p.issued_by = $${args.length}`);
  }
  if (search) {
    const digits = search.replace(/[\s+-]/g, '');
    if (/^\d{4,}$/.test(digits)) {
      args.push(`%${digits}%`);
      where.push(`p.phone LIKE $${args.length}`);
    } else {
      // an empty pass-number pattern would match every pass
      args.push(`%${search}%`, cleanId(search).length >= 3 ? `${cleanId(search)}%` : '');
      where.push(`(p.name ILIKE $${args.length - 1} OR p.id LIKE $${args.length})`);
    }
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const { n: total } = await one(`SELECT COUNT(*) AS n FROM gateway.passes p ${clause}`, args);
  const passes = await q(`${PASS_SELECT} ${clause} ORDER BY p.created_at DESC, p.rev DESC LIMIT 50 OFFSET $${args.length + 1}`, [...args, page * 50]);
  res.json({ passes, total, page });
}));

app.post('/api/passes/:id/:action(revoke|restore)', auth('admin', 'issuer'), h(async (req, res) => {
  const pass = await one('SELECT * FROM gateway.passes WHERE id = $1', [cleanId(req.params.id)]);
  if (!pass || (req.user.role === 'issuer' && pass.issued_by !== req.user.id)) return res.status(404).json({ error: 'Pass not found' });
  const revoked = req.params.action === 'revoke' ? 1 : 0;
  if (!revoked && req.user.role === 'issuer' && pass.revoked) {
    const left = req.user.quota - await quotaUsed(req.user.id);
    if (pass.persons > left) return res.status(400).json({ error: 'Quota exceeded' });
  }
  await db.tx(async (t) => {
    await t('SELECT pg_advisory_xact_lock($1)', [PASS_LOCK]);
    await t(`UPDATE gateway.passes SET revoked = $1, rev = nextval('gateway.pass_rev') WHERE id = $2`, [revoked, pass.id]);
  });
  res.json({ pass: await one(`${PASS_SELECT} WHERE p.id = $1`, [pass.id]) });
}));

app.get('/api/stats', auth('admin', 'issuer'), h(async (req, res) => {
  const mine = req.user.role === 'issuer';
  const issued = await q(`SELECT category, COUNT(*) AS passes, SUM(persons) AS persons FROM gateway.passes
                          WHERE revoked = 0 ${mine ? 'AND issued_by = $1' : ''} GROUP BY category ORDER BY category`, mine ? [req.user.id] : []);
  const out = { issued, quota: mine ? { total: req.user.quota, used: await quotaUsed(req.user.id) } : null };
  if (!mine) {
    out.days = await q(`SELECT day, COUNT(*) AS passes, SUM(persons) AS persons FROM gateway.entries WHERE flag = '' GROUP BY day ORDER BY day`);
    out.flagged = (await one(`SELECT COUNT(*) AS n FROM gateway.entries WHERE flag != ''`)).n;
    out.today = today();
  }
  res.json(out);
}));

app.get('/api/entries', auth('admin'), h(async (req, res) => {
  const day = isDay(req.query.day) ? req.query.day : today();
  const entries = await q(`
    SELECT e.id, e.pass_id, e.scanned_at, e.persons, e.offline, e.flag, p.name, p.category, u.name AS scanner
    FROM gateway.entries e LEFT JOIN gateway.passes p ON p.id = e.pass_id JOIN gateway.users u ON u.id = e.scanner_id
    WHERE e.day = $1 ORDER BY e.scanned_at DESC LIMIT 1000`, [day]);
  res.json({ day, entries });
}));

// ---------- users ----------
app.get('/api/users', auth('admin'), h(async (req, res) => {
  const users = await q(`
    SELECT u.*, (SELECT COALESCE(SUM(persons), 0) FROM gateway.passes p WHERE p.issued_by = u.id AND p.revoked = 0) AS used
    FROM gateway.users u ORDER BY u.role, u.name`);
  res.json({ users: users.map((u) => ({ ...publicUser(u), used: u.used })) });
}));

app.post('/api/users', auth('admin'), h(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const name = String(req.body.name || '').trim().slice(0, 60);
  const role = String(req.body.role || '');
  const password = String(req.body.password || '');
  const quota = Math.max(0, Math.floor(Number(req.body.quota) || 0));
  if (!/^[a-z0-9_.-]{3,30}$/.test(username)) return res.status(400).json({ error: 'Username: 3-30 letters or numbers, no spaces' });
  if (!name) return res.status(400).json({ error: 'Name is required' });
  if (!['admin', 'issuer', 'scanner'].includes(role)) return res.status(400).json({ error: 'Choose a role' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const made = await q(`INSERT INTO gateway.users(username, name, role, pass_hash, quota, created_at) VALUES ($1,$2,$3,$4,$5,$6)
                        ON CONFLICT (username) DO NOTHING RETURNING id`, [username, name, role, hashPassword(password), quota, Date.now()]);
  if (!made.length) return res.status(400).json({ error: 'Username already taken' });
  res.json({ ok: true });
}));

app.patch('/api/users/:id', auth('admin'), h(async (req, res) => {
  const user = await one('SELECT * FROM gateway.users WHERE id = $1', [Number(req.params.id) || 0]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if ('active' in req.body) {
    if (user.id === req.user.id) return res.status(400).json({ error: 'You cannot disable your own login' });
    await q('UPDATE gateway.users SET active = $1 WHERE id = $2', [req.body.active ? 1 : 0, user.id]);
  }
  if ('quota' in req.body) await q('UPDATE gateway.users SET quota = $1 WHERE id = $2', [Math.max(0, Math.floor(Number(req.body.quota) || 0)), user.id]);
  if ('password' in req.body) {
    if (String(req.body.password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    await q('UPDATE gateway.users SET pass_hash = $1 WHERE id = $2', [hashPassword(String(req.body.password)), user.id]);
  }
  res.json({ ok: true });
}));

// ---------- gate scanner ----------
app.get('/api/scan/bootstrap', auth('scanner', 'admin'), h(async (req, res) => {
  res.json({ user: publicUser(req.user), publicJwk: KEYS.publicJwk, settings: await getSettings(), tz: TZ });
}));

app.get('/api/scan/sync', auth('scanner', 'admin'), h(async (req, res) => {
  const [passes, entries, settings] = await Promise.all([
    q(`SELECT id, name, phone, persons, category, valid_from, valid_to, revoked, rev FROM gateway.passes
       WHERE rev > $1 ORDER BY rev LIMIT 5000`, [Number(req.query.rev) || 0]),
    q(`SELECT e.id, e.pass_id, e.day, e.scanned_at, e.uuid, u.name AS scanner FROM gateway.entries e
       JOIN gateway.users u ON u.id = e.scanner_id WHERE e.id > $1 AND e.received_at <= $2 ORDER BY e.id LIMIT 5000`,
      [Number(req.query.entry) || 0, Date.now() - ENTRY_SETTLE_MS]),
    getSettings(),
  ]);
  res.json({
    passes: passes.map((p) => [p.id, p.name, p.phone, p.persons, p.category, p.valid_from, p.valid_to, p.revoked, p.rev]),
    entries: entries.map((e) => [e.id, e.pass_id, e.day, e.scanned_at, e.uuid, e.scanner]),
    settings,
  });
}));

const INSERT_ENTRY = `
  INSERT INTO gateway.entries(uuid, pass_id, day, scanned_at, received_at, scanner_id, persons, offline, flag)
  VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING RETURNING id`;

// live: the device is online and asks the server to decide. Otherwise the device already
// let the person in while offline, so the entry is always recorded and only flagged.
async function recordEntry(e, live, scanner) {
  const uuid = String(e.uuid || '');
  const passId = cleanId(e.pass_id);
  const now = Date.now();
  const scannedAt = live ? now : Math.min(Number(e.scanned_at) || now, now);
  if (uuid.length < 8 || !passId) return { uuid, status: 'bad_request' };
  const known = await one('SELECT flag FROM gateway.entries WHERE uuid = $1', [uuid]);
  if (known) return { uuid, status: known.flag || 'ok' };
  const day = dayOf(scannedAt);
  const pass = await one('SELECT * FROM gateway.passes WHERE id = $1', [passId]);
  const row = (flag) => [uuid, passId, day, scannedAt, now, scanner.id, pass ? pass.persons : 0, live ? 0 : 1, flag];
  let flag = '';
  if (!pass) flag = 'unknown';
  else if (pass.revoked) flag = 'revoked';
  else if (day < pass.valid_from || day > pass.valid_to) flag = 'invalid_day';
  // the unique index decides who was first when two devices scan the same pass at the same moment
  else if (!(await q(INSERT_ENTRY, row(''))).length) flag = 'duplicate';
  if (!flag) return { uuid, status: 'ok' };
  if (live) {
    const first = flag === 'duplicate' && await one(`
      SELECT e.scanned_at, u.name AS "by" FROM gateway.entries e JOIN gateway.users u ON u.id = e.scanner_id
      WHERE e.pass_id = $1 AND e.day = $2 AND e.flag = ''`, [passId, day]);
    return { uuid, status: flag, first: first || null };
  }
  await q(INSERT_ENTRY, row(flag));
  return { uuid, status: flag };
}

app.post('/api/scan/entries', auth('scanner', 'admin'), h(async (req, res) => {
  const live = !!req.body.live;
  const list = Array.isArray(req.body.entries) ? req.body.entries.slice(0, 200) : [];
  const results = [];
  for (const e of list) results.push(await recordEntry(e || {}, live, req.user));
  res.json({ results });
}));

// ---------- pages ----------
app.get('/p/:id', h(async (req, res) => {
  const pass = await one('SELECT * FROM gateway.passes WHERE id = $1', [cleanId(req.params.id)]);
  const settings = await getSettings();
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
}));

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

// On Vercel these pages and the files in public/ are served directly (see vercel.json).
const page = (file) => (req, res) => res.sendFile(path.join(__dirname, 'public', file));
app.get('/', (req, res) => res.redirect('/admin'));
app.get('/admin', page('admin.html'));
app.get('/scan', page('scan.html'));
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.config ? err.message : 'Server error' });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`Entrance gateway running on http://localhost:${PORT}  (admin: /admin, gate: /scan)`));
}
module.exports = app;
