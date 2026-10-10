'use strict';
const $ = (s) => document.querySelector(s);
const LIVE_TIMEOUT = 2000;      // how long a scan waits for the server before deciding on its own
const LIVE_BACKOFF = 20000;     // after a failed live check, decide locally for this long
const SYNC_EVERY = 8000;
const REPEAT_WINDOW = 20000;    // re-scanning the pass this device just admitted stays green

// ---------- local storage (IndexedDB) ----------
const store = (() => {
  let opening;
  const open = () => (opening ||= new Promise((resolve, reject) => {
    const req = indexedDB.open('gate', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('kv');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  }));
  const run = async (mode, fn) => {
    const db = await open();
    return new Promise((resolve, reject) => {
      const req = fn(db.transaction('kv', mode).objectStore('kv'));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  };
  return { get: (k) => run('readonly', (s) => s.get(k)), set: (k, v) => run('readwrite', (s) => s.put(v, k)) };
})();

const S = {
  boot: null,           // { user, publicJwk, settings, tz }
  key: null,            // imported public key
  passes: new Map(),    // id -> pass
  entries: new Map(),   // "id|day" -> { t, by, uuid, own }
  queue: [],            // entries admitted offline, waiting for upload
  cursor: { rev: 0, entry: 0 },
  liveDownUntil: 0,
  needLogin: false,
};

// ---------- helpers ----------
const dayOf = (ms) => new Intl.DateTimeFormat('en-CA', { timeZone: S.boot.tz }).format(new Date(ms));
const timeOf = (ms) => new Intl.DateTimeFormat('en-IN', { timeZone: S.boot.tz, hour: '2-digit', minute: '2-digit' }).format(new Date(ms));
const prettyDay = (d) => d.split('-').reverse().slice(0, 2).join('/');
const prettyId = (id) => `${id.slice(0, 5)}-${id.slice(5)}`;
const cleanId = (s) => String(s || '').toUpperCase().replace(/[^0-9A-Z]/g, '');
const b64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

async function api(url, { method = 'GET', body, timeout = 15000 } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeout);
  try {
    const res = await fetch(url, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
      signal: ctl.signal,
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error(json.error || `Error ${res.status}`), { status: res.status });
    return json;
  } finally {
    clearTimeout(timer);
  }
}

// ---------- result screen ----------
let busy = false;
let hideTimer;
let lastText = '';
let lastAt = 0;
let audio;

function beep(ok) {
  try {
    audio ||= new (window.AudioContext || window.webkitAudioContext)();
    const tone = (freq, at, len) => {
      const osc = audio.createOscillator();
      const gain = audio.createGain();
      osc.frequency.value = freq;
      osc.connect(gain).connect(audio.destination);
      gain.gain.value = 0.3;
      osc.start(audio.currentTime + at);
      osc.stop(audio.currentTime + at + len);
    };
    if (ok) tone(1200, 0, 0.15);
    else { tone(300, 0, 0.25); tone(300, 0.35, 0.4); }
    navigator.vibrate?.(ok ? 80 : [200, 100, 300]);
  } catch { /* sound is optional */ }
}

function show(ok, reason, pass, detail) {
  const el = $('#result');
  el.className = ok ? 'allow' : 'stop';
  el.querySelector('.verdict').textContent = ok ? 'ALLOW' : 'STOP';
  el.querySelector('.reason').textContent = reason || '';
  el.querySelector('.name').textContent = pass ? pass.name : '';
  el.querySelector('.persons').textContent = pass && ok ? (pass.persons === 1 ? '1 PERSON' : `${pass.persons} PERSONS`) : '';
  const cat = el.querySelector('.cat');
  cat.textContent = pass ? pass.category : '';
  cat.hidden = !pass;
  el.querySelector('.detail').textContent = detail || '';
  el.hidden = false;
  beep(ok);
  clearTimeout(hideTimer);
  hideTimer = setTimeout(hideResult, ok ? 5000 : 10000);
  renderCounts();
}

function hideResult() {
  clearTimeout(hideTimer);
  $('#result').hidden = true;
  lastAt = Date.now();
  busy = false;
}

// ---------- deciding ----------
async function verifyToken(text) {
  const m = /TP1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)/.exec(text);
  if (!m) return { error: 'NOT A TEMPLE PASS' };
  try {
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, S.key, b64(m[2]), new TextEncoder().encode(m[1]));
    if (!valid) return { error: 'FAKE PASS' };
    const [id, name, persons, category, from, to] = JSON.parse(new TextDecoder().decode(b64(m[1])));
    return { pass: { id, name, phone: '', persons, category, from, to, revoked: 0 } };
  } catch {
    return { error: 'FAKE PASS' };
  }
}

async function handleText(text) {
  if (busy) return;
  busy = true;
  lastText = text;
  const { pass, error } = await verifyToken(text);
  if (error) return show(false, error);
  // the synced copy is newer than what is printed in the QR (it knows about cancellations)
  await admit(S.passes.get(pass.id) || pass);
}

async function admit(pass) {
  busy = true;
  const now = Date.now();
  const day = dayOf(now);
  const key = `${pass.id}|${day}`;
  if (pass.revoked) return show(false, 'CANCELLED PASS', pass);
  if (day < pass.from || day > pass.to) return show(false, 'NOT VALID TODAY', pass, `Valid ${prettyDay(pass.from)} to ${prettyDay(pass.to)}`);

  const used = (prev) => show(false, 'ALREADY USED TODAY', pass, `Entered at ${timeOf(prev.t)}${prev.by ? ` - ${prev.by}` : ''}`);
  const prev = S.entries.get(key);
  if (prev) {
    if (prev.own && now - prev.t < REPEAT_WINDOW) return show(true, '', pass, 'Already scanned just now');
    return used(prev);
  }

  const entry = { uuid: crypto.randomUUID(), pass_id: pass.id, scanned_at: now };
  if (now > S.liveDownUntil) {
    try {
      const { results } = await api('/api/scan/entries', { method: 'POST', body: { live: true, entries: [entry] }, timeout: LIVE_TIMEOUT });
      const r = results[0];
      if (r.status === 'ok') {
        S.entries.set(key, { t: now, uuid: entry.uuid, own: true });
        save('entries');
        return show(true, '', pass);
      }
      if (r.status === 'duplicate') {
        const first = { t: r.first.scanned_at, by: r.first.by };
        S.entries.set(key, first);
        save('entries');
        return used(first);
      }
      if (r.status === 'revoked') return show(false, 'CANCELLED PASS', pass);
      if (r.status === 'invalid_day') return show(false, 'NOT VALID TODAY', pass);
      return show(false, 'UNKNOWN PASS', pass);
    } catch (err) {
      if (err.status === 401) S.needLogin = true;
      S.liveDownUntil = Date.now() + LIVE_BACKOFF;
      renderStatus();
    }
  }
  // no network: the signature and the local list are enough to let them in
  S.entries.set(key, { t: now, uuid: entry.uuid, own: true });
  S.queue.push(entry);
  save('entries');
  save('queue');
  show(true, '', pass, 'Saved on this device');
}

// ---------- manual lookup ----------
function findPasses(q) {
  const id = cleanId(q);
  const digits = q.replace(/\D/g, '');
  const byPhone = digits.length >= 6 && digits.length === q.replace(/[\s+-]/g, '').length;
  const hits = [];
  for (const p of S.passes.values()) {
    if (byPhone ? p.phone.endsWith(digits.slice(-10)) : p.id === id) hits.push(p);
    if (hits.length >= 10) break;
  }
  return hits;
}

function renderHits(hits, q) {
  const box = $('#hits');
  box.textContent = '';
  if (!hits.length) {
    box.textContent = `No pass found for "${q}"`;
    return;
  }
  for (const p of hits) {
    const row = document.createElement('div');
    row.className = 'hit';
    const info = document.createElement('div');
    info.textContent = `${p.name} - ${p.category} - ${p.persons} person(s) - ${prettyId(p.id)}${p.revoked ? ' - CANCELLED' : ''}`;
    const btn = document.createElement('button');
    btn.textContent = 'Check';
    btn.onclick = () => {
      box.textContent = '';
      $('#m-q').value = '';
      if (!busy) admit(p);
    };
    row.append(info, btn);
    box.append(row);
  }
}

// ---------- sync ----------
const save = (name) => store.set(name, S[name]).catch(() => {});
let syncing = false;

async function sync() {
  if (syncing || !S.boot) return;
  syncing = true;
  try {
    while (S.queue.length) {
      const batch = S.queue.slice(0, 200);
      await api('/api/scan/entries', { method: 'POST', body: { live: false, entries: batch } });
      S.queue = S.queue.slice(batch.length);
      await save('queue');
    }
    for (;;) {
      const out = await api(`/api/scan/sync?rev=${S.cursor.rev}&entry=${S.cursor.entry}`);
      for (const [id, name, phone, persons, category, from, to, revoked, rev] of out.passes) {
        S.passes.set(id, { id, name, phone, persons, category, from, to, revoked });
        S.cursor.rev = rev;
      }
      for (const [id, passId, day, t, uuid, by] of out.entries) {
        const key = `${passId}|${day}`;
        const cur = S.entries.get(key);
        if (!cur || (cur.uuid !== uuid && t < cur.t)) S.entries.set(key, { t, by, uuid });
        S.cursor.entry = id;
      }
      S.boot.settings = out.settings;
      if (out.passes.length) await save('passes');
      if (out.entries.length) await save('entries');
      await save('cursor');
      if (out.passes.length < 5000 && out.entries.length < 5000) break;
    }
    S.liveDownUntil = 0;
    S.needLogin = false;
  } catch (err) {
    if (err.status === 401) S.needLogin = true;
    S.liveDownUntil = Date.now() + LIVE_BACKOFF;
  } finally {
    syncing = false;
    renderStatus();
    renderCounts();
  }
}

function renderStatus() {
  const el = $('#status');
  const offline = Date.now() < S.liveDownUntil;
  el.hidden = false;
  el.textContent = S.needLogin ? 'LOGIN NEEDED' : offline ? 'OFFLINE - still working' : 'ONLINE';
  el.classList.toggle('offline', offline || S.needLogin);
  $('#pending').textContent = S.queue.length ? `${S.queue.length} waiting to upload` : '';
}

function renderCounts() {
  if (!S.boot) return;
  const suffix = `|${dayOf(Date.now())}`;
  let persons = 0;
  for (const key of S.entries.keys()) {
    if (key.endsWith(suffix)) persons += S.passes.get(key.slice(0, -suffix.length))?.persons || 1;
  }
  $('#count').textContent = `Today: ${persons} persons`;
}

// ---------- camera ----------
async function startCamera() {
  const video = $('#video');
  try {
    video.srcObject = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 } },
      audio: false,
    });
    await video.play();
  } catch {
    $('#cam-msg').textContent = 'Camera is not available. Allow camera permission for this page, or type the pass number below.';
    return;
  }
  let detector = null;
  if ('BarcodeDetector' in window && (await BarcodeDetector.getSupportedFormats()).includes('qr_code')) {
    detector = new BarcodeDetector({ formats: ['qr_code'] });
  }
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const tick = async () => {
    if (!busy && video.readyState >= 2 && video.videoWidth) {
      let text = '';
      try {
        if (detector) {
          text = (await detector.detect(video))[0]?.rawValue || '';
        } else {
          const scale = Math.min(1, 800 / video.videoWidth);
          canvas.width = video.videoWidth * scale;
          canvas.height = video.videoHeight * scale;
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          text = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' })?.data || '';
        }
      } catch { /* try again on the next frame */ }
      // ignore the code that is still in front of the camera right after a result
      if (text && !(text === lastText && Date.now() - lastAt < 4000)) await handleText(text);
    }
    setTimeout(tick, 120);
  };
  tick();
}

// ---------- startup ----------
function showLogin(message) {
  $('#gate').hidden = true;
  $('#login-wrap').hidden = false;
  $('#l-msg').textContent = message || '';
}

async function start() {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
  const [boot, passes, entries, queue, cursor] = await Promise.all(['boot', 'passes', 'entries', 'queue', 'cursor'].map((k) => store.get(k).catch(() => null)));
  if (boot) Object.assign(S, { boot, passes: passes || S.passes, entries: entries || S.entries, queue: queue || [], cursor: cursor || S.cursor });
  try {
    const fresh = await api('/api/scan/bootstrap', { timeout: 6000 });
    // a different server key means a different installation: local data no longer applies
    if (S.boot && JSON.stringify(S.boot.publicJwk) !== JSON.stringify(fresh.publicJwk)) {
      Object.assign(S, { passes: new Map(), entries: new Map(), queue: [], cursor: { rev: 0, entry: 0 } });
      await Promise.all(['passes', 'entries', 'queue', 'cursor'].map(save));
    }
    S.boot = fresh;
    await save('boot');
  } catch (err) {
    if (err.status === 401 || err.status === 403) return showLogin(err.status === 403 ? 'This login cannot use the gate scanner.' : '');
    if (!S.boot) return showLogin('No internet. Connect once to set up this device.');
    S.liveDownUntil = Date.now() + LIVE_BACKOFF;
  }
  S.key = await crypto.subtle.importKey('jwk', S.boot.publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  $('#login-wrap').hidden = true;
  $('#gate').hidden = false;
  $('#title').textContent = `${S.boot.settings.festival_name} - ${S.boot.user.name}`;
  renderStatus();
  renderCounts();
  startCamera();
  sync();
  setInterval(sync, SYNC_EVERY);
}

$('#login').onsubmit = async (e) => {
  e.preventDefault();
  try {
    await api('/api/login', { method: 'POST', body: { username: $('#l-user').value, password: $('#l-pass').value } });
    location.reload();
  } catch (err) {
    $('#l-msg').textContent = err.message;
  }
};
$('#manual').onsubmit = (e) => {
  e.preventDefault();
  const q = $('#m-q').value.trim();
  if (!q || busy) return;
  // a handheld barcode scanner types the whole QR text into this box
  if (q.includes('TP1.')) {
    $('#m-q').value = '';
    return handleText(q);
  }
  renderHits(findPasses(q), q);
};
$('#result').onclick = hideResult;
$('#status').onclick = () => {
  if (S.needLogin) showLogin('Please log in again.');
};
start();
