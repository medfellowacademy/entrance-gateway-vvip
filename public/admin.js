'use strict';
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const prettyId = (id) => `${id.slice(0, 5)}-${id.slice(5)}`;
const prettyDay = (d) => d.split('-').reverse().join('/');
const timeOf = (ms) => new Date(ms).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

async function api(url, { method = 'GET', body } = {}) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (res.status === 401 && url !== '/api/login') showLogin();
  if (!res.ok) throw new Error(json.error || `Error ${res.status}`);
  return json;
}

let me, settings, categories, tab;

const TABS = [
  { id: 'issue', label: 'Issue pass', roles: ['admin', 'issuer'], render: renderIssue },
  { id: 'bulk', label: 'Bulk upload', roles: ['admin', 'issuer'], render: renderBulk },
  { id: 'passes', label: 'All passes', roles: ['admin', 'issuer'], render: renderPasses },
  { id: 'entries', label: 'Gate entries', roles: ['admin'], render: renderEntries },
  { id: 'users', label: 'Users', roles: ['admin'], render: renderUsers },
  { id: 'settings', label: 'Settings', roles: ['admin'], render: renderSettings },
];

function showLogin() {
  $('#app').hidden = true;
  $('#logout').hidden = true;
  $('#who').textContent = '';
  $('#login').hidden = false;
}

async function start() {
  try {
    ({ user: me, settings, categories } = await api('/api/me'));
  } catch {
    return showLogin();
  }
  if (me.role === 'scanner') return location.replace('/scan');
  $('#login').hidden = true;
  $('#app').hidden = false;
  $('#logout').hidden = false;
  $('#title').textContent = `${settings.festival_name} - Pass Office`;
  $('#who').textContent = `${me.name} (${me.role})`;
  const tabs = TABS.filter((t) => t.roles.includes(me.role));
  $('#tabs').innerHTML = tabs.map((t) => `<button data-tab="${t.id}">${t.label}</button>`).join('');
  openTab(tabs[0].id);
}

function openTab(id) {
  tab = TABS.find((t) => t.id === id);
  for (const b of $('#tabs').children) b.classList.toggle('on', b.dataset.tab === id);
  tab.render();
  loadStats();
}

async function loadStats() {
  const s = await api('/api/stats');
  const total = s.issued.reduce((a, r) => ({ passes: a.passes + r.passes, persons: a.persons + r.persons }), { passes: 0, persons: 0 });
  const tiles = [`<div class="stat"><b>${total.persons}</b><span>Persons with passes (${total.passes} passes)</span></div>`];
  for (const r of s.issued) tiles.push(`<div class="stat"><b>${r.persons}</b><span>${esc(r.category)}</span></div>`);
  if (s.quota) tiles.push(`<div class="stat"><b>${s.quota.total - s.quota.used}</b><span>Your quota left (of ${s.quota.total})</span></div>`);
  if (s.days) {
    const t = s.days.find((d) => d.day === s.today);
    tiles.push(`<div class="stat"><b>${t ? t.persons : 0}</b><span>Entered today</span></div>`);
    tiles.push(`<div class="stat"><b>${s.days.reduce((a, d) => a + d.persons, 0)}</b><span>Entered so far</span></div>`);
    if (s.flagged) tiles.push(`<div class="stat"><b>${s.flagged}</b><span>Entries to review</span></div>`);
  }
  $('#stats').innerHTML = tiles.join('');
}

// ---------- pass helpers ----------
const passLink = (p) => `${location.origin}/p/${p.id}`;
function whatsappLink(p) {
  const text = `${settings.festival_name}\nSpecial entry pass for ${p.name} (${p.persons} ${p.persons === 1 ? 'person' : 'persons'}).\nShow this QR code at the special gate:\n${passLink(p)}`;
  const phone = p.phone.length === 10 ? `91${p.phone}` : p.phone;
  return `https://wa.me/${phone}?text=${encodeURIComponent(text)}`;
}
function passActions(p) {
  return `
    ${p.phone ? `<a class="btn wa small" target="_blank" rel="noopener" href="${esc(whatsappLink(p))}">WhatsApp</a>` : ''}
    <a class="btn ghost small" target="_blank" href="/p/${p.id}">Open / print</a>
    <button class="ghost small" data-copy="${esc(passLink(p))}">Copy link</button>`;
}
document.addEventListener('click', async (e) => {
  const copy = e.target.closest('[data-copy]');
  if (copy) {
    await navigator.clipboard.writeText(copy.dataset.copy);
    copy.textContent = 'Copied';
  }
});

// ---------- issue ----------
function passFields() {
  return `
    <div class="grid">
      <div><label>Name</label><input name="name" required maxlength="80"></div>
      <div><label>Mobile number</label><input name="phone" inputmode="numeric" placeholder="10 digits"></div>
      <div><label>Category</label><select name="category">${categories.map((c) => `<option>${c}</option>`).join('')}</select></div>
      <div><label>Persons (1 = single, more = family)</label><input name="persons" type="number" min="1" max="20" value="1" required></div>
      <div><label>Valid from</label><input name="valid_from" type="date" value="${settings.start_date}" required></div>
      <div><label>Valid to</label><input name="valid_to" type="date" value="${settings.end_date}" required></div>
      <div><label>Note (optional)</label><input name="note" maxlength="200" placeholder="e.g. referred by"></div>
    </div>`;
}

function renderIssue() {
  $('#view').innerHTML = `
    <form class="card" id="issue">
      <h2>Issue a pass</h2>
      ${passFields()}
      <div class="row" style="margin-top:12px"><button>Create pass</button></div>
      <div class="msg err" id="i-msg"></div>
    </form>
    <div id="issued"></div>`;
  $('#issue').onsubmit = async (e) => {
    e.preventDefault();
    const form = e.target;
    const body = Object.fromEntries(new FormData(form));
    body.persons = Number(body.persons);
    $('#i-msg').textContent = '';
    try {
      const { pass } = await api('/api/passes', { method: 'POST', body });
      $('#issued').insertAdjacentHTML('afterbegin', `
        <div class="card issued">
          <h2>Pass created: ${esc(pass.name)} <span class="tag ${pass.category}">${pass.category}</span></h2>
          <p>${pass.persons} ${pass.persons === 1 ? 'person' : 'persons'} &middot; ${prettyDay(pass.valid_from)} to ${prettyDay(pass.valid_to)} &middot;
             <span class="mono">${prettyId(pass.id)}</span></p>
          <div class="row">${passActions(pass)}</div>
        </div>`);
      form.name.value = form.phone.value = form.note.value = '';
      form.persons.value = 1;
      form.name.focus();
      loadStats();
    } catch (err) {
      $('#i-msg').textContent = err.message;
    }
  };
}

// ---------- bulk ----------
function renderBulk() {
  $('#view').innerHTML = `
    <form class="card" id="bulk">
      <h2>Bulk upload</h2>
      <p class="muted">One pass per line: <b>name, mobile, category, persons</b>. Category and persons are optional (default GUEST, 1).
        You can paste straight from Excel. All passes get the festival dates (${prettyDay(settings.start_date)} to ${prettyDay(settings.end_date)}).</p>
      <textarea id="b-text" placeholder="Ramesh Kumar, 9876543210, VIP, 4&#10;Lakshmi Devi, 9123456780"></textarea>
      <div class="row" style="margin-top:12px"><button>Create passes</button></div>
      <div class="msg" id="b-msg"></div>
    </form>`;
  $('#bulk').onsubmit = async (e) => {
    e.preventDefault();
    const rows = $('#b-text').value.split('\n').map((l) => l.trim()).filter(Boolean).map((line) => {
      const [name, phone, category, persons] = line.split(/\t|,/).map((c) => c.trim());
      return { name, phone, category: category || 'GUEST', persons: Number(persons || 1) };
    });
    const msg = $('#b-msg');
    if (!rows.length) return;
    try {
      const out = await api('/api/passes/bulk', { method: 'POST', body: { rows } });
      msg.className = out.errors.length ? 'msg err' : 'msg ok';
      msg.innerHTML = `${out.created} passes created.` +
        out.errors.map((x) => `<br>Line ${x.line}: ${esc(x.error)}`).join('') +
        (out.created ? '<br>Open "All passes" to send them on WhatsApp.' : '');
      loadStats();
    } catch (err) {
      msg.className = 'msg err';
      msg.textContent = err.message;
    }
  };
}

// ---------- pass list ----------
function renderPasses() {
  $('#view').innerHTML = `
    <div class="card">
      <div class="row"><input id="p-q" placeholder="Search name, mobile or pass number" style="flex:1"><button id="p-go">Search</button></div>
      <div class="scroll"><table><thead><tr><th>Name</th><th>Category</th><th>Persons</th><th>Valid</th><th>Pass no.</th><th>Issued by</th><th>Entered</th><th></th></tr></thead>
        <tbody id="p-rows"></tbody></table></div>
      <div class="row" style="margin-top:12px"><button class="ghost small" id="p-prev">Previous</button><span class="muted" id="p-info"></span><button class="ghost small" id="p-next">Next</button></div>
    </div>`;
  let page = 0;
  const load = async () => {
    const out = await api(`/api/passes?page=${page}&q=${encodeURIComponent($('#p-q').value)}`);
    $('#p-rows').innerHTML = out.passes.map((p) => `
      <tr>
        <td class="${p.revoked ? 'strike' : ''}">${esc(p.name)}<div class="muted">${esc(p.phone)}${p.note ? ` &middot; ${esc(p.note)}` : ''}</div></td>
        <td>${p.revoked ? '<span class="tag off">CANCELLED</span>' : `<span class="tag ${p.category}">${p.category}</span>`}</td>
        <td>${p.persons}</td>
        <td>${prettyDay(p.valid_from)}${p.valid_to !== p.valid_from ? `<br>${prettyDay(p.valid_to)}` : ''}</td>
        <td class="mono">${prettyId(p.id)}</td>
        <td>${esc(p.issuer)}</td>
        <td>${p.entered ? `${p.entered} day(s)` : '-'}</td>
        <td><div class="row">${p.revoked ? '' : passActions(p)}
          <button class="ghost small" data-act="${p.revoked ? 'restore' : 'revoke'}" data-id="${p.id}">${p.revoked ? 'Restore' : 'Cancel pass'}</button></div></td>
      </tr>`).join('') || '<tr><td colspan="8" class="muted">No passes found.</td></tr>';
    $('#p-info').textContent = out.total ? `${page * 50 + 1}-${page * 50 + out.passes.length} of ${out.total}` : '';
    $('#p-prev').disabled = page === 0;
    $('#p-next').disabled = (page + 1) * 50 >= out.total;
  };
  $('#p-go').onclick = () => { page = 0; load(); };
  $('#p-q').onkeydown = (e) => { if (e.key === 'Enter') { page = 0; load(); } };
  $('#p-prev').onclick = () => { page--; load(); };
  $('#p-next').onclick = () => { page++; load(); };
  $('#p-rows').onclick = async (e) => {
    const b = e.target.closest('[data-act]');
    if (!b) return;
    if (b.dataset.act === 'revoke' && !confirm('Cancel this pass? It will be refused at the gate.')) return;
    try {
      await api(`/api/passes/${b.dataset.id}/${b.dataset.act}`, { method: 'POST' });
    } catch (err) {
      alert(err.message);
    }
    load();
    loadStats();
  };
  load();
}

// ---------- entries ----------
const FLAGS = { duplicate: 'Used twice', revoked: 'Cancelled pass', unknown: 'Unknown pass', invalid_day: 'Wrong day' };
function renderEntries() {
  $('#view').innerHTML = `
    <div class="card">
      <div class="row"><label style="margin:0">Day</label><input type="date" id="e-day" style="width:auto"><button class="ghost small" id="e-go">Refresh</button>
        <span class="muted" id="e-sum"></span></div>
      <div class="scroll"><table><thead><tr><th>Time</th><th>Name</th><th>Category</th><th>Persons</th><th>Pass no.</th><th>Device</th><th></th></tr></thead>
        <tbody id="e-rows"></tbody></table></div>
    </div>`;
  const load = async () => {
    const day = $('#e-day').value;
    const out = await api(`/api/entries${day ? `?day=${day}` : ''}`);
    $('#e-day').value = out.day;
    const good = out.entries.filter((x) => !x.flag);
    $('#e-sum').textContent = `${good.reduce((a, x) => a + x.persons, 0)} persons on ${good.length} passes`;
    $('#e-rows').innerHTML = out.entries.map((x) => `
      <tr>
        <td>${timeOf(x.scanned_at)}</td>
        <td>${esc(x.name || '?')}</td>
        <td>${x.category ? `<span class="tag ${x.category}">${x.category}</span>` : ''}</td>
        <td>${x.persons}</td>
        <td class="mono">${prettyId(x.pass_id)}</td>
        <td>${esc(x.scanner)}${x.offline ? ' <span class="muted">(offline)</span>' : ''}</td>
        <td>${x.flag ? `<span class="tag bad">${FLAGS[x.flag] || esc(x.flag)}</span>` : ''}</td>
      </tr>`).join('') || '<tr><td colspan="7" class="muted">No entries on this day.</td></tr>';
  };
  $('#e-go').onclick = load;
  $('#e-day').onchange = load;
  load();
}

// ---------- users ----------
function renderUsers() {
  $('#view').innerHTML = `
    <form class="card" id="u-new">
      <h2>Add a user</h2>
      <div class="grid">
        <div><label>Name</label><input name="name" required></div>
        <div><label>Username</label><input name="username" required autocomplete="off"></div>
        <div><label>Password</label><input name="password" required minlength="6" autocomplete="new-password"></div>
        <div><label>Role</label><select name="role">
          <option value="issuer">Issuer - committee member who gives passes</option>
          <option value="scanner">Scanner - gate device</option>
          <option value="admin">Admin - full control</option></select></div>
        <div><label>Quota (persons, issuers only)</label><input name="quota" type="number" min="0" value="100"></div>
      </div>
      <div class="row" style="margin-top:12px"><button>Add user</button></div>
      <div class="msg err" id="u-msg"></div>
    </form>
    <div class="card"><div class="scroll"><table><thead><tr><th>Name</th><th>Username</th><th>Role</th><th>Quota used</th><th></th></tr></thead><tbody id="u-rows"></tbody></table></div></div>`;
  const load = async () => {
    const { users } = await api('/api/users');
    $('#u-rows').innerHTML = users.map((u) => `
      <tr>
        <td class="${u.active ? '' : 'strike'}">${esc(u.name)}</td>
        <td class="mono">${esc(u.username)}</td>
        <td>${u.role}</td>
        <td>${u.role === 'issuer' ? `${u.used} / ${u.quota}` : u.role === 'admin' ? `${u.used}` : '-'}</td>
        <td><div class="row">
          ${u.role === 'issuer' ? `<button class="ghost small" data-do="quota" data-id="${u.id}" data-cur="${u.quota}">Change quota</button>` : ''}
          <button class="ghost small" data-do="password" data-id="${u.id}">New password</button>
          ${u.id === me.id ? '' : `<button class="ghost small" data-do="active" data-id="${u.id}" data-cur="${u.active}">${u.active ? 'Disable' : 'Enable'}</button>`}
        </div></td>
      </tr>`).join('');
  };
  $('#u-new').onsubmit = async (e) => {
    e.preventDefault();
    $('#u-msg').textContent = '';
    try {
      await api('/api/users', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) });
      e.target.reset();
      load();
    } catch (err) {
      $('#u-msg').textContent = err.message;
    }
  };
  $('#u-rows').onclick = async (e) => {
    const b = e.target.closest('[data-do]');
    if (!b) return;
    let body;
    if (b.dataset.do === 'quota') {
      const v = prompt('New quota (number of persons)', b.dataset.cur);
      if (v === null) return;
      body = { quota: Number(v) };
    } else if (b.dataset.do === 'password') {
      const v = prompt('New password (at least 6 characters)');
      if (!v) return;
      body = { password: v };
    } else {
      body = { active: b.dataset.cur !== '1' };
    }
    try {
      await api(`/api/users/${b.dataset.id}`, { method: 'PATCH', body });
    } catch (err) {
      alert(err.message);
    }
    load();
  };
  load();
}

// ---------- settings ----------
function renderSettings() {
  $('#view').innerHTML = `
    <form class="card" id="s-form">
      <h2>Festival settings</h2>
      <div class="grid">
        <div><label>Festival name (shown on every pass)</label><input name="festival_name" value="${esc(settings.festival_name)}" required></div>
        <div><label>First day</label><input name="start_date" type="date" value="${settings.start_date}" required></div>
        <div><label>Last day</label><input name="end_date" type="date" value="${settings.end_date}" required></div>
      </div>
      <div class="row" style="margin-top:12px"><button>Save</button></div>
      <div class="msg" id="s-msg"></div>
      <p class="muted">New passes use these dates by default. Passes already issued keep their own dates.</p>
    </form>
    <div class="card"><h2>Gate devices</h2>
      <p>On each gate phone open <a href="/scan">${esc(location.origin)}/scan</a> and log in with a Scanner user. Do this once while the phone has internet; after that it keeps working without network.</p></div>`;
  $('#s-form').onsubmit = async (e) => {
    e.preventDefault();
    const msg = $('#s-msg');
    try {
      ({ settings } = await api('/api/settings', { method: 'PUT', body: Object.fromEntries(new FormData(e.target)) }));
      msg.className = 'msg ok';
      msg.textContent = 'Saved';
      $('#title').textContent = `${settings.festival_name} - Pass Office`;
    } catch (err) {
      msg.className = 'msg err';
      msg.textContent = err.message;
    }
  };
}

// ---------- wiring ----------
$('#tabs').onclick = (e) => {
  if (e.target.dataset.tab) openTab(e.target.dataset.tab);
};
$('#login').onsubmit = async (e) => {
  e.preventDefault();
  $('#l-msg').textContent = '';
  try {
    await api('/api/login', { method: 'POST', body: { username: $('#l-user').value, password: $('#l-pass').value } });
    $('#l-pass').value = '';
    start();
  } catch (err) {
    $('#l-msg').textContent = err.message;
  }
};
$('#logout').onclick = async () => {
  await api('/api/logout', { method: 'POST' });
  showLogin();
};
start();
