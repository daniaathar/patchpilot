/* PatchPilot frontend (Dania). One file shared by all 5 screens.
 * Switch at the top: true = read mock JSON files, false = call Rida's real API.
 * Safety rule: server text is only ever put on the page with textContent (never innerHTML). */
const USE_MOCK = true;

const API_BASE = '/api';
const MOCK_TODAY = '2026-11-06'; // fixed date so mock numbers always match the screenshots
const MAX_UPLOAD = 1024 * 1024;  // 1 MB
const ACTIVE = ['open', 'in_progress', 'reopened'];
const DEFAULT_CONFIG = {
  slaDays: { Critical: 7, High: 14, Medium: 30, Low: 90 },
  weights: { cvss: 6, internetFacing: 10, assetPoints: { low: 0, medium: 10, high: 20, critical: 30 } },
};

/* ---------- friendly error messages (never show raw server text) ---------- */
const FRIENDLY = {
  E_AUTH: 'Please sign in to continue. Your session may have expired.',
  E_FORBIDDEN: 'You do not have permission to do that.',
  E_VALIDATION: 'Some of the information is not valid. Please check it and try again.',
  E_TOO_BIG: 'That file is too large. The maximum size is 1 MB.',
  E_RATE: 'Too many tries. Please wait a minute and try again.',
  E_SERVER: 'Something went wrong on our side. Please try again later.',
};
function friendly(code) { return FRIENDLY[code] || FRIENDLY.E_SERVER; }

/* ---------- tiny DOM helpers (textContent only) ---------- */
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  kids.flat().forEach(c => e.append(c instanceof Node ? c : document.createTextNode(String(c))));
  return e;
}
const $ = id => document.getElementById(id);
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

function showMessage(text, kind) {
  const box = $('message');
  if (!box) return;
  clear(box);
  if (text) box.append(h('div', { class: 'msg ' + (kind || 'error'), text }));
}
function showError(err) {
  const code = err && err.code ? err.code : 'E_SERVER';
  if (code === 'E_AUTH' && document.body.dataset.page !== 'login') {
    sessionStorage.removeItem('pp_user');
    sessionStorage.setItem('pp_flash', friendly('E_AUTH'));
    location.href = 'index.html';
    return;
  }
  showMessage(friendly(code), 'error');
}

/* ---------- confirmation dialog ("Are you sure?") ---------- */
function confirmAction(text) {
  const dlg = $('confirm');
  if (!dlg || typeof dlg.showModal !== 'function') return Promise.resolve(window.confirm(text));
  $('confirm-text').textContent = text;
  return new Promise(resolve => {
    dlg.addEventListener('close', () => resolve(dlg.returnValue === 'yes'), { once: true });
    dlg.returnValue = 'no';
    dlg.showModal();
  });
}

/* ---------- session ---------- */
function getUser() { try { return JSON.parse(sessionStorage.getItem('pp_user')); } catch (e) { return null; } }
function requireLogin() {
  const u = getUser();
  if (!u) { location.href = 'index.html'; return null; }
  return u;
}
const canWork = u => u && (u.role === 'analyst' || u.role === 'admin');

function buildHeader(user) {
  const top = $('top');
  if (!top) return;
  const page = document.body.dataset.page;
  const link = (href, label, key) => h('a', { href, 'aria-current': page === key ? 'page' : null, text: label });
  const nav = h('nav', { 'aria-label': 'Main' }, link('dashboard.html', 'Dashboard', 'dashboard'));
  if (canWork(user)) nav.append(link('import.html', 'Import', 'import'));
  nav.append(link('admin.html', 'Admin', 'admin'));
  const out = h('button', { type: 'button', class: 'secondary', text: 'Log out' });
  out.addEventListener('click', async () => {
    try { await api('POST', '/logout'); } catch (e) { /* ignore */ }
    sessionStorage.clear();
    location.href = 'index.html';
  });
  clear(top);
  top.append(h('span', { class: 'brand', text: 'PatchPilot' }), nav,
    h('div', { class: 'who' }, h('span', { text: user.username + ' (' + user.role + ')' }), out));
}

/* ---------- date + score helpers (used by mock mode and display) ---------- */
function todayStr() { return USE_MOCK ? MOCK_TODAY : new Date().toISOString().slice(0, 10); }
function addDays(s, n) { const d = new Date(s + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); }
function isOverdue(f) { return ACTIVE.includes(f.status) && f.dueDate && todayStr() > f.dueDate; }
function priorityOf(score) { return score >= 80 ? 'Critical' : score >= 60 ? 'High' : score >= 40 ? 'Medium' : 'Low'; }
function scoreWith(f, cfg) {
  const w = cfg.weights;
  const base = f.cvss * w.cvss, ap = w.assetPoints[f.assetCriticality] || 0, ip = f.internetFacing ? w.internetFacing : 0;
  const score = Math.min(100, Math.round((base + ap + ip) * 10) / 10);
  const priority = priorityOf(score);
  const cap = s => s[0].toUpperCase() + s.slice(1);
  return { score, priority, reasons: [
    `CVSS ${f.cvss} gives ${Math.round(base * 10) / 10} points`,
    `${cap(f.assetCriticality)} asset adds ${ap}`,
    f.internetFacing ? `Internet facing adds ${ip}` : 'Not internet facing adds 0',
    `Total ${score} means ${priority} (rule v1)`,
  ] };
}
const pretty = s => String(s).replace(/_/g, ' ');

/* ================= MOCK BACKEND (only used when USE_MOCK = true) ================= */
const mock = {
  async load(key, file) {
    const saved = sessionStorage.getItem(key);
    if (saved) return JSON.parse(saved);
    const res = await fetch('mock/' + file);
    const data = await res.json();
    sessionStorage.setItem(key, JSON.stringify(data));
    return data;
  },
  save(key, data) { sessionStorage.setItem(key, JSON.stringify(data)); },
  config() { const c = sessionStorage.getItem('pp_config'); return c ? JSON.parse(c) : JSON.parse(JSON.stringify(DEFAULT_CONFIG)); },
  async log(user, action, result, details) {
    const audit = await mock.load('pp_audit', 'audit.json');
    audit.push({ id: audit.length + 1, time: new Date().toISOString(), user, action, result, details });
    mock.save('pp_audit', audit);
  },
  fail(code) { const e = new Error(code); e.code = code; return e; },
  metrics(list) {
    const byPriority = {}, byOwner = {};
    list.forEach(f => { byPriority[f.priority] = (byPriority[f.priority] || 0) + 1; byOwner[f.owner] = (byOwner[f.owner] || 0) + 1; });
    const tracked = list.filter(f => !['false_positive', 'accepted_risk'].includes(f.status));
    const ok = tracked.filter(f => !isOverdue(f)).length;
    return {
      total: list.length, open: list.filter(f => ACTIVE.includes(f.status)).length,
      overdue: list.filter(isOverdue).length, byPriority, byOwner,
      slaPercent: tracked.length ? Math.round((ok / tracked.length) * 1000) / 10 : 100,
      avgDaysToFix: 12, reopenRate: 0.5,
    };
  },
  parseCsv(text) {
    const lines = text.split(/\r?\n/).filter(l => l.trim() !== '');
    if (!lines.length) return [];
    const split = line => { const out = []; let cur = '', q = false;
      for (const ch of line) { if (ch === '"') q = !q; else if (ch === ',' && !q) { out.push(cur); cur = ''; } else cur += ch; }
      out.push(cur); return out.map(s => s.trim()); };
    const head = split(lines[0]);
    return lines.slice(1).map(l => { const c = split(l); const o = {}; head.forEach((k, i) => { o[k] = c[i]; }); return o; });
  },
  async importFile(file, user) {
    const text = await file.text();
    let rows;
    try { rows = file.name.toLowerCase().endsWith('.json') ? JSON.parse(text) : mock.parseCsv(text); }
    catch (e) { throw mock.fail('E_VALIDATION'); }
    if (!Array.isArray(rows) || rows.length === 0) throw mock.fail('E_VALIDATION');
    const req = ['title', 'cve', 'cvss', 'asset', 'assetCriticality', 'scanner'];
    const errors = [], seen = new Map(), duplicates = [];
    let imported = 0;
    rows.forEach((r, i) => {
      const n = i + 1, bad = (code, message) => errors.push({ row: n, code, message });
      const missing = req.filter(k => r[k] === undefined || r[k] === null || String(r[k]).trim() === '');
      if (missing.length) return bad('E_MISSING', 'Missing field: ' + missing.join(', '));
      const cvss = Number(r.cvss);
      if (!(cvss >= 0 && cvss <= 10)) return bad('E_CVSS_RANGE', 'cvss out of range (must be 0 to 10)');
      if (!['low', 'medium', 'high', 'critical'].includes(String(r.assetCriticality).toLowerCase())) return bad('E_CRITICALITY', 'assetCriticality must be low, medium, high or critical');
      if (/^[=+\-@]/.test(String(r.title).trim())) return bad('E_FORMULA', 'title starts with a dangerous character (= + - @)');
      const key = String(r.cve).toLowerCase() + '|' + String(r.asset).toLowerCase();
      if (seen.has(key)) { duplicates.push({ finding: r.cve + ' on ' + r.asset, matchedId: 'row ' + seen.get(key), reason: `Same ${r.cve} on ${r.asset} already exists` }); return; }
      seen.set(key, n); imported++;
    });
    await mock.log(user.username, 'import', errors.length ? 'failure' : 'success',
      `${file.name}: ${imported} imported, ${duplicates.length} duplicates, ${errors.length} errors`);
    return { imported, duplicates, errors };
  },
  async handle(method, path, body, user) {
    const role = user ? user.role : null;
    if (path === '/login') {
      const name = String(body.username || '').toLowerCase();
      if (!['admin', 'analyst', 'viewer'].includes(name) || !body.password) {
        await mock.log('unknown', 'login', 'failure', 'Failed login for username ' + name.slice(0, 20));
        throw mock.fail('E_AUTH');
      }
      await mock.log(name, 'login', 'success', 'Login ok');
      return { user: { username: name, role: name } };
    }
    if (path === '/logout') { if (user) await mock.log(user.username, 'logout', 'success', 'Logout'); return { ok: true }; }
    if (!user) throw mock.fail('E_AUTH');

    let findings = await mock.load('pp_findings', 'findings.json');
    if (method === 'GET' && path === '/findings') {
      return role === 'viewer' ? findings.map(({ history, scanner, reasons, ...rest }) => rest) : findings;
    }
    let m = path.match(/^\/findings\/(F-\d+)$/);
    if (method === 'GET' && m) {
      const f = findings.find(x => x.id === m[1]);
      if (!f) throw mock.fail('E_VALIDATION');
      if (role === 'viewer') { const { history, scanner, ...rest } = f; return rest; }
      return f;
    }
    if (method === 'GET' && path === '/metrics') return mock.metrics(findings);
    if (method === 'GET' && path === '/audit') {
      if (role !== 'admin') { await mock.log(user.username, 'access_admin', 'denied', `${user.role} tried GET /api/audit`); throw mock.fail('E_FORBIDDEN'); }
      return mock.load('pp_audit', 'audit.json');
    }
    if (method === 'GET' && path === '/config') return mock.config();
    if (method === 'PUT' && path === '/config') {
      if (role !== 'admin') { await mock.log(user.username, 'access_admin', 'denied', `${user.role} tried PUT /api/config`); throw mock.fail('E_FORBIDDEN'); }
      const old = mock.config(), cfg = body;
      sessionStorage.setItem('pp_config', JSON.stringify(cfg));
      findings.forEach(f => {
        if (f.status === 'fixed') return;
        const r = scoreWith(f, cfg);
        f.priorityScore = r.score; f.priority = r.priority; f.reasons = r.reasons.concat(f.reasons.slice(4));
        if (f.status !== 'reopened') f.dueDate = addDays(f.firstSeen, cfg.slaDays[r.priority]);
      });
      mock.save('pp_findings', findings);
      const changes = Object.keys(cfg.slaDays).filter(k => cfg.slaDays[k] !== old.slaDays[k]).map(k => `${k} SLA days ${old.slaDays[k]} to ${cfg.slaDays[k]}`);
      await mock.log(user.username, 'config_change', 'success', changes.join('; ') || 'Rules saved');
      return { ok: true };
    }
    if (method === 'GET' && path === '/export') return mock.csv(findings);
    if (method === 'POST' && path === '/import') {
      if (!canWork(user)) throw mock.fail('E_FORBIDDEN');
      return mock.importFile(body.get('file'), user);
    }
    m = path.match(/^\/findings\/(F-\d+)\/(status|retest)$/);
    if (method === 'POST' && m) {
      if (!canWork(user)) throw mock.fail('E_FORBIDDEN');
      const f = findings.find(x => x.id === m[1]);
      if (!f) throw mock.fail('E_VALIDATION');
      const now = new Date().toISOString();
      if (m[2] === 'status') {
        const a = body.action, reason = String(body.reason || '').trim();
        if (a === 'accept_risk' && role !== 'admin') throw mock.fail('E_FORBIDDEN');
        if (['accept_risk', 'mark_false_positive'].includes(a) && !reason) throw mock.fail('E_VALIDATION');
        if (a === 'accept_risk' && !body.endDate) throw mock.fail('E_VALIDATION');
        const next = { start_work: 'in_progress', accept_risk: 'accepted_risk', mark_false_positive: 'false_positive', mark_fixed: f.status }[a];
        if (!next) throw mock.fail('E_VALIDATION');
        f.status = next;
        f.history.push({ action: a, user: user.username, time: now, note: a === 'accept_risk' ? `Accepted until ${body.endDate}: ${reason}` : (reason || pretty(a)) });
        await mock.log(user.username, 'status_change', 'success', `${f.id} ${a}`);
      } else {
        const ev = String(body.evidence || '').trim().slice(0, 500);
        if (!ev || !['pass', 'fail'].includes(body.result)) throw mock.fail('E_VALIDATION');
        const cfg = mock.config();
        if (body.result === 'pass') f.status = 'fixed';
        else { f.status = 'reopened'; f.dueDate = addDays(todayStr(), cfg.slaDays[f.priority]); }
        f.history.push({ action: 'retest_' + body.result, user: user.username, time: now, note: ev });
        await mock.log(user.username, 'retest', 'success', `${f.id} retest ${body.result}${body.result === 'fail' ? ', reopened' : ''}`);
      }
      mock.save('pp_findings', findings);
      return f;
    }
    throw mock.fail('E_SERVER');
  },
  csv(list) {
    const cols = ['id', 'title', 'cve', 'cvss', 'asset', 'priority', 'priorityScore', 'status', 'owner', 'dueDate'];
    const safe = v => { let s = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
    return cols.join(',') + '\n' + list.map(f => cols.map(c => safe(f[c])).join(',')).join('\n') + '\n';
  },
};

/* ================= API wrapper ================= */
async function api(method, path, body) {
  const user = getUser();
  if (USE_MOCK) {
    try { return await mock.handle(method, path, body, user); }
    catch (e) { if (e.code) throw e; console.error(e); throw Object.assign(new Error('E_SERVER'), { code: 'E_SERVER' }); }
  }
  const opts = { method, credentials: 'same-origin', headers: {} };
  const csrf = sessionStorage.getItem('pp_csrf');
  if (csrf && method !== 'GET') opts.headers['X-CSRF-Token'] = csrf;
  if (body instanceof FormData) opts.body = body;
  else if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(API_BASE + path, opts); } catch (e) { throw Object.assign(new Error('E_SERVER'), { code: 'E_SERVER' }); }
  const type = res.headers.get('content-type') || '';
  const data = type.includes('json') ? await res.json().catch(() => ({})) : await res.text();
  if (!res.ok) throw Object.assign(new Error('api'), { code: (data && data.error) || 'E_SERVER' });
  return data;
}

/* ================= shared rendering ================= */
function priorityBadge(p) { return h('span', { class: 'badge b-' + p, text: p }); }
function statusBadge(s) { return h('span', { class: 'badge b-status', text: pretty(s) }); }
function listOf(data) { return Array.isArray(data) ? data : (data && (data.findings || data.items)) || []; }

/* ================= PAGES ================= */
const pages = {};

pages.login = function () {
  const flash = sessionStorage.getItem('pp_flash');
  if (flash) { showMessage(flash, 'warn'); sessionStorage.removeItem('pp_flash'); }
  if (USE_MOCK) $('mock-hint').textContent = 'Demo mode: sign in as admin, analyst or viewer (any password).';
  $('login-form').addEventListener('submit', async e => {
    e.preventDefault();
    showMessage('');
    try {
      const res = await api('POST', '/login', { username: $('username').value.trim(), password: $('password').value });
      const u = res.user || res;
      sessionStorage.setItem('pp_user', JSON.stringify({ username: u.username, role: u.role }));
      if (res.csrfToken) sessionStorage.setItem('pp_csrf', res.csrfToken);
      location.href = 'dashboard.html';
    } catch (err) { $('password').value = ''; showError(err); }
  });
};

pages.dashboard = async function (user) {
  let findings = [], metrics = null, charts = [];
  try { [findings, metrics] = await Promise.all([api('GET', '/findings').then(listOf), api('GET', '/metrics')]); }
  catch (err) { return showError(err); }

  const fill = (id, values) => [...new Set(values)].sort().forEach(v => $(id).append(h('option', { value: v, text: pretty(v) })));
  fill('f-status', findings.map(f => f.status));
  fill('f-priority', findings.map(f => f.priority));
  fill('f-owner', findings.map(f => f.owner));

  $('m-total').textContent = metrics.total;
  $('m-open').textContent = metrics.open;
  $('m-overdue').textContent = metrics.overdue;
  $('m-sla').textContent = metrics.slaPercent + '%';

  function drawCharts() {
    if (typeof Chart === 'undefined') return;
    charts.forEach(c => c.destroy());
    const colors = { Critical: '#b3261e', High: '#c25a00', Medium: '#d4a017', Low: '#2e6b34' };
    const order = ['Critical', 'High', 'Medium', 'Low'].filter(k => metrics.byPriority[k]);
    const statusCount = {};
    findings.forEach(f => { statusCount[f.status] = (statusCount[f.status] || 0) + 1; });
    charts = [
      new Chart($('chart-priority'), { type: 'doughnut',
        data: { labels: order, datasets: [{ data: order.map(k => metrics.byPriority[k]), backgroundColor: order.map(k => colors[k]) }] },
        options: { maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } } }),
      new Chart($('chart-status'), { type: 'bar',
        data: { labels: Object.keys(statusCount).map(pretty), datasets: [{ label: 'Findings', data: Object.values(statusCount), backgroundColor: '#1f4fd8' }] },
        options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } }),
    ];
  }
  drawCharts();

  function render() {
    const s = $('f-status').value, p = $('f-priority').value, o = $('f-owner').value;
    const q = $('f-search').value.trim().toLowerCase(), od = $('f-overdue').checked;
    const list = findings.filter(f =>
      (!s || f.status === s) && (!p || f.priority === p) && (!o || f.owner === o) && (!od || isOverdue(f)) &&
      (!q || [f.title, f.cve, f.asset, f.id].some(x => String(x || '').toLowerCase().includes(q))))
      .sort((a, b) => b.priorityScore - a.priorityScore);
    $('count').textContent = `Showing ${list.length} of ${findings.length} findings`;
    const body = $('rows'); clear(body);
    if (!list.length) body.append(h('tr', {}, h('td', { colspan: 8, class: 'muted', text: 'No findings match these filters.' })));
    list.forEach(f => {
      const od2 = isOverdue(f);
      const due = h('td', {}, f.dueDate || '-');
      if (od2) due.append(' ', h('span', { class: 'badge b-overdue', text: 'overdue' }));
      body.append(h('tr', { class: od2 ? 'overdue' : '' },
        h('td', {}, h('a', { href: 'detail.html?id=' + encodeURIComponent(f.id), text: f.id })),
        h('td', { text: f.title }), h('td', { text: f.asset }),
        h('td', {}, priorityBadge(f.priority)), h('td', { text: f.priorityScore }),
        h('td', {}, statusBadge(f.status)), h('td', { text: f.owner }), due));
    });
  }
  ['f-status', 'f-priority', 'f-owner'].forEach(id => $(id).addEventListener('change', render));
  $('f-search').addEventListener('input', render);
  $('f-overdue').addEventListener('change', render);
  render();

  if (canWork(user)) {
    const btn = h('button', { type: 'button', text: 'Export sanitized CSV' });
    btn.addEventListener('click', async () => {
      showMessage('');
      try {
        if (USE_MOCK) {
          const csv = await api('GET', '/export');
          const a = h('a', { href: URL.createObjectURL(new Blob([csv], { type: 'text/csv' })), download: 'patchpilot_report.csv' });
          document.body.append(a); a.click(); a.remove();
        } else {
          const res = await fetch(API_BASE + '/export', { credentials: 'same-origin' });
          if (!res.ok) { const d = await res.json().catch(() => ({})); throw Object.assign(new Error('x'), { code: d.error || 'E_SERVER' }); }
          const a = h('a', { href: URL.createObjectURL(await res.blob()), download: 'patchpilot_report.csv' });
          document.body.append(a); a.click(); a.remove();
        }
        showMessage('Report downloaded.', 'ok');
      } catch (err) { showError(err); }
    });
    $('export-row').append(btn);
  }
};

pages.import = function (user) {
  if (!canWork(user)) { $('import-form').closest('section').hidden = true; return showMessage(friendly('E_FORBIDDEN'), 'error'); }
  $('import-form').addEventListener('submit', async e => {
    e.preventDefault();
    showMessage(''); $('result').hidden = true;
    const file = $('file').files[0];
    if (!file) return showMessage(friendly('E_VALIDATION'));
    if (!/\.(csv|json)$/i.test(file.name)) return showMessage(friendly('E_VALIDATION'));
    if (file.size > MAX_UPLOAD) return showMessage(friendly('E_TOO_BIG'));
    const fd = new FormData(); fd.append('file', file);
    $('import-btn').disabled = true;
    try {
      const res = await api('POST', '/import', fd);
      const errors = res.errors || [], dups = res.duplicates || [];
      const count = res.imported != null ? res.imported : (res.valid || res.unique || []).length;
      $('result').hidden = false;
      const sum = $('result-summary'); clear(sum);
      sum.append(h('div', { class: 'msg ' + (errors.length ? 'error' : 'ok'),
        text: errors.length ? `Import found ${errors.length} problem(s). ${count} row(s) were accepted.` : `Import complete: ${count} finding(s) added.` }));
      if (dups.length) sum.append(h('p', { text: `${dups.length} duplicate(s) were removed.` }));
      const eb = $('errors'); clear(eb); $('errors-wrap').hidden = !errors.length;
      errors.forEach(er => eb.append(h('tr', {}, h('td', { text: er.row }), h('td', { text: er.code }), h('td', { text: er.message }))));
      const db = $('dups'); clear(db); $('dups-wrap').hidden = !dups.length;
      dups.forEach(d => db.append(h('tr', {}, h('td', { text: typeof d.finding === 'object' ? (d.finding.cve + ' on ' + d.finding.asset) : d.finding }),
        h('td', { text: d.matchedId }), h('td', { text: d.reason }))));
    } catch (err) { showError(err); }
    finally { $('import-btn').disabled = false; }
  });
};

pages.detail = async function (user) {
  const id = new URLSearchParams(location.search).get('id') || '';
  if (!/^F-\d{4,}$/.test(id)) return showMessage(friendly('E_VALIDATION'));
  let f;
  try { f = await api('GET', '/findings/' + id); } catch (err) { return showError(err); }

  $('title').textContent = `${f.id}: ${f.title}`;
  const sum = $('summary'); clear(sum);
  [['CVE', f.cve], ['CVSS', f.cvss], ['Asset', f.asset], ['Asset criticality', f.assetCriticality],
   ['Internet facing', f.internetFacing === undefined ? '-' : (f.internetFacing ? 'Yes' : 'No')], ['Scanner', f.scanner],
   ['First seen', f.firstSeen], ['Owner', f.owner]].forEach(([k, v]) => {
    if (v === undefined) return;
    sum.append(h('dt', { text: k }), h('dd', { text: v }));
  });
  sum.append(h('dt', { text: 'Priority' }), h('dd', {}, priorityBadge(f.priority), ' score ' + f.priorityScore));
  sum.append(h('dt', { text: 'Status' }), h('dd', {}, statusBadge(f.status)));

  const rs = $('reasons'); clear(rs);
  (f.reasons || ['Details are hidden for your role.']).forEach(r => rs.append(h('li', { text: r })));
  const od = isOverdue(f);
  $('deadline').textContent = f.dueDate
    ? `Due ${f.dueDate}` + (od ? ' (overdue)' : ACTIVE.includes(f.status) ? '' : ' (clock paused or finished)') : 'No deadline';
  if (od) $('deadline').classList.add('b-overdue');

  const hs = $('history'); clear(hs);
  (f.history || []).slice().reverse().forEach(ev => hs.append(h('li', {},
    h('strong', { text: pretty(ev.action) }), ` by ${ev.user} at ${String(ev.time).replace('T', ' ').slice(0, 16)}`,
    h('div', { class: 'muted', text: ev.note || '' }))));
  if (!(f.history || []).length) hs.append(h('li', { class: 'muted', text: 'No history available for your role.' }));

  if (!canWork(user)) return;
  const isActive = ACTIVE.includes(f.status);
  if (!isActive) return;

  $('actions-card').hidden = false;
  $('retest-card').hidden = false;
  const acts = $('actions'); clear(acts);
  let pending = null;
  const doStatus = async (action, extra) => {
    showMessage('');
    try { await api('POST', `/findings/${id}/status`, Object.assign({ action }, extra || {})); location.reload(); }
    catch (err) { showError(err); }
  };
  const addBtn = (label, cls, fn) => { const b = h('button', { type: 'button', class: cls || '', text: label }); b.addEventListener('click', fn); acts.append(b); };
  if (f.status !== 'in_progress') addBtn('Start work', '', () => doStatus('start_work'));
  addBtn('Mark fixed (send to retest)', 'secondary', () => doStatus('mark_fixed', { reason: 'Fix applied, waiting for retest' }));
  addBtn('Mark false positive', 'secondary', () => openReason('mark_false_positive', 'Why is this a false positive?', false));
  if (user.role === 'admin') addBtn('Accept risk', 'danger', () => openReason('accept_risk', 'Why is the risk accepted?', true));

  function openReason(action, label, needsDate) {
    pending = action;
    $('reason-label').textContent = label;
    $('end-date-field').hidden = !needsDate;
    $('end-date').required = needsDate;
    $('reason-form').hidden = false;
    $('reason-text').focus();
  }
  $('reason-cancel').addEventListener('click', () => { $('reason-form').hidden = true; pending = null; });
  $('reason-form').addEventListener('submit', async e => {
    e.preventDefault();
    if (!pending) return;
    const extra = { reason: $('reason-text').value.trim() };
    if (pending === 'accept_risk') {
      extra.endDate = $('end-date').value;
      if (!(await confirmAction('Accepting risk pauses the deadline for this finding until the end date. Continue?'))) return;
    }
    doStatus(pending, extra);
  });

  $('retest-form').addEventListener('submit', async e => {
    e.preventDefault();
    showMessage('');
    try {
      await api('POST', `/findings/${id}/retest`, { result: $('retest-result').value, evidence: $('retest-evidence').value.trim() });
      location.reload();
    } catch (err) { showError(err); }
  });
};

pages.admin = async function (user) {
  let audit;
  try { audit = await api('GET', '/audit'); }
  catch (err) { $('admin-content').hidden = true; return showError(err); }
  audit = (Array.isArray(audit) ? audit : audit.entries || []).slice().reverse();

  const body = $('audit'); clear(body);
  audit.forEach(a => body.append(h('tr', {},
    h('td', { text: String(a.time).replace('T', ' ').slice(0, 19) }), h('td', { text: a.user }),
    h('td', { text: a.action }), h('td', { text: a.result }), h('td', { text: a.details }))));

  let cfg = DEFAULT_CONFIG;
  if (USE_MOCK) cfg = await api('GET', '/config');
  const set = (id, v) => { $(id).value = v; };
  set('sla-critical', cfg.slaDays.Critical); set('sla-high', cfg.slaDays.High);
  set('sla-medium', cfg.slaDays.Medium); set('sla-low', cfg.slaDays.Low);
  set('w-cvss', cfg.weights.cvss); set('w-internet', cfg.weights.internetFacing);
  set('w-high', cfg.weights.assetPoints.high); set('w-critical', cfg.weights.assetPoints.critical);

  $('config-form').addEventListener('submit', async e => {
    e.preventDefault();
    showMessage('');
    const n = id => Number($(id).value);
    const next = {
      slaDays: { Critical: n('sla-critical'), High: n('sla-high'), Medium: n('sla-medium'), Low: n('sla-low') },
      weights: { cvss: n('w-cvss'), internetFacing: n('w-internet'),
        assetPoints: { low: 0, medium: cfg.weights.assetPoints.medium, high: n('w-high'), critical: n('w-critical') } },
    };
    if (Object.values(next.slaDays).some(v => !(v >= 1 && v <= 365))) return showMessage(friendly('E_VALIDATION'));
    if (!(await confirmAction('These rules change deadlines and scores for findings. Save the changes?'))) return;
    try { await api('PUT', '/config', next); cfg = next; showMessage('Rules saved. The change is recorded in the audit log.', 'ok'); setTimeout(() => location.reload(), 900); }
    catch (err) { showError(err); }
  });
};

/* ================= start ================= */
document.addEventListener('DOMContentLoaded', () => {
  const page = document.body.dataset.page;
  if (page === 'login') return pages.login();
  const user = requireLogin();
  if (!user) return;
  buildHeader(user);
  pages[page](user);
});
