// ─── Config ────────────────────────────────────────────────────────────────
const API = '';  // empty = same origin; set to 'http://localhost:8000' for dev

const TOOL_DEFS = {
  git:                  { icon: '⎇', desc: 'Clone remote repositories' },
  trivy:                { icon: '⬡', desc: 'Container & SCA vulnerability scan' },
  tainter:              { icon: '⇝', desc: 'Source-to-sink taint analysis' },
  python_reachability:  { icon: '⊕', desc: 'Python call-graph reachability' },
  dynamic_reachability: { icon: '◉', desc: 'Runtime reachability tracing' },
  semgrep:              { icon: '§',  desc: 'Static pattern-based SAST' },
  route_extractor:      { icon: '⌥', desc: 'HTTP route extraction & mapping' },
  metadata:             { icon: '◇', desc: 'Dependency metadata enrichment' },
};

// ─── Partial loader ────────────────────────────────────────────────────────
const PARTIALS = [
  ['_p-login',          'partials/login.html'],
  ['_p-topbar',         'partials/topbar.html'],
  ['_p-sidebar',        'partials/sidebar.html'],
  ['_p-page-scans',     'partials/page-scans.html'],
  ['_p-page-repo',      'partials/page-repo.html'],
  ['_p-page-new',       'partials/page-new.html'],
  ['_p-page-tools',     'partials/page-tools.html'],
  ['_p-page-api',       'partials/page-api.html'],
  ['_p-page-config',    'partials/page-config.html'],
  ['_p-page-settings',  'partials/page-settings.html'],
  ['_p-page-inventory', 'partials/page-inventory.html'],
  ['_p-page-findings',  'partials/page-findings.html'],
  ['_p-page-connectors','partials/page-connectors.html'],
  ['_p-panel',          'partials/panel-detail.html'],
  ['_p-modal-explain',  'partials/modal-explain.html'],
  ['_p-modal-graph',    'partials/modal-graph.html'],
];

async function loadPartials() {
  await Promise.all(PARTIALS.map(([id, url]) =>
    fetch(url)
      .then(r => { if (!r.ok) throw new Error(`${url} → ${r.status}`); return r.text(); })
      .then(html => {
        const el = document.getElementById(id);
        if (el) el.outerHTML = html;
      })
  ));
}

// ─── Theme ─────────────────────────────────────────────────────────────────
const THEMES = ['system', 'dark', 'light'];
const THEME_ICONS = { system: '⊙', dark: '◐', light: '○' };

let _theme = localStorage.getItem('vr_theme') || 'system';

function applyTheme(t) {
  _theme = t;
  const root = document.documentElement;
  if (t === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', t);
  localStorage.setItem('vr_theme', t);
  const btn = document.getElementById('theme-btn');
  if (btn) btn.textContent = THEME_ICONS[t] + ' ' + t;
}

function cycleTheme() {
  const next = THEMES[(THEMES.indexOf(_theme) + 1) % THEMES.length];
  applyTheme(next);
}

// Apply on load before first paint
applyTheme(_theme);

// ─── Auth state ────────────────────────────────────────────────────────────
// Token survives page reloads via sessionStorage.
// On server restart (file change during dev), boot_id changes → auto-logout.
let authToken = sessionStorage.getItem('vr_token') || null;
let _loggedInUsername = sessionStorage.getItem('vr_user') || '';

function isLoggedIn() { return !!authToken; }

function setAuthToken(token) {
  authToken = token;
  if (token) {
    sessionStorage.setItem('vr_token', token);
    sessionStorage.setItem('vr_user', _loggedInUsername);
  } else {
    sessionStorage.removeItem('vr_token');
    sessionStorage.removeItem('vr_user');
    sessionStorage.removeItem('vr_boot_id');
  }
  updateAuthUI();
}

// Check if the server restarted (new boot_id) — if so, force logout
async function checkBootId() {
  try {
    const res = await fetch(API + '/health');
    if (!res.ok) return;
    const data = await res.json();
    const prevBoot = sessionStorage.getItem('vr_boot_id');
    if (prevBoot && data.boot_id && prevBoot !== data.boot_id) {
      // Server restarted — clear session
      authToken = null;
      _loggedInUsername = '';
      sessionStorage.removeItem('vr_token');
      sessionStorage.removeItem('vr_user');
      sessionStorage.removeItem('vr_boot_id');
      updateAuthUI();
      toast('Server restarted — please sign in again', 'info');
      return;
    }
    if (data.boot_id) sessionStorage.setItem('vr_boot_id', data.boot_id);
  } catch(e) { /* server unreachable — leave state as-is */ }
}

function updateAuthUI() {
  const loginPage = document.getElementById('login-page');
  const appLayout = document.getElementById('app-layout');
  const topbar = document.getElementById('topbar');
  if (isLoggedIn()) {
    loginPage.style.display = 'none';
    appLayout.style.display = '';
    topbar.style.display = '';
    const un = document.getElementById('profile-username');
    if (un) un.textContent = _loggedInUsername || 'user';
  } else {
    loginPage.style.display = '';
    appLayout.style.display = 'none';
    topbar.style.display = 'none';
  }
}

async function doLogin() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl = document.getElementById('login-error');
  if (!username || !password) { errEl.textContent = 'Username and password required'; return; }
  try {
    const res = await fetch(API + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      errEl.textContent = body.detail || 'Invalid credentials';
      return;
    }
    const data = await res.json();
    _loggedInUsername = username;
    setAuthToken(data.access_token);
    // Store current boot_id so we detect server restarts
    try {
      const h = await fetch(API + '/health');
      if (h.ok) { const hd = await h.json(); if (hd.boot_id) sessionStorage.setItem('vr_boot_id', hd.boot_id); }
    } catch(e) {}
    toast('Signed in', 'success');
    loadScans();
    startAutoRefresh();
  } catch (e) {
    errEl.textContent = 'Cannot reach API — is the server running?';
  }
}

function doLogout() {
  setAuthToken(null);
  scans = [];
  currentScan = null;
  _fixPlanLoaded = null;
  closePanel();
  closeExplainModal();
  closeGraphModal();
  toast('Signed out', 'info');
}

// ─── State ─────────────────────────────────────────────────────────────────
let scans = [];
let currentScan = null;
let currentTab = 'overview';
let autoRefreshInterval = null;
let currentRepoName = null;
let lastCreatedApiKey = null;
let _fixPlanLoaded = null;
let _explainProvider = 'none';

// ─── Repo name extraction ─────────────────────────────────────────────────
function repoName(scan) {
  const raw = scan.repo_path || scan.repo_url || '';
  if (!raw) return '(unknown)';
  // strip trailing slash/whitespace, remove .git suffix
  const clean = raw.replace(/\/+$/, '').replace(/\.git$/, '');
  // return last path/URL segment
  return clean.split(/[\/]/).filter(Boolean).pop() || clean;
}

// Group scans by repo name, newest-scan-first within each group
function groupByRepo(scanList) {
  const map = {};
  for (const s of scanList) {
    const name = repoName(s);
    if (!map[name]) map[name] = [];
    map[name].push(s);
  }
  // Sort each group newest first
  for (const name of Object.keys(map)) {
    map[name].sort((a, b) => new Date(b.started_at || 0) - new Date(a.started_at || 0));
  }
  return map;
}

// ─── Config page ───────────────────────────────────────────────────────────
const _DEFAULT_CONFIG_YAML = `scan:
  static_reachability: true
  tools:
    - git                  # auto-injected when repo_url is provided
    - trivy                # SCA — finds CVEs in installed packages (required)
    - tainter              # taint analysis — OPTIONAL, skipped gracefully if not installed
    - python_reachability  # AST call-chain analysis
    - route_extractor      # HTTP route map (Flask / FastAPI / Django)
    - metadata             # resolves PyPI → importable name map
    - dynamic_reachability # Docker-based runtime coverage (requires runtime.enabled=true)
    # - semgrep            # uncomment to enable Semgrep SAST
    # - pytest_coverage    # uncomment to run target app's own test suite

  runtime:
    enabled: true          # set to false to skip all Docker-based dynamic analysis
    timeout: 120           # max seconds for container startup + Schemathesis traffic
    coverage_wait: 10      # seconds to wait after traffic before flushing coverage
    container_port: 3000   # port the target app exposes inside its container
    ebpf:
      enabled: false       # experimental — Linux only, requires bpftrace or BCC
      mode: openat         # "openat" (portable) or "usdt" (requires Python+dtrace)
      tracer: bpftrace     # "bpftrace" or "bcc" — must be installed on the host

  openapi_generator:
    enabled: false         # auto-generate OpenAPI spec via LLM when no spec exists
    provider: none         # "none" | "anthropic" | "openai" | "ollama"
    # provider: anthropic
    # api_key_env: ANTHROPIC_API_KEY
    # model: claude-sonnet-4-20250514
    # provider: ollama
    # model: qwen2.5-coder:7b
    # ollama_base_url: http://localhost:11434
    max_tokens: 4096

  intelligent_dast:
    enabled: false         # LLM-steered DAST (SQLi / SSRF confirmation)
    provider: none         # "none" | "anthropic" | "openai" | "ollama"
    # provider: anthropic
    # api_key_env: ANTHROPIC_API_KEY
    # model: claude-sonnet-4-20250514
    # provider: ollama
    # model: qwen2.5-coder:7b
    base_url: ""           # override target URL; empty = auto-detect from container_port
    ollama_base_url: "http://localhost:11434"
    max_iter: 5
    auth_credentials: ""   # optional "user:pass" for target app authentication

risk:
  exposure: public         # "public" | "internal" | "private" — affects risk score
  data_sensitivity: high   # "low" | "medium" | "high"

policy:
  block_if: []
  # Uncomment rules to fail CI on confirmed critical findings:
  # - severity: CRITICAL
  #   verdict: CONFIRMED
  # - severity: HIGH
  #   verdict: CONFIRMED

notifications:
  slack: true            # on by default — set false to suppress; no-op if connector unconfigured
  jira: false            # (Jira ticket creation — not yet wired)`;

function _hlYaml(raw) {
  return raw
    .split('\n')
    .map(line => {
      // escape HTML first
      let s = line.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      // full-line comments (possibly indented)
      if (/^\s*#/.test(s)) return `<span style="color:var(--text-mute)">${s}</span>`;
      // inline comment — split at first unquoted #
      const ci = s.search(/ #/);
      let code = s, comment = '';
      if (ci !== -1) { code = s.slice(0, ci); comment = `<span style="color:var(--text-mute)">${s.slice(ci)}</span>`; }
      // key: value
      code = code.replace(/^(\s*)([\w_-]+)(:)(\s*)(.*)$/, (_, indent, key, colon, sp, val) => {
        const kHtml = `<span style="color:var(--green)">${key}</span>${colon}`;
        if (!val.trim()) return indent + kHtml;
        const vHtml = /^(true|false)$/.test(val.trim())
          ? `<span style="color:var(--blue)">${val}</span>`
          : /^\d+$/.test(val.trim())
            ? `<span style="color:var(--amber)">${val}</span>`
            : `<span style="color:var(--text)">${val}</span>`;
        return indent + kHtml + sp + vHtml;
      });
      // list items  - value
      code = code.replace(/^(\s*-\s)(.+)$/, (_, prefix, val) =>
        `<span style="color:var(--text-dim)">${prefix}</span><span style="color:var(--text)">${val}</span>`
      );
      return code + comment;
    })
    .join('\n');
}

function buildConfigPage() {
  const el = document.getElementById('config-page-body');
  if (!el) return;
  el.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem">
      <div style="font-size:0.85rem;color:var(--text-dim)">
        Reference copy of <code style="color:var(--green);font-size:0.8rem">config/scan.sample.yml</code>.
        Pass a path to your own config file when launching a scan.
      </div>
      <button class="action-btn" onclick="copyDefaultConfigYaml()">Copy</button>
    </div>
    <pre style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:1.25rem;font-family:var(--mono);font-size:0.76rem;line-height:1.7;overflow-x:auto;margin:0">${_hlYaml(_DEFAULT_CONFIG_YAML)}</pre>`;
}

// ─── Settings page ─────────────────────────────────────────────────────────
const _SETTINGS_SECTIONS = {
  scan: {
    tag: 'Scan', color: 'var(--green)',
    title: 'Core Scan Settings',
    desc: 'Choose which tools run and whether static reachability analysis is enabled. All tools degrade gracefully — missing tools are skipped.',
    lines: ['scan:', '  static_reachability', '  tools:'],
  },
  runtime: {
    tag: 'Runtime', color: 'var(--blue)',
    title: 'Docker Runtime',
    desc: 'Spins up the target container, drives Schemathesis traffic, and collects coverage. Requires a Dockerfile or docker-compose.yml in the repo.',
    lines: ['runtime:'],
  },
  ebpf: {
    tag: 'eBPF', color: 'var(--amber)',
    title: 'eBPF Sidecar (experimental)',
    desc: 'Language-agnostic coverage via an eBPF sidecar — no Dockerfile patching needed. Linux kernel ≥ 4.9, bpftrace or BCC required.',
    lines: ['ebpf:'],
  },
  llm: {
    tag: 'LLM', color: 'var(--text-dim)',
    title: 'LLM Features',
    desc: 'Optional AI features: OpenAPI spec generation and intelligent DAST steering. Supports Anthropic, OpenAI, and Ollama. All features work without any LLM configured.',
    lines: ['openapi_generator:', 'intelligent_dast:'],
  },
  policy: {
    tag: 'Risk & Policy', color: 'var(--red)',
    title: 'Risk & Policy Gates',
    desc: 'Set exposure level and data sensitivity for risk scoring. Add block_if rules to fail CI pipelines on confirmed critical findings.',
    lines: ['risk:', 'policy:'],
  },
};

function buildSettingsPage() {
  const pre = document.getElementById('settings-yaml-pre');
  if (pre) pre.innerHTML = _hlYaml(_DEFAULT_CONFIG_YAML);
  _renderSettingsCards('all');
  if (isLoggedIn()) loadApiKeys();
}

function _renderSettingsCards(section) {
  const container = document.getElementById('settings-cards');
  if (!container) return;
  const entries = section === 'all'
    ? Object.entries(_SETTINGS_SECTIONS)
    : Object.entries(_SETTINGS_SECTIONS).filter(([k]) => k === section);
  container.innerHTML = entries.map(([, s]) => `
    <div class="settings-info-card">
      <div class="sic-tag" style="color:${s.color}">${s.tag}</div>
      <div class="sic-title">${s.title}</div>
      <div class="sic-desc">${s.desc}</div>
    </div>`).join('');
}

function filterSettingsSection(section, btn) {
  document.querySelectorAll('.settings-filter').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  _renderSettingsCards(section);

  const pre = document.getElementById('settings-yaml-pre');
  if (!pre) return;
  if (section === 'all') {
    pre.innerHTML = _hlYaml(_DEFAULT_CONFIG_YAML);
    return;
  }
  // Highlight only lines belonging to this section by dimming everything else
  const keywords = _SETTINGS_SECTIONS[section]?.lines || [];
  const lines = _DEFAULT_CONFIG_YAML.split('\n');
  let inSection = false;
  const out = lines.map(line => {
    const trimmed = line.trim();
    const startsSection = keywords.some(k => trimmed.startsWith(k.replace(':', '').trim() + ':') || line.startsWith(k));
    const isTopLevel = line.length > 0 && line[0] !== ' ' && !line.startsWith('#');
    if (startsSection) inSection = true;
    else if (isTopLevel && !startsSection) inSection = false;
    const hl = _hlYaml(line);
    return inSection ? hl : `<span style="opacity:0.25">${hl}</span>`;
  });
  pre.innerHTML = out.join('\n');
}

async function copyTextToClipboard(text) {
  const value = String(text ?? "");
  if (!value) return false;

  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (e) {
      // Fall through to legacy copy path.
    }
  }

  try {
    const ta = document.createElement('textarea');
    ta.value = value;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.left = '-1000px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    const copied = document.execCommand && document.execCommand('copy');
    document.body.removeChild(ta);
    return !!copied;
  } catch {
    return false;
  }
}

async function copyDefaultConfigYaml() {
  const ok = await copyTextToClipboard(_DEFAULT_CONFIG_YAML);
  toast(ok ? 'Copied' : 'Copy failed — select and copy manually', ok ? 'success' : 'error');
}

async function copySettingsYaml() {
  const ok = await copyTextToClipboard(_DEFAULT_CONFIG_YAML);
  toast(ok ? 'YAML copied to clipboard' : 'Copy failed — select and copy manually', ok ? 'success' : 'error');
}

function downloadSettingsYaml() {
  const blob = new Blob([_DEFAULT_CONFIG_YAML], { type: 'text/yaml' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'vulnreach.yaml';
  a.click();
  URL.revokeObjectURL(a.href);
  toast('vulnreach.yaml downloaded', 'success');
}

function _showApiKeyHint(msg, isError = false) {
  const el = document.getElementById('api-key-hint');
  if (!el) return;
  el.style.color = isError ? 'var(--red)' : 'var(--text-dim)';
  el.textContent = msg;
}

async function loadApiKeys() {
  const body = document.getElementById('api-keys-body');
  if (!body) return;
  body.innerHTML = `<div class="empty-state"><div class="spinner" style="margin:0 auto 0.6rem"></div><div class="empty-text">Loading API keys…</div></div>`;
  try {
    const data = await apiFetch('/api-keys');
    renderApiKeys(data.api_keys || []);
  } catch (e) {
    body.innerHTML = `<div class="empty-state"><div class="empty-text">Unable to load API keys</div><div class="empty-sub">${escHtml(e.message || 'Request failed')}</div></div>`;
  }
}

function renderApiKeys(keys) {
  const body = document.getElementById('api-keys-body');
  if (!body) return;
  if (!keys.length) {
    body.innerHTML = `<div class="empty-state"><div class="empty-text">No API keys yet</div><div class="empty-sub">Create one above for curl and automation.</div></div>`;
    return;
  }

  body.innerHTML = keys.map(k => {
    const revoked = !!k.revoked_at;
    const safeId  = escHtml(k.id);
    return `
      <div class="table-row">
        <div style="font-size:0.78rem;color:var(--text)">${escHtml(k.name || 'key')}</div>
        <div style="font-family:var(--mono);font-size:0.72rem;color:var(--green)">${escHtml(k.key_prefix || '—')}</div>
        <div class="ts">${fmtDate(k.created_at)}</div>
        <div class="ts">${k.last_used_at ? fmtDate(k.last_used_at) : 'never'}</div>
        <div class="ts">${k.expires_at ? fmtDate(k.expires_at) : 'never'}</div>
        <div style="position:relative">
          ${revoked
            ? `<span class="badge-status blocked"><span class="s-dot"></span>revoked</span>`
            : ''}
          <button class="action-btn key-menu-btn" onclick="event.stopPropagation();toggleKeyMenu('${safeId}',event)" title="Actions">⋯</button>
          <div class="scan-menu-dropdown" id="key-menu-${safeId}">
            ${!revoked ? `<div class="scan-menu-item" onclick="revokeApiKey('${safeId}')"><i class="fas fa-ban" style="width:14px"></i> Revoke</div>` : ''}
            <div class="scan-menu-item danger" onclick="deleteApiKey('${safeId}')"><i class="fas fa-trash" style="width:14px"></i> Delete</div>
          </div>
        </div>
      </div>`;
  }).join('');
}

async function createApiKey() {
  const nameEl = document.getElementById('api-key-name');
  const expEl = document.getElementById('api-key-expiry');
  const btn = document.getElementById('create-api-key-btn');
  if (!nameEl || !expEl || !btn) return;

  const name = nameEl.value.trim() || 'default';
  const expRaw = expEl.value;
  const expires_in_days = expRaw === 'none' ? null : Number(expRaw);

  btn.disabled = true;
  _showApiKeyHint('Creating API key…');
  try {
    const payload = { name, expires_in_days };
    const data = await apiFetch('/api-keys', { method: 'POST', body: JSON.stringify(payload) });
    const key = data.key || {};
    lastCreatedApiKey = data.api_key || null;

    const created = document.getElementById('api-key-created');
    const value = document.getElementById('api-key-created-value');
    const curl = document.getElementById('api-key-curl-example');
    if (created && value && curl) {
      created.style.display = '';
      value.textContent = data.api_key || '';
      curl.textContent = `curl -H "Authorization: Bearer ${data.api_key || '<API_KEY>'}" http://localhost:8000/scans`;
    }

    _showApiKeyHint(`Created key "${key.name || name}" successfully.`);
    toast('API key created', 'success');
    await loadApiKeys();
  } catch (e) {
    _showApiKeyHint(`Create failed: ${e.message || 'request error'}`, true);
    toast('Failed to create API key', 'error');
  } finally {
    btn.disabled = false;
  }
}

let _openKeyMenuId = null;

function toggleKeyMenu(keyId, event) {
  event.stopPropagation();
  const next = _openKeyMenuId === keyId ? null : keyId;
  _closeAllKeyMenus();
  if (next) {
    _openKeyMenuId = next;
    const el = document.getElementById('key-menu-' + keyId);
    if (el) el.classList.add('open');
  }
}

function _closeAllKeyMenus() {
  document.querySelectorAll('[id^="key-menu-"].scan-menu-dropdown.open').forEach(el => el.classList.remove('open'));
  _openKeyMenuId = null;
}

document.addEventListener('click', _closeAllKeyMenus);

async function revokeApiKey(keyId) {
  if (!keyId) return;
  _closeAllKeyMenus();
  try {
    await apiFetch('/api-keys/' + encodeURIComponent(keyId) + '/revoke', { method: 'POST' });
    toast('API key revoked', 'success');
    await loadApiKeys();
  } catch (e) {
    toast('Failed to revoke: ' + e.message, 'error');
  }
}

async function deleteApiKey(keyId) {
  if (!keyId) return;
  _closeAllKeyMenus();
  try {
    await apiFetch('/api-keys/' + encodeURIComponent(keyId), { method: 'DELETE' });
    toast('API key deleted', 'success');
    await loadApiKeys();
  } catch (e) {
    toast('Failed to delete: ' + e.message, 'error');
  }
}

async function copyLastApiKey() {
  if (!lastCreatedApiKey) {
    toast('No newly created key to copy', 'info');
    return;
  }
  const ok = await copyTextToClipboard(lastCreatedApiKey);
  toast(ok ? 'API key copied' : 'Copy failed — select and copy manually', ok ? 'success' : 'error');
}

// ─── Init ──────────────────────────────────────────────────────────────────
async function initApp() {
  applyTheme(_theme);  // re-run now that #theme-btn exists in the DOM
  buildToolsPage();
  buildConfigPage();
  buildSettingsPage();
  // Check if server restarted since last session
  if (isLoggedIn()) {
    await checkBootId();
  }
  updateAuthUI();
  if (isLoggedIn()) {
    await loadScans();
    startAutoRefresh();
  }
}

loadPartials().then(initApp).catch(err => {
  document.body.innerHTML =
    `<div style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:monospace;color:#f87171">
       Failed to load dashboard partials: ${err.message}
     </div>`;
});

// ─── Navigation ────────────────────────────────────────────────────────────
const PAGES = ['scans','repo','new','tools','api','config','findings','settings','inventory','connectors'];

function setPage(id) {
  PAGES.forEach(p => {
    const el = document.getElementById('page-' + p);
    if (el) el.style.display = p === id ? '' : 'none';
  });
  // Highlight Scans nav item for both the repo list and repo drilldown
  const activeId = id === 'repo' ? 'scans' : id;
  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.toggle('active', n.textContent.trim().toLowerCase().startsWith(
      activeId === 'new' ? 'new' : activeId === 'api' ? 'api' : activeId === 'settings' ? 'settings' : activeId
    ));
  });
  if (id === 'config') buildConfigPage();
  if (id === 'settings') buildSettingsPage();
  if (id === 'inventory') renderInventory();
  if (id === 'connectors') initConnectors();
}

// ─── API helpers ───────────────────────────────────────────────────────────
async function apiFetch(path, opts = {}, responseType = 'json') {
  const headers = { 'Content-Type': 'application/json', ...opts.headers };
  if (authToken) headers['Authorization'] = 'Bearer ' + authToken;
  const res = await fetch(API + path, { headers, ...opts });
  if (res.status === 401) {
    // Token expired or invalid — wipe all state and return to login
    setAuthToken(null);
    currentScan = null;
    scans = [];
    _fixPlanLoaded = null;
    closePanel();
    closeExplainModal();
    closeGraphModal();
    toast('Session expired — please sign in again', 'error');
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return responseType === 'blob' ? await res.blob() : await res.json();
}

// ─── Export helpers ────────────────────────────────────────────────────────
function exportCSV(scan) {
  if (!authToken) { toast('Session expired — please sign in again', 'error'); return; }
  if (!scan) return;
  const findings = (scan.findings || []).filter(f => f.finding_type !== 'dast' && f.package);
  // Group by package
  const pkgMap = {};
  for (const f of findings) {
    const pkg = f.package;
    if (!pkgMap[pkg]) pkgMap[pkg] = { ...f, cves: [] };
    if (f.cve_id) pkgMap[pkg].cves.push(f.cve_id);
    // Upgrade to worst reachability / severity
    const tier = { DYNAMICALLY_REACHABLE: 4, STATICALLY_REACHABLE: 3, UNCERTAIN: 2, NOT_REACHABLE: 1 };
    const srank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    if ((tier[f.reachability_class] || 0) > (tier[pkgMap[pkg].reachability_class] || 0))
      pkgMap[pkg].reachability_class = f.reachability_class;
    if ((srank[f.severity] || 0) > (srank[pkgMap[pkg].severity] || 0))
      pkgMap[pkg].severity = f.severity;
  }

  const headers = ['Package','CVE IDs','Severity','Reachability','Verdict','Priority','Risk Score','Fix Version','Files','Functions'];
  const rows = Object.values(pkgMap).map(f => [
    f.package || '',
    (f.cves || []).join('; '),
    f.severity || '',
    f.reachability_class || '',
    f.verdict || '',
    f.priority || '',
    typeof f.risk_score === 'number' ? f.risk_score.toFixed(2) : '',
    f.fix_version || '',
    (f.files || []).join('; '),
    (f.functions || []).join('; '),
  ]);

  const csv = [headers, ...rows]
    .map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))
    .join('\r\n');

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `vulnreach-${(scan.scan_id || 'export').slice(0, 8)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast('CSV downloaded', 'success');
}

async function exportPDF(scanId) {
  if (!authToken) { toast('Session expired — please sign in again', 'error'); return; }
  if (!scanId) return;
  const btn = document.getElementById('panel-pdf-btn');
  const origHtml = btn ? btn.innerHTML : '';
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner" style="width:10px;height:10px"></span>'; }
  try {
    const blob = await apiFetch(`/scan/${scanId}/export/pdf`, {}, 'blob');
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnreach-${scanId.slice(0, 8)}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
    toast('PDF downloaded', 'success');
  } catch(e) {
    toast('PDF export failed: ' + e.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = origHtml; }
  }
}

// ─── Severity breakdown helper ─────────────────────────────────────────────
function pkgSummaryHtml(pkg_count, sev_breakdown, status) {
  const done = ['completed', 'blocked', 'partial'].includes(status);
  if (!done) return '<span style="color:var(--text-mute)">—</span>';
  if (!pkg_count) return '<span style="color:var(--text-mute)">0 packages</span>';
  const sev = sev_breakdown || {};
  const chips = [
    { k: 'CRITICAL', col: 'var(--red)' },
    { k: 'HIGH',     col: 'var(--amber)' },
    { k: 'MEDIUM',   col: 'var(--blue)' },
    { k: 'LOW',      col: 'var(--text-mute)' },
  ].filter(s => sev[s.k] > 0)
   .map(s => `<span style="font-size:0.65rem;font-weight:600;color:${s.col};margin-right:4px">${sev[s.k]}&thinsp;${s.k}</span>`)
   .join('');
  return `<span style="font-size:0.75rem;color:var(--text-mute)">${pkg_count} pkg${pkg_count !== 1 ? 's' : ''}</span>${chips ? `<br><span style="line-height:1.6">${chips}</span>` : ''}`;
}

// ─── Normalisation ─────────────────────────────────────────────────────────
// Flatten list-level scan row (only basic fields from /scans)
function normaliseListScan(s) {
  const meta = s.metadata || {};
  return {
    ...s,
    repo_path:      s.repo_path  || meta.repo_path  || null,
    repo_url:       s.repo_url   || meta.repo_url   || null,
    tools:          s.tools      || meta.tools       || [],
    started_at:     s.started_at || s.created_at     || null,
    pkg_count:      s.pkg_count      ?? null,
    confirmed_pkgs: s.confirmed_pkgs ?? 0,
    likely_pkgs:    s.likely_pkgs    ?? 0,
    sev_breakdown:  s.sev_breakdown  || null,
  };
}

// Full scan normalisation — joins correlation + reachability into findings[]
function normaliseScan(full) {
  const meta = full.metadata || {};
  const findings = buildFindings(full);

  // Compute per-package severity breakdown from findings (deduplicated by package)
  const pkgSev = {};
  for (const f of findings) {
    if (f.finding_type === 'dast' || !f.package) continue;
    const sev = (f.severity || '').toUpperCase();
    if (!pkgSev[f.package] || sevRank(sev) > sevRank(pkgSev[f.package])) {
      pkgSev[f.package] = sev;
    }
  }
  const sevBreakdown = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const sev of Object.values(pkgSev)) {
    if (sevBreakdown.hasOwnProperty(sev)) sevBreakdown[sev]++;
  }

  return {
    ...full,
    repo_path:       full.repo_path  || meta.repo_path  || null,
    repo_url:        full.repo_url   || meta.repo_url   || null,
    tools:           full.tools      || meta.tools       || [],
    started_at:      full.started_at || full.created_at  || null,
    pkg_count:       Object.keys(pkgSev).length || null,
    sev_breakdown:   sevBreakdown,
    failed_tools:    meta.failed_tools    || [],
    pipeline_status: meta.pipeline_status || null,
    findings,
  };
}

function sevRank(s) { return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[s] || 0; }

// Join correlation results with reachability evidence keyed by cve_id
function buildFindings(scan) {
  const correlation = scan.correlation || [];
  // Fall back to pre-built findings if no correlation data (e.g. list scan or demo)
  if (!correlation.length) return scan.findings || [];

  const reachMap = {};
  for (const r of (scan.reachability || [])) {
    if (r.cve_id) reachMap[r.cve_id] = r;
  }

  const vulnMap = {};
  for (const v of (scan.vulnerabilities || [])) {
    const ids = Array.isArray(v.cve_id) ? v.cve_id : [v.cve_id];
    for (const cid of ids) { if (cid) vulnMap[cid] = v; }
  }

  return correlation.map(c => {
    const r = reachMap[c.cve_id] || {};
    const v = vulnMap[c.cve_id]  || {};
    // Support both new schema (finding_type + evidence{}) and legacy flat schema
    const ev = c.evidence || {};
    const findingType = c.finding_type || c.evidence_type || null;

    // DAST findings carry their own evidence structure
    if (findingType === 'dast') {
      return {
        cve_id:            c.cve_id,
        verdict:           c.verdict,
        risk_score:        c.risk_score,
        priority:          c.priority,
        confidence:        c.confidence,
        finding_type:      'dast',
        severity:          ev.severity || 'HIGH',
        evidence:          ev,
        iterations_used:   ev.iterations_used || null,
      };
    }

    return {
      cve_id:            c.cve_id,
      verdict:           c.verdict,
      risk_score:        c.risk_score,
      priority:          c.priority,
      confidence:        c.confidence,
      finding_type:      findingType,
      // 4-tier classification (preferred over heuristics)
      reachability_class: c.reachability_class || ev.reachability_class || null,
      static_subtype:     c.static_subtype     || ev.static_subtype     || null,
      // Static evidence fields (may live in evidence{} or at root for legacy)
      import_detected:   ev.import_detected   ?? r.import_detected   ?? false,
      call_chain_exists: ev.call_chain_exists  ?? r.call_chain_exists  ?? false,
      sink_reachable:    ev.sink_reachable     ?? r.sink_reachable     ?? false,
      // Dynamic evidence fields
      has_taint_flow:    ev.has_taint_flow  ?? false,
      has_coverage_hit:  ev.has_coverage_hit ?? false,
      files:             Array.isArray(ev.files) ? ev.files : (Array.isArray(r.files) ? r.files : (r.file ? [r.file] : [])),
      function:          ev.function || r.function || null,
      package:           c.package  || v.package  || null,
      severity:          c.severity || v.severity || null,
      fix_version:       v.fix_version || v.fixed_version || null,
    };
  });
}

// ─── Load scans ────────────────────────────────────────────────────────────
async function loadScans() {
  try {
    const data = await apiFetch('/scans');
    scans = (data.scans || []).map(normaliseListScan);
    renderScans();
    updateStats();
    document.getElementById('nav-count').textContent = Object.keys(groupByRepo(scans)).length;
    document.getElementById('api-status').textContent = 'API connected';
  } catch(e) {
    scans = [];
    renderScans();
    updateStats();
    document.getElementById('api-status').textContent = 'API offline';
  }
  // Re-render inventory if it is currently visible
  const invPage = document.getElementById('page-inventory');
  if (invPage && invPage.style.display !== 'none') renderInventory();
  // Re-render repo drilldown if it is currently visible
  const repoPage = document.getElementById('page-repo');
  if (repoPage && repoPage.style.display !== 'none' && currentRepoName) {
    openRepoPage(encodeURIComponent(currentRepoName));
  }
}


function renderScans() {
  const body = document.getElementById('scans-body');
  if (!scans.length) {
    body.innerHTML = `<div class="empty-state">
      <div class="empty-icon">⬡</div>
      <div class="empty-text">No scans yet</div>
      <div class="empty-sub">Launch your first scan from the New Scan page</div>
    </div>`;
    return;
  }

  const groups = groupByRepo(scans);
  // Sort repo names by their latest scan date (newest repo first)
  const sortedNames = Object.keys(groups).sort((a, b) => {
    const la = groups[a][0]?.started_at || '';
    const lb = groups[b][0]?.started_at || '';
    return lb.localeCompare(la);
  });

  body.innerHTML = sortedNames.map(name => {
    const repoScans  = groups[name];
    const latest     = repoScans[0];
    const statusCounts = {};
    for (const s of repoScans) statusCounts[s.status] = (statusCounts[s.status] || 0) + 1;
    // Choose worst status badge for the row
    const worstStatus = ['blocked','failed','partial','running','started','pending','completed']
      .find(st => statusCounts[st]) || latest.status;
    const fullPath = latest.repo_path || latest.repo_url || '';
    return `
    <div class="table-row" onclick="openRepoPage('${encodeURIComponent(name)}')">
      <div class="scan-id" style="color:var(--text);font-size:0.85rem;font-weight:600">${name}</div>
      <div class="repo-path" title="${fullPath}" style="font-size:0.7rem">${truncate(fullPath, 40)}</div>
      <div style="font-size:0.75rem;color:var(--text-mute)">${repoScans.length} scan${repoScans.length !== 1 ? 's' : ''}</div>
      <div><span class="badge-status ${worstStatus}"><span class="s-dot"></span>${worstStatus}</span></div>
      <div class="ts">${fmtDate(latest.started_at)}</div>
      <div><button class="action-btn" onclick="event.stopPropagation();openRepoPage('${encodeURIComponent(name)}')">View →</button></div>
    </div>`;
  }).join('');

  const tableCard = body.closest('.table-card');
  if (tableCard) initResizableTable(tableCard);
}

// ─── Inventory page ───────────────────────────────────────────────────────
function renderInventory() {
  const grid = document.getElementById('inventory-grid');
  if (!grid) return;

  if (!scans.length) {
    grid.innerHTML = `<div class="empty-state">
      <div class="empty-icon"><i class="fas fa-warehouse"></i></div>
      <div class="empty-text">No repositories yet</div>
      <div class="empty-sub">Launch your first scan to add a repo to the inventory</div>
    </div>`;
    return;
  }

  const groups = groupByRepo(scans);
  const sorted = Object.keys(groups).sort((a, b) => {
    const la = groups[a][0]?.started_at || '';
    const lb = groups[b][0]?.started_at || '';
    return lb.localeCompare(la);
  });

  const sevOrder = ['CRITICAL','HIGH','MEDIUM','LOW'];
  const sevColor = { CRITICAL: 'var(--red)', HIGH: 'var(--amber)', MEDIUM: 'var(--blue)', LOW: 'var(--text-mute)' };

  grid.innerHTML = sorted.map(name => {
    const repoScans = groups[name];
    const latest    = repoScans[0];
    const fullPath  = latest.repo_path || latest.repo_url || '';
    const isUrl     = fullPath.startsWith('http');
    const scanCount = repoScans.length;

    // Worst status across all scans of this repo
    const worstStatus = ['failed','blocked','partial','running','started','pending','completed']
      .find(st => repoScans.some(s => s.status === st)) || latest.status || 'unknown';

    // Severity breakdown from latest completed scan
    const sev = latest.sev_breakdown || {};
    const worstSev = sevOrder.find(s => sev[s] > 0);
    const sevChips = sevOrder.filter(s => sev[s] > 0)
      .map(s => `<span class="inv-sev-chip" style="color:${sevColor[s]}">${sev[s]}&thinsp;${s}</span>`)
      .join('');

    // Tools
    const tools = (latest.tools || []);
    const toolsHtml = tools.length
      ? tools.map(t => `<span class="inv-tool-chip">${escHtml(t)}</span>`).join('')
      : '<span style="color:var(--text-mute);font-size:0.65rem">—</span>';

    // Border accent by worst severity
    const accent = worstSev === 'CRITICAL' ? 'var(--red)'
                 : worstSev === 'HIGH'     ? 'var(--amber)'
                 : worstSev === 'MEDIUM'   ? 'var(--blue)'
                 : 'var(--border)';

    const safeEncName = encodeURIComponent(name);
    const safePath    = escHtml(fullPath);
    const safeRepo    = escHtml(latest.repo_path || '');
    const safeUrl     = escHtml(latest.repo_url  || '');

    return `
    <div class="inv-card" style="border-left-color:${accent}" onclick="openRepoPage('${safeEncName}')">
      <div class="inv-card-top">
        <div class="inv-repo-name" title="${safePath}">
          <i class="fas fa-${isUrl ? 'code-branch' : 'folder'}" style="font-size:0.75rem;color:var(--text-mute);margin-right:0.4rem"></i>${escHtml(name)}
        </div>
        <span class="badge-status ${worstStatus}" style="flex-shrink:0"><span class="s-dot"></span>${worstStatus}</span>
      </div>

      <div class="inv-path" title="${safePath}">${safePath ? truncate(safePath, 55) : '<span style="color:var(--text-mute)">—</span>'}</div>

      <div class="inv-stats">
        <div class="inv-stat"><span class="inv-stat-val">${scanCount}</span><span class="inv-stat-key">scan${scanCount !== 1 ? 's' : ''}</span></div>
        <div class="inv-stat"><span class="inv-stat-val">${fmtDate(latest.started_at)}</span><span class="inv-stat-key">last scan</span></div>
        ${worstSev ? `<div class="inv-stat"><span class="inv-stat-val" style="color:${sevColor[worstSev]}">${worstSev}</span><span class="inv-stat-key">worst sev</span></div>` : ''}
      </div>

      ${sevChips ? `<div class="inv-sev-row">${sevChips}</div>` : ''}

      <div class="inv-tools">${toolsHtml}</div>

      <div class="inv-actions" onclick="event.stopPropagation()">
        <button class="btn-secondary" style="font-size:0.7rem;padding:0.3rem 0.7rem" onclick="openRepoPage('${safeEncName}')">History →</button>
        <button class="btn-primary"   style="font-size:0.7rem;padding:0.3rem 0.7rem" onclick="prefillNewScan('${safeRepo}','${safeUrl}')">+ Scan Again</button>
      </div>
    </div>`;
  }).join('');
}

function prefillNewScan(repoPath, repoUrl) {
  setPage('new');
  const pathEl = document.getElementById('f-repo-path');
  const urlEl  = document.getElementById('f-repo-url');
  if (pathEl) pathEl.value = repoPath || '';
  if (urlEl)  urlEl.value  = repoUrl  || '';
}

function exportInventoryCSV() {
  if (!authToken) { toast('Session expired — please sign in again', 'error'); return; }
  if (!scans.length) { toast('No repos to export', 'info'); return; }

  const groups  = groupByRepo(scans);
  const sevKeys = ['CRITICAL','HIGH','MEDIUM','LOW'];

  const headers = ['Repository','Path / URL','Total Scans','Last Scan','Latest Status',
                   'Worst Severity','CRITICAL','HIGH','MEDIUM','LOW','Tools'];

  const rows = Object.keys(groups)
    .sort()
    .map(name => {
      const repoScans = groups[name];
      const latest    = repoScans[0];
      const sev       = latest.sev_breakdown || {};
      const worstSev  = sevKeys.find(s => sev[s] > 0) || '';
      const worstStatus = ['failed','blocked','partial','running','started','pending','completed']
        .find(st => repoScans.some(s => s.status === st)) || latest.status || '';

      return [
        name,
        latest.repo_path || latest.repo_url || '',
        repoScans.length,
        latest.started_at || '',
        worstStatus,
        worstSev,
        sev.CRITICAL || 0,
        sev.HIGH     || 0,
        sev.MEDIUM   || 0,
        sev.LOW      || 0,
        (latest.tools || []).join('; '),
      ];
    });

  const csv = [headers, ...rows]
    .map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))
    .join('\r\n');

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `vulnreach-inventory-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast(`Exported ${Object.keys(groups).length} repos`, 'success');
}

// ─── Scan actions (cancel / delete) ───────────────────────────────────────

let _openMenuScanId = null;

function toggleScanMenu(scanId, event) {
  event.stopPropagation();
  const next = _openMenuScanId === scanId ? null : scanId;
  _closeAllMenus();
  if (next) {
    _openMenuScanId = next;
    const el = document.getElementById(`scan-menu-${scanId}`);
    if (el) el.classList.add('open');
  }
}

function _closeAllMenus() {
  document.querySelectorAll('.scan-menu-dropdown.open').forEach(el => el.classList.remove('open'));
  _openMenuScanId = null;
}

document.addEventListener('click', _closeAllMenus);

async function cancelScan(scanId, event) {
  event.stopPropagation();
  _closeAllMenus();
  try {
    await apiFetch(`/scan/${scanId}/cancel`, { method: 'POST' });
    await loadScans();
  } catch (e) {
    alert('Cancel failed: ' + (e.message || e));
  }
}

async function deleteScan(scanId, event) {
  event.stopPropagation();
  _closeAllMenus();
  try {
    await apiFetch(`/scan/${scanId}`, { method: 'DELETE' });
    await loadScans();
    // If the repo has no remaining scans, go back to repo list
    const groups = groupByRepo(scans);
    if (!groups[currentRepoName]?.length) setPage('scans');
  } catch (e) {
    alert('Delete failed: ' + (e.message || e));
  }
}

// ─── Repo drilldown ───────────────────────────────────────────────────────
function openRepoPage(encodedName) {
  currentRepoName = decodeURIComponent(encodedName);
  const groups = groupByRepo(scans);
  const repoScans = groups[currentRepoName] || [];

  const fullPath = repoScans[0]?.repo_path || repoScans[0]?.repo_url || '';
  document.getElementById('repo-page-title').textContent = currentRepoName;
  document.getElementById('repo-page-subtitle').textContent = fullPath;

  const body = document.getElementById('repo-scans-body');
  if (!repoScans.length) {
    body.innerHTML = `<div class="empty-state"><div class="empty-text">No scans</div></div>`;
  } else {
    body.innerHTML = repoScans.map(s => {
      const running = s.status === 'running' || s.status === 'started';
      return `
      <div class="table-row" onclick="openPanel('${s.scan_id}')">
        <div class="scan-id">${s.scan_id}</div>
        <div><span class="badge-status ${s.status}"><span class="s-dot"></span>${s.status}</span></div>
        <div class="ts">${fmtDate(s.started_at)}</div>
        <div>${pkgSummaryHtml(s.pkg_count, s.sev_breakdown, s.status)}</div>
        <div class="tools-pills">${(s.tools||[]).slice(0,3).map(t=>`<span class="pill">${t}</span>`).join('')}${(s.tools||[]).length>3?`<span class="pill">+${s.tools.length-3}</span>`:''}</div>
        <div style="display:flex;align-items:center;gap:0.4rem">
          <button class="action-btn" onclick="event.stopPropagation();openPanel('${s.scan_id}')">View →</button>
          <div class="scan-menu-wrap">
            <button class="scan-menu-btn" title="More actions" onclick="toggleScanMenu('${s.scan_id}', event)">⋮</button>
            <div class="scan-menu-dropdown" id="scan-menu-${s.scan_id}">
              <button class="scan-menu-item${running ? '' : ' disabled'}" onclick="${running ? `cancelScan('${s.scan_id}', event)` : 'event.stopPropagation()'}" ${running ? '' : 'disabled'}>Cancel scan</button>
              <button class="scan-menu-item danger" onclick="deleteScan('${s.scan_id}', event)">Delete scan</button>
            </div>
          </div>
        </div>
      </div>`;
    }).join('');
  }
  setPage('repo');
}

function updateStats() {
  const repos = Object.keys(groupByRepo(scans)).length;
  document.getElementById('stat-total').textContent = repos ? `${repos} repo${repos !== 1 ? 's' : ''} · ${scans.length} scans` : '—';
  document.getElementById('stat-running').textContent = scans.filter(s => s.status === 'running' || s.status === 'started').length || '—';

  // Sum confirmed/likely package counts across all completed scans
  const done = scans.filter(s => ['completed','blocked','partial'].includes(s.status));
  const confirmed = done.reduce((n, s) => n + (s.confirmed_pkgs || 0), 0);
  const likely    = done.reduce((n, s) => n + (s.likely_pkgs    || 0), 0);
  document.getElementById('stat-confirmed').textContent = done.length ? confirmed : '—';
  document.getElementById('stat-likely').textContent    = done.length ? likely    : '—';
}

// ─── Tools page ────────────────────────────────────────────────────────────
function buildToolsPage() {
  const grid = document.getElementById('tools-grid');
  grid.innerHTML = Object.entries(TOOL_DEFS).map(([k,v]) => `
    <div class="stat-card green" style="padding:1.25rem">
      <div style="font-size:1.4rem;margin-bottom:0.5rem;opacity:0.7">${v.icon}</div>
      <div style="font-weight:600;color:var(--text);margin-bottom:0.3rem;font-family:var(--sans)">${k}</div>
      <div style="font-size:0.75rem;color:var(--text-dim)">${v.desc}</div>
    </div>
  `).join('');
}

// ─── Launch scan ───────────────────────────────────────────────────────────
async function launchScan() {
  const repo_path   = document.getElementById('f-repo-path').value.trim();
  const repo_url    = document.getElementById('f-repo-url').value.trim();
  const config_path = document.getElementById('f-config-path').value.trim();

  if (!repo_path && !repo_url) { showHint('Provide a repo path or URL'); return; }
  if (!repo_url && !config_path) { showHint('Config path is required for local repo scans'); return; }
  // Tools are resolved server-side from the repo's vulnreach.yaml (auto-discovered)
  // or the built-in default config — the UI no longer selects tools.

  const btn = document.getElementById('launch-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Launching…';

  showProgress(0, 'Submitting scan request…');

  try {
    const body = {
      config_path,
      ...(repo_path ? { repo_path } : {}),
      ...(repo_url  ? { repo_url  } : {}),
    };
    const res = await apiFetch('/scan', { method:'POST', body: JSON.stringify(body) });
    showProgress(100, 'Scan queued — ID: ' + res.scan_id);
    toast(`Scan started: ${res.scan_id}`, 'success');
    setTimeout(() => { setPage('scans'); loadScans(); hideProgress(); }, 1500);
  } catch(e) {
    showProgress(0, '');
    hideProgress();
    toast('Failed to launch scan: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '▶ Launch Scan';
  }
}

function resetForm() {
  ['f-repo-path','f-repo-url','f-config-path'].forEach(id => document.getElementById(id).value='');
  hideProgress();
}

function showHint(msg) {
  const h = document.getElementById('form-hint');
  h.style.color = 'var(--red)';
  h.textContent = '⚠ ' + msg;
  setTimeout(() => h.textContent='', 3000);
}

function showProgress(pct, label) {
  document.getElementById('launch-progress').style.display = '';
  document.getElementById('progress-fill').style.width = pct+'%';
  document.getElementById('progress-label').textContent = label;
}

function hideProgress() {
  document.getElementById('launch-progress').style.display = 'none';
}

// ─── Detail panel ──────────────────────────────────────────────────────────
async function openPanel(scanId) {
  currentScan = scans.find(s => s.scan_id === scanId) || { scan_id: scanId };
  document.getElementById('panel-title').textContent = scanId;
  document.getElementById('panel-overlay').classList.add('open');
  document.getElementById('detail-panel').classList.add('open');
  document.getElementById('tab-fixplan').innerHTML = '';
  _fixPlanLoaded = null;

  renderPanelOverview(currentScan);

  try {
    const full = await apiFetch('/scan/' + scanId);
    currentScan = normaliseScan(full);
    renderPanelOverview(currentScan);
    renderPanelFindings(currentScan);
    renderPanelRaw(full);  // show raw API response, not normalised
  } catch(e) {
    renderPanelFindings(normaliseScan(currentScan));
    renderPanelRaw(currentScan);
  }
}

function closePanel() {
  const panel = document.getElementById('detail-panel');
  document.getElementById('panel-overlay').classList.remove('open');
  panel.classList.remove('open', 'dragging', 'maximised');
  panel.style.width = '';
  _updateMaxIcon();
}

function toggleMaxPanel() {
  const panel = document.getElementById('detail-panel');
  if (!panel.classList.contains('open')) return;
  panel.classList.toggle('maximised');
  if (panel.classList.contains('maximised')) {
    panel.style.width = '';
  }
  _updateMaxIcon();
}

function _updateMaxIcon() {
  const btn = document.getElementById('panel-max-btn');
  if (!btn) return;
  const panel = document.getElementById('detail-panel');
  const icon = btn.querySelector('i');
  if (panel.classList.contains('maximised')) {
    icon.className = 'fas fa-compress';
    btn.title = 'Restore';
  } else {
    icon.className = 'fas fa-expand';
    btn.title = 'Maximise';
  }
}

// ─── Sidebar toggle ──────────────────────────────────────────────────────
function toggleSidebar() {
  document.getElementById('app-layout').classList.toggle('sidebar-collapsed');
}

// ─── Profile menu ─────────────────────────────────────────────────────────
function toggleProfileMenu(event) {
  event.stopPropagation();
  document.getElementById('profile-menu').classList.toggle('open');
}
document.addEventListener('click', () => {
  const menu = document.getElementById('profile-menu');
  if (menu) menu.classList.remove('open');
});

// ─── Resizable panel (drag left edge to widen) ───────────────────────────
(function() {
  let resizing = false, startX = 0, startW = 0;
  const MIN_W = 400;

  document.addEventListener('mousemove', function(e) {
    const panel = document.getElementById('detail-panel');
    if (!panel || !panel.classList.contains('open')) return;
    if (panel.classList.contains('maximised')) { document.body.style.cursor = ''; return; }

    if (resizing) {
      const delta = startX - e.clientX;
      const newW = Math.max(MIN_W, Math.min(window.innerWidth - 20, startW + delta));
      panel.style.width = newW + 'px';
      return;
    }

    // Show resize cursor when hovering near the left edge of the panel
    const rect = panel.getBoundingClientRect();
    if (Math.abs(e.clientX - rect.left) < 6 && e.clientY >= rect.top && e.clientY <= rect.bottom) {
      document.body.style.cursor = 'ew-resize';
    } else {
      document.body.style.cursor = '';
    }
  });

  document.addEventListener('mousedown', function(e) {
    const panel = document.getElementById('detail-panel');
    if (!panel || !panel.classList.contains('open')) return;
    if (panel.classList.contains('maximised')) return;

    const rect = panel.getBoundingClientRect();
    if (Math.abs(e.clientX - rect.left) < 6 && e.clientY >= rect.top && e.clientY <= rect.bottom) {
      resizing = true;
      startX = e.clientX;
      startW = rect.width;
      panel.classList.add('dragging');
      e.preventDefault();
    }
  });

  document.addEventListener('mouseup', function() {
    if (!resizing) return;
    resizing = false;
    document.body.style.cursor = '';
    const panel = document.getElementById('detail-panel');
    if (panel) panel.classList.remove('dragging');
  });
})();

function setTab(name, el) {
  currentTab = name;
  ['overview','findings','fixplan','raw'].forEach(t => {
    document.getElementById('tab-'+t).style.display = t===name ? '' : 'none';
  });
  document.querySelectorAll('.tab-item').forEach(i => i.classList.remove('active'));
  el.classList.add('active');
  if (name === 'fixplan' && currentScan) loadFixPlan(currentScan.scan_id);
}

function renderPanelOverview(scan) {
  // Tools actually used are derived server-side from real agent execution
  // (analysis_coverage), reflecting the repo's auto-discovered config — not a
  // UI selection. Fall back to the metadata tool list for older/in-flight scans.
  const cov       = scan.analysis_coverage || {};
  const ran       = cov.tools_ran || [];
  const skipped   = cov.tools_skipped || {};   // { tool: reason }
  const errored   = cov.tools_errored || {};   // { tool: error }
  const skippedKeys = Object.keys(skipped);
  const erroredKeys = Object.keys(errored);

  const toolsHtml = ran.length || skippedKeys.length || erroredKeys.length
    ? [
        ...ran.map(t => `<span class="tool-state tool-state--ran" title="ran">${escHtml(t)}</span>`),
        ...skippedKeys.map(t => `<span class="tool-state tool-state--skipped" title="skipped: ${escHtml(skipped[t])}">${escHtml(t)} · skipped</span>`),
        ...erroredKeys.map(t => `<span class="tool-state tool-state--errored" title="error: ${escHtml(errored[t])}">${escHtml(t)} · error</span>`),
      ].join(' ')
    : ((scan.tools||[]).join(', ') || '—');

  const degradedKeys = [...skippedKeys, ...erroredKeys];
  const failedBanner = degradedKeys.length
    ? `<div style="margin-top:1rem;padding:0.6rem 0.75rem;background:var(--amber-dim);border:1px solid #f5a62330;border-radius:4px;font-size:0.7rem;color:var(--amber)">
        ⚠ ${degradedKeys.length} tool(s) did not contribute: <strong>${degradedKeys.join(', ')}</strong> — results may be incomplete
      </div>`
    : '';

  document.getElementById('tab-overview').innerHTML = `
    <div class="meta-grid">
      <div class="meta-item"><div class="meta-key">Scan ID</div><div class="meta-val green">${scan.scan_id||'—'}</div></div>
      <div class="meta-item"><div class="meta-key">Status</div><div class="meta-val"><span class="badge-status ${scan.status||'pending'}"><span class="s-dot"></span>${scan.status||'—'}</span></div></div>
      <div class="meta-item"><div class="meta-key">Repository</div><div class="meta-val">${scan.repo_path||scan.repo_url||'—'}</div></div>
      <div class="meta-item"><div class="meta-key">Started</div><div class="meta-val">${fmtDate(scan.started_at)||'—'}</div></div>
      <div class="meta-item"><div class="meta-key">Tools used</div><div class="meta-val">${toolsHtml}</div></div>
      <div class="meta-item"><div class="meta-key">Packages</div><div class="meta-val">${pkgSummaryHtml(scan.pkg_count, scan.sev_breakdown, scan.status)}</div></div>
    </div>
    ${failedBanner}
    ${scan.status==='running'||scan.status==='started'
      ? `<div class="progress-bar-wrap"><div class="progress-bar" style="width:60%"></div></div>
         <div style="font-size:0.7rem;color:var(--text-dim);margin-top:0.4rem">Scan in progress…</div>`
      : ''}
  `;
}

function renderPanelFindings(scan) {
  const findings = scan.findings || [];

  const el = document.getElementById('tab-findings');
  if (!findings.length) {
    el.innerHTML = `<div class="empty-state">
      <div class="empty-icon">✓</div>
      <div class="empty-text">No findings</div>
      <div class="empty-sub">Nothing reachable detected in this scan</div>
    </div>`;
    return;
  }

  // Split DAST findings from package findings
  const dastFindings = findings.filter(f => f.finding_type === 'dast');
  const pkgFindings  = findings.filter(f => f.finding_type !== 'dast');

  // Summary bar — count by 4-tier reachability class (fall back to verdict for legacy data)
  const _confirmedVerdicts = new Set(['CONFIRMED','STATICALLY_REACHABLE','DYNAMICALLY_CONFIRMED','DYNAMICALLY_REACHABLE']);
  const classCounts = { DYNAMICALLY_REACHABLE: 0, STATICALLY_REACHABLE: 0, UNCERTAIN: 0, NOT_REACHABLE: 0 };
  for (const f of findings) {
    if (f.finding_type === 'dast') continue;
    const rc = f.reachability_class;
    if (rc && classCounts.hasOwnProperty(rc)) {
      classCounts[rc]++;
    } else {
      // Legacy fallback: derive from verdict
      const v = f.verdict || 'NOT_OBSERVED';
      if (v === 'CONFIRMED')                classCounts.DYNAMICALLY_REACHABLE++;
      else if (v === 'LIKELY')              classCounts.STATICALLY_REACHABLE++;
      else if (v === 'POSSIBLE')            classCounts.UNCERTAIN++;
      else                                  classCounts.NOT_REACHABLE++;
    }
  }
  const summaryBar = `
    <div class="findings-summary">
      ${classCounts.DYNAMICALLY_REACHABLE ? `<span class="fsumm red">   ● ${classCounts.DYNAMICALLY_REACHABLE} Dynamically Reachable</span>`  : ''}
      ${classCounts.STATICALLY_REACHABLE  ? `<span class="fsumm amber"> ● ${classCounts.STATICALLY_REACHABLE} Statically Reachable</span>`   : ''}
      ${classCounts.UNCERTAIN             ? `<span class="fsumm blue">  ● ${classCounts.UNCERTAIN} Uncertain</span>`                          : ''}
      ${classCounts.NOT_REACHABLE         ? `<span class="fsumm dim">   ● ${classCounts.NOT_REACHABLE} Not Reachable</span>`                  : ''}
    </div>`;

  // ── DAST section ──────────────────────────────────────────────────
  let dastHtml = '';
  if (dastFindings.length) {
    const dastConfirmed = dastFindings.filter(f => f.verdict === 'CONFIRMED').length;
    const ev = dastFindings[0].evidence || dastFindings[0];
    const vulnClass = (ev.vuln_class || 'sql_injection').replace(/_/g, ' ').toUpperCase();

    dastHtml = `
    <div class="dast-section">
      <div class="dast-header">
        <span class="dast-title">INTELLIGENT DAST — ${vulnClass} (${dastConfirmed} CONFIRMED)</span>
      </div>
      ${dastFindings.map(df => {
        const de = df.evidence || df;
        const sev = de.severity || df.severity || 'HIGH';
        const sevCol = { CRITICAL:'var(--red)', HIGH:'var(--amber)', MEDIUM:'var(--blue)', LOW:'var(--text-dim)' }[sev] || 'var(--amber)';
        return `
        <div class="dast-finding">
          <div class="dast-finding-row">
            <span class="sev-chip" style="color:${sevCol}">${sev}</span>
            <span style="font-weight:600;color:var(--text)">${(de.vuln_class||'sql_injection').replace(/_/g,' ').toUpperCase()}</span>
            <span class="verdict-badge CONFIRMED" style="margin-left:auto">CONFIRMED</span>
          </div>
          <div class="dast-meta-grid">
            <div class="dast-meta-item"><span class="dast-meta-key">ENDPOINT</span><span class="dast-meta-val">${de.endpoint || '—'}</span></div>
            <div class="dast-meta-item"><span class="dast-meta-key">ITERATIONS</span><span class="dast-meta-val">${df.iterations_used || '—'}</span></div>
            <div class="dast-meta-item"><span class="dast-meta-key">COVERAGE DELTA</span><span class="dast-meta-val">${(de.files||[]).length}</span></div>
            <div class="dast-meta-item"><span class="dast-meta-key">METHOD</span><span class="dast-meta-val">${(de.confirmation_method||'—').replace(/_/g,' ')}</span></div>
          </div>
          ${de.payload ? `<div class="dast-payload"><code>${escHtml(de.payload)}</code></div>` : ''}
          ${de.reasoning ? `<div class="dast-reasoning">${escHtml(de.reasoning)}</div>` : ''}
        </div>`;
      }).join('')}
    </div>`;
  }

  // ── Package findings table ────────────────────────────────────────
  // Group by package — merge CVEs per package
  const _tierRank = { DYNAMICALLY_REACHABLE: 4, STATICALLY_REACHABLE: 3, UNCERTAIN: 2, NOT_REACHABLE: 1 };
  const pkgMap = {};
  for (const f of pkgFindings) {
    const pkg = f.package || f.cve_id || 'unknown';
    if (!pkgMap[pkg]) pkgMap[pkg] = { ...f, cves: [], allFiles: [] };
    if (f.cve_id) pkgMap[pkg].cves.push(f.cve_id);
    if (f.files) pkgMap[pkg].allFiles.push(...f.files);
    // Upgrade verdict: CONFIRMED > LIKELY > POSSIBLE > NOT_OBSERVED
    const rank = { CONFIRMED:4, LIKELY:3, POSSIBLE:2, NOT_OBSERVED:1 };
    if ((rank[f.verdict]||0) > (rank[pkgMap[pkg].verdict]||0)) {
      pkgMap[pkg].verdict = f.verdict;
      pkgMap[pkg].confidence = f.confidence;
      pkgMap[pkg].risk_score = f.risk_score;
    }
    // Upgrade reachability_class to highest tier seen across CVEs
    if ((_tierRank[f.reachability_class]||0) > (_tierRank[pkgMap[pkg].reachability_class]||0)) {
      pkgMap[pkg].reachability_class = f.reachability_class;
      pkgMap[pkg].static_subtype = f.static_subtype;
    }
    // Merge evidence
    if (f.import_detected) pkgMap[pkg].import_detected = true;
    if (f.call_chain_exists) pkgMap[pkg].call_chain_exists = true;
    if (f.sink_reachable) pkgMap[pkg].sink_reachable = true;
    if (f.has_taint_flow) pkgMap[pkg].has_taint_flow = true;
    if (f.has_coverage_hit) pkgMap[pkg].has_coverage_hit = true;
    // Collect functions
    if (f.function) {
      if (!pkgMap[pkg].allFunctions) pkgMap[pkg].allFunctions = [];
      pkgMap[pkg].allFunctions.push(f.function);
    }
    // Track finding types for status line (kept for legacy fallback)
    if (f.finding_type) {
      if (!pkgMap[pkg].findingTypes) pkgMap[pkg].findingTypes = new Set();
      pkgMap[pkg].findingTypes.add(f.finding_type);
    }
  }

  const pkgCards = Object.entries(pkgMap)
    .sort(([, a], [, b]) => {
      const tierA = _tierRank[a.reachability_class] || 0;
      const tierB = _tierRank[b.reachability_class] || 0;
      if (tierB !== tierA) return tierB - tierA;   // higher tier first
      // secondary: severity
      const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      return (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0);
    })
    .map(([pkg, f]) => {
    const verdict = f.verdict || 'NOT_OBSERVED';
    const rc = f.reachability_class || null;
    const subtype = f.static_subtype || null;

    // Badge: prefer reachability_class over raw verdict for clarity
    const rcBadgeMap = {
      'DYNAMICALLY_REACHABLE': { label: 'DYNAMICALLY REACHABLE', cls: 'DYNAMICALLY_REACHABLE' },
      'STATICALLY_REACHABLE':  { label: subtype ? `STATIC · ${subtype}` : 'STATICALLY REACHABLE', cls: 'LIKELY' },
      'UNCERTAIN':             { label: 'UNCERTAIN',              cls: 'POSSIBLE' },
      'NOT_REACHABLE':         { label: 'NOT REACHABLE',          cls: 'not-reachable' },
    };
    const legacyBadgeMap = {
      'CONFIRMED':             { label: 'CONFIRMED',              cls: 'CONFIRMED' },
      'LIKELY':                { label: 'LIKELY',                 cls: 'LIKELY' },
      'POSSIBLE':              { label: 'POSSIBLE',               cls: 'POSSIBLE' },
      'NOT_OBSERVED':          { label: 'NOT REACHABLE',          cls: 'not-reachable' },
      'DYNAMICALLY_CONFIRMED': { label: 'DYNAMICALLY CONFIRMED',  cls: 'CONFIRMED' },
      'UNREACHABLE':           { label: 'UNREACHABLE',            cls: 'not-reachable' },
    };
    const vm = (rc ? rcBadgeMap[rc] : null) || legacyBadgeMap[verdict] || { label: verdict.replace(/_/g, ' '), cls: 'LIKELY' };
    const isReachable = rc === 'DYNAMICALLY_REACHABLE' || rc === 'STATICALLY_REACHABLE'
      || _confirmedVerdicts.has(verdict) || verdict === 'LIKELY';
    const cardBorder = isReachable ? 'reachable' : 'not-reachable';

    // Severity chip
    const sev = (f.severity || '').toUpperCase();
    const sevCls = sev ? `sev-chip-sm ${sev.toLowerCase()}` : '';
    const sevHtml = sev ? `<span class="${sevCls}">${sev}</span>` : '';

    // --- Status line — driven by reachability_class (canonical); legacy heuristic as fallback ---
    let statusLabel, statusCls;
    if (rc === 'DYNAMICALLY_REACHABLE') {
      statusLabel = 'Dynamically Reachable';
      statusCls   = 'status-dynamic';
    } else if (rc === 'STATICALLY_REACHABLE') {
      const subtypeLabel = { FUNCTION: 'Statically Reachable (Function)', FILE: 'Statically Reachable (File)', IMPORT: 'Statically Reachable (Import)', TRANSITIVE: 'Statically Reachable (Transitive)' }[subtype] || 'Statically Reachable';
      statusLabel = subtypeLabel;
      statusCls   = 'status-static';
    } else if (rc === 'UNCERTAIN') {
      statusLabel = 'Uncertain (Taint Only)';
      statusCls   = 'status-imported';
    } else if (rc === 'NOT_REACHABLE') {
      statusLabel = 'Not Reachable';
      statusCls   = 'status-none';
    } else {
      // Legacy fallback
      const fTypes = f.findingTypes || new Set();
      if (fTypes.has('dynamic') && (verdict === 'CONFIRMED' || (f.has_coverage_hit && f.has_taint_flow))) {
        statusLabel = 'Dynamically Reachable'; statusCls = 'status-dynamic';
      } else if (fTypes.has('dynamic')) {
        statusLabel = 'Coverage Observed';     statusCls = 'status-static';
      } else if (fTypes.has('static') || f.call_chain_exists || f.sink_reachable) {
        statusLabel = 'Statically Reachable';  statusCls = 'status-static';
      } else if (f.import_detected) {
        statusLabel = 'Imported';              statusCls = 'status-imported';
      } else {
        statusLabel = 'Not Reachable';         statusCls = 'status-none';
      }
    }

    // --- Path section ---
    const pathChecks = [];
    if (f.import_detected)   pathChecks.push({ hit: true,  text: 'Package imported in application code' });
    if (f.call_chain_exists) pathChecks.push({ hit: true,  text: 'Call graph confirms execution path' });
    if (f.sink_reachable)    pathChecks.push({ hit: true,  text: 'Vulnerable sink is reachable' });
    if (f.has_taint_flow)    pathChecks.push({ hit: true,  text: 'Taint flow from user input to sink' });
    if (f.has_coverage_hit)  pathChecks.push({ hit: true,  text: 'Confirmed at runtime via coverage' });
    if (rc === 'UNCERTAIN')  pathChecks.push({ hit: false, text: 'Taint signal only — no call chain or runtime coverage' });
    if (!pathChecks.length)  pathChecks.push({ hit: false, text: 'No reachability evidence found' });
    const pathHtml = pathChecks.map(p =>
      `<div class="path-check ${p.hit ? 'hit' : 'miss'}">${p.hit ? '✔' : '✘'} ${p.text}</div>`
    ).join('');

    // --- Evidence chain ---
    const evSteps = [];
    if (f.import_detected)   evSteps.push('Request');
    const uniqueFiles = [...new Set(f.allFiles)].slice(0, 2);
    if (uniqueFiles.length)  evSteps.push(uniqueFiles[0].split('/').pop());
    evSteps.push(pkg);
    if (f.has_taint_flow || f.sink_reachable) evSteps.push('vulnerable API');
    if (f.sink_reachable)    evSteps.push('sink ✅');
    const evHtml = evSteps.length > 1
      ? evSteps.map(e => `<span class="ev-step">${e}</span>`).join('<span class="ev-arrow">→</span>')
      : '<span class="ev-step miss">no evidence</span>';

    // --- CVE badges ---
    const cveCls = isReachable ? 'cve-badge reachable' : 'cve-badge';
    const maxCves = 4;
    const scanId = scan.scan_id;
    const hasGraph = f.call_chain_exists;
    function _cveBadgeHtml(c) {
      const safeC = escHtml(c);
      const explainBtn = `<button class="cve-action-btn" title="Explain ${safeC}" onclick="event.stopPropagation();openExplainModal('${escHtml(scanId)}','${safeC}')">⚡</button>`;
      const graphBtn   = hasGraph
        ? `<button class="cve-action-btn graph" title="Call graph" onclick="event.stopPropagation();openGraphModal('${escHtml(scanId)}','${safeC}')">⋯</button>`
        : '';
      return `<span class="${cveCls}">${safeC}</span>${explainBtn}${graphBtn}`;
    }
    const cveHtml = f.cves.length
      ? f.cves.slice(0, maxCves).map(_cveBadgeHtml).join('')
        + (f.cves.length > maxCves ? `<span class="cve-toggle" onclick="expandCves(this,'${cveCls}','${escHtml(scanId)}',${hasGraph})">+${f.cves.length - maxCves} more</span>` : '')
      : '<span style="color:var(--text-mute)">—</span>';

    // --- Files ---
    const allUniqueFiles = [...new Set(f.allFiles)].slice(0, 4);
    const filesHtml = allUniqueFiles.length
      ? allUniqueFiles.map(fp => `<span class="file-pill">${fp}</span>`).join('')
      : '';

    // --- Functions ---
    const funcs = [...new Set(f.allFunctions || [])].slice(0, 4);
    const funcsHtml = funcs.length
      ? funcs.map(fn => `<span class="func-pill">${fn}()</span>`).join('')
      : '';

    // --- Fix ---
    const fixVer = f.fix_version || f.fixed_version || '';

    return `
    <div class="pkg-card ${cardBorder}">
      <div class="pkg-card-top">
        <span class="pkg-name">${pkg}</span>
        ${sevHtml}
        <span class="verdict-badge-sm ${vm.cls}">${vm.label}</span>
      </div>

      <div class="pkg-card-section">
        <div class="pkg-detail-label">Status</div>
        <span class="status-pill ${statusCls}">${statusLabel}</span>
      </div>

      <div class="pkg-card-section">
        <div class="pkg-detail-label">Path</div>
        <div class="path-checks">${pathHtml}</div>
      </div>

      <div class="pkg-card-section">
        <div class="pkg-detail-label">Evidence</div>
        <div class="ev-chain">${evHtml}</div>
      </div>

      <div class="pkg-card-grid">
        ${f.cves.length ? `<div><div class="pkg-detail-label">CVEs (${f.cves.length})</div><div class="cve-list" data-cves="${escHtml(JSON.stringify(f.cves))}">${cveHtml}</div></div>` : ''}
        ${filesHtml ? `<div><div class="pkg-detail-label">Files</div><div class="file-list">${filesHtml}</div></div>` : ''}
        ${funcsHtml ? `<div><div class="pkg-detail-label">Functions</div><div class="func-list">${funcsHtml}</div></div>` : ''}
        ${fixVer ? `<div><div class="pkg-detail-label">Fix</div><span class="fix-ver">Upgrade → ${fixVer}</span></div>` : ''}
      </div>
    </div>`;
  }).join('');

  el.innerHTML = summaryBar + dastHtml + pkgCards;
}

function renderPanelRaw(scan) {
  const raw = JSON.stringify(scan, null, 2);
  document.getElementById('tab-raw').innerHTML = `
    <div style="position:relative">
      <button
        id="copy-raw-btn"
        onclick="copyRawJson(this)"
        style="position:absolute;top:0.5rem;right:0.5rem;z-index:2;padding:0.25rem 0.6rem;font-size:0.65rem;font-family:var(--mono);background:var(--surface);border:1px solid var(--border);border-radius:3px;color:var(--text-dim);cursor:pointer;transition:all 0.15s"
        onmouseover="this.style.color='var(--text)';this.style.borderColor='var(--text-mute)'"
        onmouseout="this.style.color='var(--text-dim)';this.style.borderColor='var(--border)'"
      >⎘ Copy</button>
      <pre id="raw-json-pre" style="font-size:0.7rem;color:var(--text-dim);white-space:pre-wrap;word-break:break-all;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:1rem;max-height:500px;overflow:auto">${raw.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
    </div>
  `;
}

async function copyRawJson(btn) {
  const pre = document.getElementById('raw-json-pre');
  if (!pre) return;
  const ok = await copyTextToClipboard(pre.textContent || '');
  if (ok) {
    const orig = btn.innerHTML;
    btn.innerHTML = '✓ Copied';
    btn.style.color = 'var(--green)';
    btn.style.borderColor = 'var(--green)';
    setTimeout(() => {
      btn.innerHTML = orig;
      btn.style.color = 'var(--text-dim)';
      btn.style.borderColor = 'var(--border)';
    }, 2000);
  } else {
    toast('Copy failed — select and copy manually', 'error');
  }
}

// ─── Fix Plan tab ─────────────────────────────────────────────────────────
async function loadFixPlan(scanId) {
  if (!scanId || _fixPlanLoaded === scanId) return;
  const el = document.getElementById('tab-fixplan');
  el.innerHTML = `<div class="empty-state"><div class="spinner" style="margin:0 auto 0.75rem"></div><div class="empty-text">Loading fix plan…</div></div>`;
  try {
    const data = await apiFetch(`/scan/${scanId}/fix-plan`);
    _fixPlanLoaded = scanId;
    renderFixPlan(data);
  } catch(e) {
    el.innerHTML = `<div class="empty-state"><div class="empty-icon">⚠</div><div class="empty-text">Failed to load fix plan</div><div class="empty-sub">${escHtml(e.message)}</div></div>`;
  }
}

function renderFixPlan(data) {
  const el = document.getElementById('tab-fixplan');
  const plan = data.fix_plan || [];
  const summary = data.summary || {};
  if (!plan.length) {
    el.innerHTML = `<div class="empty-state"><div class="empty-icon">✓</div><div class="empty-text">No reachable CVEs to fix</div><div class="empty-sub">All detected CVEs are unreachable or already resolved</div></div>`;
    return;
  }
  const summaryHtml = `<div class="fixplan-summary">
    <div class="fixplan-summary-item"><div class="fixplan-summary-key">Packages to Upgrade</div><div class="fixplan-summary-val">${summary.packages_to_upgrade ?? plan.length}</div></div>
    <div class="fixplan-summary-item"><div class="fixplan-summary-key">Reachable CVEs Fixed</div><div class="fixplan-summary-val" style="color:var(--red)">${summary.reachable_cves_fixable ?? 0}</div></div>
  </div>`;
  const cards = plan.map((p, i) => {
    const borderCls = p.reachability_class === 'DYNAMICALLY_REACHABLE' ? 'dynamic' : 'static';
    const rcLabel = p.reachability_class === 'DYNAMICALLY_REACHABLE'
      ? `<span class="status-pill status-dynamic">Dynamically Reachable</span>`
      : `<span class="status-pill status-static">Statically Reachable</span>`;
    const upgradeHtml = p.upgrade_to
      ? `<div class="fixplan-upgrade"><span class="cur">${escHtml(p.current_version)}</span><span class="arr">→</span><span class="next">${escHtml(p.upgrade_to)}</span></div>`
      : `<div class="fixplan-upgrade"><span style="color:var(--text-mute)">No upgrade available</span></div>`;
    const reachCves = p.reachable_cves_removed.map(c => `<span class="cve-badge reachable">${escHtml(c)}</span>`).join('');
    const bonusCves = (p.unreachable_cves_also_fixed || []).length
      ? `<div style="margin-top:0.45rem"><div class="fixplan-cve-label">Also fixes (unreachable)</div><div class="fixplan-cves">${p.unreachable_cves_also_fixed.map(c=>`<span class="cve-badge">${escHtml(c)}</span>`).join('')}</div></div>`
      : '';
    return `<div class="fixplan-card ${borderCls}">
      <div class="fixplan-card-top"><span class="fixplan-pkg-name">#${i+1} ${escHtml(p.package)}</span>${rcLabel}<span style="margin-left:auto;font-size:0.65rem;color:var(--text-mute);font-family:var(--mono)">risk ${p.risk_score.toFixed(1)}</span></div>
      ${upgradeHtml}
      <div class="fixplan-cve-label">Reachable CVEs removed (${p.reachable_cves_removed.length})</div>
      <div class="fixplan-cves">${reachCves}</div>${bonusCves}
    </div>`;
  }).join('');
  el.innerHTML = summaryHtml + cards;
}

// ─── Explain modal ─────────────────────────────────────────────────────────
let _explainScanId = null, _explainCveId = null;

function openExplainModal(scanId, cveId) {
  _explainScanId = scanId; _explainCveId = cveId; _explainProvider = 'none';
  document.getElementById('explain-modal-cve').textContent = cveId;
  document.getElementById('explain-output').innerHTML = '<span style="color:var(--text-mute)">Click Generate to fetch explanation.</span>';
  document.getElementById('explain-ollama-options').style.display = 'none';
  document.querySelectorAll('.explain-provider-btn').forEach(b => b.classList.toggle('active', b.dataset.provider === 'none'));
  document.getElementById('explain-modal-overlay').classList.add('open');
  document.getElementById('explain-modal').classList.add('open');
}
function closeExplainModal() {
  document.getElementById('explain-modal-overlay').classList.remove('open');
  document.getElementById('explain-modal').classList.remove('open');
}
function setExplainProvider(provider, el) {
  _explainProvider = provider;
  document.querySelectorAll('.explain-provider-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('explain-ollama-options').style.display = provider === 'ollama' ? 'flex' : 'none';
}
async function runExplain() {
  if (!_explainScanId || !_explainCveId) return;
  const btn = document.getElementById('explain-run-btn');
  const out = document.getElementById('explain-output');
  btn.disabled = true;
  btn.innerHTML = 'Generating…';
  out.innerHTML = '<span style="color:var(--text-mute)">Contacting API…</span>';
  const body = { provider: _explainProvider };
  if (_explainProvider === 'ollama') {
    const model = document.getElementById('explain-ollama-model').value.trim();
    if (model) body.model = model;
  }
  try {
    const data = await apiFetch(
      `/scan/${_explainScanId}/explain/${encodeURIComponent(_explainCveId)}`,
      { method: 'POST', body: JSON.stringify(body) },
    );
    out.textContent = data.explanation || '(no explanation returned)';
  } catch(e) {
    out.innerHTML = `<span style="color:var(--red)">Error: ${escHtml(e.message)}</span>`;
  } finally {
    btn.disabled = false; btn.innerHTML = 'Generate';
  }
}

// ─── Graph modal ───────────────────────────────────────────────────────────
function openGraphModal(scanId, cveId) {
  document.getElementById('graph-modal-cve').textContent = cveId;
  document.getElementById('graph-output').innerHTML = '<div class="spinner" style="margin:3rem auto"></div>';
  document.getElementById('graph-modal-overlay').classList.add('open');
  document.getElementById('graph-modal').classList.add('open');
  _loadGraph(scanId, cveId);
}
function closeGraphModal() {
  document.getElementById('graph-modal-overlay').classList.remove('open');
  document.getElementById('graph-modal').classList.remove('open');
}
async function _loadGraph(scanId, cveId) {
  const out = document.getElementById('graph-output');
  try {
    const data = await apiFetch(`/scan/${encodeURIComponent(scanId)}/graph/${encodeURIComponent(cveId)}`);
    const graphText = data.call_chain_graph || '';
    if (!graphText) { out.innerHTML = '<span style="color:var(--text-mute)">No call chain graph available for this CVE.</span>'; return; }
    const id = 'mermaid-graph-' + Date.now();
    out.innerHTML = `<div class="mermaid" id="${id}">${escHtml(graphText)}</div>`;
    try {
      await mermaid.run({ nodes: [document.getElementById(id)] });
    } catch(renderErr) {
      out.innerHTML = `<div style="font-size:0.7rem;color:var(--amber);margin-bottom:0.5rem">Render failed — showing source:</div><pre style="font-size:0.68rem;color:var(--text-dim);white-space:pre-wrap;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:0.85rem">${escHtml(graphText)}</pre>`;
    }
  } catch(e) {
    out.innerHTML = `<span style="color:var(--red)">Failed: ${escHtml(e.message)}</span>`;
  }
}

// ─── Auto refresh ──────────────────────────────────────────────────────────
function startAutoRefresh() {
  autoRefreshInterval = setInterval(loadScans, 5000);
}

// ─── Resizable table columns ───────────────────────────────────────────────
const RESIZE_STORAGE_KEY = 'vulnreach_scans_col_widths';
const DEFAULT_COL_WIDTHS = [140, null, 120, 100, 140, 140]; // null = flex (1fr)

function _colWidthsToCss(widths) {
  return widths.map(w => w === null ? '1fr' : w + 'px').join(' ');
}

function _saveColWidths(widths) {
  try { localStorage.setItem(RESIZE_STORAGE_KEY, JSON.stringify(widths)); } catch (_) {}
}

function _loadColWidths() {
  try {
    const raw = localStorage.getItem(RESIZE_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length === DEFAULT_COL_WIDTHS.length) return parsed;
    }
  } catch (_) {}
  return DEFAULT_COL_WIDTHS.slice();
}

function initResizableTable(tableCard) {
  const header = tableCard.querySelector('.table-header');
  if (!header || header.dataset.resizeInit) return;
  header.dataset.resizeInit = '1';

  const colWidths = _loadColWidths();
  tableCard.style.setProperty('--col-widths', _colWidthsToCss(colWidths));

  const cols = Array.from(header.children);
  cols.forEach((col, i) => {
    if (i === cols.length - 1) return; // no handle on last column
    const handle = document.createElement('div');
    handle.className = 'col-resize-handle';
    col.appendChild(handle);

    let startX, startWidths;

    handle.addEventListener('mousedown', e => {
      e.preventDefault();
      e.stopPropagation();
      handle.classList.add('dragging');
      startX = e.clientX;

      // Resolve current widths: convert 1fr to actual px using rendered width
      startWidths = cols.map((c, j) => {
        if (colWidths[j] === null) return c.getBoundingClientRect().width;
        return colWidths[j];
      });

      function onMove(e) {
        const delta = e.clientX - startX;
        const newW = Math.max(60, startWidths[i] + delta);
        colWidths[i] = Math.round(newW);
        // If next column was 1fr, keep it as 1fr (flexible); only fix if explicitly sized
        tableCard.style.setProperty('--col-widths', _colWidthsToCss(colWidths));
      }

      function onUp() {
        handle.classList.remove('dragging');
        _saveColWidths(colWidths);
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      }

      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  });
}

// ─── Toast ─────────────────────────────────────────────────────────────────
function toast(msg, type='info') {
  const c = document.getElementById('toasts');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${type==='success'?'✓':type==='error'?'✕':'ℹ'}</span>${msg}`;
  c.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ─── Helpers ───────────────────────────────────────────────────────────────
function escHtml(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function expandCves(el, cls, scanId, hasGraph) {
  const list = el.parentNode;
  const cves = JSON.parse(list.dataset.cves || '[]');
  list.innerHTML = cves.map(c => {
    const safeC = escHtml(c);
    const explainBtn = `<button class="cve-action-btn" title="Explain ${safeC}" onclick="event.stopPropagation();openExplainModal('${escHtml(scanId)}','${safeC}')">⚡</button>`;
    const graphBtn   = hasGraph
      ? `<button class="cve-action-btn graph" title="Call graph" onclick="event.stopPropagation();openGraphModal('${escHtml(scanId)}','${safeC}')">⋯</button>`
      : '';
    return `<span class="${cls}">${safeC}</span>${explainBtn}${graphBtn}`;
  }).join('');
}
function truncate(s, n) { return s && s.length > n ? s.slice(0,n)+'…' : (s||'—'); }

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  const now = new Date();
  const diff = (now - d) / 1000;
  if (diff < 60)    return `${Math.round(diff)}s ago`;
  if (diff < 3600)  return `${Math.round(diff/60)}m ago`;
  if (diff < 86400) return `${Math.round(diff/3600)}h ago`;
  return d.toLocaleDateString();
}

// ─── Mermaid init ──────────────────────────────────────────────────────────
if (typeof mermaid !== 'undefined') {
  mermaid.initialize({
    startOnLoad: false,
    theme: 'dark',
    themeVariables: {
      background: '#080c0f',
      primaryColor: '#0d1318',
      primaryTextColor: '#c8d8e8',
      lineColor: '#1a2530',
    },
  });
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeExplainModal(); closeGraphModal(); }
});

// ─── Connectors ────────────────────────────────────────────────────────────

const _CONNECTOR_IDS = ['slack', 'jira'];

async function initConnectors() {
  for (const id of _CONNECTOR_IDS) _setConnectorHint(id, '');
  try {
    const data = await apiFetch('/connectors');
    _CONNECTOR_IDS.forEach(id => _applyConnectorState(id, data[id] || {}));
  } catch (e) {
    _CONNECTOR_IDS.forEach(id => _setConnectorHint(id, 'Could not load connector state.'));
  }
}

function _applyConnectorState(id, state) {
  const connected = state.connected === true;
  const badge = document.getElementById(`${id}-status-badge`);
  const testBtn = document.getElementById(`${id}-test-btn`);
  const discBtn = document.getElementById(`${id}-disconnect-btn`);

  if (badge) {
    badge.textContent = connected ? 'Connected' : 'Disconnected';
    badge.className = `connector-badge connector-badge--${connected ? 'connected' : 'disconnected'}`;
  }
  if (testBtn) testBtn.style.display = connected ? '' : 'none';
  if (discBtn) discBtn.style.display = connected ? '' : 'none';

  // Populate non-secret fields; never pre-fill secrets
  if (id === 'slack') {
    const ch = document.getElementById('slack-channel');
    if (ch && state.channel) ch.value = state.channel;
  }
  if (id === 'jira') {
    const url = document.getElementById('jira-base-url');
    const email = document.getElementById('jira-email');
    const proj = document.getElementById('jira-project-key');
    if (url && state.base_url) url.value = state.base_url;
    if (email && state.email) email.value = state.email;
    if (proj && state.project_key) proj.value = state.project_key;
  }
}

function _setConnectorHint(id, msg, isError) {
  const el = document.getElementById(`${id}-hint`);
  if (!el) return;
  el.textContent = msg;
  el.style.color = isError ? 'var(--red)' : 'var(--text-dim)';
}

async function saveConnector(id) {
  const btn = document.getElementById(`${id}-save-btn`);
  _setConnectorHint(id, '');

  let body = {};
  if (id === 'slack') {
    const webhookUrl = document.getElementById('slack-webhook-url').value.trim();
    const channel    = document.getElementById('slack-channel').value.trim();
    if (!webhookUrl) { _setConnectorHint(id, 'Webhook URL is required.', true); return; }
    body = { webhook_url: webhookUrl, channel };
  } else if (id === 'jira') {
    const baseUrl    = document.getElementById('jira-base-url').value.trim();
    const email      = document.getElementById('jira-email').value.trim();
    const apiToken   = document.getElementById('jira-api-token').value.trim();
    const projectKey = document.getElementById('jira-project-key').value.trim();
    if (!baseUrl)    { _setConnectorHint(id, 'Base URL is required.', true); return; }
    if (!email)      { _setConnectorHint(id, 'Email is required.', true); return; }
    if (!apiToken)   { _setConnectorHint(id, 'API token is required.', true); return; }
    if (!projectKey) { _setConnectorHint(id, 'Project key is required.', true); return; }
    body = { base_url: baseUrl, email, api_token: apiToken, project_key: projectKey };
  }

  btn.disabled = true;
  btn.textContent = 'Saving…';
  try {
    const data = await apiFetch(`/connectors/${id}`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
    _applyConnectorState(id, data);
    // Clear secret fields after successful save — they must not linger in the DOM
    if (id === 'slack') document.getElementById('slack-webhook-url').value = '';
    if (id === 'jira')  document.getElementById('jira-api-token').value = '';
    _setConnectorHint(id, 'Saved.');
    setTimeout(() => _setConnectorHint(id, ''), 3000);
  } catch (e) {
    _setConnectorHint(id, e.message || 'Save failed.', true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save';
  }
}

async function testConnector(id) {
  _setConnectorHint(id, 'Sending test…');
  try {
    await apiFetch(`/connectors/${id}/test`, { method: 'POST' });
    _setConnectorHint(id, 'Test sent successfully.');
    setTimeout(() => _setConnectorHint(id, ''), 4000);
  } catch (e) {
    _setConnectorHint(id, e.message || 'Test failed.', true);
  }
}

async function disconnectConnector(id) {
  if (!confirm(`Remove the ${id.charAt(0).toUpperCase() + id.slice(1)} connector? This cannot be undone.`)) return;
  _setConnectorHint(id, 'Disconnecting…');
  try {
    await apiFetch(`/connectors/${id}`, { method: 'DELETE' });
    _applyConnectorState(id, { connected: false });
    // Clear all fields for this connector
    if (id === 'slack') {
      document.getElementById('slack-webhook-url').value = '';
      document.getElementById('slack-channel').value = '';
    }
    if (id === 'jira') {
      ['jira-base-url','jira-email','jira-api-token','jira-project-key'].forEach(f => {
        document.getElementById(f).value = '';
      });
    }
    _setConnectorHint(id, 'Disconnected.');
    setTimeout(() => _setConnectorHint(id, ''), 3000);
  } catch (e) {
    _setConnectorHint(id, e.message || 'Disconnect failed.', true);
  }
}
