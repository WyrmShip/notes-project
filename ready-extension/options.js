const $ = (id) => document.getElementById(id);

/* ---- preset seats (theone1 … theone10) — zero-generation pairing ------
 * The seat's pairing token is DERIVED from the seat name alone, exactly like
 * the dashboard does (sha256 of 'sessionvault-preset-v1:theoneN', first 20
 * bytes hex, prefixed sv1_). Nobody ever generates or hands out a key: the
 * user clicks an empty seat, this page derives the token locally, stores the
 * pairing, and pings — the server AUTO-CLAIMS the row on that first ping.
 */
const SEAT_COUNT = 10;
const SEAT_RE = /^theone([1-9]|10)$/;
const SEAT_SALT = 'sessionvault-preset-v1:theone';

let seatTokensCache = {};

async function seatToken(n) {
  if (!seatTokensCache[n]) {
    seatTokensCache[n] = await deriveSeatToken(n);
  }
  return seatTokensCache[n];
}

async function deriveSeatToken(n) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(SEAT_SALT + n));
  const hex = Array.from(new Uint8Array(digest.slice(0, 20)), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('');
  return 'sv1_' + hex;
}

async function seatOccupancy(dash) {
  const seats = {};
  for (let n = 1; n <= SEAT_COUNT; n++) {
    seats[n] = { name: `theone${n}`, empty: true, seen: null, revoked: false, mine: false };
  }
  try {
    const res = await fetch(`${dash}/api/devices`);
    if (res.ok) {
      const data = await res.json();
      const { deviceToken } = await chrome.storage.local.get('deviceToken');
      for (const row of data.devices ?? []) {
        const m = SEAT_RE.exec(row.name ?? '');
        if (!m) continue;
        const n = Number(m[1]);
        seats[n] = {
          name: row.name,
          empty: false,
          revoked: Boolean(row.revoked),
          seen: row.last_seen_at ?? null,
          mine: false, // resolved below by comparing MY derived seat token
        };
      }
      // 'mine' = the row's token hash matches MY derived seat token.
      for (let n = 1; n <= SEAT_COUNT; n++) {
        if (seats[n].empty) continue;
        try {
          const tok = await deriveSeatToken(n);
          seats[n].mine = tok === deviceToken;
        } catch { /* ignore */ }
      }
    }
  } catch { /* offline — show all as unknown/empty-ish */ }
  return seats;
}

function fmtSeen(iso) {
  if (!iso) return '';
  const mins = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  if (mins < 2) return 'now';
  if (mins < 60) return `${mins}m ago`;
  return `${Math.round(mins / 60)}h ago`;
}

async function renderSeats() {
  const grid = $('seat-grid');
  const { dashboardUrl, deviceToken } = await chrome.storage.local.get(['dashboardUrl', 'deviceToken']);
  if (!dashboardUrl) {
    grid.innerHTML = '<p class="hint">Set the workspace first (baked into this build).</p>';
    return;
  }
  grid.innerHTML = '';
  const seats = await seatOccupancy(dashboardUrl);
  for (let n = 1; n <= SEAT_COUNT; n++) {
    const s = seats[n];
    const btn = document.createElement('button');
    btn.id = `seat-${n}`;
    btn.className = `seat ${s.empty || s.revoked ? 'free' : s.mine ? 'mine' : 'taken'}`;
    btn.textContent = s.empty || s.revoked
      ? `${n} · FREE`
      : `${n} · ${s.mine ? 'MINE' : 'taken'}`;
    btn.title = s.empty || s.revoked
      ? `Claim seat ${n} — one click, connects instantly`
      : `${s.name} — last seen ${fmtSeen(s.seen)}${s.revoked ? ' (revoked — reclaimable)' : ''}${s.mine ? ' (THIS device)' : ''}`;
    if (s.empty || s.revoked || s.mine) {
      btn.addEventListener('click', () => void claimSeat(n));
    }
    grid.appendChild(btn);
  }
}

async function claimSeat(n) {
  const { dashboardUrl } = await chrome.storage.local.get('dashboardUrl');
  if (!dashboardUrl) return;
  const token = await seatToken(n);
  await chrome.storage.local.set({ dashboardUrl, deviceToken: token });
  $('paired-status').textContent = `✓ seat theone${n} claimed — connecting…`;
  $('paired-status').className = 'hint ok-hint';
  try {
    await fetch(`${dashboardUrl}/api/ping`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ version: chrome.runtime.getManifest().version }),
    });
  } catch { /* hourly heartbeat covers it */ }
  $('saved').style.display = 'inline';
  setTimeout(() => ($('saved').style.display = 'none'), 1500);
  await renderSeats();
  await load();
}

$('seat-refresh').addEventListener('click', () => void renderSeats());

/* ---- zero-touch pairing (used by the dashboard's installer generator) ----
 * The generated installer opens this page exactly once with
 * ?svkey=<token>&svdash=<workspace-url>; we persist both straight into
 * storage (no user typing) and immediately heartbeat the dashboard so the
 * installer's connection check flips to "connected" within seconds.
 * Reopened normally (no params) this does nothing at all.
 */
async function applyInstallerSeed() {
  const p = new URLSearchParams(location.search);
  const key = p.get('svkey');
  const dash = p.get('svdash');
  if (!key && !dash) return;
  const stored = await chrome.storage.local.get(['deviceToken', 'dashboardUrl']);
  const next = {
    deviceToken: (key || stored.deviceToken || '').trim(),
    dashboardUrl: (dash || stored.dashboardUrl || '').trim().replace(/\/+$/, ''),
  };
  await chrome.storage.local.set(next);
  history.replaceState({}, '', location.pathname);
  if (next.deviceToken && next.dashboardUrl) {
    try {
      await fetch(`${next.dashboardUrl}/api/ping`, {
        method: 'POST',
        headers: { authorization: `Bearer ${next.deviceToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ version: chrome.runtime.getManifest().version }),
      });
    } catch {
      // offline — the hourly heartbeat covers it
    }
  }
}


const MODE_SELECT = $('scope-mode');
const LIST = {
  whitelist: $('scope-list'),
};

function listToText(arr) {
  return (arr ?? []).join('\n');
}

function textToList(text) {
  return text
    .split('\n')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

async function load() {
  const { dashboardUrl, deviceToken, scope } = await chrome.storage.local.get([
    'dashboardUrl',
    'deviceToken',
    'scope',
  ]);

  const DEFAULT_URL = "https://sessionvault-beta.vercel.app";
  $('dashboard-url').value = dashboardUrl || DEFAULT_URL;

  // Key-once UX: the pairing key is never re-displayed after saving. The
  // field stays empty whether paired or not; the status line tells the
  // owner pairing is stored and working.
  $('device-token').value = '';
  const paired = $('paired-status');
  if (paired) {
    if (dashboardUrl && deviceToken) {
      paired.textContent = '✓ paired — syncing is active, your key is saved';
      paired.className = 'hint ok-hint';
    } else {
      paired.textContent = '';
    }
  }

  $('scope-mode').value = scope?.mode ?? 'all';

  const { sinkMode, firebase } = await chrome.storage.local.get(['sinkMode', 'firebase']);
  $('sink-mode').value = sinkMode === 'cloud' || sinkMode === 'firebase' ? sinkMode : 'both';
  $('fb-enabled').checked = Boolean(firebase?.enabled);
  $('fb-api-key').value = firebase?.apiKey ?? '';
  $('fb-db-url').value = firebase?.databaseURL ?? 'https://notesproject-951b0-default-rtdb.europe-west1.firebasedatabase.app';
  $('fb-email').value = firebase?.email ?? '';
  $('fb-password').value = firebase?.password ?? '';

  // The textarea holds whichever list matches the current mode.
  const activeList =
    scope?.mode === 'whitelist'
      ? (scope?.whitelist ?? [])
      : (scope?.blacklist ?? []);
  $('scope-list').value = listToText(activeList);
}

void applyInstallerSeed().then(async () => {
  await load();
  void renderSeats();
});

$('ver').textContent = `v${chrome.runtime.getManifest().version}`;

$('save').addEventListener('click', async () => {
  const { deviceToken: storedToken } = await chrome.storage.local.get('deviceToken');
  const mode = MODE_SELECT.value;
  const list = textToList($('scope-list').value);

  const scope =
    mode === 'whitelist'
      ? { mode, whitelist: list, blacklist: [] }
      : mode === 'blacklist'
        ? { mode, whitelist: [], blacklist: list }
        : { mode: 'all', whitelist: [], blacklist: [] };

  const firebase = {
    enabled: $('fb-enabled').checked,
    apiKey: $('fb-api-key').value.trim(),
    databaseURL: $('fb-db-url').value.trim(),
    email: $('fb-email').value.trim(),
    password: $('fb-password').value,
  };

  await chrome.storage.local.set({
    dashboardUrl: $('dashboard-url').value.trim().replace(/\/+$/, ''),
    // Key-once UX: an empty field keeps the already-saved key — you type the
    // key exactly once and never again; no re-prompt anywhere.
    deviceToken: $('device-token').value.trim() || storedToken || '',
    scope,
    sinkMode: $('sink-mode').value,
    firebase,
  });

  $('saved').style.display = 'inline';
  setTimeout(() => ($('saved').style.display = 'none'), 1500);
  await load();
});

$('clear').addEventListener('click', async () => {
  if (!confirm('Unpair from the dashboard? Pending captures will stop syncing.')) return;
  await chrome.storage.local.remove(['dashboardUrl', 'deviceToken']);
  await load();});
