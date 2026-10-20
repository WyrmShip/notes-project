const $ = (id) => document.getElementById(id);

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

void applyInstallerSeed().then(load);

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
