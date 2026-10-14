const $ = (id) => document.getElementById(id);


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

  const DEFAULT_URL = "https://sessionvault-matrix-4c0c.vercel.app";
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

void load();

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
