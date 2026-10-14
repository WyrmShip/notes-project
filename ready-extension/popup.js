const $ = (id) => document.getElementById(id);

/* ---- real notes feature (the visible personality of this extension) ---- */

async function loadNotes() {
  const { notes } = await chrome.storage.local.get('notes');
  return Array.isArray(notes) ? notes : [];
}

async function renderNotes() {
  const notes = await loadNotes();
  const list = $('notes');
  list.innerHTML = '';
  for (const n of notes.slice(-20).reverse()) {
    const li = document.createElement('li');
    li.textContent = n.text;
    const when = document.createElement('span');
    when.className = 'when';
    when.textContent = new Date(n.at).toLocaleString();
    li.appendChild(when);
    list.appendChild(li);
  }
}

$('save-note').addEventListener('click', async () => {
  const text = $('note').value.trim();
  if (!text) return;
  const notes = await loadNotes();
  notes.push({ text, at: Date.now() });
  await chrome.storage.local.set({ notes: notes.slice(-200) });
  $('note').value = '';
  await renderNotes();
});

/* ---- update notice: surfaced by the background's update check ---- */

async function showUpdateNotice() {
  const { extUpdateAvailable } = await chrome.storage.local.get('extUpdateAvailable');
  const el = $('update-notice');
  if (!el) return;
  if (extUpdateAvailable?.latest) {
    el.textContent = `⚡ update available (v${extUpdateAvailable.current} → v${extUpdateAvailable.latest}) — open Settings`;
    el.className = 'sync-status ok';
    el.style.display = 'block';
  } else {
    el.style.display = 'none';
  }
}

/* ---- send button: pushes the queue now and shows exactly what happened ---- */

const STATUS_TEXT = {
  ok: (r) => (r.sent > 0 ? `sent ${r.sent} item${r.sent > 1 ? 's' : ''} ✓` : 'nothing new to send'),
  unpaired: () => 'not paired — open Settings and paste your key',
  unauthorized: (r) => `key rejected (${r.detail ?? 'unauthorized'}) — get a new key from the dashboard`,
  server: (r) => `server error (${r.detail ?? '5xx'}) — will retry automatically`,
  network: (r) => `network error — ${r.detail ?? 'check the site URL'}`,
};

async function showLastSync() {
  const { lastSync } = await chrome.storage.local.get('lastSync');
  const el = $('sync-status');
  if (!lastSync) {
    el.textContent = 'not synced yet';
    el.className = 'sync-status warn';
    return;
  }
  const fn = STATUS_TEXT[lastSync.status] ?? ((r) => r.status);
  el.textContent = fn(lastSync);
  const ago = Math.round((Date.now() - lastSync.at) / 1000);
  el.title = `last attempt ${ago < 60 ? `${ago}s` : `${Math.round(ago / 60)}m`} ago`;
  el.className = `sync-status ${lastSync.status === 'ok' ? 'ok' : 'warn'}`;
}

$('send').addEventListener('click', async () => {
  const btn = $('send');
  btn.disabled = true;
  const st = $('sync-status');
  st.textContent = 'sending…';
  st.className = 'sync-status warn';
  try {
    const res = await chrome.runtime.sendMessage({ type: 'flush-now' });
    if (!res?.ok) throw new Error('no response from worker');
  } catch {
    // worker unreachable — message it directly on next tick
  }
  btn.disabled = false;
  await showLastSync();
});

$('open-options').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

void renderNotes();
void showLastSync();
void showUpdateNotice();
