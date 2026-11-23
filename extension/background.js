// ARTEX Session Bridge — background service worker (Manifest V3).
//
// Observes requests the OPERATOR's browser makes (chrome.webRequest is
// observational in MV3 — we never block or modify anything) into a bounded
// ring, and serves the popup on demand. Response BODIES are NOT captured:
// MV3 without the debugger API cannot read them; the agent's own in-scope
// probes record bodies via the run's evidence proxy. This extension covers
// the human-completed auth step: the session cookies and the request wire
// truth of the 2FA/SSO flow.

const RING_MAX = 500;
let ring = []; // newest last

// Standard headers that add noise, not signal, in the operator-facing log.
const SKIP_HEADERS = new Set([
  "accept", "accept-encoding", "accept-language", "cache-control",
  "connection", "host", "origin", "pragma", "referer", "sec-ch-ua",
  "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-dest",
  "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
  "upgrade-insecure-requests", "user-agent", "content-length",
]);

function cleanHeaders(list) {
  const out = {};
  for (const h of list || []) {
    const name = (h.name || "").toLowerCase();
    if (name && !SKIP_HEADERS.has(name)) out[h.name] = (h.value || "").slice(0, 4000);
  }
  return out;
}

function push(entry) {
  ring.push(entry);
  if (ring.length > RING_MAX) ring = ring.slice(ring.length - RING_MAX);
  try { chrome.storage.session.set({ ringSize: ring.length }); } catch (e) { /* noop */ }
}

chrome.webRequest.onSendHeaders.addListener(
  (details) => {
    if (details.tabId === -1 && !details.url.startsWith("http")) return;
    push({
      kind: "request",
      method: details.method,
      url: details.url,
      ts: new Date().toISOString(),
      req_headers: cleanHeaders(details.requestHeaders),
    });
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["requestHeaders", "extraHeaders"]
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    push({
      kind: "response",
      method: details.method,
      url: details.url,
      status: details.statusCode,
      ts: new Date().toISOString(),
      resp_headers: cleanHeaders(details.responseHeaders),
    });
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["responseHeaders", "extraHeaders"]
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    push({
      kind: "error",
      method: details.method,
      url: details.url,
      status: 0,
      ts: new Date().toISOString(),
      error: String(details.error || "").slice(0, 160),
    });
  },
  { urls: ["http://*/*", "https://*/*"] }
);

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "getBuffer") {
    sendResponse({ rows: ring, size: ring.length });
  } else if (msg && msg.type === "clearBuffer") {
    ring = [];
    sendResponse({ ok: true });
  } else if (msg && msg.type === "setCookieHeader") {
    // The popup resolved the active tab's cookies into one Cookie header;
    // store it so "flush" can pair traffic with the session share.
    try { chrome.storage.session.set({ cookieHeader: msg.value }); sendResponse({ ok: true }); }
    catch (e) { sendResponse({ ok: false, error: String(e) }); }
  }
  return true; // async sendResponse allowed
});
