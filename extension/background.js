// Red-Agentic Traffic Capture — service worker.
//
// Uses the chrome.debugger API (the only reliable way in MV3 to read RESPONSE
// BODIES) to attach to the active tab, enable the Network domain, and collect
// request/response pairs. Text-based exchanges are batched (<=50) and POSTed to
// the Red-Agentic server's /api/traffic/ingest with the operator's token, so a
// human-driven login/browse session lands in the SAME traffic store the agent
// reads. Binary assets (images/fonts/media) and oversized bodies are dropped —
// evidence is the API surface, not the pixels.

const BODY_CAP = 256 * 1024;      // 256 KiB per body (matches server IngestEntry)
const BATCH_MAX = 50;
const SKIP_TYPES = new Set(["Image", "Font", "Media", "Stylesheet", "Other"]);
const SKIP_CT = /^(image|audio|video|font)\//i;

let state = {
  capturing: false,
  tabId: null,
  server: "",
  token: "",
  runId: "",
  sent: 0,
  queued: 0,
};
const reqs = new Map();   // requestId -> partial record
const batch = [];

function log(...a) { console.log("[rat]", ...a); }

async function loadCfg() {
  const c = await chrome.storage.local.get(["server", "token", "runId"]);
  state.server = (c.server || "").replace(/\/+$/, "");
  state.token = c.token || "";
  state.runId = c.runId || "";
}

async function flush(force) {
  if (!batch.length) return;
  if (!force && batch.length < BATCH_MAX) return;
  const entries = batch.splice(0, BATCH_MAX);
  state.queued = batch.length;
  try {
    const r = await fetch(`${state.server}/api/traffic/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${state.token}` },
      body: JSON.stringify({ run_id: state.runId, entries }),
    });
    if (r.ok) {
      const j = await r.json();
      state.sent += (j.written || 0);
      log("flushed", j);
    } else {
      log("ingest error", r.status);
      // put them back so a transient failure doesn't lose evidence
      batch.unshift(...entries);
    }
  } catch (e) {
    log("ingest exception", e);
    batch.unshift(...entries);
  }
  await chrome.storage.local.set({ sent: state.sent });
}

function headersToObj(list) {
  const o = {};
  for (const h of list || []) o[h.name.toLowerCase()] = h.value;
  return o;
}

function onEvent(source, method, params) {
  if (!state.capturing || source.tabId !== state.tabId) return;

  if (method === "Network.requestWillBeSent") {
    const r = params.request;
    reqs.set(params.requestId, {
      method: r.method, url: r.url,
      req_headers: r.headers || {},
      req_body: (r.postData || "").slice(0, BODY_CAP),
      t0: params.timestamp, type: params.type,
    });
  } else if (method === "Network.responseReceived") {
    const rec = reqs.get(params.requestId);
    if (!rec) return;
    rec.status = params.response.status;
    rec.resp_headers = params.response.headers || {};
    rec.type = params.type || rec.type;
    rec._ct = (params.response.headers &&
               (params.response.headers["content-type"] ||
                params.response.headers["Content-Type"])) || "";
  } else if (method === "Network.loadingFinished") {
    const rec = reqs.get(params.requestId);
    if (!rec) return;
    reqs.delete(params.requestId);
    if (SKIP_TYPES.has(rec.type) || SKIP_CT.test(rec._ct || "")) return;
    // fetch the response body via the debugger protocol
    chrome.debugger.sendCommand({ tabId: state.tabId }, "Network.getResponseBody",
      { requestId: params.requestId }, (res) => {
        if (chrome.runtime.lastError || !res) { res = { body: "", base64Encoded: false }; }
        let body = res.base64Encoded ? "" : (res.body || "");   // skip binary bodies
        rec.resp_body = body.slice(0, BODY_CAP);
        rec.elapsed_ms = Math.max(0, Math.round((params.timestamp - rec.t0) * 1000));
        delete rec.t0; delete rec.type; delete rec._ct;
        batch.push(rec);
        state.queued = batch.length;
        flush(false);
      });
  }
}

chrome.debugger.onEvent.addListener(onEvent);

async function start(tabId) {
  await loadCfg();
  if (!state.server || !state.token || !state.runId) {
    throw new Error("set server URL, token and run id in the popup first");
  }
  state.tabId = tabId;
  await chrome.debugger.attach({ tabId }, "1.3");
  await chrome.debugger.sendCommand({ tabId }, "Network.enable", {});
  state.capturing = true;
  await chrome.storage.local.set({ capturing: true, tabId });
  log("capturing tab", tabId, "-> run", state.runId);
}

async function stop() {
  state.capturing = false;
  await flush(true);
  if (state.tabId != null) {
    try { await chrome.debugger.detach({ tabId: state.tabId }); } catch (e) {}
  }
  reqs.clear();
  await chrome.storage.local.set({ capturing: false });
  log("stopped; total sent", state.sent);
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  (async () => {
    try {
      if (msg.cmd === "start") { await start(msg.tabId); reply({ ok: true }); }
      else if (msg.cmd === "stop") { await stop(); reply({ ok: true }); }
      else if (msg.cmd === "status") {
        reply({ capturing: state.capturing, sent: state.sent,
                queued: state.queued, runId: state.runId });
      }
    } catch (e) { reply({ ok: false, error: String(e.message || e) }); }
  })();
  return true;   // async reply
});

// If the tab we're attached to closes, clean up.
chrome.debugger.onDetach.addListener((source) => {
  if (source.tabId === state.tabId) { state.capturing = false; }
});
