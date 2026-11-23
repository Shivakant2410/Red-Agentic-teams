// ARTEX Session Bridge — popup logic.
// Pairing: paste the run id from the dashboard, browse/complete the auth step,
// then "Share session for this site". The extension POSTs to
//   <server>/api/traffic/ingest   { run_id, rows, sessions }
// The server scope-labels rows honestly and stores the session for the agent
// (ingest_sessions tool). Cookie VALUES travel to the run's own ingest store
// only — they are never echoed back into any transcript or report.

const $ = (id) => document.getElementById(id);
const status = (text, cls = "") => { $("status").innerHTML = `<span class="${cls}">${text}</span>`; };

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function cookieHeaderFor(url) {
  const cookies = await chrome.cookies.getAll({ url });
  if (!cookies.length) return "";
  return cookies.map((c) => `${c.name}=${c.value}`).join("; ");
}

function originOf(url) { try { return new URL(url).origin; } catch { return ""; } }

async function postIngest(payload) {
  const server = ($("server").value || "").replace(/\/+$/, "");
  if (!server) throw new Error("set the control-plane server URL first");
  const resp = await fetch(`${server}/api/traffic/ingest`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`HTTP ${resp.status} ${text.slice(0, 140)}`);
  }
  return resp.json();
}

$("share").addEventListener("click", async () => {
  try {
    $("share").disabled = true;
    const tab = await activeTab();
    if (!tab || !tab.url || !/^https?:/i.test(tab.url)) {
      status("open the target site in the active tab first", "bad");
      return;
    }
    const runId = $("runid").value.trim();
    if (!runId) { status("paste the run id from the dashboard first", "bad"); return; }

    const cookieHeader = await cookieHeaderFor(tab.url);
    if (!cookieHeader) { status("no cookies for this site — complete the login first", "bad"); return; }

    const { rows } = await chrome.runtime.sendMessage({ type: "getBuffer" });
    const origin = originOf(tab.url);
    const siteRows = rows
      .filter((r) => originOf(r.url) === origin || originOf(r.url))
      .slice(-100)
      .map((r) => ({
        method: r.method || "GET",
        url: r.url,
        status: r.status || 0,
        req_headers: r.req_headers || {},
        resp_headers: r.resp_headers || {},
      }));

    const host = origin.replace(/^https?:\/\//, "");
    const result = await postIngest({
      run_id: runId,
      source: "extension",
      rows: siteRows,
      sessions: [{
        label: host.slice(0, 48) || "session",
        headers: { Cookie: cookieHeader },
        note: `human-assisted session captured on ${host} (2FA/SSO completed by the operator)`,
      }],
    });
    await chrome.runtime.sendMessage({ type: "clearBuffer" });
    status(`shared: ${result.sessions_stored} session, ${result.rows_received} rows ` +
           `(${result.accepted} in-scope, ${result.denied} out-of-scope) — ` +
           `agent picks it up via ingest_sessions`, "ok");
  } catch (err) {
    status(String(err.message || err), "bad");
  } finally {
    $("share").disabled = false;
  }
});

$("flush").addEventListener("click", async () => {
  try {
    const runId = $("runid").value.trim();
    if (!runId) { status("paste the run id first", "bad"); return; }
    const { rows } = await chrome.runtime.sendMessage({ type: "getBuffer" });
    const payload = {
      run_id: runId,
      source: "extension",
      rows: rows.slice(-100).map((r) => ({
        method: r.method || "GET",
        url: r.url,
        status: r.status || 0,
        req_headers: r.req_headers || {},
        resp_headers: r.resp_headers || {},
        req_body: r.req_body || "",
        resp_body: r.resp_body || "",
        error: r.error || "",
      })),
    };
    const result = await postIngest(payload);
    status(`flushed ${result.rows_received} rows (${result.accepted} in-scope)`, "ok");
  } catch (err) {
    status(String(err.message || err), "bad");
  }
});

$("clear").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "clearBuffer" });
  status("buffer cleared", "ok");
});

// restore settings
chrome.storage.local.get(["server", "runId"]).then((s) => {
  $("server").value = s.server || "http://127.0.0.1:8000";
  $("runid").value = s.runId || "";
});
$("server").addEventListener("change", (e) => chrome.storage.local.set({ server: e.target.value }));
$("runid").addEventListener("change", (e) => chrome.storage.local.set({ runId: e.target.value }));
