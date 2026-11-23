const DEFAULT_SERVER = "http://127.0.0.1:8000";

function stripSensitiveUrl(raw) {
  try {
    const url = new URL(raw);
    // Query strings and fragments may contain OAuth state, reset tokens or OTPs.
    return url.origin + url.pathname;
  } catch (_) {
    return "";
  }
}

function isLocalControlPlane(raw) {
  try {
    const url = new URL(raw);
    return (url.hostname === "127.0.0.1" || url.hostname === "localhost" ||
            url.hostname === "::1") &&
           url.pathname.startsWith("/api/");
  } catch (_) {
    return true;
  }
}

async function sendIngestEvent(event, tabId = null, frameId = null) {
  const settings = await chrome.storage.local.get(
    ["serverUrl", "runId", "runToken"]
  );
  const serverUrl = (settings.serverUrl || DEFAULT_SERVER).replace(/\/+$/, "");
  const runId = String(settings.runId || "").trim();
  const runToken = String(settings.runToken || "").trim();
  if (!runId || !runToken) return;

  const payloadEvent = {
    event_type: String(event.event_type || ""),
    challenge_kind: String(event.challenge_kind || "unknown"),
    field_count: Number.isInteger(event.field_count) ? event.field_count : 0,
    resource_type: String(event.resource_type || "document"),
    url: stripSensitiveUrl(String(event.url || "")),
    tab_id: Number.isInteger(tabId) ? tabId : null,
    frame_id: Number.isInteger(frameId) ? frameId : null,
    method: String(event.method || "").slice(0, 16),
    status_code: Number.isInteger(event.status_code) ? event.status_code : null,
    request_id: String(event.request_id || "").slice(0, 128)
  };

  const response = await fetch(serverUrl + "/api/traffic/ingest", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Red-Run-Token": runToken
    },
    body: JSON.stringify({ run_id: runId, events: [payloadEvent] })
  });
  if (!response.ok) {
    throw new Error("ingest rejected (" + response.status + ")");
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "red-auth-flow-event") return false;
  sendIngestEvent(message.event || {}, sender.tab?.id, sender.frameId)
    .then(() => sendResponse({ ok: true }))
    .catch((error) => sendResponse({ ok: false, error: String(error).slice(0, 240) }));
  return true;
});

// Browser request metadata only. We deliberately do not request or inspect
// requestBody, responseBody, requestHeaders, cookies, OTP values or CAPTCHA tokens.
function recordWebRequest(details, eventType, statusCode = null) {
  if (!details || details.tabId < 0 || isLocalControlPlane(details.url)) return;
  sendIngestEvent({
    event_type: eventType,
    challenge_kind: "unknown",
    field_count: 0,
    resource_type: details.type || "other",
    url: details.url,
    method: details.method || "GET",
    status_code: statusCode,
    request_id: details.requestId || ""
  }, details.tabId, details.frameId).catch(() => {});
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => recordWebRequest(details, "http_request_started"),
  { urls: ["http://*/*", "https://*/*"] }
);

chrome.webRequest.onCompleted.addListener(
  (details) => recordWebRequest(details, "http_response_completed", details.statusCode),
  { urls: ["http://*/*", "https://*/*"] }
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => recordWebRequest(details, "http_request_failed"),
  { urls: ["http://*/*", "https://*/*"] }
);
