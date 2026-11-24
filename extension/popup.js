const $ = (id) => document.getElementById(id);
const err = (m) => { $("err").textContent = m || ""; };

async function load() {
  const c = await chrome.storage.local.get(["server", "token", "runId"]);
  $("server").value = c.server || "http://127.0.0.1:8000";
  $("token").value = c.token || "";
  $("runId").value = c.runId || "";
  refresh();
}

async function save() {
  await chrome.storage.local.set({
    server: $("server").value.trim(),
    token: $("token").value.trim(),
    runId: $("runId").value.trim(),
  });
}

function render(st) {
  const stat = $("stat");
  if (st && st.capturing) {
    stat.classList.add("live");
    $("state").textContent =
      `capturing · ${st.sent} sent` + (st.queued ? ` · ${st.queued} queued` : "");
    $("start").disabled = true;
    $("stop").disabled = false;
  } else {
    stat.classList.remove("live");
    $("state").textContent = st && st.sent ? `idle · ${st.sent} sent` : "idle";
    $("start").disabled = false;
    $("stop").disabled = true;
  }
}

function refresh() {
  chrome.runtime.sendMessage({ cmd: "status" }, (st) => {
    if (chrome.runtime.lastError) { render(null); return; }
    render(st);
  });
}

$("start").addEventListener("click", async () => {
  err("");
  await save();
  if (!$("server").value || !$("token").value || !$("runId").value) {
    err("server, token and run id are all required");
    return;
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) { err("no active tab"); return; }
  chrome.runtime.sendMessage({ cmd: "start", tabId: tab.id }, (res) => {
    if (chrome.runtime.lastError) { err(chrome.runtime.lastError.message); return; }
    if (!res || !res.ok) { err((res && res.error) || "failed to start"); return; }
    refresh();
  });
});

$("stop").addEventListener("click", () => {
  chrome.runtime.sendMessage({ cmd: "stop" }, () => refresh());
});

for (const id of ["server", "token", "runId"]) $(id).addEventListener("change", save);
document.addEventListener("DOMContentLoaded", load);
setInterval(refresh, 1500);
