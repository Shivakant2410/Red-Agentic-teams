const endpointEl = document.getElementById("endpoint");
const runIdEl = document.getElementById("runId");
const statusEl = document.getElementById("status");

chrome.storage.local.get(["endpoint", "runId"], (stored) => {
  endpointEl.value = stored.endpoint || "http://127.0.0.1:8000";
  runIdEl.value = stored.runId || "";
});

endpointEl.addEventListener("change", () => chrome.storage.local.set({ endpoint: endpointEl.value }));
runIdEl.addEventListener("change", () => chrome.storage.local.set({ runId: runIdEl.value }));

document.getElementById("capture").addEventListener("click", async () => {
  const endpoint = endpointEl.value.trim();
  const runId = runIdEl.value.trim();
  if (!endpoint || !runId) {
    statusEl.textContent = "Set the control plane URL and the run id first.";
    return;
  }
  statusEl.textContent = "Capturing…";
  const out = await chrome.runtime.sendMessage({ type: "capture", endpoint, runId });
  if (out && out.ok) {
    statusEl.textContent = `Ingested as traffic seq ${out.seq} on ${out.run_id}.`;
  } else {
    statusEl.textContent = `FAILED: ${(out && out.error) || "unknown error"}`;
  }
});
