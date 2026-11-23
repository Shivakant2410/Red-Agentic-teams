const fields = ["serverUrl", "runId", "runToken"];

chrome.storage.local.get(fields, (values) => {
  for (const field of fields) {
    const element = document.getElementById(field);
    if (values[field]) element.value = values[field];
  }
});

document.getElementById("save").addEventListener("click", () => {
  const values = {};
  for (const field of fields) {
    values[field] = document.getElementById(field).value.trim();
  }
  chrome.storage.local.set(values, () => {
    document.getElementById("status").textContent = "Settings saved locally in this browser profile.";
  });
});
