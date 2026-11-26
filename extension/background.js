// gnhf evidence capture — the human-assisted half of the ARTEX loop.
//
// Some evidence only exists after a HUMAN solves a 2FA/OTP/captcha step in
// their own browser. The agent can never see that step; this extension
// records its SHAPE — page URL, title, which credential-ish fields were
// present, whether an OTP or captcha was observed — and posts it to the
// run's control plane (POST /api/traffic/ingest), where it is scope-checked
// against the run's engagement.yaml and bound to the traffic log like any
// other evidence row.
//
// Hard rule: input VALUES are never read. The collect function uses
// getAttribute() only — the OTP the operator typed never leaves their
// machine, and the recorded evidence is exactly what a report needs: proof
// that the authenticated step happened, not its secret.

const OTP_RE = /otp|(^|_)code($|_)|2fa|totp|verification|one[-_]?time/i;
const CAPTCHA_RE = /captcha|g-recaptcha|h-captcha|turnstile/i;

// Runs in the page (via chrome.scripting.executeScript). MUST stay
// attribute-only: no .value, no innerText of form fields.
function collectPageShape() {
  const nodes = Array.from(document.querySelectorAll("input, textarea")).slice(0, 50);
  const fieldNames = [];
  let otpObserved = false;
  let captchaObserved = false;
  for (const el of nodes) {
    const label = [el.getAttribute("name"), el.getAttribute("id"),
                   el.getAttribute("autocomplete"), el.getAttribute("aria-label"),
                   el.getAttribute("placeholder")]
      .filter(Boolean).join(" ");
    if (!label) continue;
    fieldNames.push(label.slice(0, 120));
    if (OTP_RE.test(label)) otpObserved = true;
    if (CAPTCHA_RE.test(label) || CAPTCHA_RE.test(el.className || "")) captchaObserved = true;
  }
  const pageText = (document.title || "") + " " +
    Array.from(document.querySelectorAll("[class]")).slice(0, 40)
      .map((el) => el.className).join(" ");
  if (CAPTCHA_RE.test(pageText)) captchaObserved = true;
  return {
    url: location.href,
    title: document.title || "",
    otpObserved,
    captchaObserved,
    fieldNames,
  };
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "capture") {
    captureActiveTab(msg.endpoint, msg.runId).then(sendResponse);
    return true; // async sendResponse
  }
});

async function captureActiveTab(endpoint, runId) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) return { ok: false, error: "no active tab" };
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: collectPageShape,
    });
    const shape = (result && result.result) || {};
    const res = await fetch(`${endpoint.replace(/\/+$/, "")}/api/traffic/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        run_id: runId,
        url: shape.url,
        title: shape.title,
        otp_observed: shape.otpObserved,
        captcha_observed: shape.captchaObserved,
        field_names: shape.fieldNames,
        notes: "captured by operator via gnhf extension",
      }),
    });
    if (!res.ok) {
      const text = await res.text();
      return { ok: false, error: `ingest ${res.status}: ${text.slice(0, 200)}` };
    }
    return { ok: true, ...(await res.json()) };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}
