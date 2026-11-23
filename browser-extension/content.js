(() => {
  "use strict";

  // This extension deliberately observes challenge state only. It NEVER reads
  // input.value, password fields, OTP digits, cookies, CAPTCHA response tokens,
  // request bodies or response bodies.
  const sent = new Set();
  const otpSelector = [
    'input[autocomplete="one-time-code"]',
    'input[name*="otp" i]',
    'input[id*="otp" i]',
    'input[aria-label*="verification code" i]',
    'input[placeholder*="verification code" i]'
  ].join(",");

  const captchaSelector = [
    'iframe[src*="recaptcha" i]',
    'iframe[src*="hcaptcha" i]',
    'iframe[src*="challenges.cloudflare.com" i]',
    '[class*="g-recaptcha" i]',
    '[class*="h-captcha" i]',
    '[data-sitekey]'
  ].join(",");

  function safePageUrl() {
    // Never forward query strings or fragments: they may contain login state.
    return location.origin + location.pathname;
  }

  function emitOnce(eventType, challengeKind, fieldCount) {
    const key = eventType + ":" + location.pathname;
    if (sent.has(key)) return;
    sent.add(key);
    chrome.runtime.sendMessage({
      type: "red-auth-flow-event",
      event: {
        event_type: eventType,
        challenge_kind: challengeKind,
        field_count: Math.max(0, Math.min(Number(fieldCount) || 0, 20)),
        resource_type: "document",
        url: safePageUrl()
      }
    });
  }

  function inspectChallengeState() {
    const otpFields = document.querySelectorAll(otpSelector);
    if (otpFields.length) {
      emitOnce("otp_challenge_detected", "otp", otpFields.length);
    }

    const captchaWidgets = document.querySelectorAll(captchaSelector);
    if (captchaWidgets.length) {
      emitOnce("captcha_challenge_detected", "captcha", captchaWidgets.length);
    }

    if (document.querySelector('input[type="password"]')) {
      emitOnce("auth_page_detected", "unknown", 0);
    }
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.querySelector(otpSelector)) {
      // Event only: no form serialization and no field values are accessed.
      chrome.runtime.sendMessage({
        type: "red-auth-flow-event",
        event: {
          event_type: "otp_challenge_submitted",
          challenge_kind: "otp",
          field_count: Math.min(form.querySelectorAll(otpSelector).length, 20),
          resource_type: "document",
          url: safePageUrl()
        }
      });
    }

    if (form.querySelector(captchaSelector) || document.querySelector(captchaSelector)) {
      // Submission state only; CAPTCHA response tokens are never read.
      chrome.runtime.sendMessage({
        type: "red-auth-flow-event",
        event: {
          event_type: "captcha_challenge_submitted",
          challenge_kind: "captcha",
          field_count: Math.min(form.querySelectorAll(captchaSelector).length, 20),
          resource_type: "document",
          url: safePageUrl()
        }
      });
    }
  }, true);

  inspectChallengeState();
  const observer = new MutationObserver(inspectChallengeState);
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
