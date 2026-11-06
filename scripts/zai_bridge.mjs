#!/usr/bin/env node
/**
 * zai_bridge.mjs — OpenAI-compatible gate in front of the z-ai SDK (glm-4.6).
 *
 * WHY THIS EXISTS (rebuilt, now committed): the agent fleet speaks /v1/chat/completions;
 * the z-ai coding-plan endpoint speaks its own auth. The bridge is the adapter. The one
 * non-obvious property it must have is SERIAL SDK CALLS: the sandbox's z-ai account
 * rate-limits per-account, not per-connection, and a 3-worker exploit swarm fires
 * overlapping requests — the 429 storm that killed the first specialists A/B run
 * (runs/spec-ab-lab-idor-20261102-125530: "all 1 candidate models failed ... HTTP 429")
 * was N concurrent workers, not N sequential calls. So every SDK call goes through a
 * promise-chain gate that guarantees call *starts* are >= DELAY_MS apart, no matter how
 * many callers hit the bridge concurrently.
 *
 *   let _gate = Promise.resolve();
 *   function gated(fn) {
 *     const run = _gate.then(fn, fn);   // a failed predecessor must not poison the queue
 *     _gate = run.then(() => sleep(DELAY_MS), () => sleep(DELAY_MS));
 *     return run;
 *   }
 *
 * Env: ZAI_BRIDGE_KEY (optional Bearer check), ZAI_BRIDGE_PORT (default 9825),
 *      ZAI_BRIDGE_MODEL (default glm-4.6), ZAI_BRIDGE_DELAY_MS (default 400).
 *
 * Endpoints:
 *   GET  /v1/models                 -> allowlist entry so provider discovery works
 *   POST /v1/chat/completions       -> OpenAI message shape out (tools passed through)
 *
 * Run: node scripts/zai_bridge.mjs   (long-lived; launch inside one shell call)
 */

import http from "node:http";

const PORT = Number(process.env.ZAI_BRIDGE_PORT || 9825);
const MODEL = process.env.ZAI_BRIDGE_MODEL || "glm-4.6";
const DELAY_MS = Number(process.env.ZAI_BRIDGE_DELAY_MS || 400);
const BRIDGE_KEY = process.env.ZAI_BRIDGE_KEY || "";
const ZAI_SDK_PATH = process.env.ZAI_SDK_PATH ||
  "/home/z/.bun/install/global/node_modules/z-ai-web-dev-sdk/dist/index.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let _gate = Promise.resolve();
function gated(fn) {
  const run = _gate.then(fn, fn);   // a failed predecessor must not poison the queue
  _gate = run.then(() => sleep(DELAY_MS), () => sleep(DELAY_MS));
  return run;
}

let _zai = null;
async function zai() {
  if (!_zai) {
    const mod = await import(ZAI_SDK_PATH);
    const ZAI = mod.default ?? mod;
    _zai = await ZAI.create();
  }
  return _zai;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => { data += c; });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function normalizeMessages(messages) {
  // OpenAI shape in — the SDK accepts the same shape; only coerce tool messages that
  // some agents emit with null content.
  return (messages || []).map((m) => {
    if (m.role === "tool" && (m.content === null || m.content === undefined)) {
      return { ...m, content: "" };
    }
    return m;
  });
}

const server = http.createServer(async (req, res) => {
  if (BRIDGE_KEY) {
    const auth = req.headers.authorization || "";
    if (auth !== `Bearer ${BRIDGE_KEY}`) {
      return json(res, 401, { error: { message: "bad bridge key" } });
    }
  }

  if (req.method === "GET" && req.url.startsWith("/v1/models")) {
    return json(res, 200, { object: "list", data: [
      { id: MODEL, object: "model", owned_by: "zai-bridge" },
    ] });
  }

  if (req.method === "POST" && req.url.startsWith("/v1/chat/completions")) {
    let body;
    try {
      body = JSON.parse((await readBody(req)) || "{}");
    } catch {
      return json(res, 400, { error: { message: "invalid JSON" } });
    }
    const messages = normalizeMessages(body.messages);
    const started = Date.now();
    try {
      const client = await zai();
      const result = await gated(() => client.chat.completions.create({
        model: MODEL,
        messages,
        temperature: body.temperature ?? 0.2,
        ...(body.max_tokens ? { max_tokens: body.max_tokens } : {}),
        ...(body.tools ? { tools: body.tools } : {}),
        ...(body.tool_choice ? { tool_choice: body.tool_choice } : {}),
      }));
      // SDK returns an OpenAI-ish shape; normalize the parts the fleet actually reads.
      const choice = (result?.choices || [])[0] || {};
      const message = choice.message || { role: "assistant", content: "" };
      if (message.content === null || message.content === undefined) {
        message.content = "";
      }
      const out = {
        id: result?.id || `bridge-${Date.now()}`,
        object: "chat.completion",
        model: MODEL,
        choices: [{
          index: 0,
          message,
          finish_reason: choice.finish_reason || "stop",
        }],
        usage: result?.usage || {
          prompt_tokens: 0, completion_tokens: 0, total_tokens: 0,
        },
      };
      console.log(`[bridge] ${body.model || MODEL} ${Date.now() - started}ms ` +
                  `msgs=${messages.length} tools=${(body.tools || []).length} ` +
                  `finish=${out.choices[0].finish_reason}`);
      return json(res, 200, out);
    } catch (err) {
      const text = String(err?.message || err);
      const status = /\b429\b/.test(text) ? 429 : 502;
      console.error(`[bridge] ERROR ${status}: ${text.slice(0, 300)}`);
      return json(res, status, { error: { message: text.slice(0, 500) } });
    }
  }

  return json(res, 404, { error: { message: `no route: ${req.method} ${req.url}` } });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`[bridge] listening on http://127.0.0.1:${PORT}/v1 ` +
              `(model=${MODEL}, delay=${DELAY_MS}ms${BRIDGE_KEY ? ", auth=on" : ", auth=off"})`);
});
