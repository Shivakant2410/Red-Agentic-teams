"""Live recon view — the any.run-style window onto a running RECON specialist.

Two parts:

``recon_live_snapshot(run_dir)`` — one JSON snapshot the viewer polls:
  the browser's latest JPEG frame (<run>/recon_live/latest.jpg, refreshed by
  the controller on every navigate/click/fill/screenshot), the activity feed
  (<run>/recon_live/events.jsonl), a compact network tail from traffic.jsonl,
  observation-log counts (corroborated vs unverified leads) and the run's
  manifest progress. Everything is read from run artifacts — the server stays
  decoupled from the engine (same rule as /traffic and /proxy).

``LIVE_VIEW_HTML`` — a self-contained viewer (no build step, inline CSS/JS)
served at ``GET /live/{run_id}``. Responsive: single column on a phone, two
columns from ~760px; every table scrolls inside its own container.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from .traffic import read_traffic

_EVENTS_TAIL = 60
_TRAFFIC_TAIL = 30
_OBS_TAIL = 20


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _read_jsonl_tail(path: Path, limit: int) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    return rows[-limit:][::-1]


def recon_live_snapshot(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    live_dir = run_dir / "recon_live"
    frame_b64 = ""
    frame_path = live_dir / "latest.jpg"
    if frame_path.exists() and frame_path.stat().st_size > 0:
        try:
            frame_b64 = base64.b64encode(frame_path.read_bytes()).decode("ascii")
        except OSError:
            frame_b64 = ""
    manifest = _read_json(run_dir / "manifest.json", {}) or {}

    traffic = []
    try:
        traffic = read_traffic(run_dir / "traffic.jsonl", after=0, limit=100000)
    except Exception:
        traffic = []
    by_source: dict[str, int] = {}
    for row in traffic:
        src = row.get("source") or "fetch"
        by_source[src] = by_source.get(src, 0) + 1
    tail = [{
        "seq": r.get("seq"), "method": r.get("method"), "url": r.get("url"),
        "status": r.get("status"), "source": r.get("source") or "fetch",
        "tool": r.get("tool", ""),
    } for r in traffic[-_TRAFFIC_TAIL:]][::-1]

    obs_rows = _read_jsonl_tail(run_dir / "observations.jsonl", 400)
    by_validation: dict[str, int] = {}
    latest_by_key: dict[str, dict] = {}
    for row in obs_rows:
        key = f"{row.get('type')}|{row.get('target')}|{row.get('method', '')}"
        latest_by_key[key] = row
    for row in latest_by_key.values():
        state = row.get("validation", "discovered")
        by_validation[state] = by_validation.get(state, 0) + 1
    obs_sample = [{"type": r.get("type"), "target": r.get("target"),
                   "mode": r.get("mode"), "validation": r.get("validation"),
                   "source_tool": r.get("source_tool")}
                  for r in list(latest_by_key.values())[-_OBS_TAIL:]][::-1]

    return {
        "run_id": run_dir.name,
        "status": manifest.get("status", "unknown"),
        "driver": manifest.get("driver", ""),
        "steps": manifest.get("steps"),
        "tokens": manifest.get("tokens"),
        "halt_reason": manifest.get("halt_reason", ""),
        "frame_jpeg_b64": frame_b64,
        "frame_updated": _read_json(live_dir / "latest.json", None),
        "activity": _read_jsonl_tail(live_dir / "events.jsonl", _EVENTS_TAIL),
        "network": {"total": len(traffic), "by_source": by_source,
                    "rows": tail},
        "observations": {"by_validation": by_validation,
                         "unique": len(latest_by_key),
                         "rows": obs_sample},
    }


LIVE_VIEW_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Live recon — __RUN_ID__</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --edge:#21262d; --ink:#c9d1d9;
          --dim:#8b949e; --live:#3fb950; --warn:#d29922; --bad:#f85149;
          --accent:#58a6ff; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
         font: clamp(13px, 1.5vw, 15px)/1.45 ui-sans-serif, system-ui, sans-serif; }
  header { display:flex; flex-wrap:wrap; gap:.5rem 1rem; align-items:center;
           padding:.6rem .9rem; border-bottom:1px solid var(--edge);
           background:var(--panel); position:sticky; top:0; z-index:5; }
  header h1 { font-size: clamp(15px, 2.4vw, 19px); margin:0; }
  .badge { padding:.15rem .6rem; border-radius:999px; border:1px solid var(--edge);
           font-size:clamp(11px,1.3vw,13px); color:var(--dim); }
  .badge.live { color:var(--live); border-color:var(--live); }
  .dot { display:inline-block; width:.55em; height:.55em; border-radius:50%;
         background:var(--live); margin-right:.35em; animation:pulse 1.4s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.25} }
  main { display:grid; grid-template-columns: minmax(320px, 1.35fr) minmax(280px, 1fr);
         gap:.8rem; padding:.8rem; max-width:1500px; margin:0 auto; }
  @media (max-width: 760px){ main { grid-template-columns: 1fr; } }
  section { background:var(--panel); border:1px solid var(--edge);
            border-radius:10px; overflow:hidden; }
  section h2 { margin:0; padding:.55rem .8rem; font-size:clamp(12px,1.4vw,14px);
               color:var(--dim); text-transform:uppercase; letter-spacing:.06em;
               border-bottom:1px solid var(--edge); }
  .frame { position:relative; background:#000; }
  .frame img { display:block; width:100%; height:auto; max-height:62vh;
               object-fit:contain; }
  .frame .nolive { padding:2.2rem 1rem; text-align:center; color:var(--dim); }
  .feed { max-height:34vh; overflow-y:auto; }
  .feed li { padding:.4rem .8rem; border-bottom:1px solid var(--edge);
             list-style:none; word-break:break-all; }
  .feed { margin:0; padding:0; }
  .feed time { color:var(--accent); font-variant-numeric:tabular-nums; }
  .scrollbox { max-height:48vh; overflow:auto; }
  table { width:100%; border-collapse:collapse; font-size:clamp(11px,1.2vw,13px); }
  th, td { text-align:left; padding:.35rem .6rem; border-bottom:1px solid var(--edge);
           white-space:nowrap; }
  td.url { max-width:34ch; overflow:hidden; text-overflow:ellipsis; }
  @media (max-width: 520px){ td.url { max-width:18ch; } }
  th { color:var(--dim); position:sticky; top:0; background:var(--panel); }
  .s200{color:var(--live)} .s3xx{color:var(--accent)} .s4xx{color:var(--warn)}
  .s5xx,.s0{color:var(--bad)}
  .pill { padding:.05rem .45rem; border-radius:999px; font-size:.85em;
          border:1px solid var(--edge); }
  .v-corroborated{color:var(--live);border-color:var(--live)}
  .v-contradicted{color:var(--bad);border-color:var(--bad)}
  .v-discovered,.v-awaiting_corroboration{color:var(--warn);border-color:var(--warn)}
  footer { padding:.55rem .9rem; color:var(--dim); border-top:1px solid var(--edge);
           display:flex; gap:1.2rem; flex-wrap:wrap; position:sticky; bottom:0;
           background:var(--panel); font-variant-numeric:tabular-nums; }
  .wrap { overflow-x:auto; }
</style>
</head>
<body>
<header>
  <h1>Live recon</h1>
  <span class="badge">run <b>__RUN_ID__</b></span>
  <span class="badge" id="status">connecting…</span>
  <span class="badge" id="stale"></span>
</header>
<main>
  <div>
    <section>
      <h2>Browser — live frame</h2>
      <div class="frame" id="framebox">
        <div class="nolive" id="nolive">waiting for the first browser frame…</div>
        <img id="frame" alt="live browser screenshot" style="display:none">
      </div>
    </section>
    <section style="margin-top:.8rem">
      <h2>Activity</h2>
      <ul class="feed" id="activity"></ul>
    </section>
  </div>
  <div>
    <section>
      <h2>Network (proxy + browser + fetch)</h2>
      <div class="wrap scrollbox">
        <table id="net"><thead><tr><th>seq</th><th>m</th><th>url</th>
          <th>st</th><th>src</th></tr></thead><tbody></tbody></table>
      </div>
    </section>
    <section style="margin-top:.8rem">
      <h2>Observations</h2>
      <div id="obscounts" style="padding:.5rem .8rem;color:var(--dim)"></div>
      <div class="wrap scrollbox">
        <table id="obs"><thead><tr><th>type</th><th>target</th><th>state</th>
          <th>src</th></tr></thead><tbody></tbody></table>
      </div>
    </section>
  </div>
</main>
<footer>
  <span id="fsteps">steps —</span><span id="ftok">tokens —</span>
  <span id="fnet">requests —</span><span id="fobs">observations —</span>
</footer>
<script>
const RUN = "__RUN_ID__";
const $ = id => document.getElementById(id);
function esc(s){ const d=document.createElement("div"); d.textContent=String(s??""); return d.innerHTML; }
function stClass(s){ return s===0?"s0":(s<300?"s200":s<400?"s3xx":s<500?"s4xx":"s5xx"); }
async function tick(){
  try{
    const r = await fetch(`/api/runs/${encodeURIComponent(RUN)}/recon/live`, {cache:"no-store"});
    const d = await r.json();
    $("status").innerHTML = d.status === "running"
      ? '<span class="dot"></span>LIVE' : "status: " + esc(d.status);
    $("stale").textContent = d.frame_updated ? ("last frame " + d.frame_updated.ts) : "";
    if (d.frame_jpeg_b64){
      $("frame").src = "data:image/jpeg;base64," + d.frame_jpeg_b64;
      $("frame").style.display = "block";
      $("nolive").style.display = "none";
    }
    $("activity").innerHTML = (d.activity||[]).slice(0,24).map(e =>
      `<li><time>${esc((e.ts||"").slice(11,19))}</time> <b>${esc(e.action)}</b> ` +
      `${esc(e.url||"")}${e.status!=null?` → ${esc(e.status)}`:""}</li>`).join("")
      || "<li><i>no browser activity yet</i></li>";
    const tb = $("net").querySelector("tbody");
    tb.innerHTML = (d.network?.rows||[]).map(r =>
      `<tr><td>${esc(r.seq)}</td><td>${esc(r.method)}</td>` +
      `<td class="url" title="${esc(r.url)}">${esc(r.url)}</td>` +
      `<td class="${stClass(r.status)}">${esc(r.status)}</td><td>${esc(r.source)}</td></tr>`).join("");
    const bc = d.observations?.by_validation || {};
    $("obscounts").innerHTML = Object.entries(bc).map(([k,v]) =>
      `<span class="pill v-${esc(k)}">${esc(k)}: ${v}</span>`).join(" ")
      + ` <span class="pill">unique: ${d.observations?.unique ?? 0}</span>`;
    const ob = $("obs").querySelector("tbody");
    ob.innerHTML = (d.observations?.rows||[]).map(o =>
      `<tr><td>${esc(o.type)}</td><td class="url" title="${esc(o.target)}">${esc(o.target)}</td>` +
      `<td><span class="pill v-${esc(o.validation)}">${esc(o.validation)}</span></td>` +
      `<td>${esc(o.source_tool)}</td></tr>`).join("");
    $("fsteps").textContent = "steps " + (d.steps ?? "—");
    $("ftok").textContent = "tokens " + (d.tokens ?? "—");
    $("fnet").textContent = "requests " + (d.network?.total ?? 0);
    $("fobs").textContent = "observations " + (d.observations?.unique ?? 0);
  }catch(err){ $("status").textContent = "poll error: " + err; }
}
tick();
setInterval(tick, 1500);
</script>
</body>
</html>
"""
