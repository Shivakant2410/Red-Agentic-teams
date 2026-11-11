//! llmred-kernel — the computational kernel of LLMRed.
//!
//! Three engines, one contract:
//! - `scan`      traffic/evidence processing: one Aho-Corasick pass over a
//!               transcript finds every canary encoding (plain, base64,
//!               base64-nopad, rot13, unicode-tags, zero-width) — the hot
//!               loop behind the oracle layer;
//! - `graph`     dynamic attack-graph planner: Kahn layering + transitive
//!               dead-state detection + next-frontier selection;
//! - `coverage`  greedy max-coverage under budget (what to run first).
//!
//! Protocol: one JSON job per stdin line, one JSON result per stdout line,
//! flushed immediately — the Python bridge keeps a persistent process and
//! pipelines jobs. The kernel reports spans, indices and plans; it NEVER
//! emits a verdict — the three-verdict contract (SUCCEEDED / RESISTED /
//! INCONCLUSIVE) stays in the auditable Python layer. Determinism: same
//! input ⇒ same output, always; no clocks, no RNG, no parallel reduction.

use llmred_kernel::{coverage, graph, scan};

use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const CONTRACT: u32 = 1;

#[derive(Deserialize)]
struct Job {
    op: String,
    #[serde(default)]
    params: Value,
}

fn handle_job(job: &Job) -> Value {
    let res = match job.op.as_str() {
        "scan_canaries" => scan::handle(&job.params),
        "plan_attack_graph" => graph::handle(&job.params),
        "optimize_coverage" => coverage::handle(&job.params),
        other => Err(format!("unknown op: {other}")),
    };
    match res {
        Ok(v) => json!({
            "contract": CONTRACT,
            "kernel_version": env!("CARGO_PKG_VERSION"),
            "result": v
        }),
        Err(e) => json!({"contract": CONTRACT, "error": e}),
    }
}

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let result = match serde_json::from_str::<Job>(&line) {
            Ok(job) => handle_job(&job),
            Err(e) => json!({"contract": CONTRACT, "error": format!("bad job: {e}")}),
        };
        if writeln!(out, "{result}").is_err() {
            break;
        }
        let _ = out.flush();
    }
}
