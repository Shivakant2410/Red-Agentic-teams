//! Dynamic attack-graph planner.
//!
//! Nodes are attack states `(technique, stage)` supplied by the caller with
//! `requires` edges (predecessor states + capability labels such as
//! `memory_surface` or `tool_ledger`). `achieved` carries what is already
//! proven (capabilities of the deployment + stages with evidence). The
//! planner answers, deterministically:
//! - `ready_now`: next runnable frontier (requires all satisfied by
//!   `achieved`), ordered score-desc then id-asc, capped by `budget`;
//! - `levels`: full Kahn layering of the reachable graph (the run order when
//!   every reachable node eventually succeeds);
//! - `dead`: states that can NEVER fire in this deployment, transitively —
//!   any require that is neither a node, nor achieved, nor itself alive kills
//!   the node (this is the PERSISTED dead-stage lesson, generalized: no
//!   memory surface ⇒ every PERSISTED state is provably dead before the run);
//! - `dead_reasons`: the first blocking require per dead node (deterministic:
//!   requires-list order);
//! - `stalled`: alive but trapped in a require cycle — never schedulable.
//!
//! The kernel layers and prunes; it never claims a stage WILL succeed.

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
pub struct Node {
    pub id: String,
    pub score: f64,
    pub requires: Vec<String>,
}

fn parse_nodes(v: &Value) -> Result<Vec<Node>, String> {
    let arr = v
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or("params.nodes missing")?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut nodes = Vec::with_capacity(arr.len());
    for n in arr {
        let id = n
            .get("id")
            .and_then(Value::as_str)
            .ok_or("node.id missing")?
            .to_string();
        if !seen.insert(id.clone()) {
            return Err(format!("duplicate node id: {id}"));
        }
        let mut requires: Vec<String> = n
            .get("requires")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        requires.sort();
        requires.dedup();
        nodes.push(Node {
            id,
            score: n.get("score").and_then(Value::as_f64).unwrap_or(0.0),
            requires,
        });
    }
    Ok(nodes)
}

fn order_key(a: &&Node, b: &&Node) -> std::cmp::Ordering {
    a.score
        .partial_cmp(&b.score)
        .unwrap_or(std::cmp::Ordering::Equal)
        .reverse()
        .then(a.id.cmp(&b.id))
}

pub fn plan(nodes: &[Node], achieved: &[&str], budget: usize) -> Value {
    let ids: HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
    let achieved_set: HashSet<&str> = achieved.iter().copied().collect();

    // Transitive dead-marking to fixpoint.
    let mut dead: HashSet<String> = HashSet::new();
    loop {
        let mut changed = false;
        for n in nodes {
            if dead.contains(&n.id) {
                continue;
            }
            let blocked = n.requires.iter().find(|r| {
                let known = ids.contains(r.as_str()) || achieved_set.contains(r.as_str());
                !known || dead.contains(*r)
            });
            if blocked.is_some() {
                dead.insert(n.id.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Dead reason: the first require that is unknown or dead.
    let mut dead_reasons: HashMap<String, String> = HashMap::new();
    for n in nodes {
        if let Some(r) = n.requires.iter().find(|r| {
            let known = ids.contains(r.as_str()) || achieved_set.contains(r.as_str());
            !known || dead.contains(*r)
        }) {
            if dead.contains(&n.id) {
                dead_reasons.insert(n.id.clone(), r.clone());
            }
        }
    }

    // Kahn layering over alive, unachieved nodes.
    let mut indeg: HashMap<&str, usize> = HashMap::new();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
    for n in nodes {
        if dead.contains(&n.id) || achieved_set.contains(n.id.as_str()) {
            continue;
        }
        let d = n
            .requires
            .iter()
            .filter(|r| {
                !achieved_set.contains(r.as_str())
                    && ids.contains(r.as_str())
                    && !dead.contains(r.as_str())
            })
            .count();
        indeg.insert(n.id.as_str(), d);
        for r in n.requires.iter() {
            if !achieved_set.contains(r.as_str())
                && ids.contains(r.as_str())
                && !dead.contains(r.as_str())
            {
                dependents.entry(r.as_str()).or_default().push(n.id.as_str());
            }
        }
    }

    let score_of: HashMap<&str, f64> = nodes.iter().map(|n| (n.id.as_str(), n.score)).collect();
    let mut frontier: Vec<&str> = indeg
        .iter()
        .filter(|(_, &d)| d == 0)
        .map(|(id, _)| *id)
        .collect();
    frontier.sort_by(|a, b| {
        let (sa, sb) = (score_of.get(a).copied().unwrap_or(0.0), score_of.get(b).copied().unwrap_or(0.0));
        sb.partial_cmp(&sa)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.cmp(b))
    });

    let mut levels: Vec<Vec<String>> = Vec::new();
    let mut leveled: HashSet<String> = HashSet::new();
    while !frontier.is_empty() {
        levels.push(frontier.iter().map(|s| s.to_string()).collect());
        for id in &frontier {
            leveled.insert(id.to_string());
        }
        let mut next: Vec<&str> = Vec::new();
        for id in &frontier {
            if let Some(deps) = dependents.get(*id) {
                for d in deps.clone() {
                    if let Some(dd) = indeg.get_mut(d) {
                        *dd -= 1;
                        if *dd == 0 {
                            next.push(d);
                        }
                    }
                }
            }
        }
        next.sort_by(|a, b| {
            let (sa, sb) = (score_of.get(a).copied().unwrap_or(0.0), score_of.get(b).copied().unwrap_or(0.0));
            sb.partial_cmp(&sa)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.cmp(b))
        });
        frontier = next;
    }

    // ready_now: next runnable frontier given `achieved` only.
    let mut ready_now: Vec<&Node> = nodes
        .iter()
        .filter(|n| {
            !dead.contains(&n.id)
                && !achieved_set.contains(n.id.as_str())
                && n.requires.iter().all(|r| achieved_set.contains(r.as_str()))
        })
        .collect();
    ready_now.sort_by(order_key);
    ready_now.truncate(budget);

    let mut stalled: Vec<String> = nodes
        .iter()
        .filter(|n| {
            !dead.contains(&n.id)
                && !achieved_set.contains(n.id.as_str())
                && !leveled.contains(&n.id)
        })
        .map(|n| n.id.clone())
        .collect();
    stalled.sort();

    let mut dead_list: Vec<String> = dead.into_iter().collect();
    dead_list.sort();
    let reasons: Vec<Value> = dead_list
        .iter()
        .map(|id| {
            json!({
                "node": id,
                "missing": dead_reasons.get(id).cloned().unwrap_or_default(),
            })
        })
        .collect();

    json!({
        "levels": levels,
        "ready_now": ready_now.iter().map(|n| n.id.clone()).collect::<Vec<_>>(),
        "dead": dead_list,
        "dead_reasons": reasons,
        "stalled": stalled,
    })
}

pub fn handle(params: &Value) -> Result<Value, String> {
    let nodes = parse_nodes(params)?;
    let achieved: Vec<String> = params
        .get("achieved")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let budget = params
        .get("budget")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX) as usize;
    let achieved_refs: Vec<&str> = achieved.iter().map(String::as_str).collect();
    Ok(plan(&nodes, &achieved_refs, budget))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, score: f64, requires: &[&str]) -> Node {
        Node {
            id: id.to_string(),
            score,
            requires: requires.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn dead_stage_without_capability() {
        // The PERSISTED lesson: no memory_surface ⇒ every PERSISTED state dies.
        let nodes = vec![
            node("PI.A1#EXPOSED", 1.0, &[]),
            node("PI.A1#RELAYED", 2.0, &["PI.A1#EXPOSED"]),
            node("PI.B6#EXPOSED", 1.0, &[]),
            node("PI.B6#PERSISTED", 2.0, &["PI.B6#EXPOSED", "memory_surface"]),
        ];
        let out = plan(&nodes, &[], 10);
        assert_eq!(out["dead"].as_array().unwrap().len(), 1);
        assert_eq!(out["dead"][0], "PI.B6#PERSISTED");
        let reasons = out["dead_reasons"].as_array().unwrap();
        assert_eq!(reasons[0]["missing"], "memory_surface");
        assert_eq!(out["levels"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn alive_with_capability() {
        let nodes = vec![
            node("PI.B6#EXPOSED", 1.0, &[]),
            node("PI.B6#PERSISTED", 2.0, &["PI.B6#EXPOSED", "memory_surface"]),
            node("PI.B6#EXECUTED", 3.0, &["PI.B6#PERSISTED", "tool_ledger"]),
        ];
        let out = plan(&nodes, &["memory_surface", "tool_ledger"], 10);
        assert_eq!(out["dead"].as_array().unwrap().len(), 0);
        let ready = out["ready_now"].as_array().unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], "PI.B6#EXPOSED");
        assert_eq!(out["levels"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn achieved_shrinks_levels_and_selects_ready_now() {
        let nodes = vec![
            node("A#EXPOSED", 1.0, &[]),
            node("A#RELAYED", 2.0, &["A#EXPOSED"]),
            node("B#EXPOSED", 1.5, &[]),
        ];
        let out = plan(&nodes, &["A#EXPOSED"], 10);
        // score desc: A#RELAYED (2.0) before B#EXPOSED (1.5).
        assert_eq!(out["ready_now"], json!(["A#RELAYED", "B#EXPOSED"]));
    }

    #[test]
    fn budget_caps_ready_now() {
        let nodes = vec![node("a", 1.0, &[]), node("b", 1.0, &[]), node("c", 1.0, &[])];
        let out = plan(&nodes, &[], 2);
        assert_eq!(out["ready_now"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn cycle_is_stalled_not_dead() {
        let nodes = vec![
            node("a", 1.0, &["b"]),
            node("b", 1.0, &["a"]),
            node("c", 1.0, &[]),
        ];
        let out = plan(&nodes, &[], 10);
        assert_eq!(out["dead"].as_array().unwrap().len(), 0);
        assert_eq!(out["stalled"], json!(["a", "b"]));
        assert_eq!(out["levels"][0], json!(["c"]));
    }

    #[test]
    fn dead_blocks_descendants_transitively() {
        let nodes = vec![
            node("a#EXPOSED", 1.0, &[]),
            node("a#PERSISTED", 2.0, &["a#EXPOSED", "memory_surface"]),
            node("a#EXECUTED", 3.0, &["a#PERSISTED", "tool_ledger"]),
        ];
        let out = plan(&nodes, &[], 10);
        // PERSISTED dies (no memory surface) → EXECUTED dies through it.
assert_eq!(out["dead"], json!(["a#EXECUTED", "a#PERSISTED"]));
        // dead_list is sorted: [a#EXECUTED, a#PERSISTED]. a#EXECUTED's first
        // blocking require (requires order) is a#PERSISTED (dead); a#PERSISTED's
        // is the unknown capability label memory_surface.
        assert_eq!(out["dead_reasons"][0]["missing"], "a#PERSISTED");
        assert_eq!(out["dead_reasons"][1]["missing"], "memory_surface");
    }
}
