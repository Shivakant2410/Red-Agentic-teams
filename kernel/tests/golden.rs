use llmred_kernel::coverage::optimize;
use serde_json::json;
use llmred_kernel::graph::{plan, Node};
use llmred_kernel::scan::scan;

fn node(id: &str, score: f64, requires: &[&str]) -> Node {
    Node {
        id: id.to_string(),
        score,
        requires: requires.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn golden_full_pipeline() {
    // scan: transcript with plain + smuggled canary
    let canary = "canary-9f2c";
    let mut text = String::from("system prompt ... ");
    text.push_str(canary);
    text.push(' ');
    text.push_str(&llmred_kernel::variants::tag_encode(canary));
    let hits = scan(&text, &[canary.to_string()]).unwrap();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].variant, "plain");
    assert_eq!(hits[0].pos, 18);
    assert_eq!(hits[1].variant, "unicode_tags");

    // graph: memory-poisoning path dies without a memory surface
    let nodes = vec![
        node("PI.B6#EXPOSED", 1.0, &[]),
        node("PI.B6#PERSISTED", 2.0, &["PI.B6#EXPOSED", "memory_surface"]),
        node("PI.B6#EXECUTED", 3.0, &["PI.B6#PERSISTED", "tool_ledger"]),
        node("PI.A1#EXPOSED", 1.0, &[]),
        node("PI.A1#RELAYED", 2.0, &["PI.A1#EXPOSED"]),
        node("PI.A1#EXECUTED", 3.0, &["PI.A1#RELAYED", "tool_ledger"]),
    ];
    let out = plan(&nodes, &["memory_surface", "tool_ledger"], 50);
    assert_eq!(out["dead"].as_array().unwrap().len(), 0);
    assert_eq!(out["ready_now"][0], "PI.A1#EXPOSED"); // 1.0 vs 1.0 → id asc

    let out_no_mem = plan(&nodes, &["tool_ledger"], 50);
assert_eq!(out_no_mem["dead"], json!(["PI.B6#EXECUTED", "PI.B6#PERSISTED"]));

    // coverage
    let items_json = serde_json::json!({
        "items": [
            {"id": "p1", "score": 1.0, "covers": ["PI.A1", "PI.B6"]},
            {"id": "p2", "score": 2.0, "covers": ["PI.A1"]},
            {"id": "p3", "score": 1.0, "covers": ["PI.E4"]}
        ],
        "budget": 2
    });
    let items = llmred_kernel::coverage::handle(&items_json).unwrap();
    assert_eq!(items["selected"], json!(["p1", "p3"]));
    let _ = optimize(&[], 1);
}
