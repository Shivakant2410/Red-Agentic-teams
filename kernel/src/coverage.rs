//! Coverage optimizer: greedy max-coverage under a budget — which payload
//! cells to run first so the oracle machinery discriminates the most labels
//! per cell spent. Deterministic tie-break: (new labels desc, score desc,
//! id asc). The `selected` list is in pick order (marginal-gain order), the
//! same order the Python reference emits.

use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};

pub struct Item {
    pub id: String,
    pub score: f64,
    pub covers: Vec<String>,
}

fn parse_items(v: &Value) -> Result<Vec<Item>, String> {
    let arr = v
        .get("items")
        .and_then(Value::as_array)
        .ok_or("params.items missing")?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut items = Vec::with_capacity(arr.len());
    for it in arr {
        let id = it
            .get("id")
            .and_then(Value::as_str)
            .ok_or("item.id missing")?
            .to_string();
        if !seen.insert(id.clone()) {
            return Err(format!("duplicate item id: {id}"));
        }
        items.push(Item {
            id,
            score: it.get("score").and_then(Value::as_f64).unwrap_or(0.0),
            covers: it
                .get("covers")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    Ok(items)
}

pub fn optimize(items: &[Item], budget: usize) -> Value {
    let mut covered: HashSet<String> = HashSet::new();
    let mut selected: Vec<String> = Vec::new();
    let mut chosen: HashSet<String> = HashSet::new();
    for _ in 0..budget {
        let mut best: Option<&Item> = None;
        let mut best_new: usize = 0;
        for it in items {
            if chosen.contains(&it.id) {
                continue;
            }
            let new = it.covers.iter().filter(|l| !covered.contains(*l)).count();
            if new == 0 {
                continue;
            }
            let take = match best {
                None => true,
                Some(b) => {
                    new > best_new
                        || (new == best_new
                            && (it.score > b.score
                                || (it.score == b.score && it.id < b.id)))
                }
            };
            if take {
                best = Some(it);
                best_new = new;
            }
        }
        match best {
            None => break,
            Some(it) => {
                for l in &it.covers {
                    covered.insert(l.clone());
                }
                chosen.insert(it.id.clone());
                selected.push(it.id.clone());
            }
        }
    }
    let all: BTreeSet<String> = items.iter().flat_map(|i| i.covers.iter().cloned()).collect();
    let uncovered: Vec<String> = all
        .iter()
        .filter(|l| !covered.contains(l.as_str()))
        .cloned()
        .collect();
    let mut covered_labels: Vec<String> = covered.into_iter().collect();
    covered_labels.sort();
    json!({
        "selected": selected,
        "covered_labels": covered_labels,
        "uncovered": uncovered,
    })
}

pub fn handle(params: &Value) -> Result<Value, String> {
    let items = parse_items(params)?;
    let budget = params
        .get("budget")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX) as usize;
    Ok(optimize(&items, budget))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, score: f64, covers: &[&str]) -> Item {
        Item {
            id: id.to_string(),
            score,
            covers: covers.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn greedy_picks_max_marginal_gain() {
        let items = vec![
            item("a", 1.0, &["s1", "s2"]),
            item("b", 5.0, &["s1"]),
            item("c", 1.0, &["s3"]),
        ];
        let out = optimize(&items, 2);
        assert_eq!(out["selected"], json!(["a", "c"]));
        assert_eq!(out["uncovered"], json!([]));
    }

    #[test]
    fn tie_break_score_then_id() {
        let items = vec![
            item("z", 2.0, &["s1"]),
            item("y", 2.0, &["s1"]),
            item("x", 3.0, &["s2"]),
        ];
        let out = optimize(&items, 2);
        assert_eq!(out["selected"], json!(["x", "y"])); // score 3 first, then tie 2.0 → id asc
    }

    #[test]
    fn budget_respected_and_uncovered_reported() {
        let items = vec![
            item("a", 1.0, &["s1"]),
            item("b", 1.0, &["s2"]),
            item("c", 1.0, &["s3"]),
        ];
        let out = optimize(&items, 1);
        assert_eq!(out["selected"], json!(["a"]));
        assert_eq!(out["uncovered"], json!(["s2", "s3"]));
    }

    #[test]
    fn empty_items() {
        let out = optimize(&[], 5);
        assert_eq!(out["selected"], json!([]));
    }
}
