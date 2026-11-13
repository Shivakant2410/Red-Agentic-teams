//! Traffic/evidence scanner: one Aho-Corasick pass finds every canary variant
//! occurrence in a transcript. This is the hot loop `oracles.canary_hits`
//! runs per cell per probe — O(transcript) instead of O(transcript × needles).
//!
//! Semantics contract (must equal Python exactly):
//! - case-insensitive: both haystack and needles are lowercased first
//!   (Python: `low = text.lower()`, `needle.lower()`), and reported `pos` is
//!   a CHARACTER offset into the lowercased haystack — same as Python's
//!   `low.find`.
//! - overlapping matches count (Python steps `start = idx + 1`).
//! - output is grouped by canary then by variant in the canonical variant
//!   order, positions ascending within a variant.
//! - the scanner reports spans; it never decides anything.

use crate::variants::{lower, variants};
use aho_corasick::AhoCorasick;
use serde_json::{json, Value};

pub struct Hit {
    pub canary_index: usize,
    pub variant: &'static str,
    pub pos: usize,
    pub len: usize,
}

pub fn scan(text: &str, canaries: &[String]) -> Result<Vec<Hit>, String> {
    if canaries.is_empty() || text.is_empty() {
        return Ok(Vec::new());
    }
    let hay = lower(text);

    // byte offset -> char offset map for the lowercased haystack. Valid-UTF-8
    // patterns can only match at char boundaries, so interior bytes never get
    // looked up; the last slot maps the one-past-the-end byte.
    let mut map: Vec<u32> = vec![0; hay.len() + 1];
    let mut ci: u32 = 0;
    for (bi, _) in hay.char_indices() {
        map[bi] = ci;
        ci += 1;
    }
    map[hay.len()] = ci;

    // One pattern instance per (canary, variant), in canonical order.
    let mut needles: Vec<String> = Vec::new();
    let mut owner: Vec<(usize, &'static str)> = Vec::new();
    for (ci, canary) in canaries.iter().enumerate() {
        for (name, needle) in variants(canary) {
            if needle.is_empty() {
                continue;
            }
            needles.push(lower(&needle));
            owner.push((ci, name));
        }
    }
    if needles.is_empty() {
        return Ok(Vec::new());
    }

    let ac = AhoCorasick::builder()
        .match_kind(aho_corasick::MatchKind::Standard)
        .build(&needles)
        .map_err(|e| format!("automaton build failed: {e}"))?;

    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); needles.len()];
    for mat in ac.find_overlapping_iter(hay.as_bytes()) {
        let pi = mat.pattern().as_usize();
        buckets[pi].push(map[mat.start()] as usize);
    }

    let mut hits = Vec::new();
    for (pi, positions) in buckets.iter().enumerate() {
        let (canary_index, variant) = owner[pi];
        for &pos in positions {
            hits.push(Hit {
                canary_index,
                variant,
                pos,
                len: needles[pi].chars().count(),
            });
        }
    }
    Ok(hits)
}

pub fn handle(params: &Value) -> Result<Value, String> {
    let text = params
        .get("text")
        .and_then(Value::as_str)
        .ok_or("params.text missing")?;
    let canaries: Vec<String> = params
        .get("canaries")
        .and_then(Value::as_array)
        .ok_or("params.canaries missing")?
        .iter()
        .map(|c| c.as_str().unwrap_or_default().to_string())
        .collect();
    let hits = scan(text, &canaries)?;
    Ok(json!({
        "hits": hits.iter().map(|h| json!({
            "canary_index": h.canary_index,
            "variant": h.variant,
            "pos": h.pos,
            "len": h.len,
        })).collect::<Vec<_>>()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> String {
        s.to_string()
    }

    #[test]
    fn overlapping_positions_match_python_semantics() {
        // Python `find` loop with start=idx+1 finds "aa" in "aaa" at 0 AND 1.
        let hits = scan("aaa", &[c("aa")]).unwrap();
        let poss: Vec<usize> = hits.iter().map(|h| h.pos).collect();
        assert_eq!(poss, vec![0, 1]);
    }

    #[test]
    fn ten_variants_found() {
        let canary = "can-123";
        let mut text = String::from("noise ");
        for (_, needle) in crate::variants::variants(canary) {
            text.push_str(&needle);
            text.push(' ');
        }
        let hits = scan(&text, &[c(canary)]).unwrap();
        let names: Vec<&str> = hits.iter().map(|h| h.variant).collect();
        for v in [
            "plain", "base64", "base64-nopad", "rot13", "unicode_tags",
            "zero_width", "atbash", "caesar1", "caesar3", "caesar25",
        ] {
            assert!(names.contains(&v), "missing variant {v}");
        }
    }

    #[test]
    fn case_insensitive_and_char_positions() {
        // 'É' is 2 bytes in UTF-8; a match after it must still report the
        // CHARACTER offset (Python str.find semantics).
        let hits = scan("É CANARY-AB", &[c("canary-ab")]).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pos, 2);
    }

    #[test]
    fn empty_inputs() {
        assert!(scan("", &[c("x")]).unwrap().is_empty());
        assert!(scan("text", &[]).unwrap().is_empty());
        assert!(scan("text", &[c("")]).unwrap().is_empty());
    }

    #[test]
    fn near_miss_never_counts() {
        // Different suffix / case-flipped prefix must not match — the
        // false-positive control the spec demands.
        assert!(scan("CANARY-AC CANARY-a", &[c("canary-ab")]).unwrap().is_empty());
    }
}
