//! Property + differential fuzz for the scan engine — the Rust-side half of
//! `kernel/fuzz/fuzz_scan.py`. Deterministic (inline xorshift64*, no deps, no
//! nightly, no libFuzzer): every seed replays identically, so a failure is a
//! reproducer by construction.
//!
//! Three properties, per iteration:
//!   INVARIANT      every reported hit slice-matches its variant's needle in
//!                  the LOWERED haystack at [pos, pos+len) — char offsets,
//!                  strictly ascending per (canary, variant), len == needle
//!                  char count, inside bounds;
//!   DIFFERENTIAL   kernel hits == brute-force search exactly (values AND
//!                  order) on small haystacks — the Aho-Corasick automaton
//!                  is cross-checked against a naive scanner;
//!   NO-PANIC       adversarial unicode soup (zero-width family, tag plane,
//!                  CJK, emoji, combining marks, RTL) never panics.

use llmred_kernel::scan::scan;
use llmred_kernel::variants::{lower, variants};

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

fn make_canary(rng: &mut XorShift) -> String {
    let hex: Vec<char> = "0123456789abcdef".chars().collect();
    let mut c = String::from("pic-");
    for _ in 0..16 {
        c.push(hex[rng.below(16)]);
    }
    c
}

const JUNK: &[&str] = &["noise ", "memo ... ", "junk\t", "tail ",
                        "system prompt ... ", "x"];

fn gen_soup(rng: &mut XorShift, n: usize) -> String {
    let ascii: Vec<char> = "abcdef0123456789 -_.:\n\tPIC".chars().collect();
    let wide: Vec<char> = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}',
                           '\u{FEFF}', '\u{00E9}', '\u{4E00}', '\u{1F600}',
                           '\u{0301}', '\u{05D0}', '\u{FF21}', '\u{E0041}',
                           '\u{E0061}']
        .to_vec();
    let mut out = String::new();
    for _ in 0..n {
        out.push(if rng.below(3) == 0 {
            *rng.pick(&wide)
        } else {
            *rng.pick(&ascii)
        });
    }
    out
}

fn gen_sandwich(rng: &mut XorShift, canaries: &[String]) -> String {
    let mut text = String::new();
    for _ in 0..rng.below(4) + 1 {
        text.push_str(rng.pick(JUNK));
        let canary = rng.pick(canaries);
        let vs = variants(canary);
        let (_, needle) = rng.pick(&vs);
        text.push_str(needle);
        text.push(' ');
    }
    text
}

fn gen_near_miss(rng: &mut XorShift, canaries: &[String]) -> String {
    let canary = rng.pick(canaries);
    let mut blob = variants(canary)[6].1.clone(); // "atbash"
    let bytes: Vec<char> = blob.chars().collect();
    let i = rng.below(bytes.len());
    let mut flipped = String::new();
    for (j, ch) in bytes.iter().enumerate() {
        flipped.push(if j == i && rng.below(2) == 0 { 'q' } else { *ch });
    }
    blob = flipped;
    blob.push(' ');
    blob.push_str(canary);
    blob
}

fn gen_patho(rng: &mut XorShift, canaries: &[String]) -> String {
    let canary = rng.pick(canaries);
    let k = rng.below(6) + 2;
    canary.repeat(k)
}

fn check_invariants(text: &str, canaries: &[String], hits: &[llmred_kernel::scan::Hit]) {
    let low = lower(text);
    let chars: Vec<char> = low.chars().collect();
    let mut last: std::collections::HashMap<(usize, String), usize> =
        std::collections::HashMap::new();
    for h in hits {
        let needle = variants(&canaries[h.canary_index])
            .into_iter()
            .find(|(name, _)| *name == h.variant)
            .map(|(_, n)| n)
            .unwrap_or_else(|| panic!("unknown variant {}", h.variant));
        let nl = lower(&needle);
        let nchars: Vec<char> = nl.chars().collect();
        assert_eq!(h.len, nchars.len(), "len != needle chars");
        assert!(h.pos + h.len <= chars.len(), "hit outside lowered haystack");
        assert_eq!(
            &chars[h.pos..h.pos + h.len],
            &nchars[..],
            "hit does not slice-match"
        );
        let key = (h.canary_index, h.variant.to_string());
        let prev = last.insert(key, h.pos);
        if let Some(p) = prev {
            assert!(h.pos > p, "positions not strictly ascending per variant");
        }
    }
}

/// Brute-force reference: overlapping find of every lowered needle over the
/// lowered haystack (char offsets), in the kernel's canonical order.
fn brute_force(text: &str, canaries: &[String]) -> Vec<(usize, String, usize)> {
    let low = lower(text);
    let hay: Vec<char> = low.chars().collect();
    let mut out = Vec::new();
    for (ci, canary) in canaries.iter().enumerate() {
        for (name, needle) in variants(canary) {
            let nl: Vec<char> = lower(&needle).chars().collect();
            if nl.is_empty() {
                continue;
            }
            for start in 0..hay.len() {
                if start + nl.len() > hay.len() {
                    break;
                }
                if hay[start..start + nl.len()] == nl[..] {
                    out.push((ci, name.to_string(), start));
                }
            }
        }
    }
    out
}

fn kernel_hits(text: &str, canaries: &[String]) -> Vec<(usize, String, usize)> {
    scan(text, canaries)
        .unwrap()
        .into_iter()
        .map(|h| (h.canary_index, h.variant.to_string(), h.pos))
        .collect()
}

#[test]
fn fuzz_scan_property_differential() {
    let mut rng = XorShift(0x5EED_2026_1114_0001);
    for i in 0..600 {
        let n_canaries = rng.below(3) + 1;
        let canaries: Vec<String> =
            (0..n_canaries).map(|_| make_canary(&mut rng)).collect();
        let gen = rng.below(4);
        let n = rng.below(300) + 1;
        let text = match gen {
            0 => gen_soup(&mut rng, n),
            1 => gen_sandwich(&mut rng, &canaries),
            2 => gen_near_miss(&mut rng, &canaries),
            _ => gen_patho(&mut rng, &canaries),
        };
        let hits = scan(&text, &canaries).unwrap();
        check_invariants(&text, &canaries, &hits);
        if text.chars().count() < 4_000 {
            assert_eq!(
                kernel_hits(&text, &canaries),
                brute_force(&text, &canaries),
                "kernel != brute force at iteration {i}: {text:?}"
            );
        }
    }
}

#[test]
fn fuzz_scan_no_panic_on_unicode_soup() {
    let mut rng = XorShift(0x5EED_2026_1114_0002);
    let canaries: Vec<String> = (0..2).map(|_| make_canary(&mut rng)).collect();
    for _ in 0..400 {
        let n = rng.below(2_000) + 1;
        let text = gen_soup(&mut rng, n);
        let _ = scan(&text, &canaries).unwrap();
    }
}

#[test]
fn kernel_binary_rejects_invalid_utf8_without_panic() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_llmred-kernel"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"{\"op\":\"scan_cana")?;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(&[0xFF, 0xFE, 0x80])?;
            child.stdin.take(); // EOF
            child.wait_with_output()
        })
        .expect("spawn kernel");
    assert!(out.status.success(), "invalid utf-8 must not panic the kernel");
    assert!(out.stdout.is_empty(), "truncated line is skipped silently");
}

#[test]
fn kernel_binary_answers_bad_json_with_error_envelope() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_llmred-kernel"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"this is not json\n")?;
            child.stdin.take();
            child.wait_with_output()
        })
        .expect("spawn kernel");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("\"error\""), "bad json -> error envelope, got {s}");
    assert!(!s.contains("\"result\""));
}
