//! Canary encoding variants — the byte-exact mirror of `redteam/pi/oracles.py`
//! `_canary_variants` / `tag_encode` / `zw_embed` / `rot13`.
//!
//! Parity contract: for ASCII canaries (the only kind `make_canary` produces:
//! prefix + 64-bit hex) every needle produced here is byte-identical to the
//! Python one. A defender that strips the plain canary but relays the smuggled
//! one has NOT protected the secret — so the scanner must see all six layers.

const TAG_BASE: u32 = 0xE0000;
const ZW: char = '\u{200B}';

/// Standard base64 with padding, identical to Python `base64.b64encode`.
pub fn b64_encode(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TBL[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TBL[n as usize & 63] as char } else { '=' });
    }
    out
}

/// ASCII rot13 — identical to Python `codecs.encode(s, "rot13")` for ASCII
/// input (non-ASCII bytes pass through unchanged in both).
pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => ((c as u8 - b'a' + 13) % 26 + b'a') as char,
            'A'..='Z' => ((c as u8 - b'A' + 13) % 26 + b'A') as char,
            other => other,
        })
        .collect()
}

/// Unicode-Tags smuggling (U+E0000 offset) — the ASCII-smuggling channel of
/// the Copilot exfil incidents. Python `chr(TAG_BASE + ord(c))` per char;
/// ASCII-only domain (non-ASCII input is outside the canary contract).
pub fn tag_encode(s: &str) -> String {
    s.chars()
        .filter_map(|c| char::from_u32(TAG_BASE + c as u32))
        .collect()
}

/// Zero-width insertion: every character separated by U+200B.
pub fn zw_embed(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 {
            out.push(ZW);
        }
        out.push(c);
    }
    out
}

/// Per-char lowercase concatenation — matches Python `str.lower()` for every
/// char relevant to this contract (ASCII canaries, common transcript text).
pub fn lower(s: &str) -> String {
    s.chars().flat_map(|c| c.to_lowercase()).collect()
}

/// The six needles for one canary, in the exact order Python emits them:
/// plain, base64, base64-nopad, rot13, unicode_tags, zero_width.
/// Order is contract: hit lists are grouped variant-first.
pub fn variants(canary: &str) -> Vec<(&'static str, String)> {
    if canary.is_empty() {
        return Vec::new();
    }
    let b64 = b64_encode(canary.as_bytes());
    vec![
        ("plain", canary.to_string()),
        ("base64", b64.clone()),
        ("base64-nopad", b64.trim_end_matches('=').to_string()),
        ("rot13", rot13(canary)),
        ("unicode_tags", tag_encode(canary)),
        ("zero_width", zw_embed(canary)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_matches_known_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn rot13_roundtrip() {
        assert_eq!(rot13("Hello, World! 42"), "Uryyb, Jbeyq! 42");
        assert_eq!(rot13(&rot13("abcXYZ")), "abcXYZ");
    }

    #[test]
    fn tag_plane() {
        // Python: chr(0xE0000 + ord(c)) — additive offset, 'A' = 0x41.
        assert_eq!(tag_encode("A"), "\u{E0041}");
        assert_eq!(tag_encode("a1").chars().count(), 2);
    }

    #[test]
    fn zw_between_every_char() {
        assert_eq!(zw_embed("ab"), "a\u{200B}b");
        assert_eq!(zw_embed(""), "");
    }

    #[test]
    fn variant_order_is_contract() {
        let names: Vec<&str> = variants("AB1").iter().map(|(n, _)| *n).collect();
        assert_eq!(names, ["plain", "base64", "base64-nopad", "rot13", "unicode_tags", "zero_width"]);
        let v = variants("");
        assert!(v.is_empty());
    }
}
