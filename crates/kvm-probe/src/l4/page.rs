//! The HID test page (Plan D L4): what the Mac shows while the probe sends
//! HID, so that a snapshot of the KVM's own video shows what the Mac did.
//! It is the only thing `hid-type` types into, and the pattern below is
//! the only thing it types.

/// `assets/hid-test.html`, one line.
pub const PAGE: &str = include_str!("../../assets/hid-test.html");

/// The page as the `data:` URL `hid-page-url` prints for the owner.
#[must_use]
pub fn url() -> String {
    format!("data:text/html,{}", PAGE.trim_end())
}

/// FNV-1a 32 over UTF-16 code units: the page's `h()`.
#[must_use]
pub fn fnv1a32(s: &str) -> u32 {
    s.encode_utf16().fold(0x811c_9dc5u32, |a, u| {
        (a ^ u32::from(u)).wrapping_mul(0x0100_0193)
    })
}

const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-=[];',./";

/// What `hid-type` types: `n` characters cycling through `ALPHABET` —
/// letters both cases (Shift exercised), digits and punctuation.
#[must_use]
pub fn pattern(n: usize) -> String {
    ALPHABET.chars().cycle().take(n).collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use kvm_proto::keymap::us_stroke;

    /// The owner opens the URL by hand: one line, no `#` (a fragment) or
    /// `%` (an escape), plain US-layout ASCII so it can be typed or pasted.
    #[test]
    fn the_page_url_is_one_typeable_line() {
        let u = url();
        assert!(u.starts_with("data:text/html,<title>"));
        assert!(u.len() <= 1500, "{} bytes", u.len());
        for c in u.chars() {
            assert!(c.is_ascii() && !c.is_ascii_control(), "{c:?}");
            assert!(!matches!(c, '#' | '%'), "{c:?}");
            assert!(us_stroke(c).is_some(), "{c:?}");
        }
    }

    /// The page is self-contained: one line, and nothing in it loads,
    /// sends or reads anything beyond the key and mouse events it shows —
    /// no URL, no external resource, no network API, no storage, no
    /// clipboard.
    #[test]
    fn the_page_is_self_contained() {
        assert!(PAGE.ends_with('\n') && PAGE.matches('\n').count() == 1);
        let lower = PAGE.to_ascii_lowercase();
        for banned in [
            "http",
            "//",
            "src=",
            "href",
            "action=",
            "url(",
            "@import",
            "<link",
            "<img",
            "<iframe",
            "<object",
            "<embed",
            "<form",
            "<meta",
            "fetch",
            "xmlhttp",
            "websocket",
            "eventsource",
            "beacon",
            "import",
            "worker",
            "storage",
            "cookie",
            "clipboard",
            "paste",
            "opener",
            "location",
            "window.open",
            "postmessage",
            "indexeddb",
        ] {
            assert!(!lower.contains(banned), "the page contains {banned:?}");
        }
    }

    /// PD3 I4: the `rate` line's count is the characters typed (`t.length`),
    /// timed from the first character to the last — never the keydown count,
    /// which also counts each shifted character's Shift keydown and would
    /// overstate the KVM's report rate (by ~39% on the pattern).
    #[test]
    fn the_rate_line_counts_only_typed_characters() {
        assert!(PAGE.contains(r#""\nrate "+t.length+" "+Math.round(l-f)"#));
        assert!(!PAGE.contains(r#""\nrate "+n"#));
        // The first and last instants are taken only when a character is
        // added to the text.
        assert!(PAGE.contains("if(c){if(!t)f=performance.now();l=performance.now();t+=c}"));
    }

    /// The page's hash is FNV-1a 32 over UTF-16 code units, as `h()` in
    /// the page computes it.
    #[test]
    fn fnv1a32_matches_the_reference_vectors() {
        assert_eq!(fnv1a32(""), 0x811c_9dc5);
        assert_eq!(fnv1a32("a"), 0xe40c_292c);
        assert_eq!(fnv1a32("foobar"), 0xbf9c_f968);
        assert!(PAGE.contains("2166136261") && PAGE.contains("16777619"));
    }

    #[test]
    fn the_pattern_is_deterministic_and_typeable() {
        let p = pattern(200);
        assert_eq!(p.chars().count(), 200);
        assert_eq!(p, pattern(200));
        assert!(p.starts_with("abcdefghijklmnopqrstuvwxyzABC"));
        assert!(p.chars().all(|c| us_stroke(c).is_some()));
        assert!(
            p.chars().any(|c| us_stroke(c).unwrap().shift),
            "Shift is exercised"
        );
    }
}
