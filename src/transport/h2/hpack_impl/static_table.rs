//! HPACK static table (RFC 7541 Appendix A).
//!
//! The static table consists of 61 predefined header fields that are
//! always available and never change.

/// Static table entry: (name, value)
pub type StaticEntry = (&'static [u8], &'static [u8]);

/// Static table with 61 entries from RFC 7541 Appendix A.
///
/// Index 0 is reserved. Valid indices are 1-61.
pub const STATIC_TABLE: &[StaticEntry; 61] = &[
    // Index 1
    (b":authority", b""),
    // Index 2
    (b":method", b"GET"),
    // Index 3
    (b":method", b"POST"),
    // Index 4
    (b":path", b"/"),
    // Index 5
    (b":path", b"/index.html"),
    // Index 6
    (b":scheme", b"http"),
    // Index 7
    (b":scheme", b"https"),
    // Index 8
    (b":status", b"200"),
    // Index 9
    (b":status", b"204"),
    // Index 10
    (b":status", b"206"),
    // Index 11
    (b":status", b"304"),
    // Index 12
    (b":status", b"400"),
    // Index 13
    (b":status", b"404"),
    // Index 14
    (b":status", b"500"),
    // Index 15
    (b"accept-charset", b""),
    // Index 16
    (b"accept-encoding", b"gzip, deflate"),
    // Index 17
    (b"accept-language", b""),
    // Index 18
    (b"accept-ranges", b""),
    // Index 19
    (b"accept", b""),
    // Index 20
    (b"access-control-allow-origin", b""),
    // Index 21
    (b"age", b""),
    // Index 22
    (b"allow", b""),
    // Index 23
    (b"authorization", b""),
    // Index 24
    (b"cache-control", b""),
    // Index 25
    (b"content-disposition", b""),
    // Index 26
    (b"content-encoding", b""),
    // Index 27
    (b"content-language", b""),
    // Index 28
    (b"content-length", b""),
    // Index 29
    (b"content-location", b""),
    // Index 30
    (b"content-range", b""),
    // Index 31
    (b"content-type", b""),
    // Index 32
    (b"cookie", b""),
    // Index 33
    (b"date", b""),
    // Index 34
    (b"etag", b""),
    // Index 35
    (b"expect", b""),
    // Index 36
    (b"expires", b""),
    // Index 37
    (b"from", b""),
    // Index 38
    (b"host", b""),
    // Index 39
    (b"if-match", b""),
    // Index 40
    (b"if-modified-since", b""),
    // Index 41
    (b"if-none-match", b""),
    // Index 42
    (b"if-range", b""),
    // Index 43
    (b"if-unmodified-since", b""),
    // Index 44
    (b"last-modified", b""),
    // Index 45
    (b"link", b""),
    // Index 46
    (b"location", b""),
    // Index 47
    (b"max-forwards", b""),
    // Index 48
    (b"proxy-authenticate", b""),
    // Index 49
    (b"proxy-authorization", b""),
    // Index 50
    (b"range", b""),
    // Index 51
    (b"referer", b""),
    // Index 52
    (b"refresh", b""),
    // Index 53
    (b"retry-after", b""),
    // Index 54
    (b"server", b""),
    // Index 55
    (b"set-cookie", b""),
    // Index 56
    (b"strict-transport-security", b""),
    // Index 57
    (b"transfer-encoding", b""),
    // Index 58
    (b"user-agent", b""),
    // Index 59
    (b"vary", b""),
    // Index 60
    (b"via", b""),
    // Index 61
    (b"www-authenticate", b""),
];

/// Get a static table entry by index (1-61).
///
/// Returns None if index is out of range.
pub fn get_static_entry(index: usize) -> Option<StaticEntry> {
    if index >= 1 && index <= STATIC_TABLE.len() {
        Some(STATIC_TABLE[index - 1])
    } else {
        None
    }
}

/// Case-insensitive ASCII byte comparison for HPACK static table lookup.
pub(crate) fn bytes_eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Find a static table entry by name and value.
///
/// Returns the index (1-61) if found, None otherwise.
pub fn find_static_entry(name: &[u8], value: &[u8]) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, v)| bytes_eq_ignore_ascii_case(n, name) && *v == value)
        .map(|idx| idx + 1)
}

/// Find a static table entry by name only.
///
/// Returns the first matching index (1-61) if found, None otherwise.
pub fn find_static_entry_by_name(name: &[u8]) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, _)| bytes_eq_ignore_ascii_case(n, name))
        .map(|idx| idx + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_table_size() {
        assert_eq!(STATIC_TABLE.len(), 61);
    }

    #[test]
    fn test_get_static_entry() {
        assert_eq!(
            get_static_entry(1),
            Some((b":authority".as_slice(), b"".as_slice()))
        );
        assert_eq!(
            get_static_entry(2),
            Some((b":method".as_slice(), b"GET".as_slice()))
        );
        assert_eq!(
            get_static_entry(61),
            Some((b"www-authenticate".as_slice(), b"".as_slice()))
        );
        assert_eq!(get_static_entry(0), None);
        assert_eq!(get_static_entry(62), None);
    }

    #[test]
    fn test_find_static_entry() {
        assert_eq!(find_static_entry(b":method", b"GET"), Some(2));
        assert_eq!(find_static_entry(b":method", b"POST"), Some(3));
        assert_eq!(find_static_entry(b":method", b"PUT"), None);
    }

    #[test]
    fn test_find_static_entry_by_name() {
        assert_eq!(find_static_entry_by_name(b":method"), Some(2));
        assert_eq!(find_static_entry_by_name(b":authority"), Some(1));
        assert_eq!(find_static_entry_by_name(b"nonexistent"), None);
    }
}
