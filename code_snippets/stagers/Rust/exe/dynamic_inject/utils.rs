// utils.rs
// Shared helpers used across modules.

/// Convert a Rust &str to a null-terminated UTF-16 Vec<u16>.
/// Required for any Windows API that takes LPCWSTR / LPWSTR.
pub fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
