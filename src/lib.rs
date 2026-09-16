//! MST/2 codec: byte-level parsing and encoding for the Mega × ScorpioFS
//! MST/2 protocol, per specs 03 (descriptor), 05 (MTP2 metadata pages),
//! 06 (TreeFrame) and 07 (chunk maps) of the Mega_ScorpioFS spec bundle.
//!
//! This crate is pure: no I/O, no async, no transport. Callers own bytes.

pub mod chunkmap;
pub mod descriptor;
pub mod metapage;
pub mod treeframe;

/// Codec error. Every rejection from the spec maps to one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// Input ended before a complete structure could be read.
    Truncated(&'static str),
    /// A fixed magic, version, kind or reserved field did not match.
    BadConstant(&'static str),
    /// A length was out of the range the spec allows.
    BadLength(&'static str),
    /// Checked arithmetic overflowed.
    Overflow(&'static str),
    /// A name or path violated canonical UTF-8 / component rules.
    BadName(&'static str),
    /// An ordering, partition or structural invariant was violated.
    BadOrdering(&'static str),
    /// A digest (SHA-256) did not match the expected value.
    DigestMismatch(&'static str),
    /// A value that must be unique appeared twice.
    Duplicate(&'static str),
    /// Valid per spec but not implemented by this codec profile
    /// (e.g. the optional ZSTD frame flag).
    Unsupported(&'static str),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::Truncated(w) => write!(f, "truncated input while reading {w}"),
            CodecError::BadConstant(w) => write!(f, "bad constant or version: {w}"),
            CodecError::BadLength(w) => write!(f, "length out of range: {w}"),
            CodecError::Overflow(w) => write!(f, "arithmetic overflow: {w}"),
            CodecError::BadName(w) => write!(f, "non-canonical name or path: {w}"),
            CodecError::BadOrdering(w) => write!(f, "ordering or structure violated: {w}"),
            CodecError::DigestMismatch(w) => write!(f, "digest mismatch: {w}"),
            CodecError::Duplicate(w) => write!(f, "duplicate value: {w}"),
            CodecError::Unsupported(w) => write!(f, "unsupported by this codec profile: {w}"),
        }
    }
}

impl std::error::Error for CodecError {}

pub type CodecResult<T> = Result<T, CodecError>;

pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Read a little-endian integer with bounds checking.
pub(crate) fn read_u16(buf: &[u8], off: usize) -> CodecResult<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or(CodecError::Truncated("u16"))
}

pub(crate) fn read_u32(buf: &[u8], off: usize) -> CodecResult<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(CodecError::Truncated("u32"))
}

pub(crate) fn read_u64(buf: &[u8], off: usize) -> CodecResult<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .ok_or(CodecError::Truncated("u64"))
}

pub(crate) fn write_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub(crate) fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub(crate) fn write_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Validate a canonical name per spec 05 §2: 1..255 bytes, UTF-8,
/// no NUL, no `/`, not `.` or `..`, no case folding or normalization.
pub(crate) fn validate_name(name: &[u8]) -> CodecResult<()> {
    if name.is_empty() {
        return Err(CodecError::BadName("empty name"));
    }
    if name.len() > 255 {
        return Err(CodecError::BadName("name longer than 255 bytes"));
    }
    let s = std::str::from_utf8(name).map_err(|_| CodecError::BadName("not UTF-8"))?;
    if s.contains('\0') {
        return Err(CodecError::BadName("NUL in name"));
    }
    if s.contains('/') {
        return Err(CodecError::BadName("slash in name"));
    }
    if s == "." || s == ".." {
        return Err(CodecError::BadName("dot component"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_rules() {
        assert!(validate_name(b"a.txt").is_ok());
        assert!(validate_name(b"").is_err());
        assert!(validate_name(&[b'a'; 256]).is_err());
        assert!(validate_name(&[b'a'; 255]).is_ok());
        assert!(validate_name(b"a/b").is_err());
        assert!(validate_name(b"a\0b").is_err());
        assert!(validate_name(b".").is_err());
        assert!(validate_name(b"..").is_err());
        assert!(validate_name(&[0xff, 0xfe]).is_err()); // invalid UTF-8
    }
}
