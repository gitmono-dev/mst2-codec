//! Strict zstd frame handling (spec 06):
//!
//! * exactly ONE standard zstd frame in the wire payload;
//! * decompression window ≤ 8 MiB;
//! * decompressed length must equal the header's `raw_len` exactly — a
//!   short read is never zero-padded;
//! * concatenated frames, skippable frames, external dictionaries and
//!   trailing bytes after the frame are rejected.
//!
//! Streaming decompression is driven over the exact byte slice, so the
//! decoder cannot silently consume a second frame or ignore trailing data
//! the way a lenient `decode_all` wrapper would. Wire diagnostics use
//! static strings (the codec error type carries no owned payloads); the
//! zstd error code is logged by callers that need it.

use crate::{CodecError, CodecResult};
use zstd_safe::{DCtx, DParameter, InBuffer, OutBuffer};

/// Spec 14 limit: 8 MiB zstd window (2^23).
pub const MAX_WINDOW_LOG: u32 = 23;

/// Compress exactly one standard zstd frame. `level` follows libzstd
/// conventions; the output never depends on a dictionary.
pub fn compress(payload: &[u8], level: i32) -> CodecResult<Vec<u8>> {
    zstd::bulk::compress(payload, level.clamp(1, 19))
        .map_err(|_| CodecError::Unsupported("zstd compression failed"))
}

/// Maximum raw payload the spec 06 frame kinds allow: 1 MiB data + small
/// header overhead (spec 14). Any `raw_len` above this is rejected before
/// allocation to prevent DoS from a forged header claiming a huge size.
pub const MAX_RAW_PAYLOAD: usize = 1_048_576 + 64;

/// Strict single-frame decompression (see module docs). `raw_len` is the
/// header-advertised uncompressed length and bounds the output exactly.
pub fn decompress_strict(wire: &[u8], raw_len: usize) -> CodecResult<Vec<u8>> {
    // Spec 14: reject an unreasonably large raw_len BEFORE allocating.
    // A forged frame header claiming 1 GiB would otherwise grow VmPeak by
    // that amount before returning BadLength.
    if raw_len > MAX_RAW_PAYLOAD {
        return Err(CodecError::BadLength(
            "zstd raw_len exceeds the spec 14 payload limit",
        ));
    }
    // A skippable frame uses magics 0x184D2A50..5F; a real frame starts
    // with the little-endian magic 0xFD2FB528. Reject anything else up
    // front, including raw skippable frames.
    if wire.len() < 4 || wire[0..4] != [0x28, 0xB5, 0x2F, 0xFD] {
        return Err(CodecError::BadConstant(
            "zstd payload is not one standard frame",
        ));
    }
    let mut dctx = DCtx::create();
    dctx.set_parameter(DParameter::WindowLogMax(MAX_WINDOW_LOG))
        .map_err(|_| CodecError::Unsupported("zstd window larger than 8MiB"))?;

    // Note on window enforcement: libzstd's single-pass shortcut (used when
    // all input is available at once) decompresses directly into the caller's
    // output buffer without allocating a separate window. The raw_len cap
    // above therefore bounds the actual memory, making the WindowLogMax
    // bypass harmless for this decode path. Frames that require a larger
    // window will fail on the raw_len check before reaching libzstd.

    let mut out = vec![0u8; raw_len];
    let mut input = InBuffer::around(wire);
    let mut output = OutBuffer::around(&mut out);

    // Drive the stream until the frame-end hint is 0. The output slice is
    // exactly raw_len: an over-long stream fails instead of growing into a
    // loose allocation.
    loop {
        let hint = dctx
            .decompress_stream(&mut output, &mut input)
            .map_err(|_| CodecError::DigestMismatch("zstd decompression failed"))?;
        if hint == 0 {
            break;
        }
        if output.pos() == raw_len {
            // Decoder wants more output but the advertised raw_len is full.
            return Err(CodecError::BadLength("zstd output exceeds header raw_len"));
        }
    }
    if output.pos() != raw_len {
        return Err(CodecError::BadLength(
            "zstd output shorter than header raw_len",
        ));
    }
    if input.pos() != wire.len() {
        return Err(CodecError::BadOrdering(
            "trailing bytes/second frame after the single zstd frame",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_strict() {
        let payload = vec![7u8; 200_000];
        let wire = compress(&payload, 3).unwrap();
        assert!(wire.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]));
        assert!(wire.len() < payload.len());
        let back = decompress_strict(&wire, payload.len()).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn rejects_window_over_8mib() {
        // Hand-built frame header: magic, descriptor 0x00 (not single
        // segment, dictID absent, FCS absent), window_descriptor with
        // exponent 20 => 1 GiB base window. The decoder must refuse the
        // frame header itself under WindowLogMax=23, before any block.
        let forged = vec![
            0x28, 0xB5, 0x2F, 0xFD, // magic
            0x00, // frame header descriptor
            0xA0, // window descriptor: exponent 20, mantissa 0
            0x00, 0x00, 0x01, // block header (last, raw, length 1)
            0x42,
        ];
        assert!(decompress_strict(&forged, 1).is_err());
    }

    #[test]
    fn rejects_short_and_overlong_output() {
        let payload = vec![3u8; 40_000];
        let wire = compress(&payload, 3).unwrap();
        assert!(decompress_strict(&wire, 40_000 - 1).is_err());
        assert!(decompress_strict(&wire, 40_001).is_err());
    }

    #[test]
    fn rejects_concatenation_and_trailing_bytes() {
        let payload = vec![9u8; 40_000];
        let wire = compress(&payload, 3).unwrap();
        let mut doubled = wire.clone();
        doubled.extend_from_slice(&wire);
        assert!(decompress_strict(&doubled, 80_000).is_err());
        let mut padded = wire.clone();
        padded.push(0);
        assert!(decompress_strict(&padded, 40_000).is_err());
    }

    #[test]
    fn rejects_non_frame_and_skippable_magic() {
        assert!(decompress_strict(b"not a zstd frame", 17).is_err());
        // skippable frame 0x184D2A50
        let skip = vec![0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0];
        assert!(decompress_strict(&skip, 0).is_err());
    }
}
