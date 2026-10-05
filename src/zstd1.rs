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

/// Maximum raw payload the spec 06 frame kinds allow: 1 MiB data + the
/// frame's own structural fields (a full CHUNK frame carries the 1 MiB chunk
/// plus map_id/file_content_id/chunk_index/chunk_len — 76 bytes;
/// spec 14). Any `raw_len` above this is rejected
/// before allocation to prevent DoS from a forged header claiming a huge
/// size.
pub const MAX_RAW_PAYLOAD: usize = 1_048_576 + 76;

fn validate_frame_header(wire: &[u8], raw_len: usize) -> CodecResult<()> {
    // Direct-output decoding can bypass libzstd's window setting.
    let descriptor = *wire.get(4).ok_or(CodecError::Truncated("zstd header"))?;
    if descriptor & 0x08 != 0 {
        return Err(CodecError::BadConstant("zstd reserved header bit"));
    }
    let single_segment = descriptor & 0x20 != 0;
    let mut offset = 5;
    if !single_segment {
        let window = *wire
            .get(offset)
            .ok_or(CodecError::Truncated("zstd window"))?;
        offset += 1;
        let base = 1u64 << (10 + (window >> 3));
        let bytes = base + (base >> 3) * u64::from(window & 7);
        if bytes > 1u64 << MAX_WINDOW_LOG {
            return Err(CodecError::BadLength("zstd window exceeds 8MiB"));
        }
    }
    let dictionary_len = match descriptor & 3 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let dictionary = wire
        .get(offset..offset + dictionary_len)
        .ok_or(CodecError::Truncated("zstd dictionary ID"))?;
    if dictionary.iter().any(|byte| *byte != 0) {
        return Err(CodecError::Unsupported("external zstd dictionary"));
    }
    offset += dictionary_len;
    let content_size_len = match descriptor >> 6 {
        0 => {
            if single_segment {
                1
            } else {
                0
            }
        }
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if content_size_len != 0 {
        let bytes = wire
            .get(offset..offset + content_size_len)
            .ok_or(CodecError::Truncated("zstd content size"))?;
        let mut size = bytes
            .iter()
            .enumerate()
            .fold(0u64, |size, (i, byte)| size | (u64::from(*byte) << (8 * i)));
        if content_size_len == 2 {
            size += 256;
        }
        if single_segment && size > 1u64 << MAX_WINDOW_LOG {
            return Err(CodecError::BadLength("zstd window exceeds 8MiB"));
        }
        if size != raw_len as u64 {
            return Err(CodecError::BadLength(
                "zstd content size differs from raw_len",
            ));
        }
    }
    Ok(())
}

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
    validate_frame_header(wire, raw_len)?;
    let mut dctx = DCtx::create();
    dctx.set_parameter(DParameter::WindowLogMax(MAX_WINDOW_LOG))
        .map_err(|_| CodecError::Unsupported("zstd window larger than 8MiB"))?;

    let mut out = vec![0u8; raw_len];
    let mut input = InBuffer::around(wire);
    let mut output = OutBuffer::around(&mut out);

    // Drive the stream until the frame-end hint is 0. The output slice is
    // exactly raw_len: an over-long stream fails instead of growing into a
    // loose allocation.
    loop {
        let previous = (input.pos(), output.pos());
        let hint = dctx
            .decompress_stream(&mut output, &mut input)
            .map_err(|_| CodecError::DigestMismatch("zstd decompression failed"))?;
        if hint == 0 {
            break;
        }
        if previous == (input.pos(), output.pos()) {
            return Err(CodecError::Truncated("zstd frame"));
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
    fn advertised_window_is_checked_even_for_a_one_byte_raw_block() {
        let mut frame = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x68, 0x09, 0x00, 0x00, 0x42];
        assert_eq!(decompress_strict(&frame, 1).unwrap(), vec![0x42]);
        frame[5] = 0x69;
        assert!(matches!(
            decompress_strict(&frame, 1),
            Err(CodecError::BadLength("zstd window exceeds 8MiB"))
        ));
    }

    #[test]
    fn dictionary_id_and_single_segment_content_size_are_checked() {
        let dictionary = [0x28, 0xB5, 0x2F, 0xFD, 0x01, 0x00, 0x01, 0x09, 0, 0, 0x42];
        assert!(matches!(
            decompress_strict(&dictionary, 1),
            Err(CodecError::Unsupported("external zstd dictionary"))
        ));
        let single = [0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x01, 0x09, 0, 0, 0x42];
        assert_eq!(decompress_strict(&single, 1).unwrap(), vec![0x42]);
        assert!(matches!(
            decompress_strict(&single, 2),
            Err(CodecError::BadLength(_))
        ));
    }

    #[test]
    fn every_truncated_prefix_returns_an_error() {
        let payload = vec![0x73; 4096];
        let wire = compress(&payload, 3).unwrap();
        for end in 0..wire.len() {
            assert!(
                decompress_strict(&wire[..end], payload.len()).is_err(),
                "prefix={end}"
            );
        }
        let raw_block = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x09, 0, 0, 0x42];
        assert!(matches!(
            decompress_strict(&raw_block[..9], 1),
            Err(CodecError::Truncated(_))
        ));
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

    #[test]
    fn full_mib_chunk_payload_fits_under_the_cap() {
        // A full 1 MiB CHUNK frame's raw payload is the chunk plus its 76
        // bytes of frame fields (map_id + file_content_id + chunk_index + chunk_len):
        // the cap must accept it or every max-size chunk read over zstd
        // fails (regression for the 0.3.0 +64 estimate).
        let payload_len = 1_048_576 + 76;
        let payload = vec![0xA5u8; payload_len];
        let wire = compress(&payload, 1).unwrap();
        assert_eq!(decompress_strict(&wire, payload_len).unwrap(), payload);
        // Just above the cap is still refused.
        let over = vec![0xA5u8; MAX_RAW_PAYLOAD + 1];
        assert!(decompress_strict(&compress(&over, 1).unwrap(), over.len()).is_err());
    }
}
