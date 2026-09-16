//! MST/2 TreeFrame wire format — spec 06.
//!
//! Fixed 64-byte header; kinds META(1), OBJECT(2), CHUNK(3), END(254),
//! ERROR(255). Identity (uncompressed) encoding is mandatory and is the only
//! one this codec handles; the optional ZSTD flag is rejected here (the
//! transport layer may add it behind an explicit feature).

use crate::{read_u16, read_u32, read_u64, sha256, CodecError, CodecResult};

pub const VERSION: u16 = 2;
pub const HEADER_LEN: usize = 64;

pub const KIND_META: u8 = 1;
pub const KIND_OBJECT: u8 = 2;
pub const KIND_CHUNK: u8 = 3;
pub const KIND_END: u8 = 254;
pub const KIND_ERROR: u8 = 255;

pub const FLAG_ZSTD: u8 = 0b0000_0001;

pub const META_MAX_PAGES: usize = 64;
pub const META_MAX_RAW: usize = 1_048_576;
pub const OBJECT_MAX_COUNT: usize = 128;
pub const OBJECT_MAX_LEN: u32 = 262_144;
pub const OBJECT_MAX_RAW: usize = 1_048_576;
pub const CHUNK_MAX_LEN: u32 = 1_048_576;
pub const ERROR_MAX_BYTES: usize = 4096;

/// A parsed frame header (payload digest included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: u8,
    pub flags: u8,
    pub wire_len: u32,
    pub raw_len: u32,
    pub stream_id: u32,
    pub sequence: u64,
    pub payload_sha256: [u8; 32],
}

/// A fully validated frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Meta(MetaPayload),
    Object(ObjectPayload),
    Chunk(ChunkPayload),
    End(EndPayload),
    Error(ErrorPayload),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaPayload {
    /// `(page_id, canonical MTP2 page bytes)`.
    pub pages: Vec<([u8; 32], Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPayload {
    /// `(content_id, raw object bytes)` in table order.
    pub objects: Vec<([u8; 32], Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkPayload {
    pub map_id: [u8; 32],
    pub file_content_id: [u8; 32],
    pub chunk_index: u64,
    pub chunk_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndPayload {
    pub request_item_count: u32,
    pub unique_unit_count: u32,
    pub logical_bytes: u64,
    pub request_body_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorPayload {
    pub code: String,
    pub retryable: bool,
    pub request_id: String,
}

/// Parse and validate one frame (header + payload) from `buf`, returning the
/// frame and the total consumed length. Digest, kind, flags and payload
/// structure are all checked.
pub fn parse_frame(buf: &[u8]) -> CodecResult<(Frame, usize)> {
    if buf.len() < HEADER_LEN {
        return Err(CodecError::Truncated("frame header"));
    }
    if &buf[0..4] != b"MST2" {
        return Err(CodecError::BadConstant("MST2 magic"));
    }
    if read_u16(buf, 4)? != VERSION {
        return Err(CodecError::BadConstant("frame version"));
    }
    let kind = buf[6];
    let flags = buf[7];
    if read_u32(buf, 8)? as usize != HEADER_LEN {
        return Err(CodecError::BadConstant("header_len must be 64"));
    }
    if flags & !FLAG_ZSTD != 0 {
        return Err(CodecError::BadConstant("unknown frame flags"));
    }
    let wire_len = read_u32(buf, 12)?;
    let raw_len = read_u32(buf, 16)?;
    let stream_id = read_u32(buf, 20)?;
    if stream_id == 0 {
        return Err(CodecError::BadConstant("stream_id must be non-zero"));
    }
    let _sequence = read_u64(buf, 24)?;
    let mut payload_sha256 = [0u8; 32];
    payload_sha256.copy_from_slice(&buf[32..64]);

    if matches!(kind, KIND_END | KIND_ERROR) && flags & FLAG_ZSTD != 0 {
        return Err(CodecError::BadConstant("END/ERROR must not be compressed"));
    }
    if flags & FLAG_ZSTD == 0 && wire_len != raw_len {
        return Err(CodecError::BadLength(
            "identity encoding requires wire_len == raw_len",
        ));
    }
    if flags & FLAG_ZSTD != 0 {
        // zstd negotiation is transport-level; this codec handles identity only.
        return Err(CodecError::Unsupported(
            "zstd flag set; identity codec only",
        ));
    }

    let total = HEADER_LEN + wire_len as usize;
    if buf.len() < total {
        return Err(CodecError::Truncated("frame payload"));
    }
    let payload = &buf[HEADER_LEN..total];
    let digest = sha256(&[payload]);
    if digest != payload_sha256 {
        return Err(CodecError::DigestMismatch("frame payload"));
    }

    let frame = match kind {
        KIND_META => Frame::Meta(decode_meta(payload)?),
        KIND_OBJECT => Frame::Object(decode_object(payload)?),
        KIND_CHUNK => Frame::Chunk(decode_chunk(payload, raw_len)?),
        KIND_END => Frame::End(decode_end(payload)?),
        KIND_ERROR => Frame::Error(decode_error(payload)?),
        _ => return Err(CodecError::BadConstant("frame kind")),
    };
    Ok((frame, total))
}

/// Parse a whole HTTP-body byte stream: frames must share one non-zero
/// stream_id, sequences must start at 0 and increase consecutively, exactly
/// one final END (or an ERROR terminator) and nothing after it.
pub fn parse_stream(buf: &[u8]) -> CodecResult<Vec<Frame>> {
    let mut frames = Vec::new();
    let mut off = 0usize;
    let mut stream_id: Option<u32> = None;
    let mut expect_seq = 0u64;
    let mut terminated = false;
    while off < buf.len() {
        if terminated {
            return Err(CodecError::BadOrdering("bytes after END/ERROR frame"));
        }
        let (frame, used) = parse_frame(&buf[off..])?;
        off += used;
        // stream/sequence rules are header-level; re-derive from the raw
        // header so this helper does not depend on enum internals.
        let sid = read_u32(&buf[off - used..], 20)?;
        let seq = read_u64(&buf[off - used..], 24)?;
        match stream_id {
            None => stream_id = Some(sid),
            Some(s) if s != sid => {
                return Err(CodecError::BadOrdering("stream_id changed mid-stream"))
            }
            _ => {}
        }
        if seq != expect_seq {
            return Err(CodecError::BadOrdering(
                "sequence must increase consecutively from 0",
            ));
        }
        expect_seq += 1;
        if matches!(frame, Frame::End(_) | Frame::Error(_)) {
            terminated = true;
        }
        frames.push(frame);
    }
    if !terminated {
        return Err(CodecError::BadOrdering("stream missing END/ERROR frame"));
    }
    Ok(frames)
}

fn decode_meta(payload: &[u8]) -> CodecResult<MetaPayload> {
    if payload.len() > META_MAX_RAW {
        return Err(CodecError::BadLength("META raw payload over 1MiB"));
    }
    if payload.len() < 4 {
        return Err(CodecError::Truncated("META header"));
    }
    let count = read_u16(payload, 0)? as usize;
    if !(1..=META_MAX_PAGES).contains(&count) {
        return Err(CodecError::BadLength("META count must be 1..64"));
    }
    if read_u16(payload, 2)? != 0 {
        return Err(CodecError::BadConstant("META reserved"));
    }
    let mut off = 4usize;
    let mut pages = Vec::with_capacity(count);
    let mut seen: Vec<[u8; 32]> = Vec::with_capacity(count);
    for _ in 0..count {
        let mut pid = [0u8; 32];
        pid.copy_from_slice(
            payload
                .get(off..off + 32)
                .ok_or(CodecError::Truncated("page_id"))?,
        );
        off += 32;
        let page_len = read_u32(payload, off)? as usize;
        off += 4;
        if page_len > crate::metapage::PAGE_MAX_BYTES {
            return Err(CodecError::BadLength("META page over 16KiB"));
        }
        let page = payload
            .get(off..off + page_len)
            .ok_or(CodecError::Truncated("META page bytes"))?
            .to_vec();
        off += page_len;
        if crate::metapage::page_id(&page) != pid {
            return Err(CodecError::DigestMismatch("META page_id"));
        }
        if seen.contains(&pid) {
            return Err(CodecError::Duplicate("META page_id"));
        }
        seen.push(pid);
        pages.push((pid, page));
    }
    if off != payload.len() {
        return Err(CodecError::BadLength("trailing bytes in META payload"));
    }
    Ok(MetaPayload { pages })
}

fn decode_object(payload: &[u8]) -> CodecResult<ObjectPayload> {
    if payload.len() > OBJECT_MAX_RAW {
        return Err(CodecError::BadLength("OBJECT raw payload over 1MiB"));
    }
    if payload.len() < 4 {
        return Err(CodecError::Truncated("OBJECT header"));
    }
    let count = read_u16(payload, 0)? as usize;
    if !(1..=OBJECT_MAX_COUNT).contains(&count) {
        return Err(CodecError::BadLength("OBJECT count must be 1..128"));
    }
    if read_u16(payload, 2)? != 0 {
        return Err(CodecError::BadConstant("OBJECT reserved"));
    }
    let table_len = count * 40usize;
    let data = payload
        .get(4 + table_len..)
        .ok_or(CodecError::Truncated("OBJECT data area"))?;
    let mut objects = Vec::with_capacity(count);
    let mut seen: Vec<[u8; 32]> = Vec::with_capacity(count);
    let mut expect_off = 0u32;
    for i in 0..count {
        let t = &payload[4 + i * 40..4 + (i + 1) * 40];
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&t[0..32]);
        let object_len = read_u32(t, 32)?;
        let data_offset = read_u32(t, 36)?;
        if object_len > OBJECT_MAX_LEN {
            return Err(CodecError::BadLength("object over 256KiB"));
        }
        if data_offset != expect_off {
            return Err(CodecError::BadOrdering(
                "OBJECT offsets must concatenate exactly (no holes or overlaps)",
            ));
        }
        expect_off = expect_off
            .checked_add(object_len)
            .ok_or(CodecError::Overflow("data end"))?;
        if seen.contains(&cid) {
            return Err(CodecError::Duplicate("content_id"));
        }
        seen.push(cid);
        let start = data_offset as usize;
        let end = start + object_len as usize;
        let bytes = data
            .get(start..end)
            .ok_or(CodecError::Truncated("object data"))?;
        // Verify the full content digest.
        if sha256(&[bytes]) != cid {
            return Err(CodecError::DigestMismatch("object content"));
        }
        objects.push((cid, bytes.to_vec()));
    }
    if data.len() != expect_off as usize {
        return Err(CodecError::BadLength("OBJECT data area length mismatch"));
    }
    Ok(ObjectPayload { objects })
}

fn decode_chunk(payload: &[u8], raw_len: u32) -> CodecResult<ChunkPayload> {
    if payload.len() < 76 {
        return Err(CodecError::Truncated("CHUNK header"));
    }
    if raw_len as usize != payload.len() {
        return Err(CodecError::BadLength("CHUNK raw_len mismatch"));
    }
    let chunk_len = read_u32(payload, 72)?;
    if chunk_len as usize != payload.len() - 76 {
        return Err(CodecError::BadLength("CHUNK chunk_len mismatch"));
    }
    if chunk_len > CHUNK_MAX_LEN {
        return Err(CodecError::BadLength("chunk over 1MiB"));
    }
    let mut map_id = [0u8; 32];
    map_id.copy_from_slice(&payload[0..32]);
    let mut file_content_id = [0u8; 32];
    file_content_id.copy_from_slice(&payload[32..64]);
    let chunk_index = read_u64(payload, 64)?;
    Ok(ChunkPayload {
        map_id,
        file_content_id,
        chunk_index,
        chunk_bytes: payload[76..].to_vec(),
    })
}

fn decode_end(payload: &[u8]) -> CodecResult<EndPayload> {
    if payload.len() != 48 {
        return Err(CodecError::BadLength(
            "END payload must be exactly 48 bytes",
        ));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&payload[16..48]);
    Ok(EndPayload {
        request_item_count: read_u32(payload, 0)?,
        unique_unit_count: read_u32(payload, 4)?,
        logical_bytes: read_u64(payload, 8)?,
        request_body_sha256: h,
    })
}

fn decode_error(payload: &[u8]) -> CodecResult<ErrorPayload> {
    if payload.len() > ERROR_MAX_BYTES {
        return Err(CodecError::BadLength("ERROR payload over 4096 bytes"));
    }
    let s = std::str::from_utf8(payload).map_err(|_| CodecError::BadConstant("ERROR not UTF-8"))?;
    parse_error_json(s)
}

/// Strict closed-schema parser for `{code, retryable, request_id}`.
fn parse_error_json(s: &str) -> CodecResult<ErrorPayload> {
    let mut fields: [Option<String>; 3] = [None, None, None];
    let mut it = JsonScan::new(s);
    it.skip_ws();
    if !it.take(b'{') {
        return Err(CodecError::BadConstant("ERROR json object expected"));
    }
    it.skip_ws();
    if it.take(b'}') {
        return Err(CodecError::BadConstant("ERROR json empty object"));
    }
    loop {
        it.skip_ws();
        let key = it.string()?;
        it.skip_ws();
        if !it.take(b':') {
            return Err(CodecError::BadConstant("ERROR json colon expected"));
        }
        it.skip_ws();
        let idx = match key.as_str() {
            "code" => 0,
            "retryable" => 1,
            "request_id" => 2,
            _ => return Err(CodecError::BadConstant("ERROR json unknown key")),
        };
        if fields[idx].is_some() {
            return Err(CodecError::Duplicate("ERROR json key"));
        }
        if idx == 1 {
            fields[idx] = Some(it.boolean()?.to_string());
        } else {
            fields[idx] = Some(it.string()?);
        }
        it.skip_ws();
        if it.take(b'}') {
            break;
        }
        if !it.take(b',') {
            return Err(CodecError::BadConstant("ERROR json comma expected"));
        }
    }
    it.skip_ws();
    if !it.eof() {
        return Err(CodecError::BadConstant("ERROR json trailing data"));
    }
    let code = fields[0]
        .take()
        .ok_or(CodecError::BadConstant("ERROR code missing"))?;
    let retryable_raw = fields[1]
        .take()
        .ok_or(CodecError::BadConstant("ERROR retryable missing"))?;
    let request_id = fields[2]
        .take()
        .ok_or(CodecError::BadConstant("ERROR request_id missing"))?;
    Ok(ErrorPayload {
        code,
        retryable: retryable_raw == "true",
        request_id,
    })
}

/// Minimal strict JSON scanner (strings with escapes, booleans, structure
/// punctuation only — enough for the closed ERROR schema).
struct JsonScan<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> JsonScan<'a> {
    fn new(s: &'a str) -> Self {
        JsonScan {
            b: s.as_bytes(),
            i: 0,
        }
    }
    fn eof(&self) -> bool {
        self.i >= self.b.len()
    }
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn take(&mut self, c: u8) -> bool {
        if self.i < self.b.len() && self.b[self.i] == c {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn string(&mut self) -> CodecResult<String> {
        if !self.take(b'"') {
            return Err(CodecError::BadConstant("json string expected"));
        }
        let mut out = Vec::new();
        loop {
            let c = *self
                .b
                .get(self.i)
                .ok_or(CodecError::Truncated("json string"))?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = *self
                        .b
                        .get(self.i)
                        .ok_or(CodecError::Truncated("json escape"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            if self.i + 4 > self.b.len() {
                                return Err(CodecError::Truncated("json \\u"));
                            }
                            let hex = std::str::from_utf8(&self.b[self.i..self.i + 4])
                                .map_err(|_| CodecError::BadConstant("json \\u"))?;
                            let cp = u32::from_str_radix(hex, 16)
                                .map_err(|_| CodecError::BadConstant("json \\u"))?;
                            self.i += 4;
                            let ch = char::from_u32(cp)
                                .ok_or(CodecError::BadConstant("json \\u codepoint"))?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(CodecError::BadConstant("json escape")),
                    }
                }
                0x00..=0x1F => {
                    return Err(CodecError::BadConstant("raw control char in json string"))
                }
                _ => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| CodecError::BadConstant("json string utf8"))
    }
    fn boolean(&mut self) -> CodecResult<bool> {
        if s(&self.b[self.i..]).starts_with("true") {
            self.i += 4;
            Ok(true)
        } else if s(&self.b[self.i..]).starts_with("false") {
            self.i += 5;
            Ok(false)
        } else {
            Err(CodecError::BadConstant("json boolean expected"))
        }
    }
}

fn s(b: &[u8]) -> &str {
    std::str::from_utf8(b).unwrap_or("")
}

// ---------------------------------------------------------------- encoding

fn header(
    kind: u8,
    flags: u8,
    wire_len: u32,
    raw_len: u32,
    stream_id: u32,
    sequence: u64,
    payload_sha256: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(b"MST2");
    crate::write_u16(&mut out, VERSION);
    out.push(kind);
    out.push(flags);
    crate::write_u32(&mut out, HEADER_LEN as u32);
    crate::write_u32(&mut out, wire_len);
    crate::write_u32(&mut out, raw_len);
    crate::write_u32(&mut out, stream_id);
    crate::write_u64(&mut out, sequence);
    out.extend_from_slice(&payload_sha256);
    out
}

fn frame_bytes(kind: u8, payload: &[u8], stream_id: u32, sequence: u64) -> Vec<u8> {
    let digest = sha256(&[payload]);
    let mut out = header(
        kind,
        0,
        payload.len() as u32,
        payload.len() as u32,
        stream_id,
        sequence,
        digest,
    );
    out.extend_from_slice(payload);
    out
}

impl MetaPayload {
    pub fn encode(&self, stream_id: u32, sequence: u64) -> CodecResult<Vec<u8>> {
        if self.pages.is_empty() || self.pages.len() > META_MAX_PAGES {
            return Err(CodecError::BadLength("META count must be 1..64"));
        }
        let mut payload = Vec::new();
        crate::write_u16(&mut payload, self.pages.len() as u16);
        crate::write_u16(&mut payload, 0);
        for (pid, page) in &self.pages {
            if crate::metapage::page_id(page) != *pid {
                return Err(CodecError::DigestMismatch("META page_id"));
            }
            payload.extend_from_slice(pid);
            crate::write_u32(&mut payload, page.len() as u32);
            payload.extend_from_slice(page);
        }
        if payload.len() > META_MAX_RAW {
            return Err(CodecError::BadLength("META raw payload over 1MiB"));
        }
        Ok(frame_bytes(KIND_META, &payload, stream_id, sequence))
    }
}

impl ObjectPayload {
    pub fn encode(&self, stream_id: u32, sequence: u64) -> CodecResult<Vec<u8>> {
        if self.objects.is_empty() || self.objects.len() > OBJECT_MAX_COUNT {
            return Err(CodecError::BadLength("OBJECT count must be 1..128"));
        }
        let mut payload = Vec::new();
        crate::write_u16(&mut payload, self.objects.len() as u16);
        crate::write_u16(&mut payload, 0);
        let mut off = 0u32;
        for (cid, data) in &self.objects {
            if sha256(&[data]) != *cid {
                return Err(CodecError::DigestMismatch("object content"));
            }
            if data.len() as u64 > OBJECT_MAX_LEN as u64 {
                return Err(CodecError::BadLength("object over 256KiB"));
            }
            payload.extend_from_slice(cid);
            crate::write_u32(&mut payload, data.len() as u32);
            crate::write_u32(&mut payload, off);
            off = off
                .checked_add(data.len() as u32)
                .ok_or(CodecError::Overflow("offset"))?;
        }
        for (_, data) in &self.objects {
            payload.extend_from_slice(data);
        }
        if payload.len() > OBJECT_MAX_RAW {
            return Err(CodecError::BadLength("OBJECT raw payload over 1MiB"));
        }
        Ok(frame_bytes(KIND_OBJECT, &payload, stream_id, sequence))
    }
}

impl ChunkPayload {
    pub fn encode(&self, stream_id: u32, sequence: u64) -> CodecResult<Vec<u8>> {
        if self.chunk_bytes.len() as u64 > CHUNK_MAX_LEN as u64 {
            return Err(CodecError::BadLength("chunk over 1MiB"));
        }
        let mut payload = Vec::with_capacity(76 + self.chunk_bytes.len());
        payload.extend_from_slice(&self.map_id);
        payload.extend_from_slice(&self.file_content_id);
        crate::write_u64(&mut payload, self.chunk_index);
        crate::write_u32(&mut payload, self.chunk_bytes.len() as u32);
        payload.extend_from_slice(&self.chunk_bytes);
        Ok(frame_bytes(KIND_CHUNK, &payload, stream_id, sequence))
    }
}

impl EndPayload {
    pub fn encode(&self, stream_id: u32, sequence: u64) -> Vec<u8> {
        let mut payload = Vec::with_capacity(48);
        crate::write_u32(&mut payload, self.request_item_count);
        crate::write_u32(&mut payload, self.unique_unit_count);
        crate::write_u64(&mut payload, self.logical_bytes);
        payload.extend_from_slice(&self.request_body_sha256);
        frame_bytes(KIND_END, &payload, stream_id, sequence)
    }
}

impl ErrorPayload {
    /// Encode with a canonical (compact) JSON body.
    pub fn encode(&self, stream_id: u32, sequence: u64) -> CodecResult<Vec<u8>> {
        let mut payload = String::new();
        payload.push_str("{\"code\":");
        payload.push_str(&json_string(&self.code));
        payload.push_str(",\"retryable\":");
        payload.push_str(if self.retryable { "true" } else { "false" });
        payload.push_str(",\"request_id\":");
        payload.push_str(&json_string(&self.request_id));
        payload.push('}');
        if payload.len() > ERROR_MAX_BYTES {
            return Err(CodecError::BadLength("ERROR payload over 4096 bytes"));
        }
        Ok(frame_bytes(
            KIND_ERROR,
            payload.as_bytes(),
            stream_id,
            sequence,
        ))
    }
}

fn json_string(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metapage::{page_id, Entry, EntryKind, Page};

    fn sid() -> u32 {
        42
    }

    fn sample_page() -> Vec<u8> {
        Page::Leaf {
            entries: vec![Entry::file(EntryKind::Regular, b"a", 1, [9; 32])],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn meta_frame_roundtrip() {
        let page = sample_page();
        let p = MetaPayload {
            pages: vec![(page_id(&page), page)],
        };
        let bytes = p.encode(sid(), 0).unwrap();
        let (frame, used) = parse_frame(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(frame, Frame::Meta(p));
    }

    #[test]
    fn object_frame_roundtrip_and_digest() {
        let d1 = crate::sha256(&[b"hello"]);
        let d2 = crate::sha256(&[b""]);
        let p = ObjectPayload {
            objects: vec![(d1, b"hello".to_vec()), (d2, vec![])],
        };
        let bytes = p.encode(sid(), 0).unwrap();
        let (frame, _) = parse_frame(&bytes).unwrap();
        assert_eq!(frame, Frame::Object(p));
    }

    #[test]
    fn object_digest_mismatch_rejected() {
        // Frame digest correct for payload, but object content digest wrong.
        let mut payload = Vec::new();
        crate::write_u16(&mut payload, 1);
        crate::write_u16(&mut payload, 0);
        payload.extend_from_slice(&[1; 32]);
        crate::write_u32(&mut payload, 5); // object_len
        crate::write_u32(&mut payload, 0); // offset
        payload.extend_from_slice(b"xxxxx"); // not SHA256([1;32]) content
        let bytes = frame_bytes(KIND_OBJECT, &payload, sid(), 0);
        assert!(matches!(
            parse_frame(&bytes),
            Err(CodecError::DigestMismatch(_))
        ));
    }

    #[test]
    fn chunk_frame_roundtrip() {
        let p = ChunkPayload {
            map_id: [3; 32],
            file_content_id: [4; 32],
            chunk_index: 7,
            chunk_bytes: vec![0xAB; 1000],
        };
        let bytes = p.encode(sid(), 3).unwrap();
        let (frame, _) = parse_frame(&bytes).unwrap();
        assert_eq!(frame, Frame::Chunk(p));
    }

    #[test]
    fn end_frame_exact_48() {
        let p = EndPayload {
            request_item_count: 2,
            unique_unit_count: 2,
            logical_bytes: 1024,
            request_body_sha256: [5; 32],
        };
        let bytes = p.encode(sid(), 1);
        let (frame, _) = parse_frame(&bytes).unwrap();
        assert_eq!(frame, Frame::End(p));
        // 49 bytes must be rejected.
        let mut payload = Vec::new();
        crate::write_u32(&mut payload, 2);
        crate::write_u32(&mut payload, 2);
        crate::write_u64(&mut payload, 1024);
        payload.extend_from_slice(&[5; 32]);
        payload.push(0);
        let bad = frame_bytes(KIND_END, &payload, sid(), 1);
        assert!(parse_frame(&bad).is_err());
    }

    #[test]
    fn error_frame_closed_schema() {
        let p = ErrorPayload {
            code: "SNAPSHOT_NOT_READY".into(),
            retryable: true,
            request_id: "req-1".into(),
        };
        let bytes = p.encode(sid(), 0).unwrap();
        let (frame, _) = parse_frame(&bytes).unwrap();
        assert_eq!(frame, Frame::Error(p));
        // Unknown key must be rejected (closed schema).
        let bad = b"{\"code\":\"X\",\"retryable\":false,\"request_id\":\"r\",\"extra\":1}";
        assert!(parse_error_json(std::str::from_utf8(bad).unwrap()).is_err());
        // Missing key must be rejected.
        let bad = b"{\"code\":\"X\",\"retryable\":false}";
        assert!(parse_error_json(std::str::from_utf8(bad).unwrap()).is_err());
        // Duplicate key must be rejected.
        let bad = b"{\"code\":\"X\",\"code\":\"Y\",\"retryable\":false,\"request_id\":\"r\"}";
        assert!(parse_error_json(std::str::from_utf8(bad).unwrap()).is_err());
    }

    #[test]
    fn stream_rules() {
        let page = sample_page();
        let page_len = page.len();
        let meta = MetaPayload {
            pages: vec![(page_id(&page), page)],
        };
        let end = EndPayload {
            request_item_count: 1,
            unique_unit_count: 1,
            logical_bytes: page_len as u64,
            request_body_sha256: [7; 32],
        };
        let mut stream = meta.encode(sid(), 0).unwrap();
        stream.extend_from_slice(&end.encode(sid(), 1));
        let frames = parse_stream(&stream).unwrap();
        assert_eq!(frames.len(), 2);
        // Wrong sequence: rejected.
        let mut bad = meta.encode(sid(), 0).unwrap();
        bad.extend_from_slice(&end.encode(sid(), 2));
        assert!(parse_stream(&bad).is_err());
        // Different stream_id: rejected.
        let mut bad = meta.encode(sid(), 0).unwrap();
        bad.extend_from_slice(&end.encode(43, 1));
        assert!(parse_stream(&bad).is_err());
        // Missing END: rejected.
        let one = meta.encode(sid(), 0).unwrap();
        assert!(parse_stream(&one).is_err());
        // Bytes after END: rejected.
        let mut bad = stream.clone();
        bad.extend_from_slice(&end.encode(sid(), 2));
        assert!(parse_stream(&bad).is_err());
    }

    #[test]
    fn header_rules() {
        let p = EndPayload {
            request_item_count: 0,
            unique_unit_count: 0,
            logical_bytes: 0,
            request_body_sha256: [0; 32],
        };
        let mut bytes = p.encode(sid(), 0);
        bytes[7] = FLAG_ZSTD; // END must not be compressed
        assert!(parse_frame(&bytes).is_err());
        let mut bytes = p.encode(sid(), 0);
        bytes[20..24].copy_from_slice(&0u32.to_le_bytes()); // stream_id = 0
        assert!(parse_frame(&bytes).is_err());
        let mut bytes = p.encode(sid(), 0);
        bytes[8..12].copy_from_slice(&128u32.to_le_bytes()); // header_len != 64
        assert!(parse_frame(&bytes).is_err());
        let mut bytes = p.encode(sid(), 0);
        bytes[6] = 9; // unknown kind
        assert!(parse_frame(&bytes).is_err());
        // Payload digest mismatch.
        let mut bytes = p.encode(sid(), 0);
        let n = bytes.len();
        bytes[n - 1] ^= 1;
        assert!(matches!(
            parse_frame(&bytes),
            Err(CodecError::DigestMismatch(_))
        ));
    }
}
