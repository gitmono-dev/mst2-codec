//! Chunk maps (MCM2/MCL2) and pages_root Merkle — spec 07.
//!
//! `content_id = SHA256(raw file bytes)`; chunk maps are a separate,
//! individually authenticated read layout for files > 256 KiB. Fixed chunk
//! size 1 MiB; pages hold up to 256 chunk digests each.

use crate::{
    read_u16, read_u32, read_u64, sha256, write_u16, write_u32, write_u64, CodecError, CodecResult,
};

pub const CHUNK_SIZE: u32 = 1_048_576;
pub const CHUNKS_PER_PAGE: usize = 256;
pub const MAP_LEN: usize = 100;

const MAP_DOMAIN: &[u8] = b"mega.mst2.chunkmap\0";
const LEAF_DOMAIN: &[u8] = b"mega.mst2.chunkleaf\0";
const BRANCH_DOMAIN: &[u8] = b"mega.mst2.chunkbranch\0";

pub const MAP_MAGIC: &[u8; 4] = b"MCM2";
pub const LEAF_MAGIC: &[u8; 4] = b"MCL2";

/// Parsed chunk-map descriptor (spec 07 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkMap {
    pub file_content_id: [u8; 32],
    pub file_size: u64,
    pub chunk_count: u64,
    pub page_count: u64,
    pub pages_root: [u8; 32],
}

/// Parsed chunk-map leaf page (spec 07 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkLeaf {
    pub page_index: u64,
    /// Chunk digests, each over raw chunk bytes.
    pub chunk_sha256: Vec<[u8; 32]>,
}

/// One proof step from a leaf toward the root (spec 07 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStep {
    /// Which side the sibling sits on.
    pub side: ProofSide,
    /// Leaf count of the sibling subtree (decimal-string in JSON).
    pub sibling_pages: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSide {
    Left,
    Right,
}

impl ChunkMap {
    pub fn new(
        file_content_id: [u8; 32],
        file_size: u64,
        pages_root: [u8; 32],
    ) -> CodecResult<Self> {
        if file_size == 0 {
            // Empty files do not use a map.
            return Err(CodecError::BadLength(
                "empty file must not have a chunk map",
            ));
        }
        let chunk_count = file_size.div_ceil(CHUNK_SIZE as u64);
        let page_count = chunk_count.div_ceil(CHUNKS_PER_PAGE as u64);
        Ok(ChunkMap {
            file_content_id,
            file_size,
            chunk_count,
            page_count,
            pages_root,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAP_LEN);
        out.extend_from_slice(MAP_MAGIC);
        write_u16(&mut out, 2); // schema_version
        write_u16(&mut out, 0); // reserved
        out.extend_from_slice(&self.file_content_id);
        write_u64(&mut out, self.file_size);
        write_u32(&mut out, CHUNK_SIZE);
        write_u64(&mut out, self.chunk_count);
        write_u64(&mut out, self.page_count);
        out.extend_from_slice(&self.pages_root);
        debug_assert_eq!(out.len(), MAP_LEN);
        out
    }

    pub fn decode(buf: &[u8]) -> CodecResult<Self> {
        if buf.len() != MAP_LEN {
            return Err(CodecError::BadLength("chunk map must be exactly 100 bytes"));
        }
        if &buf[0..4] != MAP_MAGIC {
            return Err(CodecError::BadConstant("MCM2 magic"));
        }
        if read_u16(buf, 4)? != 2 {
            return Err(CodecError::BadConstant("chunk map schema_version"));
        }
        if read_u16(buf, 6)? != 0 {
            return Err(CodecError::BadConstant("chunk map reserved"));
        }
        let mut file_content_id = [0u8; 32];
        file_content_id.copy_from_slice(&buf[8..40]);
        let file_size = read_u64(buf, 40)?;
        let chunk_size = read_u32(buf, 48)?;
        if chunk_size != CHUNK_SIZE {
            return Err(CodecError::BadConstant(
                "only chunk_size 1MiB accepted this profile",
            ));
        }
        let chunk_count = read_u64(buf, 52)?;
        let page_count = read_u64(buf, 60)?;
        let mut pages_root = [0u8; 32];
        pages_root.copy_from_slice(&buf[68..100]);
        if file_size == 0 {
            return Err(CodecError::BadLength(
                "empty file must not have a chunk map",
            ));
        }
        let expect_chunks = file_size.div_ceil(CHUNK_SIZE as u64);
        if chunk_count != expect_chunks {
            return Err(CodecError::BadLength(
                "chunk_count != ceil(file_size/chunk_size)",
            ));
        }
        if chunk_count == 0 {
            return Err(CodecError::BadLength("chunk_count must be at least 1"));
        }
        let expect_pages = chunk_count.div_ceil(CHUNKS_PER_PAGE as u64);
        if page_count != expect_pages {
            return Err(CodecError::BadLength("page_count != ceil(chunk_count/256)"));
        }
        Ok(ChunkMap {
            file_content_id,
            file_size,
            chunk_count,
            page_count,
            pages_root,
        })
    }

    /// `map_id = SHA256(b"mega.mst2.chunkmap\0" || bytes)`.
    pub fn map_id(&self) -> [u8; 32] {
        let bytes = self.encode();
        sha256(&[MAP_DOMAIN, &bytes])
    }

    /// Last chunk index (0-based).
    pub fn last_chunk_index(&self) -> u64 {
        self.chunk_count - 1
    }

    /// Length of chunk `index` derived from file_size (spec 07 §4).
    pub fn chunk_len(&self, index: u64) -> CodecResult<u64> {
        if index >= self.chunk_count {
            return Err(CodecError::BadLength("chunk index out of range"));
        }
        if index < self.last_chunk_index() {
            Ok(CHUNK_SIZE as u64)
        } else {
            let rem = self.file_size - index * CHUNK_SIZE as u64;
            // The last chunk is the remaining positive length.
            Ok(rem)
        }
    }
}

impl ChunkLeaf {
    /// Encode canonical leaf bytes.
    pub fn encode(&self) -> CodecResult<Vec<u8>> {
        if self.chunk_sha256.is_empty() || self.chunk_sha256.len() > CHUNKS_PER_PAGE {
            return Err(CodecError::BadLength("leaf count must be 1..256"));
        }
        let mut out = Vec::with_capacity(16 + 32 * self.chunk_sha256.len());
        out.extend_from_slice(LEAF_MAGIC);
        write_u64(&mut out, self.page_index);
        write_u16(&mut out, self.chunk_sha256.len() as u16);
        write_u16(&mut out, 0); // reserved
        for d in &self.chunk_sha256 {
            out.extend_from_slice(d);
        }
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> CodecResult<Self> {
        if buf.len() < 16 {
            return Err(CodecError::Truncated("chunk leaf header"));
        }
        if &buf[0..4] != LEAF_MAGIC {
            return Err(CodecError::BadConstant("MCL2 magic"));
        }
        let page_index = read_u64(buf, 4)?;
        let count = read_u16(buf, 12)? as usize;
        if !(1..=CHUNKS_PER_PAGE).contains(&count) {
            return Err(CodecError::BadLength("leaf count must be 1..256"));
        }
        if read_u16(buf, 14)? != 0 {
            return Err(CodecError::BadConstant("chunk leaf reserved"));
        }
        if buf.len() != 16 + 32 * count {
            return Err(CodecError::BadLength("leaf length must be 16 + 32*count"));
        }
        let mut chunk_sha256 = Vec::with_capacity(count);
        for i in 0..count {
            let mut d = [0u8; 32];
            d.copy_from_slice(&buf[16 + i * 32..16 + (i + 1) * 32]);
            chunk_sha256.push(d);
        }
        Ok(ChunkLeaf {
            page_index,
            chunk_sha256,
        })
    }

    /// `L_i = SHA256(b"mega.mst2.chunkleaf\0" || leaf_bytes)`.
    pub fn leaf_hash(&self) -> CodecResult<[u8; 32]> {
        Ok(sha256(&[LEAF_DOMAIN, &self.encode()?]))
    }

    /// Expected count for page `page_index` of a map with `chunk_count`
    /// chunks: 256 except possibly the last page.
    pub fn expected_count(chunk_count: u64, page_index: u64) -> u64 {
        let full = chunk_count / CHUNKS_PER_PAGE as u64;
        let rem = chunk_count % CHUNKS_PER_PAGE as u64;
        if page_index < full {
            CHUNKS_PER_PAGE as u64
        } else {
            rem.max(1)
        }
    }
}

/// Node hash for the pages_root Merkle tree (spec 07 §5).
fn branch_hash(left: &[u8; 32], right: &[u8; 32], left_count: u64, right_count: u64) -> [u8; 32] {
    let mut counts = Vec::with_capacity(16);
    counts.extend_from_slice(&left_count.to_le_bytes());
    counts.extend_from_slice(&right_count.to_le_bytes());
    sha256(&[BRANCH_DOMAIN, &counts, left, right])
}

/// Largest power of two strictly less than `n` (n > 1).
fn largest_pow2_below(n: u64) -> u64 {
    debug_assert!(n > 1);
    let mut k = 1u64 << 63;
    while k >= n {
        k >>= 1;
    }
    k
}

/// Build the pages_root over leaf hashes in page_index order (spec 07 §5).
pub fn merkle_root(leaves: &[[u8; 32]]) -> CodecResult<[u8; 32]> {
    if leaves.is_empty() {
        // Empty mapping is illegal; empty files need no map.
        return Err(CodecError::BadLength("merkle over zero leaves"));
    }
    Ok(build_subtree(leaves).0)
}

fn build_subtree(leaves: &[[u8; 32]]) -> ([u8; 32], u64) {
    let n = leaves.len() as u64;
    if n == 1 {
        return (leaves[0], 1);
    }
    let k = largest_pow2_below(n);
    let (left, lc) = build_subtree(&leaves[..k as usize]);
    let (right, rc) = build_subtree(&leaves[k as usize..]);
    (branch_hash(&left, &right, lc, rc), n)
}

/// The unique split path from leaf `page_index` to the root of a tree with
/// `page_count` leaves, ordered **bottom-up** (innermost sibling first),
/// which is the order proofs are verified in. Verification must derive this
/// itself and check the supplied proof against it — matching the root alone
/// is not enough.
pub fn expected_proof_shape(
    page_count: u64,
    page_index: u64,
) -> CodecResult<Vec<(ProofSide, u64)>> {
    if page_count == 0 || page_index >= page_count {
        return Err(CodecError::BadLength("page_index out of range"));
    }
    let mut steps = Vec::new();
    let mut idx = page_index;
    let mut n = page_count;
    while n > 1 {
        let k = largest_pow2_below(n);
        if idx < k {
            steps.push((ProofSide::Right, n - k));
            n = k;
        } else {
            steps.push((ProofSide::Left, k));
            idx -= k;
            n -= k;
        }
    }
    // The derivation walks root→leaf; proofs verify leaf→root.
    steps.reverse();
    Ok(steps)
}

/// Verify a leaf + proof against `pages_root`. Checks the derived split
/// path (length, side, sibling counts) as well as the final digest.
pub fn verify_leaf(
    page_count: u64,
    page_index: u64,
    leaf_hash: [u8; 32],
    proof: &[ProofStep],
    pages_root: [u8; 32],
) -> CodecResult<()> {
    let shape = expected_proof_shape(page_count, page_index)?;
    if proof.len() != shape.len() {
        return Err(CodecError::BadLength(
            "proof length does not match tree shape",
        ));
    }
    let mut cur = leaf_hash;
    let mut cur_count = 1u64;
    for (step, (side, sib_count)) in proof.iter().zip(shape.iter()) {
        if &step.side != side || step.sibling_pages != *sib_count {
            return Err(CodecError::BadOrdering(
                "proof step does not match derived path",
            ));
        }
        cur = match side {
            ProofSide::Right => branch_hash(&cur, &step.digest, cur_count, *sib_count),
            ProofSide::Left => branch_hash(&step.digest, &cur, *sib_count, cur_count),
        };
        cur_count += *sib_count;
    }
    if cur != pages_root {
        return Err(CodecError::DigestMismatch("pages_root"));
    }
    Ok(())
}

/// Generate the proof for leaf `page_index` from the full leaf-hash list.
pub fn leaf_proof(leaves: &[[u8; 32]], page_index: u64) -> CodecResult<Vec<ProofStep>> {
    if page_index >= leaves.len() as u64 {
        return Err(CodecError::BadLength("page_index out of range"));
    }
    let mut steps = Vec::new();
    let mut idx = page_index as usize;
    let mut rest = leaves;
    while rest.len() > 1 {
        let n = rest.len() as u64;
        let k = largest_pow2_below(n) as usize;
        if idx < k {
            let (root, count) = build_subtree(&rest[k..]);
            steps.push(ProofStep {
                side: ProofSide::Right,
                sibling_pages: count,
                digest: root,
            });
            rest = &rest[..k];
        } else {
            let (root, count) = build_subtree(&rest[..k]);
            steps.push(ProofStep {
                side: ProofSide::Left,
                sibling_pages: count,
                digest: root,
            });
            rest = &rest[k..];
            idx -= k;
        }
    }
    // Emit bottom-up (innermost sibling first), matching verification order.
    steps.reverse();
    Ok(steps)
}

/// Range-read arithmetic (spec 07 §6): which chunks cover
/// `[offset, min(file_size, offset+length))`.
pub fn range_chunks(offset: u64, length: u64, file_size: u64) -> CodecResult<(u64, u64)> {
    if length == 0 {
        return Err(CodecError::BadLength("zero-length read"));
    }
    if offset >= file_size {
        return Err(CodecError::BadLength("offset at or past EOF"));
    }
    // overflow-safe end
    let end = if length >= file_size - offset {
        file_size
    } else {
        offset + length
    };
    let chunk = CHUNK_SIZE as u64;
    let start_chunk = offset / chunk;
    let end_chunk = (end - 1) / chunk;
    Ok((start_chunk, end_chunk))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_digest(seed: u8, i: usize) -> [u8; 32] {
        let mut d = [seed; 32];
        d[0] = (i & 0xff) as u8;
        d[1] = ((i >> 8) & 0xff) as u8;
        d
    }

    #[test]
    fn map_roundtrip_and_map_id() {
        let m = ChunkMap::new([1; 32], 5 * 1024 * 1024, [2; 32]).unwrap();
        assert_eq!(m.chunk_count, 5);
        assert_eq!(m.page_count, 1);
        let bytes = m.encode();
        assert_eq!(bytes.len(), 100);
        assert_eq!(ChunkMap::decode(&bytes).unwrap(), m);
        let id = m.map_id();
        assert_eq!(id, sha256(&[MAP_DOMAIN, &bytes]));
        // Single-chunk file
        let m2 = ChunkMap::new([1; 32], 1, [2; 32]).unwrap();
        assert_eq!(m2.chunk_count, 1);
        assert_eq!(m2.chunk_len(0).unwrap(), 1);
    }

    #[test]
    fn map_field_validation() {
        let m = ChunkMap::new([1; 32], 1024, [2; 32]).unwrap();
        let mut bytes = m.encode();
        bytes[4] = 3; // schema_version
        assert!(ChunkMap::decode(&bytes).is_err());
        let mut bytes = m.encode();
        bytes[48..52].copy_from_slice(&512u32.to_le_bytes()); // chunk_size
        assert!(ChunkMap::decode(&bytes).is_err());
        let mut bytes = m.encode();
        bytes[52..60].copy_from_slice(&99u64.to_le_bytes()); // chunk_count wrong
        assert!(ChunkMap::decode(&bytes).is_err());
        // Empty file map rejected.
        assert!(ChunkMap::new([1; 32], 0, [2; 32]).is_err());
    }

    #[test]
    fn leaf_roundtrip_and_last_page_rule() {
        let leaf = ChunkLeaf {
            page_index: 0,
            chunk_sha256: vec![[9; 32]; 256],
        };
        let bytes = leaf.encode().unwrap();
        assert_eq!(bytes.len(), 16 + 32 * 256);
        assert_eq!(ChunkLeaf::decode(&bytes).unwrap(), leaf);
        // 0 or 257 digests rejected
        assert!(ChunkLeaf {
            page_index: 0,
            chunk_sha256: vec![]
        }
        .encode()
        .is_err());
        assert!(ChunkLeaf {
            page_index: 0,
            chunk_sha256: vec![[9; 32]; 257]
        }
        .encode()
        .is_err());
        // All but the last page must have exactly 256 (checked via helper).
        assert_eq!(ChunkLeaf::expected_count(600, 0), 256);
        assert_eq!(ChunkLeaf::expected_count(600, 1), 256);
        assert_eq!(ChunkLeaf::expected_count(600, 2), 88);
        assert_eq!(ChunkLeaf::expected_count(256, 0), 256);
    }

    #[test]
    fn chunk_len_rules() {
        // 2.5 MiB file: chunks 0,1 = 1MiB; chunk 2 = 512KiB.
        let size = 2 * CHUNK_SIZE as u64 + 512 * 1024;
        let m = ChunkMap::new([1; 32], size, [2; 32]).unwrap();
        assert_eq!(m.chunk_count, 3);
        assert_eq!(m.chunk_len(0).unwrap(), CHUNK_SIZE as u64);
        assert_eq!(m.chunk_len(1).unwrap(), CHUNK_SIZE as u64);
        assert_eq!(m.chunk_len(2).unwrap(), 512 * 1024);
        assert!(m.chunk_len(3).is_err());
        // BODY-09: exact multiple — last chunk is full, not zero.
        let m = ChunkMap::new([1; 32], 3 * CHUNK_SIZE as u64, [2; 32]).unwrap();
        assert_eq!(m.chunk_len(2).unwrap(), CHUNK_SIZE as u64);
    }

    #[test]
    fn merkle_single_and_multi() {
        // n = 1: root = L0.
        let leaves = vec![fake_digest(1, 0)];
        assert_eq!(merkle_root(&leaves).unwrap(), leaves[0]);
        // n = 2: branch with counts 1,1.
        let leaves = vec![fake_digest(1, 0), fake_digest(1, 1)];
        let expect = branch_hash(&leaves[0], &leaves[1], 1, 1);
        assert_eq!(merkle_root(&leaves).unwrap(), expect);
        // n = 3: k = 2 → left 2 leaves, right 1.
        let leaves = vec![fake_digest(1, 0), fake_digest(1, 1), fake_digest(1, 2)];
        let (lroot, lc) = build_subtree(&leaves[..2]);
        let (rroot, rc) = build_subtree(&leaves[2..]);
        assert_eq!(
            merkle_root(&leaves).unwrap(),
            branch_hash(&lroot, &rroot, lc, rc)
        );
    }

    #[test]
    fn proof_roundtrip_all_positions() {
        for n in [2u64, 3, 4, 5, 7, 8, 9, 600] {
            let leaves: Vec<[u8; 32]> = (0..n).map(|i| fake_digest(3, i as usize)).collect();
            let root = merkle_root(&leaves).unwrap();
            for i in 0..n {
                let proof = leaf_proof(&leaves, i).unwrap();
                verify_leaf(n, i, leaves[i as usize], &proof, root).unwrap();
            }
            // Tampered proof rejected.
            let mut proof = leaf_proof(&leaves, 0).unwrap();
            proof[0].digest[0] ^= 1;
            assert!(verify_leaf(n, 0, leaves[0], &proof, root).is_err());
            // Wrong length rejected.
            assert!(verify_leaf(n, 0, leaves[0], &[], root).is_err());
            // Wrong leaf rejected.
            assert!(verify_leaf(n, 0, [0xff; 32], &leaf_proof(&leaves, 0).unwrap(), root).is_err());
        }
    }

    #[test]
    fn proof_shape_is_derived_independently() {
        // n=5, k=4: leaf 4 sits in the right subtree (1 leaf) → single
        // (Left,4) step. Leaf 0 walks (Right,1) → (Right,2) → (Right,1).
        let shape = expected_proof_shape(5, 4).unwrap();
        assert_eq!(shape, vec![(ProofSide::Left, 4)]);
        let shape = expected_proof_shape(5, 0).unwrap();
        assert_eq!(
            shape,
            vec![
                (ProofSide::Right, 1),
                (ProofSide::Right, 2),
                (ProofSide::Right, 1)
            ]
        );
        assert!(expected_proof_shape(0, 0).is_err());
        assert!(expected_proof_shape(5, 5).is_err());
    }

    #[test]
    fn range_arithmetic() {
        let size = 100 * 1024 * 1024u64; // 100 MiB
                                         // Spec 07 §6 example: 64 KiB at offset 100 MiB would be past EOF for
                                         // this file; use in-bounds cases here.
        let (s, e) = range_chunks(0, 64 * 1024, size).unwrap();
        assert_eq!((s, e), (0, 0));
        let (s, e) = range_chunks(100 * 1024 * 1024 - 1, 1, size).unwrap();
        assert_eq!((s, e), (99, 99));
        // Crossing a boundary takes two chunks.
        let (s, e) = range_chunks(CHUNK_SIZE as u64 - 1, 2, size).unwrap();
        assert_eq!((s, e), (0, 1));
        // Zero-length read and past-EOF rejected.
        assert!(range_chunks(0, 0, size).is_err());
        assert!(range_chunks(size, 1, size).is_err());
        // Overflow-safe: huge length clamps to EOF.
        let (s, e) = range_chunks(size - 1, u64::MAX, size).unwrap();
        assert_eq!((s, e), (99, 99));
    }
}
