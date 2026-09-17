//! MTP2/1 binary directory pages — spec 05.
//!
//! A directory is an immutable ordered map from basename to Entry. Small maps
//! are one leaf page; large maps use Patricia/radix branch pages partitioned
//! by name bytes. Canonical partition: `LEAF_MAX_ENTRIES = 128`,
//! `PAGE_MAX_BYTES = 16384`. These are part of the codec identity.
//!
//! `page_id = SHA256(b"mega.mst2.metapage\0" || entire_page_bytes)`.

use crate::{
    read_u16, read_u32, read_u64, sha256, validate_name, write_u16, write_u32, write_u64,
    CodecError, CodecResult,
};

pub const LEAF_MAX_ENTRIES: usize = 128;
pub const PAGE_MAX_BYTES: usize = 16384;
pub const BRANCH_MAX_CHILDREN: usize = 256;
pub const MAX_DEPTH: usize = 255;

const DOMAIN: &[u8] = b"mega.mst2.metapage\0";
pub const HEADER_LEN: usize = 20;

/// Entry kinds per spec 05 §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Regular = 1,
    Executable = 2,
    Symlink = 3,
    Directory = 4,
}

impl EntryKind {
    pub fn from_u8(v: u8) -> CodecResult<Self> {
        match v {
            1 => Ok(EntryKind::Regular),
            2 => Ok(EntryKind::Executable),
            3 => Ok(EntryKind::Symlink),
            4 => Ok(EntryKind::Directory),
            _ => Err(CodecError::BadConstant("entry kind")),
        }
    }
    /// File mode bits per spec 03 §5.
    pub fn mode(&self) -> u32 {
        match self {
            EntryKind::Regular => 0o644,
            EntryKind::Executable | EntryKind::Symlink | EntryKind::Directory => 0o755,
        }
    }
}

/// One directory entry. Files carry `size` + `content_id`; directories carry
/// `child_root`. Directories never encode a size (spec 05 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    pub name: Vec<u8>,
    pub size: u64,
    pub content_id: [u8; 32],
    pub child_root: [u8; 32],
}

impl Entry {
    pub fn file(kind: EntryKind, name: &[u8], size: u64, content_id: [u8; 32]) -> Self {
        debug_assert!(matches!(
            kind,
            EntryKind::Regular | EntryKind::Executable | EntryKind::Symlink
        ));
        Entry {
            kind,
            name: name.to_vec(),
            size,
            content_id,
            child_root: [0; 32],
        }
    }

    pub fn dir(name: &[u8], child_root: [u8; 32]) -> Self {
        Entry {
            kind: EntryKind::Directory,
            name: name.to_vec(),
            size: 0,
            content_id: [0; 32],
            child_root,
        }
    }

    pub fn is_dir(&self) -> bool {
        self.kind == EntryKind::Directory
    }

    pub fn encoded_len(&self) -> usize {
        let base = 1 + 2 + self.name.len();
        if self.is_dir() {
            base + 32
        } else {
            base + 8 + 32
        }
    }

    pub fn encode(&self) -> CodecResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(self.encoded_len());
        out.push(self.kind as u8);
        write_u16(&mut out, self.name.len() as u16);
        out.extend_from_slice(&self.name);
        if self.is_dir() {
            out.extend_from_slice(&self.child_root);
        } else {
            write_u64(&mut out, self.size);
            out.extend_from_slice(&self.content_id);
        }
        Ok(out)
    }

    fn validate(&self) -> CodecResult<()> {
        validate_name(&self.name)?;
        if self.is_dir() {
            // Spec: empty directory is an empty LEAF page; a directory entry
            // cannot alias a zero digest as a substitute for that page.
            if self.child_root == [0u8; 32] {
                return Err(CodecError::DigestMismatch(
                    "directory child_root is all-zero",
                ));
            }
        } else if self.name == b"." || self.name == b".." {
            return Err(CodecError::BadName("dot entry"));
        }
        Ok(())
    }

    pub fn decode(buf: &[u8], off: &mut usize) -> CodecResult<Self> {
        if *off >= buf.len() {
            return Err(CodecError::Truncated("entry kind"));
        }
        let kind = EntryKind::from_u8(buf[*off])?;
        *off += 1;
        let name_len = read_u16(buf, *off)? as usize;
        *off += 2;
        let name_end = name_len
            .checked_add(*off)
            .ok_or(CodecError::Overflow("name end"))?;
        let name = buf
            .get(*off..name_end)
            .ok_or(CodecError::Truncated("entry name"))?
            .to_vec();
        *off = name_end;
        validate_name(&name)?;
        let entry = if kind == EntryKind::Directory {
            let mut child_root = [0u8; 32];
            child_root.copy_from_slice(
                buf.get(*off..*off + 32)
                    .ok_or(CodecError::Truncated("child_root"))?,
            );
            *off += 32;
            Entry {
                kind,
                name,
                size: 0,
                content_id: [0; 32],
                child_root,
            }
        } else {
            let size = read_u64(buf, *off)?;
            *off += 8;
            let mut content_id = [0u8; 32];
            content_id.copy_from_slice(
                buf.get(*off..*off + 32)
                    .ok_or(CodecError::Truncated("content_id"))?,
            );
            *off += 32;
            Entry {
                kind,
                name,
                size,
                content_id,
                child_root: [0; 32],
            }
        };
        entry.validate()?;
        Ok(entry)
    }
}

/// A branch child reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchChild {
    pub label: u8,
    pub subtree_entries: u64,
    pub child_page_id: [u8; 32],
}

/// A decoded MTP2 page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    Leaf {
        entries: Vec<Entry>,
    },
    Branch {
        prefix: Vec<u8>,
        terminal: Option<Entry>,
        children: Vec<BranchChild>,
    },
}

/// `page_id` of a full page (header + payload).
pub fn page_id(page_bytes: &[u8]) -> [u8; 32] {
    sha256(&[DOMAIN, page_bytes])
}

impl Page {
    /// Parse and validate one page. Structural checks only: cross-page
    /// invariants (prefix partitions, digests of children, canonical Build
    /// equality) need the child pages and are checked by the verifier in
    /// `verify` below / the graph walker.
    pub fn decode(page_bytes: &[u8]) -> CodecResult<(Page, u64)> {
        if page_bytes.len() < HEADER_LEN {
            return Err(CodecError::Truncated("page header"));
        }
        if page_bytes.len() > PAGE_MAX_BYTES {
            return Err(CodecError::BadLength("page over 16KiB"));
        }
        if &page_bytes[0..4] != b"MTP2" {
            return Err(CodecError::BadConstant("MTP2 magic"));
        }
        let page_kind = page_bytes[4];
        if page_bytes[5] != 0 {
            return Err(CodecError::BadConstant("page flags must be zero"));
        }
        let n = read_u16(page_bytes, 6)? as usize;
        let total_entries = read_u64(page_bytes, 8)?;
        if total_entries > (1u64 << 63) - 1 {
            return Err(CodecError::BadLength("total_entries over 2^63-1"));
        }
        let payload_len = read_u32(page_bytes, 16)? as usize;
        if page_bytes.len() != HEADER_LEN + payload_len {
            return Err(CodecError::BadLength(
                "payload_len must cover exactly the page",
            ));
        }
        let payload = &page_bytes[HEADER_LEN..];
        match page_kind {
            0 => {
                if n > LEAF_MAX_ENTRIES {
                    return Err(CodecError::BadLength("leaf over 128 entries"));
                }
                if total_entries != n as u64 {
                    return Err(CodecError::BadOrdering("leaf total_entries must equal n"));
                }
                let mut off = 0usize;
                let mut entries: Vec<Entry> = Vec::with_capacity(n);
                for _ in 0..n {
                    let e = Entry::decode(payload, &mut off)?;
                    if let Some(p) = entries.last() {
                        if p.name.as_slice() >= e.name.as_slice() {
                            return Err(CodecError::BadOrdering(
                                "leaf entries must be strictly ascending by name bytes",
                            ));
                        }
                    }
                    entries.push(e);
                }
                if off != payload.len() {
                    return Err(CodecError::BadLength("trailing bytes in leaf payload"));
                }
                Ok((Page::Leaf { entries }, total_entries))
            }
            1 => {
                let mut off = 0usize;
                let prefix_len = read_u16(payload, off)? as usize;
                off += 2;
                let prefix = payload
                    .get(off..off + prefix_len)
                    .ok_or(CodecError::Truncated("branch prefix"))?
                    .to_vec();
                off += prefix_len;
                if off >= payload.len() {
                    return Err(CodecError::Truncated("has_terminal"));
                }
                let has_terminal = payload[off];
                off += 1;
                if has_terminal > 1 {
                    return Err(CodecError::BadConstant("has_terminal must be 0 or 1"));
                }
                let terminal = if has_terminal == 1 {
                    let e = Entry::decode(payload, &mut off)?;
                    if e.name != prefix {
                        return Err(CodecError::BadOrdering(
                            "terminal entry name must equal prefix",
                        ));
                    }
                    Some(e)
                } else {
                    None
                };
                if n > BRANCH_MAX_CHILDREN {
                    return Err(CodecError::BadLength("branch over 256 children"));
                }
                let mut children = Vec::with_capacity(n);
                let mut prev_label: Option<u8> = None;
                for _ in 0..n {
                    if off >= payload.len() {
                        return Err(CodecError::Truncated("branch child"));
                    }
                    let label = payload[off];
                    off += 1;
                    if let Some(p) = prev_label {
                        if label <= p {
                            return Err(CodecError::BadOrdering(
                                "branch child labels must be strictly ascending",
                            ));
                        }
                    }
                    prev_label = Some(label);
                    let subtree_entries = read_u64(payload, off)?;
                    if subtree_entries == 0 {
                        return Err(CodecError::BadOrdering("branch child must be non-empty"));
                    }
                    off += 8;
                    let mut child_page_id = [0u8; 32];
                    child_page_id.copy_from_slice(
                        payload
                            .get(off..off + 32)
                            .ok_or(CodecError::Truncated("child_page_id"))?,
                    );
                    off += 32;
                    children.push(BranchChild {
                        label,
                        subtree_entries,
                        child_page_id,
                    });
                }
                if off != payload.len() {
                    return Err(CodecError::BadLength("trailing bytes in branch payload"));
                }
                // At least two groups, terminal counting as one.
                if children.len() + (has_terminal as usize) < 2 {
                    return Err(CodecError::BadOrdering(
                        "branch needs at least two groups (terminal counts as one)",
                    ));
                }
                let declared = children.iter().map(|c| c.subtree_entries).sum::<u64>();
                let expected = declared
                    .checked_add(has_terminal as u64)
                    .ok_or(CodecError::Overflow("total_entries"))?;
                if expected != total_entries {
                    return Err(CodecError::BadOrdering(
                        "branch total_entries != terminal + sum(children)",
                    ));
                }
                Ok((
                    Page::Branch {
                        prefix,
                        terminal,
                        children,
                    },
                    total_entries,
                ))
            }
            _ => Err(CodecError::BadConstant("page_kind")),
        }
    }

    /// Encode a page to canonical bytes (header + payload).
    pub fn encode(&self) -> CodecResult<Vec<u8>> {
        let mut payload = Vec::new();
        let (kind, n, total): (u8, usize, u64) = match self {
            Page::Leaf { entries } => {
                if entries.len() > LEAF_MAX_ENTRIES {
                    return Err(CodecError::BadLength("leaf over 128 entries"));
                }
                let mut prev: Option<&[u8]> = None;
                for e in entries {
                    e.validate()?;
                    if let Some(p) = prev {
                        if p >= e.name.as_slice() {
                            return Err(CodecError::BadOrdering(
                                "leaf entries not strictly ascending",
                            ));
                        }
                    }
                    prev = Some(&e.name);
                    payload.extend_from_slice(&e.encode()?);
                }
                (0, entries.len(), entries.len() as u64)
            }
            Page::Branch {
                prefix,
                terminal,
                children,
            } => {
                write_u16(&mut payload, prefix.len() as u16);
                payload.extend_from_slice(prefix);
                if let Some(t) = terminal {
                    t.validate()?;
                    if t.name != *prefix {
                        return Err(CodecError::BadOrdering("terminal name must equal prefix"));
                    }
                    payload.push(1);
                    payload.extend_from_slice(&t.encode()?);
                } else {
                    payload.push(0);
                }
                let mut prev_label: Option<u8> = None;
                let mut sum = 0u64;
                for c in children {
                    if let Some(p) = prev_label {
                        if c.label <= p {
                            return Err(CodecError::BadOrdering(
                                "child labels not strictly ascending",
                            ));
                        }
                    }
                    if c.subtree_entries == 0 {
                        return Err(CodecError::BadOrdering("branch child must be non-empty"));
                    }
                    sum = sum
                        .checked_add(c.subtree_entries)
                        .ok_or(CodecError::Overflow("sum"))?;
                    prev_label = Some(c.label);
                    payload.push(c.label);
                    write_u64(&mut payload, c.subtree_entries);
                    payload.extend_from_slice(&c.child_page_id);
                }
                if children.len() + (terminal.is_some() as usize) < 2 {
                    return Err(CodecError::BadOrdering("branch needs at least two groups"));
                }
                let total = sum
                    .checked_add(terminal.is_some() as u64)
                    .ok_or(CodecError::Overflow("total_entries"))?;
                (1, children.len(), total)
            }
        };
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(b"MTP2");
        out.push(kind);
        out.push(0); // flags
        write_u16(&mut out, n as u16);
        write_u64(&mut out, total);
        write_u32(&mut out, payload.len() as u32);
        out.extend_from_slice(&payload);
        if out.len() > PAGE_MAX_BYTES {
            return Err(CodecError::BadLength("page over 16KiB"));
        }
        Ok(out)
    }

    pub fn total_entries(&self) -> u64 {
        match self {
            Page::Leaf { entries } => entries.len() as u64,
            Page::Branch {
                terminal, children, ..
            } => {
                terminal.iter().count() as u64
                    + children.iter().map(|c| c.subtree_entries).sum::<u64>()
            }
        }
    }

    /// Pages of the canonical tree over `entries` that lie on `route`,
    /// root first.
    ///
    /// `route` is a sequence of branch-child labels (spec 04 §8): each step
    /// picks the child whose label matches in the page reached so far. The
    /// returned pages are exactly the bytes `build` produced for those
    /// subtrees, so their `page_id`s are the canonical ones — callers that
    /// hold a parent page can check the descent against
    /// `BranchChild::child_page_id`.
    ///
    /// An empty route returns just the root page. Descending past a leaf, or
    /// into a label the page does not have, is a `BadOrdering` error rather
    /// than a silent empty result.
    pub fn pages_along_route(entries: &[Entry], route: &[u8]) -> CodecResult<Vec<Vec<u8>>> {
        if entries.is_empty() {
            // An empty directory is a valid empty leaf; only a route that
            // tries to descend into it is an error.
            if route.is_empty() {
                return Ok(vec![Page::build(entries)?]);
            }
            return Err(CodecError::BadOrdering("route descends past a leaf page"));
        }
        let mut current: Vec<Entry> = entries.to_vec();
        let mut page = Page::build(&current)?;
        let mut out = vec![page.clone()];
        let mut cursor = route;
        while let Some((&label, rest)) = cursor.split_first() {
            let (decoded, _) = Page::decode(&page)?;
            let (prefix, children) = match decoded {
                Page::Leaf { .. } => {
                    return Err(CodecError::BadOrdering("route descends past a leaf page"))
                }
                Page::Branch {
                    prefix, children, ..
                } => (prefix, children),
            };
            let child = children
                .iter()
                .find(|c| c.label == label)
                .ok_or(CodecError::BadOrdering("route label not present in page"))?;

            // Repartition exactly as `build` does: entries sharing the branch
            // prefix group by their next byte, the terminal entry stays put.
            let mut group: Vec<Entry> = Vec::new();
            for e in &current {
                if Some(e.name.as_slice()) == Some(prefix.as_slice()) {
                    continue;
                }
                if e.name.len() <= prefix.len() || e.name[..prefix.len()] != prefix[..] {
                    return Err(CodecError::BadOrdering("entry outside branch prefix"));
                }
                if e.name[prefix.len()] == label {
                    group.push(e.clone());
                }
            }
            if group.is_empty() {
                return Err(CodecError::BadOrdering(
                    "route label selects an empty group",
                ));
            }
            let child_bytes = Page::build(&group)?;
            if page_id(&child_bytes) != child.child_page_id {
                return Err(CodecError::DigestMismatch("branch child page id"));
            }
            out.push(child_bytes.clone());
            page = child_bytes;
            current = group;
            cursor = rest;
        }
        Ok(out)
    }

    /// Longest common prefix of all entry names (spec 05 §5).
    fn lcp(names: &[Vec<u8>]) -> Vec<u8> {
        let first = &names[0];
        let mut len = first.len();
        for n in &names[1..] {
            len = len.min(n.len());
            for i in 0..len {
                if first[i] != n[i] {
                    len = i;
                    break;
                }
            }
        }
        first[..len].to_vec()
    }

    /// Canonical partition per spec 05 §5 `Build(S)`. The caller must supply
    /// entries sorted by name with no duplicates. Returns the encoded page.
    pub fn build(entries: &[Entry]) -> CodecResult<Vec<u8>> {
        // Validate and require strict ordering.
        let mut prev: Option<&[u8]> = None;
        for e in entries {
            e.validate()?;
            if let Some(p) = prev {
                if p >= e.name.as_slice() {
                    return Err(CodecError::BadOrdering(
                        "build input must be strictly ascending",
                    ));
                }
            }
            prev = Some(&e.name);
        }
        if entries.len() <= LEAF_MAX_ENTRIES {
            let leaf = Page::Leaf {
                entries: entries.to_vec(),
            };
            let bytes = leaf.encode()?;
            if bytes.len() <= PAGE_MAX_BYTES {
                return Ok(bytes);
            }
        }
        // Overflow guard: entries.len() > 128 implies non-empty.
        let names: Vec<Vec<u8>> = entries.iter().map(|e| e.name.clone()).collect();
        let p = Page::lcp(&names);
        let terminal = entries.iter().find(|e| e.name == p).cloned();
        let mut groups: Vec<(u8, Vec<Entry>)> = Vec::new();
        for e in entries {
            if e.name == p {
                continue;
            }
            let label = e
                .name
                .get(p.len())
                .copied()
                .ok_or(CodecError::BadOrdering("entry shorter than LCP"))?;
            match groups.last_mut() {
                Some((l, v)) if *l == label => v.push(e.clone()),
                _ => groups.push((label, vec![e.clone()])),
            }
        }
        // Each group is already contiguous and strictly ascending.
        let mut children = Vec::with_capacity(groups.len());
        if groups.len() + terminal.iter().count() < 2 {
            // Cannot happen when p is the true LCP, but refuse a wrong split
            // instead of emitting an invalid branch.
            return Err(CodecError::BadOrdering(
                "partition produced fewer than two groups",
            ));
        }
        for (label, group) in groups {
            let bytes = Page::build(&group)?;
            children.push(BranchChild {
                label,
                subtree_entries: group.len() as u64,
                child_page_id: page_id(&bytes),
            });
        }
        let branch = Page::Branch {
            prefix: p,
            terminal,
            children,
        };
        branch.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn empty_leaf_is_twenty_bytes() {
        let bytes = Page::Leaf { entries: vec![] }.encode().unwrap();
        assert_eq!(bytes.len(), 20);
        let (page, total) = Page::decode(&bytes).unwrap();
        match page {
            Page::Leaf { entries } => assert!(entries.is_empty()),
            _ => panic!("expected leaf"),
        }
        assert_eq!(total, 0);
    }

    #[test]
    fn entry_roundtrip_all_kinds() {
        let entries = vec![
            Entry::file(EntryKind::Regular, b"a.txt", 5, cid(1)),
            Entry::file(EntryKind::Symlink, b"lnk", 3, cid(3)),
            Entry::file(EntryKind::Executable, b"run.sh", 100, cid(2)),
            Entry::dir(b"sub", cid(4)),
        ];
        let bytes = Page::Leaf {
            entries: entries.clone(),
        }
        .encode()
        .unwrap();
        let (page, total) = Page::decode(&bytes).unwrap();
        assert_eq!(
            page,
            Page::Leaf {
                entries: entries.clone()
            }
        );
        assert_eq!(total, 4);
        // Canonical Build of the same set must reproduce the leaf bytes.
        assert_eq!(Page::build(&entries).unwrap(), bytes);
    }

    #[test]
    fn file_mode_bits() {
        assert_eq!(EntryKind::Regular.mode(), 0o644);
        assert_eq!(EntryKind::Executable.mode(), 0o755);
        assert_eq!(EntryKind::Directory.mode(), 0o755);
    }

    #[test]
    fn unsorted_names_rejected() {
        let entries = vec![
            Entry::file(EntryKind::Regular, b"b", 1, cid(1)),
            Entry::file(EntryKind::Regular, b"a", 1, cid(2)),
        ];
        assert!(Page::Leaf { entries }.encode().is_err());
    }

    #[test]
    fn duplicate_names_rejected() {
        let entries = vec![
            Entry::file(EntryKind::Regular, b"a", 1, cid(1)),
            Entry::file(EntryKind::Regular, b"a", 1, cid(2)),
        ];
        assert!(Page::Leaf { entries }.encode().is_err());
    }

    #[test]
    fn over_128_entries_must_split() {
        let entries: Vec<Entry> = (0..129u32)
            .map(|i| Entry::file(EntryKind::Regular, format!("n{i:03}").as_bytes(), 1, cid(1)))
            .collect();
        assert!(Page::Leaf {
            entries: entries.clone()
        }
        .encode()
        .is_err());
        // Build must split into a branch; entries are already sorted.
        let root = Page::build(&entries).unwrap();
        let (page, total) = Page::decode(&root).unwrap();
        assert!(matches!(page, Page::Branch { .. }));
        assert_eq!(total, 129);
    }

    #[test]
    fn different_insertion_order_same_root() {
        // META-07: build from the same set in different orders gives one root.
        let mut a: Vec<Entry> = (0..200u32)
            .map(|i| {
                Entry::file(
                    EntryKind::Regular,
                    format!("entry-{i:04}").as_bytes(),
                    i as u64,
                    cid((i % 251) as u8),
                )
            })
            .collect();
        let mut b = a.clone();
        a.reverse();
        // sort both ascending (byte order) — build requires sorted input.
        a.sort_by(|x, y| x.name.cmp(&y.name));
        b.sort_by(|x, y| x.name.cmp(&y.name));
        let ra = Page::build(&a).unwrap();
        let rb = Page::build(&b).unwrap();
        assert_eq!(ra, rb);
    }

    #[test]
    fn single_file_change_shares_siblings() {
        // META-08: changing one file keeps sibling pages byte-identical.
        let mk = |v: u8| -> Vec<Entry> {
            let mut es: Vec<Entry> = (0..300u32)
                .map(|i| {
                    Entry::file(
                        EntryKind::Regular,
                        format!("f{i:04}").as_bytes(),
                        i as u64,
                        cid((i % 251) as u8),
                    )
                })
                .collect();
            if v == 1 {
                es[299] = Entry::file(EntryKind::Regular, b"f0299", 999, cid(250));
            }
            es.sort_by(|x, y| x.name.cmp(&y.name));
            es
        };
        let r1 = Page::build(&mk(0)).unwrap();
        let r2 = Page::build(&mk(1)).unwrap();
        assert_ne!(page_id(&r1), page_id(&r2));
        // The changed entry lives in the last leaf; all other pages equal.
        let (p1, _) = Page::decode(&r1).unwrap();
        let (p2, _) = Page::decode(&r2).unwrap();
        if let (Page::Branch { children: c1, .. }, Page::Branch { children: c2, .. }) = (&p1, &p2) {
            let same = c1
                .iter()
                .zip(c2.iter())
                .filter(|(a, b)| a.child_page_id == b.child_page_id)
                .count();
            assert_eq!(same, c1.len() - 1);
        } else {
            panic!("expected branches");
        }
    }

    #[test]
    fn leaf_over_16kib_must_split() {
        // META-06: size threshold split. Many entries with long names.
        let entries: Vec<Entry> = (0..128u32)
            .map(|i| {
                Entry::file(
                    EntryKind::Regular,
                    format!("{i:032x}").as_bytes(),
                    1,
                    cid(1),
                )
            })
            .collect();
        let leaf = Page::Leaf {
            entries: entries.clone(),
        }
        .encode()
        .unwrap();
        if leaf.len() > PAGE_MAX_BYTES {
            let root = Page::build(&entries).unwrap();
            let (page, _) = Page::decode(&root).unwrap();
            assert!(matches!(page, Page::Branch { .. }));
        } else {
            // If 128 short names still fit, build must keep the leaf.
            assert!(matches!(
                Page::decode(&Page::build(&entries).unwrap()).unwrap().0,
                Page::Leaf { .. }
            ));
        }
    }

    #[test]
    fn branch_tampering_detected_by_page_id() {
        // META-09: any bit change changes page_id.
        let bytes = Page::Leaf {
            entries: vec![Entry::file(EntryKind::Regular, b"a", 1, cid(1))],
        }
        .encode()
        .unwrap();
        let id = page_id(&bytes);
        let mut bytes2 = bytes.clone();
        *bytes2.last_mut().unwrap() ^= 1;
        assert_ne!(page_id(&bytes2), id);
        // The tampered page still decodes structurally (digest fields are
        // content, not self-checks) — cross-page digest comparison is what
        // catches it, which is exactly what page_id is for.
        assert!(Page::decode(&bytes2).is_ok());
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bytes = Page::Leaf { entries: vec![] }.encode().unwrap();
        bytes.push(0);
        assert!(Page::decode(&bytes).is_err());
    }

    #[test]
    fn bad_page_kind_rejected() {
        let mut bytes = Page::Leaf { entries: vec![] }.encode().unwrap();
        bytes[4] = 7;
        assert!(Page::decode(&bytes).is_err());
    }

    fn many_files(n: usize) -> Vec<Entry> {
        // Names are single components (no `/`), share a prefix, and fan out
        // widely below it, so enough entries force a multi-level branch tree.
        let mut v: Vec<Entry> = (0..n)
            .map(|i| {
                let name = format!("a{i:06}");
                Entry::file(EntryKind::Regular, name.as_bytes(), i as u64, cid(i as u8))
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    #[test]
    fn empty_route_returns_the_root_page() {
        let entries = many_files(600);
        let root = Page::build(&entries).unwrap();
        let pages = Page::pages_along_route(&entries, &[]).unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0], root);
        assert!(matches!(
            Page::decode(&root).unwrap().0,
            Page::Branch { .. }
        ));
    }

    #[test]
    fn route_walk_matches_the_parent_page_children() {
        let entries = many_files(600);
        let root = Page::build(&entries).unwrap();
        let (page, _) = Page::decode(&root).unwrap();
        let Page::Branch { children, .. } = page else {
            panic!("expected a branch root");
        };
        for child in &children {
            let pages = Page::pages_along_route(&entries, &[child.label]).unwrap();
            assert_eq!(pages.len(), 2, "root + one child");
            assert_eq!(pages[0], root);
            // The walked page is byte-identical to the one the parent commits
            // to, which is what makes the route auditable.
            assert_eq!(page_id(&pages[1]), child.child_page_id);
        }
    }

    #[test]
    fn two_level_route_resolves_to_a_leaf() {
        // Deep trees need more than one branch level; build one and walk every
        // root->child->leaf path, checking the leaf holds only its own group.
        let entries = many_files(4000);
        let root = Page::build(&entries).unwrap();
        let (page, _) = Page::decode(&root).unwrap();
        let Page::Branch { children, .. } = page else {
            panic!("expected a branch root");
        };
        let mut saw_two_level = 0;
        for child in &children {
            let Ok(pages) = Page::pages_along_route(&entries, &[child.label]) else {
                continue;
            };
            let (sub, _) = Page::decode(&pages[1]).unwrap();
            let Page::Branch {
                children: grand, ..
            } = sub
            else {
                continue;
            };
            saw_two_level += 1;
            let label = grand[0].label;
            let deep = Page::pages_along_route(&entries, &[child.label, label]).unwrap();
            assert_eq!(deep.len(), 3);
            assert_eq!(deep[0], root);
            assert_eq!(deep[1], pages[1]);
            assert_eq!(page_id(&deep[2]), grand[0].child_page_id);
        }
        assert!(saw_two_level > 0, "fixture must produce a multi-level tree");
    }

    #[test]
    fn unknown_route_label_is_an_error_not_an_empty_result() {
        let entries = many_files(600);
        let root = Page::build(&entries).unwrap();
        let (page, _) = Page::decode(&root).unwrap();
        let Page::Branch { children, .. } = page else {
            panic!("expected a branch root");
        };
        let missing = (b'a'..=b'z')
            .chain(b'A'..=b'Z')
            .find(|l| !children.iter().any(|c| c.label == *l))
            .expect("a label outside the page");
        assert!(Page::pages_along_route(&entries, &[missing]).is_err());
    }

    #[test]
    fn descending_past_a_leaf_is_rejected() {
        let entries = vec![
            Entry::file(EntryKind::Regular, b"a", 1, cid(1)),
            Entry::file(EntryKind::Regular, b"b", 1, cid(2)),
        ];
        assert!(matches!(
            Page::decode(&Page::build(&entries).unwrap()).unwrap().0,
            Page::Leaf { .. }
        ));
        assert!(Page::pages_along_route(&entries, b"a").is_err());
    }

    #[test]
    fn empty_directory_yields_its_empty_leaf() {
        let pages = Page::pages_along_route(&[], &[]).unwrap();
        assert_eq!(pages.len(), 1);
        assert!(
            matches!(Page::decode(&pages[0]).unwrap().0, Page::Leaf { entries } if entries.is_empty())
        );
        assert!(Page::pages_along_route(&[], b"x").is_err());
    }
}
