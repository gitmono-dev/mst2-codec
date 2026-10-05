//! Local node and component-key codec from Mega draft c488b78's
//! `docs/spec/namespace-index-v1.md`. This is not an index walker or store.
//!
//! Labels may split UTF-8. A walker must validate incoming child labels,
//! assembled value keys, requested digests, source membership and retention.
//! Node decoding alone establishes none of those graph relationships.

use super::{validate_absolute_path, PATH_MAX_BYTES};
use crate::{sha256, CodecError, CodecResult};

pub mod index;

pub const NODE_MAX_BYTES: usize = 16_384;
pub const CHILD_MAX_COUNT: usize = 256;
const NODE_DOMAIN: &[u8] = b"mega.namespace-radix.v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadixChild {
    pub edge: u8,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadixNode {
    label: Vec<u8>,
    binding: Option<[u8; 32]>,
    children: Vec<RadixChild>,
}

impl RadixNode {
    /// Validate only the local canonical shape, not the assembled value path.
    pub fn new(
        label: Vec<u8>,
        binding: Option<[u8; 32]>,
        children: Vec<RadixChild>,
    ) -> CodecResult<Self> {
        if label.len() > PATH_MAX_BYTES {
            return Err(CodecError::BadLength("radix label"));
        }
        if children.len() > CHILD_MAX_COUNT {
            return Err(CodecError::BadLength("radix fanout"));
        }
        for pair in children.windows(2) {
            if pair[0].edge >= pair[1].edge {
                return Err(CodecError::BadOrdering("radix child edges"));
            }
        }
        if binding.is_none() && (children.len() == 1 || (children.is_empty() && !label.is_empty()))
        {
            return Err(CodecError::BadOrdering("noncanonical radix compression"));
        }
        Ok(Self {
            label,
            binding,
            children,
        })
    }

    /// Canonical implicit empty index; it need not have a stored row.
    pub fn empty() -> Self {
        Self {
            label: Vec::new(),
            binding: None,
            children: Vec::new(),
        }
    }

    pub fn label(&self) -> &[u8] {
        &self.label
    }

    pub fn binding(&self) -> Option<&[u8; 32]> {
        self.binding.as_ref()
    }

    pub fn children(&self) -> &[RadixChild] {
        &self.children
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = NODE_DOMAIN.to_vec();
        out.extend_from_slice(&(self.label.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.label);
        out.push(u8::from(self.binding.is_some()));
        if let Some(binding) = self.binding {
            out.extend_from_slice(&binding);
        }
        out.extend_from_slice(&(self.children.len() as u16).to_be_bytes());
        for child in &self.children {
            out.push(child.edge);
            out.extend_from_slice(&child.digest);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> CodecResult<Self> {
        if bytes.len() > NODE_MAX_BYTES {
            return Err(CodecError::BadLength("radix node"));
        }
        let mut input = bytes
            .strip_prefix(NODE_DOMAIN)
            .ok_or(CodecError::BadConstant("radix domain"))?;
        let label_len = read_u16(&mut input)?;
        if label_len > PATH_MAX_BYTES {
            return Err(CodecError::BadLength("radix label"));
        }
        let label = take(&mut input, label_len)?.to_vec();
        let binding = match take(&mut input, 1)?[0] {
            0 => None,
            1 => Some(read_digest(&mut input)?),
            _ => return Err(CodecError::BadConstant("radix binding presence")),
        };
        let child_count = read_u16(&mut input)?;
        if child_count > CHILD_MAX_COUNT {
            return Err(CodecError::BadLength("radix fanout"));
        }
        let mut children = Vec::with_capacity(child_count);
        for _ in 0..child_count {
            children.push(RadixChild {
                edge: take(&mut input, 1)?[0],
                digest: read_digest(&mut input)?,
            });
        }
        if !input.is_empty() {
            return Err(CodecError::BadLength("radix trailing bytes"));
        }
        Self::new(label, binding, children)
    }

    /// Derive identity; the caller must separately compare a requested digest.
    pub fn id(&self) -> [u8; 32] {
        sha256(&[&self.encode()])
    }
}

pub fn empty_root() -> [u8; 32] {
    RadixNode::empty().id()
}

/// Preserve v1 key encoding and structural path limits. MST/2 endpoints must
/// separately enforce their 256-component profile before serving a path.
pub fn encode_key(path: &str) -> CodecResult<Vec<u8>> {
    validate_absolute_path(path)?;
    if path == "/" {
        return Ok(Vec::new());
    }
    let mut key = path.as_bytes()[1..].to_vec();
    for byte in &mut key {
        if *byte == b'/' {
            *byte = 0;
        }
    }
    key.push(0);
    Ok(key)
}

/// Decode a complete value key, never a partial compressed label. Slashes in
/// encoded keys and a NUL-only root are rejected as noncanonical encodings.
pub fn decode_key(key: &[u8]) -> CodecResult<String> {
    if key.len() > PATH_MAX_BYTES {
        return Err(CodecError::BadLength("radix key"));
    }
    if key.is_empty() {
        return Ok("/".to_string());
    }
    if key.last() != Some(&0) || key.contains(&b'/') {
        return Err(CodecError::BadName("radix key boundary"));
    }
    let mut path = Vec::with_capacity(key.len());
    path.push(b'/');
    path.extend(
        key[..key.len() - 1]
            .iter()
            .map(|byte| if *byte == 0 { b'/' } else { *byte }),
    );
    let path = String::from_utf8(path).map_err(|_| CodecError::BadName("radix key UTF-8"))?;
    validate_absolute_path(&path)?;
    if encode_key(&path)?.as_slice() != key {
        return Err(CodecError::BadName("noncanonical radix key"));
    }
    Ok(path)
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> CodecResult<&'a [u8]> {
    let head = input
        .get(..count)
        .ok_or(CodecError::Truncated("radix node field"))?;
    *input = &input[count..];
    Ok(head)
}

fn read_u16(input: &mut &[u8]) -> CodecResult<usize> {
    let bytes = take(input, 2)?;
    Ok(usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
}

fn read_digest(input: &mut &[u8]) -> CodecResult<[u8; 32]> {
    let bytes = take(input, 32)?;
    let mut digest = [0; 32];
    digest.copy_from_slice(bytes);
    Ok(digest)
}

#[cfg(test)]
mod tests;
