//! Iterative immutable binding-index operations over a caller-owned byte store.
//!
//! The fixed v1 node/key codecs determine identity. Only visited graph edges and
//! value keys are checked; this does not validate a complete namespace graph,
//! resolve binding/source membership or implement persistence/publication/GC.

use std::fmt;

use super::{decode_key, empty_root, encode_key, RadixChild, RadixNode, NODE_MAX_BYTES};
use crate::{namespace::PATH_MAX_BYTES, sha256, CodecError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexError {
    Codec(CodecError),
    Store(String),
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(f),
            Self::Store(message) => write!(f, "binding index store unavailable: {message}"),
        }
    }
}

impl std::error::Error for IndexError {}

impl From<CodecError> for IndexError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

pub type IndexResult<T> = Result<T, IndexError>;

/// Implementations must insert immutable bytes, rejecting conflicting existing
/// bytes for an ID. Durability, transactions and root publication are external.
/// Missing/corrupt storage is an error, never an empty node or absent binding.
pub trait NodeStore {
    fn read(&mut self, id: &[u8; 32]) -> IndexResult<Vec<u8>>;
    fn insert(&mut self, id: &[u8; 32], bytes: &[u8]) -> IndexResult<()>;
}

pub struct RadixIndex<'a, S: NodeStore> {
    store: &'a mut S,
}

impl<'a, S: NodeStore> RadixIndex<'a, S> {
    pub fn new(store: &'a mut S) -> Self {
        Self { store }
    }

    fn load(&mut self, id: &[u8; 32], edge: Option<u8>, prefix: &[u8]) -> IndexResult<RadixNode> {
        let node = if *id == empty_root() {
            RadixNode::empty()
        } else {
            let bytes = self.store.read(id)?;
            if bytes.len() > NODE_MAX_BYTES {
                return Err(CodecError::BadLength("radix stored node").into());
            }
            if sha256(&[&bytes]) != *id {
                return Err(CodecError::DigestMismatch("radix stored node").into());
            }
            RadixNode::decode(&bytes)?
        };
        if edge.is_some_and(|edge| node.label.first() != Some(&edge)) {
            return Err(CodecError::BadOrdering("radix incoming child label").into());
        }
        validate_position(prefix, &node)?;
        Ok(node)
    }

    /// A transient edit may need compression before it has canonical local shape.
    fn save(&mut self, mut node: RadixNode, prefix: &[u8]) -> IndexResult<Option<[u8; 32]>> {
        if node.binding.is_none() {
            if node.children.is_empty() {
                return Ok(None);
            }
            if node.children.len() == 1 {
                let child_ref = &node.children[0];
                let child_prefix = joined_key(prefix, &node.label)?;
                let child = self.load(&child_ref.digest, Some(child_ref.edge), &child_prefix)?;
                node.label.extend_from_slice(&child.label);
                node.binding = child.binding;
                node.children = child.children;
            }
        }
        validate_position(prefix, &node)?;
        let node = RadixNode::new(node.label, node.binding, node.children)?;
        let bytes = node.encode();
        let id = sha256(&[&bytes]);
        self.store.insert(&id, &bytes)?;
        Ok(Some(id))
    }

    /// Copy only changed ancestors, retaining old roots. A no-op writes no nodes.
    /// On failure no new root is returned; inserted orphan nodes may remain and
    /// must be handled by the caller's transaction/retention policy.
    pub fn update(
        &mut self,
        root: &[u8; 32],
        path: &str,
        binding: Option<[u8; 32]>,
    ) -> IndexResult<[u8; 32]> {
        let key = encode_key(path)?;
        let mut offset = 0;
        let mut id = *root;
        let mut edge = None;
        let mut ancestors = Vec::new();
        let mut replacement;
        loop {
            let mut node = self.load(&id, edge, &key[..offset])?;
            let remaining = &key[offset..];
            let common = remaining
                .iter()
                .zip(&node.label)
                .take_while(|(a, b)| a == b)
                .count();
            if common < node.label.len() {
                let Some(binding) = binding else {
                    return Ok(*root);
                };
                let mut parent = RadixNode {
                    label: node.label[..common].to_vec(),
                    binding: None,
                    children: Vec::new(),
                };
                node.label.drain(..common);
                let child_prefix = joined_key(&key[..offset], &parent.label)?;
                let child_edge = node.label[0];
                let child_id = required_id(self.save(node, &child_prefix)?)?;
                set_child(&mut parent.children, child_edge, Some(child_id));
                if common == remaining.len() {
                    parent.binding = Some(binding);
                } else {
                    let suffix = &remaining[common..];
                    let leaf = RadixNode::new(suffix.to_vec(), Some(binding), Vec::new())?;
                    let leaf_id = required_id(self.save(leaf, &child_prefix)?)?;
                    set_child(&mut parent.children, suffix[0], Some(leaf_id));
                }
                replacement = self.save(parent, &key[..offset])?;
                break;
            }
            let parent_offset = offset;
            offset += common;
            if offset == key.len() {
                if node.binding == binding {
                    return Ok(*root);
                }
                node.binding = binding;
                replacement = self.save(node, &key[..parent_offset])?;
                break;
            }
            let next_edge = key[offset];
            if let Some(child) = node.children.iter().find(|child| child.edge == next_edge) {
                id = child.digest;
                edge = Some(next_edge);
                ancestors.push((node, next_edge, parent_offset));
            } else {
                let Some(binding) = binding else {
                    return Ok(*root);
                };
                let leaf = RadixNode::new(key[offset..].to_vec(), Some(binding), Vec::new())?;
                let leaf_id = required_id(self.save(leaf, &key[..offset])?)?;
                set_child(&mut node.children, next_edge, Some(leaf_id));
                replacement = self.save(node, &key[..parent_offset])?;
                break;
            }
        }
        while let Some((mut parent, edge, parent_offset)) = ancestors.pop() {
            set_child(&mut parent.children, edge, replacement);
            replacement = self.save(parent, &key[..parent_offset])?;
        }
        Ok(replacement.unwrap_or_else(empty_root))
    }

    pub fn get(&mut self, root: &[u8; 32], path: &str) -> IndexResult<Option<[u8; 32]>> {
        Ok(self.walk(root, path, false)?.map(|(_, binding)| binding))
    }

    pub fn longest_prefix(
        &mut self,
        root: &[u8; 32],
        path: &str,
    ) -> IndexResult<Option<(String, [u8; 32])>> {
        self.walk(root, path, true)
    }

    fn walk(
        &mut self,
        root: &[u8; 32],
        path: &str,
        ancestors: bool,
    ) -> IndexResult<Option<(String, [u8; 32])>> {
        let key = encode_key(path)?;
        let mut id = *root;
        let mut edge = None;
        let mut offset = 0;
        let mut found = None;
        loop {
            let node = self.load(&id, edge, &key[..offset])?;
            if !key[offset..].starts_with(&node.label) {
                break;
            }
            offset += node.label.len();
            if let Some(binding) = node.binding {
                found = Some((decode_key(&key[..offset])?, binding));
            }
            if offset == key.len() {
                return Ok(found.filter(|(matched, _)| ancestors || matched == path));
            }
            let next_edge = key[offset];
            let Some(child) = node.children.iter().find(|child| child.edge == next_edge) else {
                break;
            };
            id = child.digest;
            edge = Some(next_edge);
        }
        Ok(if ancestors { found } else { None })
    }
}

fn joined_key(prefix: &[u8], label: &[u8]) -> IndexResult<Vec<u8>> {
    if prefix.len() + label.len() > PATH_MAX_BYTES {
        return Err(CodecError::BadLength("radix assembled key").into());
    }
    Ok([prefix, label].concat())
}

fn validate_position(prefix: &[u8], node: &RadixNode) -> IndexResult<()> {
    let assembled = joined_key(prefix, &node.label)?;
    if node.binding.is_some() {
        decode_key(&assembled)?;
    }
    Ok(())
}

fn set_child(children: &mut Vec<RadixChild>, edge: u8, digest: Option<[u8; 32]>) {
    let position = children.binary_search_by_key(&edge, |child| child.edge);
    match (position, digest) {
        (Ok(index), Some(digest)) => children[index].digest = digest,
        (Ok(index), None) => {
            children.remove(index);
        }
        (Err(index), Some(digest)) => children.insert(index, RadixChild { edge, digest }),
        (Err(_), None) => {}
    }
}

fn required_id(id: Option<[u8; 32]>) -> IndexResult<[u8; 32]> {
    id.ok_or_else(|| CodecError::BadOrdering("unexpected empty radix replacement").into())
}

#[cfg(test)]
mod tests;
