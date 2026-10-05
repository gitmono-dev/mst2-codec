//! Canonical source/binding/view identities from the fixed namespace v1 contract.
//!
//! The authority is Mega draft c488b78a82361ecc6e5bb285977b8439993c062e,
//! `docs/spec/source-snapshot-v1.md` and `namespace-manifest-v1.md`.
//! These structural codecs do not attest membership, authorize reads, retain
//! objects, interpret overrides or enforce release policy at publication.

use crate::{sha256, CodecError, CodecResult};

pub const MANIFEST_MAX_BYTES: usize = 16_384;
const PATH_MAX_BYTES: usize = 4096;
const SOURCE_DOMAIN: &[u8] = b"mega.source-snapshot.v1\0";
const BINDING_DOMAIN: &[u8] = b"mega.namespace-binding.v1\0";
const VIEW_DOMAIN: &[u8] = b"mega.namespace-view.v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSnapshot {
    source_id: String,
    scope_path: String,
    commit_oid: String,
    root_tree_oid: String,
}

impl SourceSnapshot {
    /// v1 supports only SHA-1 object IDs; other formats require negotiation.
    pub fn new(
        source_id: String,
        scope_path: String,
        commit_oid: String,
        root_tree_oid: String,
    ) -> CodecResult<Self> {
        validate_uuid(&source_id)?;
        validate_absolute_path(&scope_path)?;
        validate_oid(&commit_oid)?;
        validate_oid(&root_tree_oid)?;
        Ok(Self {
            source_id,
            scope_path,
            commit_oid,
            root_tree_oid,
        })
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }
    pub fn scope_path(&self) -> &str {
        &self.scope_path
    }
    pub fn commit_oid(&self) -> &str {
        &self.commit_oid
    }
    pub fn root_tree_oid(&self) -> &str {
        &self.root_tree_oid
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = SOURCE_DOMAIN.to_vec();
        for field in [
            self.source_id.as_str(),
            self.scope_path.as_str(),
            "sha1",
            self.commit_oid.as_str(),
            self.root_tree_oid.as_str(),
        ] {
            write_field(&mut out, field.as_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> CodecResult<Self> {
        let mut input = Input::new(bytes, SOURCE_DOMAIN)?;
        let source_id = input.text()?.to_owned();
        let scope_path = input.text()?.to_owned();
        if input.text()? != "sha1" {
            return Err(CodecError::BadConstant("source object format"));
        }
        let commit_oid = input.text()?.to_owned();
        let root_tree_oid = input.text()?.to_owned();
        input.finish()?;
        Self::new(source_id, scope_path, commit_oid, root_tree_oid)
    }

    pub fn id(&self) -> [u8; 32] {
        sha256(&[&self.encode()])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingPolicy {
    Mutable,
    ImmutableRelease,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceBinding {
    mount_path: String,
    source: SourceSnapshot,
    source_subpath: String,
    policy: BindingPolicy,
}

impl NamespaceBinding {
    pub fn new(
        mount_path: String,
        source: SourceSnapshot,
        source_subpath: String,
        policy: BindingPolicy,
    ) -> CodecResult<Self> {
        validate_absolute_path(&mount_path)?;
        validate_relative_path(&source_subpath)?;
        let composed_len = if source_subpath.is_empty() {
            source.scope_path.len()
        } else if source.scope_path == "/" {
            1 + source_subpath.len()
        } else {
            source.scope_path.len() + 1 + source_subpath.len()
        };
        if composed_len > PATH_MAX_BYTES {
            return Err(CodecError::BadLength("composed source path"));
        }
        Ok(Self {
            mount_path,
            source,
            source_subpath,
            policy,
        })
    }

    pub fn mount_path(&self) -> &str {
        &self.mount_path
    }
    pub fn source(&self) -> &SourceSnapshot {
        &self.source
    }
    pub fn source_subpath(&self) -> &str {
        &self.source_subpath
    }
    pub fn policy(&self) -> BindingPolicy {
        self.policy
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = BINDING_DOMAIN.to_vec();
        write_field(&mut out, self.mount_path.as_bytes());
        write_field(&mut out, &self.source.encode());
        write_field(&mut out, self.source_subpath.as_bytes());
        out.push(match self.policy {
            BindingPolicy::Mutable => 1,
            BindingPolicy::ImmutableRelease => 2,
        });
        out
    }

    pub fn decode(bytes: &[u8]) -> CodecResult<Self> {
        let mut input = Input::new(bytes, BINDING_DOMAIN)?;
        let mount_path = input.text()?.to_owned();
        let source = SourceSnapshot::decode(input.field()?)?;
        let source_subpath = input.text()?.to_owned();
        let policy = match input.byte()? {
            1 => BindingPolicy::Mutable,
            2 => BindingPolicy::ImmutableRelease,
            _ => return Err(CodecError::BadConstant("binding policy")),
        };
        input.finish()?;
        Self::new(mount_path, source, source_subpath, policy)
    }

    pub fn id(&self) -> [u8; 32] {
        sha256(&[&self.encode()])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceView {
    instance_id: String,
    native: SourceSnapshot,
    bindings_root: [u8; 32],
    overrides_root: Option<[u8; 32]>,
}

impl NamespaceView {
    /// An override root is identity data, not permission to serve overrides.
    pub fn new(
        instance_id: String,
        native: SourceSnapshot,
        bindings_root: [u8; 32],
        overrides_root: Option<[u8; 32]>,
    ) -> CodecResult<Self> {
        validate_uuid(&instance_id)?;
        if native.scope_path != "/" {
            return Err(CodecError::BadName("native scope must be root"));
        }
        Ok(Self {
            instance_id,
            native,
            bindings_root,
            overrides_root,
        })
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
    pub fn native(&self) -> &SourceSnapshot {
        &self.native
    }
    pub fn bindings_root(&self) -> &[u8; 32] {
        &self.bindings_root
    }
    pub fn overrides_root(&self) -> Option<&[u8; 32]> {
        self.overrides_root.as_ref()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = VIEW_DOMAIN.to_vec();
        out.extend_from_slice(&1u16.to_be_bytes());
        write_field(&mut out, self.instance_id.as_bytes());
        write_field(&mut out, &self.native.encode());
        out.extend_from_slice(&self.bindings_root);
        match self.overrides_root {
            None => out.push(0),
            Some(root) => {
                out.push(1);
                out.extend_from_slice(&root);
            }
        }
        out.push(1); // git_raw_v1
        out
    }

    pub fn decode(bytes: &[u8]) -> CodecResult<Self> {
        let mut input = Input::new(bytes, VIEW_DOMAIN)?;
        if input.take(2)? != 1u16.to_be_bytes() {
            return Err(CodecError::BadConstant("namespace schema"));
        }
        let instance_id = input.text()?.to_owned();
        let native = SourceSnapshot::decode(input.field()?)?;
        let bindings_root = input.digest()?;
        let overrides_root = match input.byte()? {
            0 => None,
            1 => Some(input.digest()?),
            _ => return Err(CodecError::BadConstant("override presence")),
        };
        if input.byte()? != 1 {
            return Err(CodecError::BadConstant("materialization policy"));
        }
        input.finish()?;
        Self::new(instance_id, native, bindings_root, overrides_root)
    }

    pub fn id(&self) -> [u8; 32] {
        sha256(&[&self.encode()])
    }
}

fn validate_uuid(value: &str) -> CodecResult<()> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || !bytes.iter().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        })
        || !bytes.iter().any(|b| *b != b'0' && *b != b'-')
    {
        return Err(CodecError::BadName("canonical non-nil UUID"));
    }
    Ok(())
}

fn validate_oid(value: &str) -> CodecResult<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CodecError::BadName("canonical SHA-1 OID"));
    }
    Ok(())
}

fn validate_absolute_path(path: &str) -> CodecResult<()> {
    if path.len() > PATH_MAX_BYTES {
        return Err(CodecError::BadLength("absolute path"));
    }
    let relative = path
        .strip_prefix('/')
        .ok_or(CodecError::BadName("absolute path"))?;
    validate_relative_path(relative)
}

fn validate_relative_path(path: &str) -> CodecResult<()> {
    if path.len() > PATH_MAX_BYTES {
        return Err(CodecError::BadLength("relative path"));
    }
    if path.is_empty() {
        return Ok(());
    }
    for name in path.split('/') {
        crate::validate_name(name.as_bytes())?;
    }
    Ok(())
}

fn write_field(out: &mut Vec<u8>, bytes: &[u8]) {
    // Constructors bound all fields, so every length fits u32 and every
    // complete manifest is smaller than MANIFEST_MAX_BYTES.
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Input<'a> {
    remaining: &'a [u8],
}

impl<'a> Input<'a> {
    fn new(bytes: &'a [u8], domain: &[u8]) -> CodecResult<Self> {
        if bytes.len() > MANIFEST_MAX_BYTES {
            return Err(CodecError::BadLength("manifest"));
        }
        let remaining = bytes
            .strip_prefix(domain)
            .ok_or(CodecError::BadConstant("manifest domain"))?;
        Ok(Self { remaining })
    }

    fn take(&mut self, length: usize) -> CodecResult<&'a [u8]> {
        let bytes = self
            .remaining
            .get(..length)
            .ok_or(CodecError::Truncated("manifest field"))?;
        self.remaining = &self.remaining[length..];
        Ok(bytes)
    }

    fn byte(&mut self) -> CodecResult<u8> {
        Ok(self.take(1)?[0])
    }
    fn digest(&mut self) -> CodecResult<[u8; 32]> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn field(&mut self) -> CodecResult<&'a [u8]> {
        let length = u32::from_be_bytes(self.take(4)?.try_into().unwrap());
        let length =
            usize::try_from(length).map_err(|_| CodecError::Overflow("manifest length"))?;
        self.take(length)
    }
    fn text(&mut self) -> CodecResult<&'a str> {
        std::str::from_utf8(self.field()?).map_err(|_| CodecError::BadName("manifest UTF-8"))
    }
    fn finish(self) -> CodecResult<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(CodecError::BadLength("manifest trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests;
