//! ServingDescriptor (MSD2) — spec 03 §2/§3.
//!
//! Canonical bytes:
//! ```text
//! "MSD2"                    4 bytes
//! schema_version            u16 = 2
//! metadata_codec            u16 = 1
//! instance_uuid             16 bytes
//! namespace_view_digest     32 bytes
//! scope_byte_length         u16
//! scope_utf8                scope_byte_length bytes
//! materialization_policy    u16 = 1
//! fs_semantics              u16 = 1
//! access_projection         u16 = 0
//! reserved                  u16 = 0
//! metadata_root_digest      32 bytes
//! ```
//! `base_length = 98 + scope_byte_length`; no trailing bytes.
//! `snapshot_id = SHA256(b"mega.mst2.descriptor\0" || descriptor_bytes)`.

use crate::{read_u16, sha256, write_u16, CodecError, CodecResult};

pub const SCHEMA_VERSION: u16 = 2;
pub const METADATA_CODEC: u16 = 1;
pub const MATERIALIZATION_POLICY_GIT_RAW_V1: u16 = 1;
pub const FS_SEMANTICS_LINUX_CODE_V1: u16 = 1;
pub const ACCESS_PROJECTION_EXACT_FULL: u16 = 0;
pub const BASE_LENGTH: usize = 98;

const DOMAIN: &[u8] = b"mega.mst2.descriptor\0";

/// A parsed ServingDescriptor. `snapshot_id` is derived, never stored in bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingDescriptor {
    pub instance_uuid: [u8; 16],
    pub namespace_view_id: [u8; 32],
    pub scope: String,
    pub metadata_root: [u8; 32],
}

impl ServingDescriptor {
    pub fn schema_version(&self) -> u16 {
        SCHEMA_VERSION
    }
    pub fn metadata_codec(&self) -> u16 {
        METADATA_CODEC
    }
    pub fn materialization_policy(&self) -> u16 {
        MATERIALIZATION_POLICY_GIT_RAW_V1
    }
    pub fn fs_semantics(&self) -> u16 {
        FS_SEMANTICS_LINUX_CODE_V1
    }
    pub fn access_projection(&self) -> u16 {
        ACCESS_PROJECTION_EXACT_FULL
    }

    /// Encode to canonical bytes.
    pub fn encode(&self) -> CodecResult<Vec<u8>> {
        validate_scope(&self.scope)?;
        let mut out = Vec::with_capacity(BASE_LENGTH + self.scope.len());
        out.extend_from_slice(b"MSD2");
        write_u16(&mut out, SCHEMA_VERSION);
        write_u16(&mut out, METADATA_CODEC);
        out.extend_from_slice(&self.instance_uuid);
        out.extend_from_slice(&self.namespace_view_id);
        write_u16(&mut out, self.scope.len() as u16);
        out.extend_from_slice(self.scope.as_bytes());
        write_u16(&mut out, MATERIALIZATION_POLICY_GIT_RAW_V1);
        write_u16(&mut out, FS_SEMANTICS_LINUX_CODE_V1);
        write_u16(&mut out, ACCESS_PROJECTION_EXACT_FULL);
        write_u16(&mut out, 0); // reserved
        out.extend_from_slice(&self.metadata_root);
        debug_assert_eq!(out.len(), BASE_LENGTH + self.scope.len());
        Ok(out)
    }

    /// `snapshot_id = SHA256(b"mega.mst2.descriptor\0" || descriptor_bytes)`.
    pub fn snapshot_id(&self) -> CodecResult<[u8; 32]> {
        let bytes = self.encode()?;
        Ok(sha256(&[DOMAIN, &bytes]))
    }

    /// Parse and fully validate canonical bytes. Unknown versions, non-zero
    /// reserved, invalid UTF-8 and non-canonical scope are rejected.
    pub fn decode(buf: &[u8]) -> CodecResult<Self> {
        if buf.len() < BASE_LENGTH {
            return Err(CodecError::Truncated("descriptor header"));
        }
        if &buf[0..4] != b"MSD2" {
            return Err(CodecError::BadConstant("MSD2 magic"));
        }
        if read_u16(buf, 4)? != SCHEMA_VERSION {
            return Err(CodecError::BadConstant("schema_version"));
        }
        if read_u16(buf, 6)? != METADATA_CODEC {
            return Err(CodecError::BadConstant("metadata_codec"));
        }
        let scope_len = read_u16(buf, 56)? as usize;
        if buf.len() != BASE_LENGTH + scope_len {
            return Err(CodecError::BadLength(
                "descriptor must be exactly 98 + scope_byte_length",
            ));
        }
        if read_u16(buf, 58 + scope_len)? != MATERIALIZATION_POLICY_GIT_RAW_V1 {
            return Err(CodecError::BadConstant("materialization_policy"));
        }
        if read_u16(buf, 60 + scope_len)? != FS_SEMANTICS_LINUX_CODE_V1 {
            return Err(CodecError::BadConstant("fs_semantics"));
        }
        if read_u16(buf, 62 + scope_len)? != ACCESS_PROJECTION_EXACT_FULL {
            return Err(CodecError::BadConstant("access_projection"));
        }
        if read_u16(buf, 64 + scope_len)? != 0 {
            return Err(CodecError::BadConstant("reserved must be zero"));
        }
        let mut instance_uuid = [0u8; 16];
        instance_uuid.copy_from_slice(&buf[8..24]);
        let mut namespace_view_id = [0u8; 32];
        namespace_view_id.copy_from_slice(&buf[24..56]);
        let scope_bytes = &buf[58..58 + scope_len];
        let scope = std::str::from_utf8(scope_bytes)
            .map_err(|_| CodecError::BadName("scope not UTF-8"))?
            .to_string();
        validate_scope(&scope)?;
        let mut metadata_root = [0u8; 32];
        metadata_root.copy_from_slice(&buf[66 + scope_len..98 + scope_len]);
        Ok(ServingDescriptor {
            instance_uuid,
            namespace_view_id,
            scope,
            metadata_root,
        })
    }
}

/// Canonical Mega absolute UTF-8 path: starts with `/`, no trailing slash
/// (except the root itself), no empty/`.`/`..` components, no NUL,
/// each component at most 256 bytes (spec 02 §3; note this component cap is
/// wider than the 255-byte MTP2 name cap of spec 05 §2).
pub fn validate_scope(scope: &str) -> CodecResult<()> {
    if scope.is_empty() || !scope.starts_with('/') {
        return Err(CodecError::BadName("scope must be absolute"));
    }
    if scope.contains('\0') {
        return Err(CodecError::BadName("NUL in scope"));
    }
    if scope.len() > 1 && scope.ends_with('/') {
        return Err(CodecError::BadName("trailing slash"));
    }
    if scope == "/" {
        return Ok(());
    }
    for comp in scope[1..].split('/') {
        if comp.is_empty() {
            return Err(CodecError::BadName("empty path component"));
        }
        if comp == "." || comp == ".." {
            return Err(CodecError::BadName("dot component"));
        }
        if comp.len() > 256 {
            return Err(CodecError::BadName("path component over 256 bytes"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ServingDescriptor {
        ServingDescriptor {
            instance_uuid: [7u8; 16],
            namespace_view_id: [1u8; 32],
            scope: "/".to_string(),
            metadata_root: [2u8; 32],
        }
    }

    #[test]
    fn roundtrip_root_scope() {
        let d = sample();
        let bytes = d.encode().unwrap();
        assert_eq!(bytes.len(), 99); // 98 + 1 ("/")
        assert_eq!(&bytes[0..4], b"MSD2");
        let back = ServingDescriptor::decode(&bytes).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn snapshot_id_is_domain_separated() {
        let d = sample();
        let bytes = d.encode().unwrap();
        let id = d.snapshot_id().unwrap();
        let manual = crate::sha256(&[b"mega.mst2.descriptor\0", &bytes]);
        assert_eq!(id, manual);
        // A different descriptor must not share the id.
        let mut d2 = d.clone();
        d2.metadata_root[0] ^= 1;
        assert_ne!(d2.snapshot_id().unwrap(), id);
    }

    #[test]
    fn rejects_bad_versions_and_reserved() {
        let mut bytes = sample().encode().unwrap();
        bytes[4] = 3; // schema_version
        assert!(ServingDescriptor::decode(&bytes).is_err());
        let mut bytes = sample().encode().unwrap();
        bytes[6] = 2; // metadata_codec
        assert!(ServingDescriptor::decode(&bytes).is_err());
        // reserved (u16) sits at offset 64 + scope_len; scope is "/" (1 byte)
        let mut bytes = sample().encode().unwrap();
        bytes[64 + 1 + 1] = 1; // reserved high byte
        assert!(ServingDescriptor::decode(&bytes).is_err());
        // Corrupting the metadata_root still parses (digest is data, not
        // check) but yields different roots.
        let mut bytes = sample().encode().unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 1;
        let d = ServingDescriptor::decode(&bytes).unwrap();
        assert_ne!(d.metadata_root, [2u8; 32]);
    }

    #[test]
    fn rejects_bad_length_and_scope() {
        let mut bytes = sample().encode().unwrap();
        bytes.push(0); // trailing byte
        assert!(ServingDescriptor::decode(&bytes).is_err());
        let mut d = sample();
        d.scope = "relative".into();
        assert!(d.encode().is_err());
        let mut d = sample();
        d.scope = "/a/..".into();
        assert!(d.encode().is_err());
        let mut d = sample();
        d.scope = "/a//b".into();
        assert!(d.encode().is_err());
        let mut d = sample();
        d.scope = "/a/".into();
        assert!(d.encode().is_err());
    }

    #[test]
    fn scope_component_length_limit() {
        let mut d = sample();
        d.scope = format!("/{}", "a".repeat(256));
        assert!(d.encode().is_ok());
        d.scope = format!("/{}", "a".repeat(257));
        assert!(d.encode().is_err());
    }
}
