use super::*;
use serde_json::Value;

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn source(value: &Value) -> SourceSnapshot {
    assert_eq!(value["object_format"], "sha1");
    SourceSnapshot::new(
        value["source_id"].as_str().unwrap().into(),
        value["scope_path"].as_str().unwrap().into(),
        value["commit_oid"].as_str().unwrap().into(),
        value["root_tree_oid"].as_str().unwrap().into(),
    )
    .unwrap()
}

fn root_source() -> SourceSnapshot {
    SourceSnapshot::new(
        "11111111-1111-4111-8111-111111111111".into(),
        "/".into(),
        "1".repeat(40),
        "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
    )
    .unwrap()
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/namespace-v1.json")).unwrap()
}

#[test]
fn independent_dotnet_source_vectors_match_bytes_identity_and_decoding() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/source-v1.json")).unwrap();
    for vector in vectors.as_array().unwrap() {
        let expected = unhex(vector["canonical_hex"].as_str().unwrap());
        let source = source(&vector["source"]);
        assert_eq!(source.encode(), expected);
        assert_eq!(SourceSnapshot::decode(&expected).unwrap(), source);
        assert_eq!(
            format!("sha256:{}", hex(&source.id())),
            vector["source_id_digest"]
        );
    }
}

#[test]
fn independent_dotnet_binding_and_view_vectors_match() {
    let vectors = vectors();
    for vector in vectors["bindings"].as_array().unwrap() {
        let value = &vector["binding"];
        let policy = match value["policy"].as_str().unwrap() {
            "mutable" => BindingPolicy::Mutable,
            "immutable_release" => BindingPolicy::ImmutableRelease,
            _ => panic!("invalid independent fixture"),
        };
        let binding = NamespaceBinding::new(
            value["mount_path"].as_str().unwrap().into(),
            source(&value["source_snapshot"]),
            value["source_subpath"].as_str().unwrap().into(),
            policy,
        )
        .unwrap();
        let expected = unhex(vector["canonical_hex"].as_str().unwrap());
        assert_eq!(binding.encode(), expected);
        assert_eq!(NamespaceBinding::decode(&expected).unwrap(), binding);
        assert_eq!(format!("sha256:{}", hex(&binding.id())), vector["digest"]);
    }
    for vector in vectors["views"].as_array().unwrap() {
        let value = &vector["view"];
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["materialization_policy"], "git_raw_v1");
        let digest = |v: &Value| -> [u8; 32] {
            unhex(v.as_str().unwrap().strip_prefix("sha256:").unwrap())
                .try_into()
                .unwrap()
        };
        let overrides =
            (!value["overrides_root"].is_null()).then(|| digest(&value["overrides_root"]));
        let view = NamespaceView::new(
            value["instance_id"].as_str().unwrap().into(),
            source(&value["native"]),
            digest(&value["bindings_root"]),
            overrides,
        )
        .unwrap();
        let expected = unhex(vector["canonical_hex"].as_str().unwrap());
        assert_eq!(view.encode(), expected);
        assert_eq!(NamespaceView::decode(&expected).unwrap(), view);
        assert_eq!(format!("sha256:{}", hex(&view.id())), vector["digest"]);
    }
}

#[test]
fn every_truncation_trailing_byte_and_oversized_manifest_is_rejected() {
    let source = root_source().encode();
    let binding = NamespaceBinding::new(
        "/a".into(),
        root_source(),
        "".into(),
        BindingPolicy::Mutable,
    )
    .unwrap()
    .encode();
    let view = NamespaceView::new(
        "22222222-2222-4222-8222-222222222222".into(),
        root_source(),
        [7; 32],
        Some([8; 32]),
    )
    .unwrap()
    .encode();
    for (bytes, decode) in [(
        source,
        SourceSnapshot::decode as fn(&[u8]) -> CodecResult<SourceSnapshot>,
    )] {
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end]).is_err());
        }
        let mut extra = bytes;
        extra.push(0);
        assert!(decode(&extra).is_err());
    }
    for end in 0..binding.len() {
        assert!(NamespaceBinding::decode(&binding[..end]).is_err());
    }
    for end in 0..view.len() {
        assert!(NamespaceView::decode(&view[..end]).is_err());
    }
    let mut extra = binding;
    extra.push(0);
    assert!(NamespaceBinding::decode(&extra).is_err());
    let mut extra = view;
    extra.push(0);
    assert!(NamespaceView::decode(&extra).is_err());
    let oversized = vec![0; MANIFEST_MAX_BYTES + 1];
    assert_eq!(
        SourceSnapshot::decode(&oversized).unwrap_err(),
        CodecError::BadLength("manifest")
    );
    assert!(NamespaceBinding::decode(&oversized).is_err());
    assert!(NamespaceView::decode(&oversized).is_err());
}

#[test]
fn malformed_domains_lengths_utf8_and_tags_fail_closed() {
    let mut source = root_source().encode();
    source[0] ^= 1;
    assert!(SourceSnapshot::decode(&source).is_err());
    let mut source = root_source().encode();
    source[SOURCE_DOMAIN.len()..SOURCE_DOMAIN.len() + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(SourceSnapshot::decode(&source).is_err());
    let mut source = root_source().encode();
    source[SOURCE_DOMAIN.len() + 4] = 0xff;
    assert!(SourceSnapshot::decode(&source).is_err());
    let mut source = root_source().encode();
    let tag = source.windows(4).position(|w| w == b"sha1").unwrap();
    source[tag..tag + 4].copy_from_slice(b"sha2");
    assert!(SourceSnapshot::decode(&source).is_err());
    let binding = NamespaceBinding::new(
        "/a".into(),
        root_source(),
        "".into(),
        BindingPolicy::Mutable,
    )
    .unwrap()
    .encode();
    for tag in [0, 3, 255] {
        let mut bad = binding.clone();
        *bad.last_mut().unwrap() = tag;
        assert!(NamespaceBinding::decode(&bad).is_err());
    }
    let view = NamespaceView::new(
        "22222222-2222-4222-8222-222222222222".into(),
        root_source(),
        [7; 32],
        None,
    )
    .unwrap()
    .encode();
    for tag in [2, 255] {
        let mut bad = view.clone();
        let len = bad.len();
        bad[len - 2] = tag;
        assert!(NamespaceView::decode(&bad).is_err());
    }
    let mut bad = view.clone();
    bad[VIEW_DOMAIN.len() + 1] = 2;
    assert!(NamespaceView::decode(&bad).is_err());
    let mut bad = view;
    *bad.last_mut().unwrap() = 2;
    assert!(NamespaceView::decode(&bad).is_err());
}

#[test]
fn canonical_paths_preserve_unicode_case_plus_and_literal_backslash() {
    let mut source = root_source();
    for path in ["", "relative", "/a/", "/a//b", "/.", "/a/../b", "/a\0b"] {
        assert!(
            SourceSnapshot::new(
                source.source_id.clone(),
                path.into(),
                source.commit_oid.clone(),
                source.root_tree_oid.clone()
            )
            .is_err(),
            "{path:?}"
        );
    }
    source.scope_path = "/库+1/Case/\\literal".into();
    assert_eq!(SourceSnapshot::decode(&source.encode()).unwrap(), source);
    let composed = "/é";
    let decomposed = "/e\u{301}";
    let mut first = source.clone();
    first.scope_path = composed.into();
    let mut second = source;
    second.scope_path = decomposed.into();
    assert_ne!(first.id(), second.id());
}

#[test]
fn exact_maximum_paths_and_source_composition_are_checked() {
    let path = format!("/{}", vec!["x".repeat(255); 16].join("/"));
    assert_eq!(path.len(), PATH_MAX_BYTES);
    let binding = NamespaceBinding::new(
        path.clone(),
        root_source(),
        path[1..].into(),
        BindingPolicy::Mutable,
    )
    .unwrap();
    assert!(binding.encode().len() <= MANIFEST_MAX_BYTES);
    assert_eq!(
        NamespaceBinding::decode(&binding.encode()).unwrap(),
        binding
    );
    let mut scoped = root_source();
    scoped.scope_path = path.clone();
    assert!(
        NamespaceBinding::new("/a".into(), scoped, "z".into(), BindingPolicy::Mutable).is_err()
    );
    assert!(SourceSnapshot::new(
        root_source().source_id,
        format!("{path}/z"),
        "1".repeat(40),
        "2".repeat(40)
    )
    .is_err());
    assert!(NamespaceBinding::new(
        "/a".into(),
        root_source(),
        "x".repeat(256),
        BindingPolicy::Mutable
    )
    .is_err());
}

#[test]
fn canonical_uuids_and_oids_cannot_be_normalized_into_valid_identity() {
    let good = root_source();
    for id in [
        "00000000-0000-0000-0000-000000000000",
        "11111111111141118111111111111111",
        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
    ] {
        assert!(SourceSnapshot::new(
            id.into(),
            "/".into(),
            good.commit_oid.clone(),
            good.root_tree_oid.clone()
        )
        .is_err());
    }
    for oid in [
        "a".repeat(39),
        "a".repeat(41),
        "A".repeat(40),
        "g".repeat(40),
    ] {
        assert!(SourceSnapshot::new(
            good.source_id.clone(),
            "/".into(),
            oid,
            good.root_tree_oid.clone()
        )
        .is_err());
    }
    let mut scoped = good;
    scoped.scope_path = "/a".into();
    assert!(NamespaceView::new(
        "22222222-2222-4222-8222-222222222222".into(),
        scoped,
        [0; 32],
        None
    )
    .is_err());
}

#[test]
fn identity_changes_with_provenance_policy_route_instance_and_override_presence() {
    let source = root_source();
    let mut next = source.clone();
    next.commit_oid = "2".repeat(40);
    assert_ne!(
        source.id(),
        next.id(),
        "same tree with new commit changes provenance"
    );
    let binding = NamespaceBinding::new(
        "/a".into(),
        source.clone(),
        "".into(),
        BindingPolicy::Mutable,
    )
    .unwrap();
    let mut release = binding.clone();
    release.policy = BindingPolicy::ImmutableRelease;
    assert_ne!(binding.id(), release.id());
    let mut moved = binding.clone();
    moved.mount_path = "/ab".into();
    assert_ne!(binding.id(), moved.id());
    let mut subpath = binding.clone();
    subpath.source_subpath = "src".into();
    assert_ne!(binding.id(), subpath.id());
    let view = NamespaceView::new(
        "22222222-2222-4222-8222-222222222222".into(),
        source,
        [0; 32],
        None,
    )
    .unwrap();
    let mut with_empty_override = view.clone();
    with_empty_override.overrides_root = Some([0; 32]);
    assert_ne!(view.id(), with_empty_override.id());
    let mut provenance = view.clone();
    provenance.native = next;
    assert_ne!(view.id(), provenance.id());
    let mut other_instance = view.clone();
    other_instance.instance_id = "33333333-3333-4333-8333-333333333333".into();
    assert_ne!(view.id(), other_instance.id());
}
