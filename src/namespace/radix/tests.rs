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

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/namespace-radix-v1.json"
    ))
    .unwrap()
}

fn child(edge: u8, fill: u8) -> RadixChild {
    RadixChild {
        edge,
        digest: [fill; 32],
    }
}

#[test]
fn frozen_independent_dotnet_vectors_match_local_nodes_bytes_and_identity() {
    let expected_nodes = [
        RadixNode::empty(),
        RadixNode::new(b"a\0".to_vec(), Some([0x11; 32]), Vec::new()).unwrap(),
        RadixNode::new(Vec::new(), None, vec![child(b'a', 0x22), child(b'b', 0x33)]).unwrap(),
    ];
    let frozen_vectors = vectors();
    assert_eq!(
        frozen_vectors.as_array().unwrap().len(),
        expected_nodes.len()
    );
    for (vector, expected_node) in frozen_vectors
        .as_array()
        .unwrap()
        .iter()
        .zip(expected_nodes)
    {
        let bytes = unhex(vector["canonical_hex"].as_str().unwrap());
        let decoded = RadixNode::decode(&bytes).unwrap();
        assert_eq!(decoded, expected_node);
        assert_eq!(expected_node.encode(), bytes);
        assert_eq!(format!("sha256:{}", hex(&decoded.id())), vector["digest"]);
    }
    assert_eq!(
        hex(&empty_root()),
        "18946486089198dfa8eeb70fa90e04b137c579dc08ae1e6f8bceafc0d35ef677"
    );
}

#[test]
fn every_frozen_node_truncation_and_trailing_byte_is_rejected() {
    for vector in vectors().as_array().unwrap() {
        let bytes = unhex(vector["canonical_hex"].as_str().unwrap());
        for end in 0..bytes.len() {
            assert!(
                RadixNode::decode(&bytes[..end]).is_err(),
                "{}: {end}",
                vector["name"]
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(RadixNode::decode(&trailing).is_err());
    }
    assert_eq!(
        RadixNode::decode(&vec![0; NODE_MAX_BYTES + 1]).unwrap_err(),
        CodecError::BadLength("radix node")
    );
}

#[test]
fn domain_presence_tags_and_unbounded_lengths_fail_closed() {
    let empty = RadixNode::empty().encode();
    let mut domain = empty.clone();
    domain[0] ^= 1;
    assert!(RadixNode::decode(&domain).is_err());
    for tag in [2, 255] {
        let mut bad = empty.clone();
        bad[NODE_DOMAIN.len() + 2] = tag;
        assert!(RadixNode::decode(&bad).is_err());
    }
    for label_length in [4097u16, u16::MAX] {
        let mut bad = empty.clone();
        bad[NODE_DOMAIN.len()..NODE_DOMAIN.len() + 2].copy_from_slice(&label_length.to_be_bytes());
        assert_eq!(
            RadixNode::decode(&bad).unwrap_err(),
            CodecError::BadLength("radix label")
        );
    }
    for count in [257u16, u16::MAX] {
        let mut bad = empty.clone();
        let start = NODE_DOMAIN.len() + 3;
        bad[start..start + 2].copy_from_slice(&count.to_be_bytes());
        assert_eq!(
            RadixNode::decode(&bad).unwrap_err(),
            CodecError::BadLength("radix fanout")
        );
    }
}

#[test]
fn duplicate_and_unsorted_edges_are_not_normalized_into_canonical_nodes() {
    let branch = RadixNode::new(Vec::new(), None, vec![child(b'a', 1), child(b'b', 2)]).unwrap();
    let first_edge = NODE_DOMAIN.len() + 2 + 1 + 2;
    for second_edge in *b"a0" {
        let mut bad = branch.encode();
        bad[first_edge + 33] = second_edge;
        assert!(matches!(
            RadixNode::decode(&bad),
            Err(CodecError::BadOrdering(_))
        ));
    }
    for children in [
        vec![child(b'a', 1), child(b'a', 2)],
        vec![child(b'b', 1), child(b'a', 2)],
    ] {
        assert!(RadixNode::new(Vec::new(), None, children).is_err());
    }
}

#[test]
fn noncanonical_uncompressed_nodes_fail_in_constructors_and_decoder() {
    assert!(RadixNode::new(Vec::new(), None, vec![child(b'a', 1)]).is_err());
    assert!(RadixNode::new(b"a".to_vec(), None, Vec::new()).is_err());
    // Handwritten encodings deliberately bypass constructors.
    let mut one_child = NODE_DOMAIN.to_vec();
    one_child.extend_from_slice(&[0, 0, 0, 0, 1, b'a']);
    one_child.extend_from_slice(&[1; 32]);
    assert!(RadixNode::decode(&one_child).is_err());
    let mut labelled_empty = NODE_DOMAIN.to_vec();
    labelled_empty.extend_from_slice(&[0, 1, b'a', 0, 0, 0]);
    assert!(RadixNode::decode(&labelled_empty).is_err());
    let root_binding = RadixNode::new(Vec::new(), Some([1; 32]), Vec::new()).unwrap();
    assert!(root_binding.binding().is_some());
    let bound_branch =
        RadixNode::new(b"a\0".to_vec(), Some([1; 32]), vec![child(b'b', 2)]).unwrap();
    assert_eq!(
        RadixNode::decode(&bound_branch.encode()).unwrap(),
        bound_branch
    );
}

#[test]
fn maximum_label_and_all_256_byte_edges_fit_the_frozen_node_budget() {
    let children = (0..=255).map(|edge| child(edge, edge)).collect();
    let node = RadixNode::new(vec![b'a'; PATH_MAX_BYTES], Some([7; 32]), children).unwrap();
    assert_eq!(node.children().first().unwrap().edge, 0);
    assert_eq!(node.children().last().unwrap().edge, 255);
    assert_eq!(node.children().len(), CHILD_MAX_COUNT);
    assert!(node.encode().len() <= NODE_MAX_BYTES);
    assert_eq!(RadixNode::decode(&node.encode()).unwrap(), node);
    assert!(RadixNode::new(vec![b'a'; PATH_MAX_BYTES + 1], Some([7; 32]), Vec::new()).is_err());
    assert!(RadixNode::new(Vec::new(), Some([7; 32]), vec![child(0, 1); 257]).is_err());
}

#[test]
fn local_labels_may_split_utf8_but_complete_value_keys_must_be_valid() {
    let node = RadixNode::new(vec![0xa9, 0], Some([7; 32]), Vec::new()).unwrap();
    assert_eq!(node.label(), &[0xa9, 0]);
    assert_eq!(RadixNode::decode(&node.encode()).unwrap(), node);
    assert!(
        decode_key(node.label()).is_err(),
        "child label is not a complete key"
    );
    let assembled = [vec![0xc3], node.label().to_vec()].concat();
    assert_eq!(decode_key(&assembled).unwrap(), "/é");
    let prefix = RadixNode::new(vec![0xc3], None, vec![child(0xa9, 1), child(0xb1, 2)]).unwrap();
    assert_eq!(RadixNode::decode(&prefix.encode()).unwrap(), prefix);
    let overlong_assembled = [vec![b'a'; 3000], vec![b'b'; 2000], vec![0]].concat();
    assert!(decode_key(&overlong_assembled).is_err());
}

#[test]
fn component_key_bytes_match_handwritten_examples_and_do_not_match_neighbors() {
    for (path, expected) in [
        ("/", b"".as_slice()),
        ("/a", b"a\0".as_slice()),
        ("/a/b", b"a\0b\0".as_slice()),
        ("/x/lib", b"x\0lib\0".as_slice()),
        ("/x/library", b"x\0library\0".as_slice()),
    ] {
        assert_eq!(encode_key(path).unwrap(), expected);
        assert_eq!(decode_key(expected).unwrap(), path);
    }
    let ancestor = encode_key("/x/lib").unwrap();
    assert!(encode_key("/x/lib/file").unwrap().starts_with(&ancestor));
    assert!(!encode_key("/x/library/file")
        .unwrap()
        .starts_with(&ancestor));
}

#[test]
fn keys_use_encoded_byte_order_preserve_case_unicode_plus_and_literal_backslash() {
    assert!(encode_key("/a").unwrap() < encode_key("/a/b").unwrap());
    assert!(encode_key("/a/b").unwrap() < encode_key("/a+").unwrap());
    assert!("/a/b" > "/a+", "slash-string order is a different order");
    for path in ["/Case", "/case", "/库+1/\\literal", "/é", "/e\u{301}"] {
        assert_eq!(decode_key(&encode_key(path).unwrap()).unwrap(), path);
    }
    assert_ne!(encode_key("/Case").unwrap(), encode_key("/case").unwrap());
    assert_ne!(encode_key("/é").unwrap(), encode_key("/e\u{301}").unwrap());
}

#[test]
fn noncanonical_complete_keys_are_rejected_without_aliasing_paths() {
    for key in [
        b"a".as_slice(),
        b"\0".as_slice(),
        b"\0a\0".as_slice(),
        b"a\0\0".as_slice(),
        b"a/b\0".as_slice(),
        b".\0".as_slice(),
        b"..\0".as_slice(),
        &[0xff, 0],
    ] {
        assert!(decode_key(key).is_err(), "{key:?}");
    }
    let mut overlong_component = vec![b'a'; 256];
    overlong_component.push(0);
    assert!(decode_key(&overlong_component).is_err());
    assert!(decode_key(&vec![0; PATH_MAX_BYTES + 1]).is_err());
    for path in ["", "relative", "/a/", "/a//b", "/a/..", "/a\0"] {
        assert!(encode_key(path).is_err(), "{path:?}");
    }
}

#[test]
fn exact_key_byte_component_limits_and_legacy_depth_are_preserved() {
    let path = format!("/{}", vec!["a".repeat(255); 16].join("/"));
    assert_eq!(path.len(), PATH_MAX_BYTES);
    let key = encode_key(&path).unwrap();
    assert_eq!(key.len(), PATH_MAX_BYTES);
    assert_eq!(decode_key(&key).unwrap(), path);
    assert!(encode_key(&format!("{path}/z")).is_err());
    assert!(encode_key(&format!("/{}a", "é".repeat(127))).is_ok());
    assert!(encode_key(&format!("/{}", "é".repeat(128))).is_err());
    let legacy_deep = format!("/{}", vec!["a"; 257].join("/"));
    assert_eq!(
        decode_key(&encode_key(&legacy_deep).unwrap()).unwrap(),
        legacy_deep
    );
}

#[test]
fn identity_covers_labels_binding_values_edges_and_child_digests() {
    let base = RadixNode::new(b"a\0".to_vec(), Some([1; 32]), vec![child(b'b', 2)]).unwrap();
    let changed = [
        RadixNode::new(b"c\0".to_vec(), Some([1; 32]), vec![child(b'b', 2)]).unwrap(),
        RadixNode::new(b"a\0".to_vec(), Some([3; 32]), vec![child(b'b', 2)]).unwrap(),
        RadixNode::new(b"a\0".to_vec(), Some([1; 32]), vec![child(b'c', 2)]).unwrap(),
        RadixNode::new(b"a\0".to_vec(), Some([1; 32]), vec![child(b'b', 3)]).unwrap(),
    ];
    for node in changed {
        assert_ne!(base.id(), node.id());
    }
}
