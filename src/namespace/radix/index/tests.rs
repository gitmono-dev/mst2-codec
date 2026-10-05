use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[derive(Default)]
struct MemoryStore {
    nodes: BTreeMap<[u8; 32], Vec<u8>>,
    reads: usize,
    writes: usize,
    fail_write_at: Option<usize>,
    written: BTreeSet<[u8; 32]>,
}

impl NodeStore for MemoryStore {
    fn read(&mut self, id: &[u8; 32]) -> IndexResult<Vec<u8>> {
        self.reads += 1;
        self.nodes
            .get(id)
            .cloned()
            .ok_or_else(|| IndexError::Store("missing node".into()))
    }

    fn insert(&mut self, id: &[u8; 32], bytes: &[u8]) -> IndexResult<()> {
        self.writes += 1;
        if self.fail_write_at == Some(self.writes) {
            return Err(IndexError::Store("injected insertion failure".into()));
        }
        if self.nodes.get(id).is_some_and(|existing| existing != bytes) {
            return Err(IndexError::Store("conflicting immutable bytes".into()));
        }
        self.nodes.insert(*id, bytes.to_vec());
        self.written.insert(*id);
        Ok(())
    }
}

fn value(id: u8) -> [u8; 32] {
    [id; 32]
}

fn build(store: &mut MemoryStore, items: &[(&str, u8)]) -> [u8; 32] {
    let mut root = empty_root();
    let mut index = RadixIndex::new(store);
    for (path, id) in items {
        root = index.update(&root, path, Some(value(*id))).unwrap();
    }
    root
}

/// Brute component-vector oracle; it does not use the production byte-key
/// encoder, compressed labels, trie walker or prefix matching implementation.
fn expected_prefix(map: &BTreeMap<String, [u8; 32]>, path: &str) -> Option<(String, [u8; 32])> {
    let comps: Vec<_> = path.split('/').filter(|s| !s.is_empty()).collect();
    map.iter()
        .filter(|(candidate, _)| {
            let prefix: Vec<_> = candidate.split('/').filter(|s| !s.is_empty()).collect();
            prefix.len() <= comps.len() && prefix.iter().zip(&comps).all(|(a, b)| a == b)
        })
        .max_by_key(|(candidate, _)| candidate.split('/').filter(|s| !s.is_empty()).count())
        .map(|(path, id)| (path.clone(), *id))
}

fn check_map(
    store: &mut MemoryStore,
    root: &[u8; 32],
    expected: &BTreeMap<String, [u8; 32]>,
    probes: &[String],
) {
    let mut index = RadixIndex::new(store);
    for path in probes {
        assert_eq!(
            index.get(root, path).unwrap(),
            expected.get(path).copied(),
            "get {path}"
        );
        assert_eq!(
            index.longest_prefix(root, path).unwrap(),
            expected_prefix(expected, path),
            "prefix {path}"
        );
    }
}

#[test]
fn fixed_map_oracle_covers_root_neighbors_unicode_nested_mounts_and_mutation_trace() {
    let paths = [
        "/",
        "/x/lib",
        "/x/library",
        "/x/lib/vendor/b",
        "/x/lib/vendor/beta",
        "/x/é",
        "/x/ê",
        "/x/e\u{301}",
        "/Case",
        "/case",
        "/库+1/\\literal",
    ];
    let mut probes: Vec<_> = paths.iter().map(|s| s.to_string()).collect();
    probes.extend(paths.iter().map(|s| {
        if *s == "/" {
            "/absent/deep".to_string()
        } else {
            format!("{s}/unvisited/deep")
        }
    }));
    probes.extend(["/x/liberation", "/x/libraryz", "/unknown"].map(str::to_string));
    let mut store = MemoryStore::default();
    let mut root = empty_root();
    let mut expected = BTreeMap::new();
    let mut history = Vec::new();
    for round in 0..100usize {
        let slot = (round * 7 + 3) % paths.len();
        let path = paths[slot];
        let mutation = if round % 4 == 0 {
            None
        } else {
            Some(value((round % 251 + 1) as u8))
        };
        history.push((root, expected.clone()));
        root = RadixIndex::new(&mut store)
            .update(&root, path, mutation)
            .unwrap();
        if let Some(id) = mutation {
            expected.insert(path.to_string(), id);
        } else {
            expected.remove(path);
        }
        check_map(&mut store, &root, &expected, &probes);
    }
    for (root, expected) in history.iter().step_by(9) {
        check_map(&mut store, root, expected, &probes);
    }
}

#[test]
fn insertion_order_and_delete_reinsert_have_identical_canonical_roots() {
    let items = [
        ("/", 1),
        ("/x/lib", 2),
        ("/x/lib/vendor/b", 3),
        ("/x/library", 4),
        ("/é", 5),
        ("/ê", 6),
    ];
    let mut first = MemoryStore::default();
    let expected = build(&mut first, &items);
    for order in [
        vec![5, 4, 3, 2, 1, 0],
        vec![1, 5, 2, 0, 4, 3],
        vec![3, 0, 5, 2, 1, 4],
    ] {
        let ordered: Vec<_> = order.iter().map(|i| items[*i]).collect();
        let mut store = MemoryStore::default();
        assert_eq!(build(&mut store, &ordered), expected);
    }
    for (path, id) in items {
        let removed = RadixIndex::new(&mut first)
            .update(&expected, path, None)
            .unwrap();
        assert_eq!(
            RadixIndex::new(&mut first).get(&removed, path).unwrap(),
            None
        );
        let restored = RadixIndex::new(&mut first)
            .update(&removed, path, Some(value(id)))
            .unwrap();
        assert_eq!(restored, expected, "{path}");
    }
}

#[test]
fn noops_and_empty_index_do_not_write_or_read_implicit_empty_nodes() {
    let mut store = MemoryStore::default();
    let empty = empty_root();
    assert_eq!(RadixIndex::new(&mut store).get(&empty, "/a").unwrap(), None);
    assert_eq!(
        RadixIndex::new(&mut store)
            .update(&empty, "/a", None)
            .unwrap(),
        empty
    );
    assert_eq!((store.reads, store.writes), (0, 0));
    let root = build(&mut store, &[("/a", 1), ("/a/b", 2), ("/ab", 3)]);
    let writes = store.writes;
    for (path, mutation) in [
        ("/a", Some(value(1))),
        ("/missing", None),
        ("/a/missing", None),
    ] {
        assert_eq!(
            RadixIndex::new(&mut store)
                .update(&root, path, mutation)
                .unwrap(),
            root
        );
    }
    assert_eq!(store.writes, writes);
    let mut root = root;
    for path in ["/a", "/a/b", "/ab"] {
        root = RadixIndex::new(&mut store)
            .update(&root, path, None)
            .unwrap();
    }
    assert_eq!(root, empty);
}

#[test]
fn one_change_rewrites_only_its_path_and_old_nodes_remain_immutable() {
    let mut store = MemoryStore::default();
    let root = build(
        &mut store,
        &[("/a/one", 1), ("/a/two", 2), ("/b/untouched", 3)],
    );
    let before = store.nodes.clone();
    let old_node = RadixNode::decode(before.get(&root).unwrap()).unwrap();
    let untouched = old_node
        .children()
        .iter()
        .find(|child| child.edge == b'b')
        .unwrap()
        .digest;
    store.written.clear();
    let next = RadixIndex::new(&mut store)
        .update(&root, "/a/one", Some(value(4)))
        .unwrap();
    let new_node = RadixNode::decode(store.nodes.get(&next).unwrap()).unwrap();
    assert_eq!(
        new_node
            .children()
            .iter()
            .find(|child| child.edge == b'b')
            .unwrap()
            .digest,
        untouched
    );
    assert!(!store.written.contains(&untouched));
    assert!(store.written.len() <= 3, "leaf and changed ancestors only");
    for (id, bytes) in before {
        assert_eq!(store.nodes.get(&id), Some(&bytes));
    }
    assert_eq!(
        RadixIndex::new(&mut store).get(&root, "/a/one").unwrap(),
        Some(value(1))
    );
    assert_eq!(
        RadixIndex::new(&mut store).get(&next, "/a/one").unwrap(),
        Some(value(4))
    );
}

#[test]
fn missing_corrupt_and_oversized_store_nodes_are_errors_not_absence() {
    let mut store = MemoryStore::default();
    assert!(matches!(
        RadixIndex::new(&mut store).get(&value(9), "/a"),
        Err(IndexError::Store(_))
    ));
    let root = build(&mut store, &[("/a", 1)]);
    store.nodes.get_mut(&root).unwrap()[0] ^= 1;
    assert!(matches!(
        RadixIndex::new(&mut store).get(&root, "/a"),
        Err(IndexError::Codec(CodecError::DigestMismatch(_)))
    ));
    store.nodes.insert(root, vec![0; NODE_MAX_BYTES + 1]);
    assert!(matches!(
        RadixIndex::new(&mut store).get(&root, "/a"),
        Err(IndexError::Codec(CodecError::BadLength(_)))
    ));
}

fn store_node(store: &mut MemoryStore, node: RadixNode) -> [u8; 32] {
    let id = node.id();
    store.nodes.insert(id, node.encode());
    id
}

#[test]
fn incoming_edge_and_invalid_complete_value_keys_are_checked_on_access() {
    let mut store = MemoryStore::default();
    let mismatched = store_node(
        &mut store,
        RadixNode::new(b"b\0".to_vec(), Some(value(1)), Vec::new()).unwrap(),
    );
    let root = store_node(
        &mut store,
        RadixNode::new(
            Vec::new(),
            Some(value(2)),
            vec![RadixChild {
                edge: b'a',
                digest: mismatched,
            }],
        )
        .unwrap(),
    );
    assert!(matches!(
        RadixIndex::new(&mut store).get(&root, "/a"),
        Err(IndexError::Codec(CodecError::BadOrdering(_)))
    ));
    for label in [b"a".to_vec(), b"a/b\0".to_vec(), vec![0xff, 0], vec![0]] {
        let root = store_node(
            &mut store,
            RadixNode::new(label, Some(value(1)), Vec::new()).unwrap(),
        );
        assert!(matches!(
            RadixIndex::new(&mut store).get(&root, "/absent"),
            Err(IndexError::Codec(_))
        ));
        assert!(RadixIndex::new(&mut store)
            .update(&root, "/new", Some(value(2)))
            .is_err());
    }
}

#[test]
fn locally_valid_child_cannot_exceed_the_assembled_key_budget() {
    let mut store = MemoryStore::default();
    let path = format!("/{}", vec!["a".repeat(255); 16].join("/"));
    let key = encode_key(&path).unwrap();
    let child = store_node(
        &mut store,
        RadixNode::new(b"aa\0".to_vec(), Some(value(1)), Vec::new()).unwrap(),
    );
    let root = store_node(
        &mut store,
        RadixNode::new(
            key[..4094].to_vec(),
            None,
            vec![
                RadixChild {
                    edge: b'a',
                    digest: child,
                },
                RadixChild {
                    edge: b'b',
                    digest: child,
                },
            ],
        )
        .unwrap(),
    );
    assert!(matches!(
        RadixIndex::new(&mut store).get(&root, &path),
        Err(IndexError::Codec(CodecError::BadLength(
            "radix assembled key"
        )))
    ));
    assert!(RadixIndex::new(&mut store)
        .update(&root, &path, Some(value(2)))
        .is_err());
}

#[test]
fn split_utf8_labels_resolve_complete_unicode_keys_correctly() {
    let mut store = MemoryStore::default();
    let root = build(&mut store, &[("/é", 1), ("/ê", 2), ("/e\u{301}", 3)]);
    for (path, id) in [("/é", 1), ("/ê", 2), ("/e\u{301}", 3)] {
        assert_eq!(
            RadixIndex::new(&mut store).get(&root, path).unwrap(),
            Some(value(id))
        );
    }
    let root_node = RadixNode::decode(store.nodes.get(&root).unwrap()).unwrap();
    let utf8_child = root_node
        .children()
        .iter()
        .find(|child| child.edge == 0xc3)
        .unwrap();
    let utf8_node = RadixNode::decode(store.nodes.get(&utf8_child.digest).unwrap()).unwrap();
    assert_eq!(utf8_node.label(), &[0xc3]);
}

#[test]
fn insertion_failure_never_returns_a_new_root_and_old_mapping_can_be_retried() {
    for fail_offset in 1..=3 {
        let mut store = MemoryStore::default();
        let root = build(&mut store, &[("/a/one", 1), ("/a/two", 2), ("/b/old", 3)]);
        let before = store.nodes.clone();
        store.fail_write_at = Some(store.writes + fail_offset);
        let failed = RadixIndex::new(&mut store).update(&root, "/a/one", Some(value(4)));
        assert!(
            matches!(failed, Err(IndexError::Store(_))),
            "offset {fail_offset}"
        );
        for (id, bytes) in &before {
            assert_eq!(store.nodes.get(id), Some(bytes));
        }
        store.fail_write_at = None;
        assert_eq!(
            RadixIndex::new(&mut store).get(&root, "/a/one").unwrap(),
            Some(value(1))
        );
        let next = RadixIndex::new(&mut store)
            .update(&root, "/a/one", Some(value(4)))
            .unwrap();
        assert_eq!(
            RadixIndex::new(&mut store).get(&next, "/a/one").unwrap(),
            Some(value(4))
        );
    }
}

#[test]
fn source_store_failure_during_collapse_preserves_old_root() {
    let mut store = MemoryStore::default();
    let root = build(&mut store, &[("/a", 1), ("/b", 2)]);
    let root_node = RadixNode::decode(store.nodes.get(&root).unwrap()).unwrap();
    let sibling = root_node
        .children()
        .iter()
        .find(|child| child.edge == b'b')
        .unwrap()
        .digest;
    let sibling_bytes = store.nodes.remove(&sibling).unwrap();
    assert!(matches!(
        RadixIndex::new(&mut store).update(&root, "/a", None),
        Err(IndexError::Store(_))
    ));
    store.nodes.insert(sibling, sibling_bytes);
    assert_eq!(
        RadixIndex::new(&mut store).get(&root, "/a").unwrap(),
        Some(value(1))
    );
}

#[test]
fn legacy_max_key_and_deep_updates_remain_iterative_and_bounded() {
    let mut store = MemoryStore::default();
    let path = format!("/{}", vec!["a".repeat(255); 16].join("/"));
    let root = RadixIndex::new(&mut store)
        .update(&empty_root(), &path, Some(value(1)))
        .unwrap();
    assert_eq!(
        RadixIndex::new(&mut store).get(&root, &path).unwrap(),
        Some(value(1))
    );
    assert!(RadixIndex::new(&mut store)
        .update(&root, &format!("{path}/z"), Some(value(2)))
        .is_err());
    let mut root = empty_root();
    let mut current = String::new();
    for round in 0..600 {
        current.push_str("/a");
        root = RadixIndex::new(&mut store)
            .update(&root, &current, Some(value((round % 251 + 1) as u8)))
            .unwrap();
    }
    assert_eq!(
        RadixIndex::new(&mut store).get(&root, &current).unwrap(),
        Some(value((599 % 251 + 1) as u8))
    );
    assert_eq!(
        RadixIndex::new(&mut store)
            .longest_prefix(&root, &format!("{current}/z"))
            .unwrap()
            .unwrap()
            .0,
        current
    );
}
