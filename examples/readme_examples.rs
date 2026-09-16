//! The snippets from `README.md`, compiled.
//!
//! `cargo test` and `cargo clippy --all-targets` build this example, so a
//! change that breaks a documented API breaks the build instead of quietly
//! turning the README into a lie.
use mst2_codec::chunkmap::{leaf_proof, merkle_root, verify_leaf};
use mst2_codec::metapage::{page_id, Entry, EntryKind, Page};
use mst2_codec::treeframe::{parse_stream, EndPayload, Frame, MetaPayload};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A directory is built canonically: the same entries always produce the
    // same bytes, and therefore the same page_id, on every machine.
    let page_bytes = Page::build(&[
        Entry::file(EntryKind::Regular, b"README.md", 23, [7u8; 32]),
        Entry::dir(b"src", [9u8; 32]),
    ])?;
    let id = page_id(&page_bytes);

    // Decoding validates structure, ordering and limits; encoding a decoded
    // page is byte-identical to the input.
    let (page, total_entries) = Page::decode(&page_bytes)?;
    assert_eq!(page.encode()?, page_bytes);
    assert_eq!(page.total_entries(), total_entries);

    // A response is a sequence of frames sharing one stream id, ending in END.
    let stream_id = 1u32;
    let mut stream = MetaPayload {
        pages: vec![(id, page_bytes.clone())],
    }
    .encode(stream_id, 0)?;
    stream.extend_from_slice(
        &EndPayload {
            request_item_count: 1,
            unique_unit_count: 1,
            logical_bytes: page_bytes.len() as u64,
            request_body_sha256: [0u8; 32],
        }
        .encode(stream_id, 1),
    );
    let frames = parse_stream(&stream)?; // gaps, missing END, trailing bytes: all errors
    assert!(matches!(frames.last(), Some(Frame::End(_))));

    // The verifier derives the split path itself from (page_count, page_index)
    // and checks the proof against it.
    let leaves: Vec<[u8; 32]> = (0..600).map(|i| [i as u8; 32]).collect();
    let root = merkle_root(&leaves)?;
    let proof = leaf_proof(&leaves, 42)?;
    verify_leaf(600, 42, leaves[42], &proof, root)?;
    Ok(())
}
