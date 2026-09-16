# mst2-codec

Byte-level implementation of the **MST/2 wire formats** — the transfer protocol
between a monoengine/mega2 server and ScorpioFS clients.

The crate is deliberately small and boring: bytes in, bytes out. It contains no
I/O, no async runtime, no HTTP, no storage. Its only dependency is `sha2`.

```toml
[dependencies]
mst2-codec = { git = "https://github.com/gitmono-dev/mst2-codec" }
```

## Why this crate exists

Two independent implementations read and write the same protocol: the server
produces pages, frames and chunk maps; the client parses and verifies them. If
those two ever disagree about a length prefix or a digest domain string, the
result is not a compile error — it is silent corruption or a client that
refuses valid data. This crate is the single source of truth for those bytes, so
"what the server wrote" and "what the client accepts" are the same code.

The normative definitions live in the `Mega_ScorpioFS_MST2_Specs` bundle
(`specs/03`, `05`, `06`, `07`). Where this implementation and the prose disagree,
the prose wins and the code is the bug.

## Wire formats

| Module | Format | Spec |
| --- | --- | --- |
| [`descriptor`](src/descriptor.rs) | **MSD2** serving descriptor — pins a view to a metadata root and derives `snapshot_id` | 03 §2–§3 |
| [`metapage`](src/metapage.rs) | **MTP2/1** directory pages — canonical leaf/branch partition, `page_id` | 05 |
| [`treeframe`](src/treeframe.rs) | **MST/2** frames — 64-byte header, META/OBJECT/CHUNK/END/ERROR payloads, stream rules | 06 |
| [`chunkmap`](src/chunkmap.rs) | **MCM2/MCL2** chunk map — 1 MiB chunks, Merkle `pages_root`, proofs, range arithmetic | 07 |

Identity (uncompressed) frame encoding is implemented. The optional zstd flag is
recognized and rejected with `CodecError::Unsupported` rather than guessed at;
compression belongs to a transport layer that negotiates it.

## Usage

```rust
use mst2_codec::metapage::{page_id, Entry, EntryKind, Page};

// A directory is built canonically: the same entries always produce the same
// bytes, and therefore the same page_id, on every machine.
let page_bytes = Page::build(&[
    Entry::file(EntryKind::Regular, b"README.md", 23, [7u8; 32]),
    Entry::dir(b"src", [9u8; 32]),
])?;
let id = page_id(&page_bytes);

// Decoding validates structure, ordering and limits; encoding a decoded page
// is byte-identical to the input. That round-trip is the property the tests
// lean on hardest.
let (page, total_entries) = Page::decode(&page_bytes)?;
assert_eq!(page.encode()?, page_bytes);
assert_eq!(page.total_entries(), total_entries);
```

```rust
// continues the snippet above: `id` and `page_bytes` come from the page we built
use mst2_codec::treeframe::{parse_stream, EndPayload, Frame, MetaPayload};

// A response is a sequence of frames sharing one stream id, ending in END.
let mut stream = MetaPayload { pages: vec![(id, page_bytes.clone())] }.encode(stream_id, 0)?;
stream.extend_from_slice(&EndPayload {
    request_item_count: 1,
    unique_unit_count: 1,
    logical_bytes: page_bytes.len() as u64,
    request_body_sha256: [0u8; 32],
}.encode(stream_id, 1));

let frames = parse_stream(&stream)?; // sequence gaps, missing END, trailing bytes: all errors
assert!(matches!(frames.last(), Some(Frame::End(_))));
```

```rust
use mst2_codec::chunkmap::{leaf_proof, merkle_root, verify_leaf};

let leaves: Vec<[u8; 32]> = (0..600).map(|i| [i as u8; 32]).collect();
let root = merkle_root(&leaves)?;
let proof = leaf_proof(&leaves, 42)?;

// The verifier derives the split path itself from (page_count, page_index)
// and checks the proof against it — matching the root alone is not accepted.
verify_leaf(600, 42, leaves[42], &proof, root)?;
```

## Testing

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

- **34 unit tests** cover canonical encoding, ordering, limits, truncation,
  tampering and the negative cases each format must reject.
- **6 cross-validation tests** replay the 15 fixtures in [`vectors/`](vectors/)
  and compare against the reference Python codec's byte output — the same
  vectors the specification bundle ships.
- The snippets above are compiled as [`examples/readme_examples.rs`](examples/readme_examples.rs),
  so `cargo test` fails if the documented API drifts.

Two honest caveats, because they matter when reading a green test run:

1. The fixtures are marked `independent_oracle: false`. They were produced by the
   reference implementation, so agreement here shows the Rust and Python
   readings of the spec text match — **it is not a correctness proof**. See
   [`vectors/PROVENANCE.md`](vectors/PROVENANCE.md).
2. What would be proof is the independent Git/source oracle of spec 16 §2: an
   external resolver that shares no code with either codec. That lives with the
   system tests, not here.

## Design rules

- **Canonical encoding.** One byte string per value. Insertion order, heap
  layout and platform do not affect output; `encode(decode(x)) == x`.
- **Fail closed.** Unknown versions, non-zero reserved fields, unknown frame
  kinds, bad lengths and malformed payloads are typed errors. Nothing is
  inferred from a plausible-looking byte.
- **No silent widening.** A value outside the frozen profile (a chunk size other
  than 1 MiB, a 32-bit where the spec says 64) is rejected, never truncated or
  coerced. Loosening a bound is a specification change, not a patch.
- **Limits are format, not tuning.** `LEAF_MAX_ENTRIES = 128`,
  `PAGE_MAX_BYTES = 16384`, 1 MiB chunks and 256 chunks per map page are part
  of the codec identity — the same reason they are frozen in the prose.

## Status

`0.1.0`. Not published to crates.io; consumers use a git or path dependency.

Implemented: MSD2 descriptors, MTP2/1 pages, MST/2 identity frames (META,
OBJECT, CHUNK, END, ERROR) with full stream validation, MCM2/MCL2 maps with
Merkle proofs and range arithmetic.

Not implemented, by design: zstd frames (flag rejected), Git pack or delta
handling, socket/disk transport, any notion of authorization or retention.

## Related repositories

- [`monoengine`](https://github.com/gitmono-dev/mega2) — the server that
  produces these bytes and serves them over HTTP.
- [`scorpiofs`](https://github.com/gitmono-dev/scorpiofs) — the FUSE client that
  consumes and verifies them.
- `Mega_ScorpioFS_MST2_Specs` — the normative specification bundle; `vectors/`
  here is a frozen copy of its fixtures.

## License

Apache-2.0.
