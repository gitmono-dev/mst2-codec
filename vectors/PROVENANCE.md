# Vector provenance

These 15 synthetic fixtures (+ `manifest.json`) are a **frozen copy** taken from
the Mega_ScorpioFS MST/2 specification bundle so that this repository is
self-contained — `tests/vectors.rs` must never depend on a sibling spec-bundle
checkout.

| Field | Value |
| --- | --- |
| Source bundle | `Mega_ScorpioFS_MST2_Specs_0.2.1_2026-09-15/mega_scorpio_mst2_specs/vectors` |
| Frozen on | 2026-09-16 |
| `manifest.json` SHA-256 | `41f8604d71977702161c83c584ce02c55128bd1c8239191ecb997f816b3225b8` |
| Files | 15 vectors + `manifest.json` (332 KiB total) |
| Generator | `reference/generate_vectors.py` (Python standard-library reference codec) |
| `independent_oracle` | **`false`** |

## What these fixtures are — and are not

They are **regression fixtures**, not a correctness proof. `manifest.json` marks
`independent_oracle: false` because the vectors were produced by the same
reference implementation that the Rust codec is compared against in spirit; the
agreement checked by `tests/vectors.rs` is *cross-language byte agreement*, which
catches divergence between the Rust and Python readings of the spec text.

Real correctness still requires the independent Git/source oracle described in
spec 16 §2 — a resolver that shares no code with either codec.

## Refreshing the copy

Only when the specification bundle is re-versioned, and never silently:

1. Confirm the spec-version bump is intentional and recorded in the spec
   bundle's `CHANGELOG.md`.
2. Copy `vectors/` from the new bundle over this directory.
3. Update the table above (source bundle name, date, new `manifest.json` digest).
4. Run `cargo test`. Any fixture that changes meaning without a corresponding
   spec change is a specification defect — file an errata rather than editing
   the fixture, per the spec's "no silent widening" rule.
