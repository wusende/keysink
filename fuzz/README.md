# Fuzzing

keysink ships a self-contained fuzzing suite (no nightly toolchain or
`cargo-fuzz` needed) built from three layers:

1. **Pure-function targets** — `src/fuzz.rs`. Seeded random inputs hammer
   parsers and pure helpers (`vkey::mask`, `percent_encode`,
   `extract_vkey`, `build_upstream_url`, `forward_headers`,
   `is_stream_request`, `contains_terminator`, `parse_retry_after`,
   `backoff`, store JSON parsing, age decryption, password-hash parsing,
   audit line encoding) and assert both panic-freedom and functional
   invariants.
2. **Scenario tests** — `tests/fuzz_vault.rs`, `tests/fuzz_proxy.rs`.
   Vault corruption matrix (bitflips / truncation / wrong key / passphrase
   blob as store), concurrent `store::update` writers, the hot-reload
   watcher (pickup, refuse-downgrade), full end-to-end proxy fuzzing against
   a mock upstream, and SSE terminator marker-split fuzzing over real
   chunked HTTP streams.
3. **Performance scenarios** — budgeted smoke tests (10k-route table build,
   header forwarding throughput, 32MB body probing, audit flood, 100
   concurrent proxied requests) that fail the suite on regression.

## Running

```bash
cargo test fuzz              # default: fixed seed, reproducible, ~30s
KEYSINK_FUZZ_ITERS=200000 \
KEYSINK_FUZZ_SEED=12345 \
cargo test --release fuzz    # deep run, different seed
```

## Corpus and artifacts

- `fuzz/corpus/<target>/` — hand-curated inputs replayed before random
  generation. Commit regression inputs here.
- `fuzz/artifacts/` — where a failing input lands when a target hits
  (gitignored). Shrink it into a minimal unit test in the owning module,
  then delete the artifact.
