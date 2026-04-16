# RFC 9204 — QPACK: Field Compression for HTTP/3

## Status: ✅ Complete

See the section-level status matrix in [STATUS.md](STATUS.md#rfc-9204--qpack-field-compression-for-http3).

## Implementation

| Area | File |
|------|------|
| Static table + field-line codec | `src/h3/qpack.zig` |
| Dynamic table (FIFO ring) | `src/h3/qpack.zig` (`DynamicTable`) |
| Encoder state machine | `src/h3/qpack.zig` (`QpackEncoder`) |
| Decoder state machine | `src/h3/qpack.zig` (`QpackDecoder`) |
| Huffman (RFC 7541 Appendix B) | `src/h3/huffman.zig` |
| Encoder/decoder stream wiring | `src/h3/connection.zig` |

## Test coverage

- `qpack.zig`: 19 tests — static table round-trips, dynamic table
  insertion/eviction/relative-indexing/post-base, RIC encode/decode,
  encoder instruction emission, encoder↔decoder instruction roundtrip,
  Set-Capacity handling, second-encode reuses dynamic table.
- `huffman.zig`: 11 tests — encode/decode round-trips, padding rules,
  invalid-encoding rejection, EOS-symbol rejection.
- Plus the H3 integration tests in `connection.zig` exercise the
  encoder/decoder streams end-to-end.

## §2 Compression Overview — ✅ Done

Static table references + optional dynamic table. Each encoded header
block has a two-part prefix (Required Insert Count + Delta Base) followed
by zero or more field-line representations.

## §3 Reference Tables

### §3.1 Static Table — ✅ Done

All 99 entries from Appendix A are present in `static_table`
(qpack.zig:18). `findStaticMatch(name, value)` returns the best index
(full match preferred, else name-only match).

### §3.2 Dynamic Table — ✅ Done

FIFO ring buffer with inline storage — no heap allocation per entry.

| Limit | Value | Source |
|-------|-------|--------|
| Max entries | 128 | `DynamicTable.MAX_ENTRIES` |
| Max name length | 128 bytes | `DynEntry.name_buf` |
| Max value length | 512 bytes | `DynEntry.value_buf` |
| Capacity | Peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (≤4096 advertised) | `setCapacity()` |

Oversized entries are silently skipped by the encoder
(`tryInsertWithStaticNameRef`, `tryInsertWithLiteralName`); decoder-side
insertion errors propagate as QPACK stream errors.

### §3.2.1 Dynamic Table Size — ✅ Done

`computeEntrySize(name, value)` returns `name.len + value.len + 32` per
the spec formula. Eviction happens on insert when `size + entry > cap`.

### §3.2.2 Dynamic Table Capacity — ✅ Done

- Local max is set via `setCapacity(cap)` on both encoder (from peer's
  SETTINGS) and decoder (local advertised value, default 4096).
- Encoder emits `Set Dynamic Table Capacity` instruction (001xxxxx) on
  each `setCapacity()` call.
- Decoder enforces `cap ≤ local_max`; values exceeding the advertised
  maximum produce `error.CapacityExceeded` → `QPACK_ENCODER_STREAM_ERROR`.

### §3.2.3 Absolute, Relative, Post-Base Indices — ✅ Done

- `get(abs_idx)` — absolute lookup; returns `null` once evicted.
- `getRelative(base, rel_idx)` — `abs = base - rel_idx - 1`.
- `getPostBase(base, post_idx)` — `abs = base + post_idx`.

## §4 Wire Format

### §4.1 Encoder Instructions — ✅ Done

| Instruction | Pattern | Implementation |
|-------------|---------|----------------|
| Set Dynamic Table Capacity | `001xxxxx` | `QpackEncoder.setCapacity()` emits |
| Insert with Name Reference | `1Txxxxxx` | `tryInsertWithStaticNameRef()` (T=1) / name ref for dynamic (T=0, encoder emits literal name variant instead in practice) |
| Insert with Literal Name | `01Hxxxxx` | `tryInsertWithLiteralName()` (H=0 currently) |
| Duplicate | `000xxxxx` | Supported in `processEncoderInstruction()` decode path |

### §4.2 Decoder Instructions — ✅ Done

| Instruction | Pattern | Implementation |
|-------------|---------|----------------|
| Header Acknowledgment | `1xxxxxxx` | `emitHeaderAck(stream_id)` after decode with dynamic refs |
| Stream Cancellation | `01xxxxxx` | Parsed; no per-stream state to reclaim (see caveats) |
| Insert Count Increment | `00xxxxxx` | Parsed; `increment == 0` → `QPACK_DECODER_STREAM_ERROR` per §4.4.3 |

### §4.3 Encoder Stream — ✅ Done

Opened by `H3Connection.initConnection()` with type 0x02. The encoder
accumulates pending instructions in `instruction_buf`;
`flushEncoderInstructions()` drains them onto the wire after each
header block is encoded.

### §4.4 Decoder Stream — ✅ Done

Opened with type 0x03. The decoder emits Header Ack on any decode that
resolved a dynamic reference; `flushDecoderInstructions()` is called from
the request poll loop.

### §4.5 Field Line Representations — ✅ Done

| Rep | Pattern | Encoder | Decoder |
|-----|---------|---------|---------|
| Indexed Field Line (static) | `11NNNNNN` | ✅ | ✅ |
| Indexed Field Line (dynamic) | `10NNNNNN` | ✅ | ✅ |
| Indexed with Post-Base | `0001NNNN` | (emitted by encoder only when base < RIC — current encoder sets base=RIC so not emitted) | ✅ decode |
| Literal with Name Reference | `01NTNNNN` | ✅ T=1; dynamic T=0 decoded | ✅ both |
| Literal with Post-Base Name Reference | `0000NNNN` | — (see above) | ✅ decode |
| Literal with Literal Name | `001NHNNN` | ✅ (H=0) | ✅ (H=0 or H=1) |

Decoder also handles Huffman-encoded names/values on the literal-name
path via `huffman.decode()`.

### §4.5.1 Required Insert Count — ✅ Done

`encodeRequiredInsertCount(ric, max_entries)` and
`decodeRequiredInsertCount(encoded, max_entries, total_insert_count)`
implement the wrapping algorithm. Invalid encodings (RIC > 2·MaxEntries,
result ≤ 0, max_entries == 0 with non-zero encoded) return
`error.InvalidRIC`.

### §4.5.5 Decompression Failure — ✅ Done

Any error from `QpackDecoder.decode()` (bad index, truncated string,
corrupt Huffman, buffer too small, too many headers, …) yields
`H3_QPACK_DECOMPRESSION_FAILED` via `closeWithError()` in the H3 bidi
poll loop (connection.zig:976).

## §5 Configuration — ✅ Done

- `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 4096` advertised in local SETTINGS.
- `SETTINGS_QPACK_BLOCKED_STREAMS = 0` advertised — see caveats.
- Peer's advertised capacity is forwarded to the encoder on SETTINGS
  receipt, which then emits the Set Capacity encoder instruction.

## §6 Error Codes — ✅ Done

| Code | Value | Trigger |
|------|------:|---------|
| `QPACK_DECOMPRESSION_FAILED` | 0x0200 | Any decode error on a request HEADERS block |
| `QPACK_ENCODER_STREAM_ERROR` | 0x0201 | Peer's encoder violates stream rules (e.g. capacity overrun) |
| `QPACK_DECODER_STREAM_ERROR` | 0x0202 | Peer sends Insert Count Increment of 0 |

## Caveats / Known limitations

- **Huffman encoding** is not emitted by the encoder (`encodeString` sets
  H=0). The decoder fully supports both Huffman- and plain-encoded
  strings, so this is a size/bandwidth trade-off rather than a
  correctness issue. Adding Huffman encoding would be a pure encoder
  change via `huffman.encodedLength`/`huffman.encode` already present.
- **Huffman table history (Apr 2026)**: the RFC 7541 Appendix B table in
  `huffman.zig` was originally incorrect for symbols 22–31, 127, and the
  entire 128–256 range (including EOS). Zig↔Zig interop worked because
  the table was self-consistent; cross-impl interop silently corrupted
  any Huffman-encoded header value containing bytes ≥128 or a handful
  of control chars. Discovered during RFC 9114 adversarial testing,
  fixed by transcribing Appendix B directly. A per-byte round-trip test
  (`encode+decode every byte 0..255 round-trips`) and a quic-go cross-impl
  regression check both pass.
- **`qpack_blocked_streams = 0`** — we do not support out-of-order
  header blocks that reference dynamic entries not yet received on the
  encoder stream. The encoder only references entries already inserted
  by the time the block is encoded (so header blocks are never blocked
  on the decoder side). If a peer emits a block with
  `Required Insert Count` ahead of our current insert count, decoding
  fails rather than waiting.
- **No Stream Cancellation bookkeeping** — per-stream reference counts
  are not tracked, so incoming Stream Cancellation instructions are
  consumed but no internal state changes. This is correct behavior for
  our model (we don't maintain per-stream insertion credit).
- **Conservative insertion** — encoder skips insertion when entry size
  exceeds capacity or inline storage limits (name ≤128, value ≤512).
  Oversized fields are encoded as literals without dynamic-table
  caching.
- **`huffman_scratch`** is a 16 KiB file-scope buffer shared across
  decode calls. Decoded slices are valid only until the next
  `decodeHeaders` / `QpackDecoder.decode` call on the same thread —
  callers must consume or copy immediately.
- **Encoder always sets `Base = RIC`** (Delta Base = 0, sign=0). This
  means post-base representations (`0001NNNN`, `0000NNNN`) are never
  emitted. The decoder handles them anyway for interop.
