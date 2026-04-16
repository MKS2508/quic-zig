# Media-over-QUIC Transport — draft-ietf-moq-transport-17

Status: in progress. Phase 1 (wire primitives) under implementation.

Reference: `draft-ietf-moq-transport-17` (expires 2026-09). Cross-checked against `moq-rs` (kixelated/moq-rs) `main`, which implements draft-14/15/16/17 concurrently.

## Wire facts pinned for implementation

### Identifiers

| Item | Value | Source |
| --- | --- | --- |
| ALPN (raw QUIC) | `"moqt-17"` (7 ASCII bytes) | §3.1 |
| ALPN (final RFC) | `"moqt"` — NOT used during draft | §3.1 |
| Version code (internal) | `0xff00_0011` | moq-rs `ietf/version.rs:71` |
| Wire version negotiation | ALPN-only — **no `SUPPORTED_VERSIONS` param** in SETUP | §9.4, changelog |
| WT path | configurable (implementation default `/moq`) | §3.2 |

### MoQ varint (§1.4.1) — NOT the QUIC varint

MoQ uses a distinct "leading-ones" varint encoding. **Cannot reuse `quic/packet.zig` varint helpers.** The first byte's number of leading 1-bits determines total length: 1, 2, 3, 4, 5, 6, 8, or 9 bytes. A dedicated `src/moq/wire.zig` implements this.

### Control streams (§3.3)

- **Pair of unidirectional streams**, one opened by each peer. (Breaking change from pre-v17 bidi.)
- First message on each uni control stream is `SETUP` (type `0x2F00`), whose type varint doubles as the stream identifier.
- Both peers call `open_uni()` unconditionally after connect/accept.

### Request streams (§3.3)

Peer-initiated **bidirectional** streams carry a single request + response. First frame's message type identifies the request:
`TRACK_STATUS | SUBSCRIBE | PUBLISH | FETCH | PUBLISH_NAMESPACE | SUBSCRIBE_NAMESPACE`.
The `REQUEST_OK` / `REQUEST_ERROR` response travels back on the same bidi stream — **they carry no `request_id` field** on the wire; the stream itself is the identifier.

### Control-message framing (§9)

```
Type (moq-varint) | Length (u16, big-endian) | Payload (Length bytes)
```

Length is a **fixed 16-bit unsigned**, not a varint. Same framing applies to SETUP.

### Control message type codes (draft-17 §9 Table 4)

| Name | Code | Section |
| --- | --- | --- |
| SETUP | `0x2F00` | 9.4 |
| GOAWAY | `0x10` | 9.5 |
| REQUEST_OK | `0x07` | 9.6 |
| REQUEST_ERROR | `0x05` | 9.7 |
| SUBSCRIBE | `0x03` | 9.8 |
| SUBSCRIBE_OK | `0x04` | 9.9 |
| REQUEST_UPDATE | `0x02` | 9.10 |
| PUBLISH | `0x1D` | 9.11 |
| PUBLISH_OK | `0x1E` | 9.12 |
| PUBLISH_DONE | `0x0B` | 9.13 |
| FETCH | `0x16` | 9.14 |
| FETCH_OK | `0x18` | 9.15 |
| TRACK_STATUS | `0x0D` | 9.16 |
| PUBLISH_NAMESPACE | `0x06` | 9.17 |
| NAMESPACE | `0x08` | 9.18 |
| NAMESPACE_DONE | `0x0E` | 9.19 |
| SUBSCRIBE_NAMESPACE | `0x11` | 9.20 |
| PUBLISH_BLOCKED | `0x0F` | 9.21 |

**Reserved / legacy codes (MUST NOT emit; receipt → terminate):** `0x01`, `0x20`, `0x21`, `0x40`, `0x41` (legacy SETUP variants for draft ≤16 / ≤10).

**Removed messages (folded into REQUEST_OK/ERROR or signaled via stream close):** SUBSCRIBE_ERROR, SUBSCRIBE_DONE, FETCH_ERROR, FETCH_CANCEL, PUBLISH_ERROR, UNSUBSCRIBE, MAX_REQUEST_ID, REQUESTS_BLOCKED, TRACK_STATUS_REQUEST, and all the PUBLISH_NAMESPACE_*/SUBSCRIBE_NAMESPACE_* variants.

### SETUP Options (§9.4.1)

No count prefix; options fill the `u16 Length`. Delta-encoded key-value pairs (§1.4.3): even key → value is a single varint; odd key → value is varint-length-prefixed bytes. Keys MUST appear in ascending order.

| Option | Code | Shape |
| --- | --- | --- |
| PATH | `0x01` | length-prefixed bytes |
| AUTHORIZATION_TOKEN | `0x03` | length-prefixed token struct |
| MAX_AUTH_TOKEN_CACHE_SIZE | `0x04` | varint |
| AUTHORITY | `0x05` | length-prefixed bytes (URI authority) |
| MOQT_IMPLEMENTATION | `0x07` | length-prefixed UTF-8 |

`MAX_REQUEST_ID` (was `0x02` in v14–16) **removed** in v17.

### Data streams

#### Subgroup streams (§10.4.2)

Valid stream-type varints: `0x10..0x15`, `0x18..0x1D`, `0x30..0x35`, `0x38..0x3D`. Bit-4 always 1 (selector). Bits:

| Mask | Bit | Name | Meaning |
| --- | --- | --- | --- |
| `0x01` | 0 | PROPERTIES | Per-object Properties field present |
| `0x06` | 1-2 | SUBGROUP_ID_MODE | `00`=id is 0 (absent); `01`=absent, equals first object id; `10`=explicit in header; `11`=reserved (PROTOCOL_VIOLATION) |
| `0x08` | 3 | END_OF_GROUP | FIN signals largest object id in group |
| `0x10` | 4 | (selector) | Always 1 |
| `0x20` | 5 | DEFAULT_PRIORITY | Publisher Priority absent; inherit from control |

Header layout:

```
Type (moq-varint)
Track Alias (moq-varint)
Group ID (moq-varint)
[Subgroup ID (moq-varint)]      // only if SUBGROUP_ID_MODE == 0b10
[Publisher Priority (u8)]       // only if DEFAULT_PRIORITY == 0
```

No `final_object_id` field — end of group inferred from `END_OF_GROUP` bit + FIN.

Invalid subgroup stream-type codes (PROTOCOL_VIOLATION): `0x16, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F`.

#### Fetch stream (§10.4.4)

```
Type (moq-varint) = 0x05
Request ID (moq-varint)
```

Followed by per-object records with their own `Serialization Flags (varint)` + optional fields.

#### Datagram objects (§10.3.1)

Valid type range: `0x00..0x0F`, `0x20..0x2F`. Bit 4 is always 0 (datagram selector).

| Mask | Name |
| --- | --- |
| `0x01` | PROPERTIES |
| `0x02` | END_OF_GROUP |
| `0x04` | ZERO_OBJECT_ID (Object ID field absent) |
| `0x08` | DEFAULT_PRIORITY |
| `0x20` | STATUS (object-status present, no payload) |

Layout:

```
Type (moq-varint)
Track Alias (moq-varint)
Group ID (moq-varint)
[Object ID (moq-varint)]       // absent if ZERO_OBJECT_ID
[Publisher Priority (u8)]      // absent if DEFAULT_PRIORITY
[Properties (..)]              // if PROPERTIES
[Object Status (moq-varint)]   // if STATUS (no payload)
[Object Payload (..)]          // if !STATUS (remainder of datagram)
```

Invalid datagram types: `0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F` (STATUS + END_OF_GROUP together).

### Required QUIC features

- RFC 9221 DATAGRAM extension MUST be negotiated. Already supported by this stack.

### moq-rs interop reality

- `main` implements draft-14/15/16/17 simultaneously, keyed by ALPN.
- Supports both raw QUIC and WebTransport.
- Shares struct names across drafts; IDs `0x05`/`0x07`/`0x08` are overloaded per draft — for draft-17 we treat them as REQUEST_ERROR / REQUEST_OK / NAMESPACE respectively.

## Implementation state

| Component | State |
| --- | --- |
| Wire primitives (`src/moq/wire.zig`, `message_codes.zig`) | done; 15 tests |
| Control message codec (`src/moq/message.zig`) | done for SETUP, GOAWAY, REQUEST_OK/ERROR, SUBSCRIBE(+parameters), SUBSCRIBE_OK, PUBLISH, PUBLISH_OK/DONE, PUBLISH_NAMESPACE/BLOCKED, NAMESPACE/DONE, SUBSCRIBE_NAMESPACE, FETCH/FETCH_OK, TRACK_STATUS, REQUEST_UPDATE |
| Object framing (`src/moq/object.zig`) | subgroup headers (all id-mode + priority variants), datagram objects, fetch stream headers — done with round-trip tests |
| Transport abstraction | skipped — built directly on event_loop's `.quic` and `.webtransport` protocols |
| Session / SETUP | done in-app (not as library abstraction); verified Zig↔Zig and Zig↔moq-rs |
| Publisher / Subscriber | `moq_client.zig` has `--mode publish` / subscribe; `moq_server.zig` is a publisher |
| Relay | done in `apps/moq_relay.zig`: pub/sub fanout with alias remapping + synthetic origin |
| Browser (WebTransport) demo | done in `apps/moq_browser_server.zig` + `interop/browser/moq.html` |
| Interop vs moq-rs | SETUP + SUBSCRIBE validated (wire format confirmed); data plane blocked by moq-rs auth config (their issue) |
| Datagram objects | codec done + tested; runtime path deferred (needs `.quic` datagram dispatch in event_loop) |
| FETCH stream | header codec done; runtime request/response flow deferred |
| Namespace discovery | message codecs done (SUBSCRIBE_NAMESPACE, NAMESPACE, NAMESPACE_DONE, PUBLISH_NAMESPACE); runtime flow deferred |

## Verified interop matrix

| Scenario | SETUP | SUBSCRIBE | Objects |
| --- | --- | --- | --- |
| Zig ↔ Zig (raw QUIC, loopback) | ✅ | ✅ | ✅ |
| Zig client → moq-rs relay | ✅ | ✅ (`subscribe started` logged) | ⚠ blocked by moq-rs publisher auth |
| moq-rs client → Zig server | ✅ | n/a (subscriber idle) | n/a |
| Browser (Chrome) ↔ Zig WT server | ✅ | ✅ | ✅ |
| Zig pub → Zig relay → Zig sub | ✅ | ✅ | ✅ (built-in origin) |

## Caveats and deferred work

- No AUTHORIZATION_TOKEN policy engine — wire-level decode only.
- No real media codec; object payloads are opaque bytes.
- No moq-lite / warp dialect.
- Cache policy in relay starts as "last 2 groups LRU" — tunable later.
