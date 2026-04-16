// Media-over-QUIC Transport — draft-ietf-moq-transport-17.
// Version identifiers. See SPEC/DRAFT_IETF_MOQ_TRANSPORT_17.md.

pub const DRAFT_NUMBER: u32 = 17;

// Internal version code used by moq-rs and other implementations to
// identify draft-17. Not placed on the wire in draft-17 (version
// negotiation is ALPN-only; see §3.1 and §9.4).
pub const WIRE_VERSION: u64 = 0xff00_0011;

// ALPN for raw QUIC connections. Final RFC will use "moqt".
pub const ALPN: []const u8 = "moqt-17";
