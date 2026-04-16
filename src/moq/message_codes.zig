// Numeric constants for MoQ Transport draft-17.
// Single source of truth — ranges/tables cross-referenced in
// SPEC/DRAFT_IETF_MOQ_TRANSPORT_17.md.

// Control message types (draft-17 §9 Table 4).
pub const MSG_SETUP: u64 = 0x2F00;
pub const MSG_GOAWAY: u64 = 0x10;
pub const MSG_REQUEST_OK: u64 = 0x07;
pub const MSG_REQUEST_ERROR: u64 = 0x05;
pub const MSG_SUBSCRIBE: u64 = 0x03;
pub const MSG_SUBSCRIBE_OK: u64 = 0x04;
pub const MSG_REQUEST_UPDATE: u64 = 0x02;
pub const MSG_PUBLISH: u64 = 0x1D;
pub const MSG_PUBLISH_OK: u64 = 0x1E;
pub const MSG_PUBLISH_DONE: u64 = 0x0B;
pub const MSG_FETCH: u64 = 0x16;
pub const MSG_FETCH_OK: u64 = 0x18;
pub const MSG_TRACK_STATUS: u64 = 0x0D;
pub const MSG_PUBLISH_NAMESPACE: u64 = 0x06;
pub const MSG_NAMESPACE: u64 = 0x08;
pub const MSG_NAMESPACE_DONE: u64 = 0x0E;
pub const MSG_SUBSCRIBE_NAMESPACE: u64 = 0x11;
pub const MSG_PUBLISH_BLOCKED: u64 = 0x0F;

pub fn isReservedLegacyMessageType(t: u64) bool {
    return switch (t) {
        0x01, 0x20, 0x21, 0x40, 0x41 => true,
        else => false,
    };
}

// SETUP options (§9.4.1). Option keys obey the even/odd encoding rule
// of §1.4.3: even key → varint value, odd key → length-prefixed bytes.
pub const OPT_PATH: u64 = 0x01;
pub const OPT_AUTHORIZATION_TOKEN: u64 = 0x03;
pub const OPT_MAX_AUTH_TOKEN_CACHE_SIZE: u64 = 0x04;
pub const OPT_AUTHORITY: u64 = 0x05;
pub const OPT_MOQT_IMPLEMENTATION: u64 = 0x07;

// Data-stream type code for a FETCH stream (§10.4.4).
pub const STREAM_FETCH: u64 = 0x05;

// Subgroup stream type bit-field (§10.4.2). Bit 4 (0x10) is the
// selector; valid codes are 0x10..0x15, 0x18..0x1D, 0x30..0x35, 0x38..0x3D.
pub const SUBGROUP_BIT_PROPERTIES: u64 = 0x01;
pub const SUBGROUP_MASK_ID_MODE: u64 = 0x06;
pub const SUBGROUP_BIT_END_OF_GROUP: u64 = 0x08;
pub const SUBGROUP_BIT_SELECTOR: u64 = 0x10;
pub const SUBGROUP_BIT_DEFAULT_PRIORITY: u64 = 0x20;

pub const SubgroupIdMode = enum(u2) {
    zero = 0b00, // Subgroup ID is 0; absent from header.
    first_object = 0b01, // Subgroup ID equals first Object ID; absent.
    explicit = 0b10, // Subgroup ID carried explicitly in header.
    reserved = 0b11, // Receipt is a PROTOCOL_VIOLATION.
};

pub fn isSubgroupStreamType(t: u64) bool {
    // Must have selector bit set.
    if ((t & SUBGROUP_BIT_SELECTOR) == 0) return false;
    // Reserved-id-mode must not be present.
    const mode: u2 = @truncate((t & SUBGROUP_MASK_ID_MODE) >> 1);
    if (mode == @intFromEnum(SubgroupIdMode.reserved)) return false;
    // High bits above those we know (0-5) must be zero for the range we accept.
    return (t & ~@as(u64, 0x3F)) == 0;
}

// Datagram object type bit-field (§10.3.1). Valid codes 0x00..0x0F, 0x20..0x2F.
pub const DGRAM_BIT_PROPERTIES: u64 = 0x01;
pub const DGRAM_BIT_END_OF_GROUP: u64 = 0x02;
pub const DGRAM_BIT_ZERO_OBJECT_ID: u64 = 0x04;
pub const DGRAM_BIT_DEFAULT_PRIORITY: u64 = 0x08;
pub const DGRAM_BIT_STATUS: u64 = 0x20;

pub fn isDatagramObjectType(t: u64) bool {
    // Bit 4 (0x10) must be clear (it would select a subgroup stream).
    if ((t & 0x10) != 0) return false;
    // STATUS + END_OF_GROUP combined is disallowed.
    if ((t & (DGRAM_BIT_STATUS | DGRAM_BIT_END_OF_GROUP)) ==
        (DGRAM_BIT_STATUS | DGRAM_BIT_END_OF_GROUP)) return false;
    // High bits above those we know must be zero.
    return (t & ~@as(u64, 0x2F)) == 0;
}

// Error codes (draft-17 §11).
pub const ERR_NO_ERROR: u64 = 0x00;
pub const ERR_INTERNAL_ERROR: u64 = 0x01;
pub const ERR_UNAUTHORIZED: u64 = 0x02;
pub const ERR_PROTOCOL_VIOLATION: u64 = 0x03;
pub const ERR_KEY_VALUE_FORMATTING_ERROR: u64 = 0x04;
pub const ERR_VERSION_NEGOTIATION_FAILED: u64 = 0x05;
pub const ERR_DUPLICATE_TRACK_ALIAS: u64 = 0x06;
pub const ERR_PARAMETER_LENGTH_MISMATCH: u64 = 0x07;
pub const ERR_TOO_MANY_REQUESTS: u64 = 0x08;
pub const ERR_INVALID_REQUEST_ID: u64 = 0x09;
pub const ERR_MALFORMED_TRACK: u64 = 0x0A;
pub const ERR_TOO_MANY_SUBSCRIBES: u64 = 0x0B;
