//! Public Zig package API for zig-ctap2.
//!
//! C ABI consumers should include `include/ctap2.h` and link `libctap2.a`.
//! Zig package consumers import this module and use the protocol, framing,
//! CBOR, PIN, and HID modules directly.

pub const cbor = @import("cbor.zig");
pub const ctap2 = @import("ctap2.zig");
pub const ctaphid = @import("ctaphid.zig");
pub const hid = @import("hid.zig");
pub const pin = @import("pin.zig");

pub const statusMessage = ctap2.statusMessage;

test {
    _ = cbor;
    _ = ctap2;
    _ = ctaphid;
    _ = hid;
    _ = pin;
    _ = statusMessage;
}
