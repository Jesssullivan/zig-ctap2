/// Platform-selected USB HID transport for FIDO2 devices.
///
/// Comptime selects between IOKit (macOS) and hidraw (Linux).
/// Both implementations export the same interface:
///   Device, enumerate(), openFirst()
const std = @import("std");
const builtin = @import("builtin");

pub const platform = if (builtin.os.tag == .macos)
    @import("hid_macos.zig")
else if (builtin.os.tag == .linux)
    @import("hid_linux.zig")
else
    @compileError("Unsupported platform for USB HID FIDO2. Supported: macOS, Linux.");

pub const Device = platform.Device;
pub const Error = platform.Error;
pub const enumerate = platform.enumerate;
pub const openFirst = platform.openFirst;
