/// Platform-selected USB HID transport.
const std = @import("std");
const builtin = @import("builtin");

pub const impl = if (builtin.os.tag == .macos)
    @import("hid_macos.zig")
else if (builtin.os.tag == .linux)
    @import("hid_linux.zig")
else
    @compileError("Unsupported platform for USB HID FIDO2");
