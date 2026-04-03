/// Linux USB HID transport via hidraw.
///
/// Enumerates FIDO2 devices by scanning /dev/hidraw* and checking
/// sysfs for the FIDO usage page (0xF1D0). Provides read/write
/// for 64-byte CTAPHID packets.

const std = @import("std");
const posix = std.posix;

pub const Error = error{
    NoDeviceFound,
    DevicesNotAccessible,
    OpenFailed,
    WriteFailed,
    ReadFailed,
    Timeout,
};

/// FIDO HID usage page.
const FIDO_USAGE_PAGE: u16 = 0xF1D0;

/// A handle to an open FIDO2 HID device.
pub const Device = struct {
    fd: posix.fd_t,
    path: [64]u8 = std.mem.zeroes([64]u8),

    /// Write a 64-byte packet to the device.
    pub fn write(self: *Device, packet: *const [64]u8) Error!void {
        const written = posix.write(self.fd, packet) catch return Error.WriteFailed;
        if (written != 64) return Error.WriteFailed;
    }

    /// Read a 64-byte packet from the device with timeout.
    pub fn read(self: *Device, timeout_ms: u32) Error![64]u8 {
        // Use poll for timeout
        var fds = [1]posix.pollfd{.{
            .fd = self.fd,
            .events = posix.POLL.IN,
            .revents = 0,
        }};

        const poll_result = posix.poll(&fds, @intCast(timeout_ms)) catch return Error.ReadFailed;
        if (poll_result == 0) return Error.Timeout;
        if (fds[0].revents & posix.POLL.IN == 0) return Error.ReadFailed;

        var buf: [64]u8 = std.mem.zeroes([64]u8);
        const bytes_read = posix.read(self.fd, &buf) catch return Error.ReadFailed;
        if (bytes_read == 0) return Error.ReadFailed;

        return buf;
    }

    /// Close the device.
    pub fn close(self: *Device) void {
        posix.close(self.fd);
    }
};

/// Check if a hidraw device is a FIDO2 device by reading sysfs.
fn isFidoDevice(path: []const u8) bool {
    // Path: /dev/hidrawN → sysfs: /sys/class/hidraw/hidrawN/device/report_descriptor
    // We need to parse the HID report descriptor to find usage page 0xF1D0
    //
    // Simpler approach: check the uevent file for HID_UNIQ or look at
    // /sys/class/hidraw/hidrawN/device/uevent for vendor/product

    // Extract hidrawN from path
    const basename_start = std.mem.lastIndexOf(u8, path, "/") orelse return false;
    const basename = path[basename_start + 1 ..];

    var sysfs_path_buf: [256]u8 = undefined;
    const sysfs_path = std.fmt.bufPrint(&sysfs_path_buf, "/sys/class/hidraw/{s}/device/report_descriptor", .{basename}) catch return false;

    // Read the raw HID report descriptor
    const file = std.fs.openFileAbsolute(sysfs_path, .{}) catch return false;
    defer file.close();

    var desc_buf: [4096]u8 = undefined;
    const desc_len = file.readAll(&desc_buf) catch return false;
    const desc = desc_buf[0..desc_len];

    // Parse HID descriptor looking for usage page 0xF1D0
    // Format: 0x06 <page_lo> <page_hi> for 2-byte usage page
    var i: usize = 0;
    while (i < desc.len) {
        const item = desc[i];
        const item_size = item & 0x03;
        const item_type = (item >> 2) & 0x03;
        const item_tag = (item >> 4) & 0x0F;

        // Per HID spec: size field 3 means 4 data bytes
        const data_bytes: usize = if (item_size == 3) 4 else item_size;

        // Bounds check: ensure data bytes are within descriptor
        if (i + 1 + data_bytes > desc.len) break;

        if (item_type == 1 and item_tag == 0 and item_size == 2) {
            // Usage Page (2 bytes)
            const page = @as(u16, desc[i + 1]) | (@as(u16, desc[i + 2]) << 8);
            if (page == FIDO_USAGE_PAGE) return true;
        }

        // Advance past this item
        i += 1 + data_bytes;
    }

    return false;
}

/// Enumerate connected FIDO2 USB HID devices.
/// Scans /sys/class/hidraw/ to discover all hidraw devices (not limited
/// to a fixed range). Returns DevicesNotAccessible if FIDO devices are
/// found but none could be opened (likely a permissions issue).
pub fn enumerate(allocator: std.mem.Allocator) ![]Device {
    var devices: std.ArrayList(Device) = .empty;
    errdefer {
        for (devices.items) |*dev| dev.close();
        devices.deinit(allocator);
    }

    // Scan /sys/class/hidraw/ for actual device entries
    var fido_found: usize = 0;
    var open_failed: usize = 0;
    const sysfs_dir = std.fs.openDirAbsolute("/sys/class/hidraw", .{ .iterate = true }) catch {
        // Fallback: scan /dev/hidraw0..255 if sysfs is unavailable
        return enumerateFallback(allocator);
    };
    // sysfs_dir is const, close via a mutable copy after iteration
    var dir = sysfs_dir;
    defer dir.close();
    var iter = dir.iterate();

    while (iter.next() catch null) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "hidraw")) continue;

        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/dev/{s}", .{entry.name}) catch continue;

        if (!isFidoDevice(path)) continue;
        fido_found += 1;

        const fd = posix.open(path, .{ .ACCMODE = .RDWR }, 0) catch {
            open_failed += 1;
            continue;
        };

        var dev = Device{ .fd = fd };
        @memcpy(dev.path[0..path.len], path);
        try devices.append(allocator, dev);
    }

    // Distinguish "no FIDO devices" from "found but can't open" (permissions)
    if (devices.items.len == 0 and fido_found > 0 and open_failed == fido_found) {
        return Error.DevicesNotAccessible;
    }

    return try devices.toOwnedSlice(allocator);
}

/// Fallback enumeration when /sys/class/hidraw is not available.
/// Scans /dev/hidraw0 through /dev/hidraw255.
fn enumerateFallback(allocator: std.mem.Allocator) ![]Device {
    var devices: std.ArrayList(Device) = .empty;
    errdefer {
        for (devices.items) |*dev| dev.close();
        devices.deinit(allocator);
    }

    var idx: u16 = 0;
    while (idx < 256) : (idx += 1) {
        var path_buf: [32]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/dev/hidraw{d}", .{idx}) catch continue;

        if (!isFidoDevice(path)) continue;

        const fd = posix.open(path, .{ .ACCMODE = .RDWR }, 0) catch continue;

        var dev = Device{ .fd = fd };
        @memcpy(dev.path[0..path.len], path);
        try devices.append(allocator, dev);
    }

    return try devices.toOwnedSlice(allocator);
}

/// Find and open the first available FIDO2 device.
pub fn openFirst(allocator: std.mem.Allocator) !Device {
    const devices = try enumerate(allocator);
    if (devices.len == 0) return Error.NoDeviceFound;

    const first = devices[0];
    for (devices[1..]) |*dev| {
        dev.close();
    }
    allocator.free(devices);
    return first;
}
