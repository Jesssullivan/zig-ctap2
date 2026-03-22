/// macOS USB HID transport via IOKit.
///
/// Enumerates FIDO2 devices (USB HID usage page 0xF1D0), opens them,
/// and provides read/write for 64-byte CTAPHID packets.

const std = @import("std");
const c = @cImport({
    @cInclude("IOKit/hid/IOHIDManager.h");
    @cInclude("CoreFoundation/CoreFoundation.h");
});

pub const Error = error{
    NoDeviceFound,
    OpenFailed,
    WriteFailed,
    ReadFailed,
    Timeout,
};

/// FIDO HID usage page per spec.
const FIDO_USAGE_PAGE: u32 = 0xF1D0;
const FIDO_USAGE: u32 = 0x01;

/// A handle to an open FIDO2 HID device.
pub const Device = struct {
    ref: c.IOHIDDeviceRef,
    report_buf: [64]u8 = std.mem.zeroes([64]u8),
    report_ready: bool = false,

    /// Last IOReturn error code for debugging.
    pub var last_ioreturn: c_int = 0;

    /// Write a 64-byte packet to the device.
    pub fn write(self: *Device, packet: *const [64]u8) Error!void {
        const ptr: [*c]const u8 = @ptrCast(packet);
        const result = c.IOHIDDeviceSetReport(
            self.ref,
            c.kIOHIDReportTypeOutput,
            0, // report ID
            ptr,
            @as(c.CFIndex, 64),
        );
        last_ioreturn = @intCast(result);
        if (result != c.kIOReturnSuccess) return Error.WriteFailed;
    }

    /// Read a 64-byte packet from the device with timeout.
    pub fn read(self: *Device, timeout_ms: u32) Error![64]u8 {
        self.report_ready = false;

        // Create a unique run loop mode for this read
        const mode = c.CFStringCreateWithCString(
            null,
            "com.zigctap2.hid.read",
            c.kCFStringEncodingUTF8,
        );
        defer c.CFRelease(mode);

        // Register input report callback
        c.IOHIDDeviceRegisterInputReportCallback(
            self.ref,
            &self.report_buf,
            64,
            &reportCallback,
            @ptrCast(self),
        );

        // Schedule with run loop
        c.IOHIDDeviceScheduleWithRunLoop(
            self.ref,
            c.CFRunLoopGetCurrent(),
            mode,
        );

        // Run until we get data or timeout
        const timeout_sec: f64 = @as(f64, @floatFromInt(timeout_ms)) / 1000.0;
        const run_result = c.CFRunLoopRunInMode(mode, timeout_sec, @intFromBool(true));

        // Unschedule
        c.IOHIDDeviceUnscheduleFromRunLoop(
            self.ref,
            c.CFRunLoopGetCurrent(),
            mode,
        );

        if (run_result == c.kCFRunLoopRunTimedOut or !self.report_ready) {
            return Error.Timeout;
        }

        return self.report_buf;
    }

    /// Close the device.
    pub fn close(self: *Device) void {
        _ = c.IOHIDDeviceClose(self.ref, c.kIOHIDOptionsTypeNone);
    }
};

/// IOKit input report callback — fires when device sends data.
fn reportCallback(
    context: ?*anyopaque,
    _: c.IOReturn,
    _: ?*anyopaque,
    _: c.IOHIDReportType,
    _: u32,
    _: [*c]u8,
    _: c.CFIndex,
) callconv(.c) void {
    if (context) |ctx| {
        const dev: *Device = @ptrCast(@alignCast(ctx));
        dev.report_ready = true;
        // Stop the run loop so read() returns
        c.CFRunLoopStop(c.CFRunLoopGetCurrent());
    }
}

/// Enumerate connected FIDO2 USB HID devices.
/// Returns device refs that must be closed by the caller.
pub fn enumerate(allocator: std.mem.Allocator) ![]Device {
    const manager = c.IOHIDManagerCreate(c.kCFAllocatorDefault, c.kIOHIDManagerOptionNone);
    if (manager == null) return Error.NoDeviceFound;
    defer c.CFRelease(manager);

    // Match FIDO HID devices (usage page 0xF1D0)
    const usage_page_key = c.CFStringCreateWithCString(null, c.kIOHIDDeviceUsagePageKey, c.kCFStringEncodingUTF8);
    defer c.CFRelease(usage_page_key);
    const usage_key = c.CFStringCreateWithCString(null, c.kIOHIDDeviceUsageKey, c.kCFStringEncodingUTF8);
    defer c.CFRelease(usage_key);
    const usage_page_val = c.CFNumberCreate(null, c.kCFNumberSInt32Type, &@as(i32, @intCast(FIDO_USAGE_PAGE)));
    defer c.CFRelease(usage_page_val);
    const usage_val = c.CFNumberCreate(null, c.kCFNumberSInt32Type, &@as(i32, @intCast(FIDO_USAGE)));
    defer c.CFRelease(usage_val);

    var keys = [_]?*const anyopaque{ usage_page_key, usage_key };
    var values = [_]?*const anyopaque{ usage_page_val, usage_val };
    const matching = c.CFDictionaryCreate(
        null,
        @ptrCast(&keys),
        @ptrCast(&values),
        2,
        &c.kCFTypeDictionaryKeyCallBacks,
        &c.kCFTypeDictionaryValueCallBacks,
    );
    defer c.CFRelease(matching);

    c.IOHIDManagerSetDeviceMatching(manager, matching);
    _ = c.IOHIDManagerOpen(manager, c.kIOHIDManagerOptionNone);

    const device_set = c.IOHIDManagerCopyDevices(manager);
    if (device_set == null) return &[0]Device{};
    defer c.CFRelease(device_set);

    const count: usize = @intCast(c.CFSetGetCount(device_set));
    if (count == 0) return &[0]Device{};

    // Get device refs from CFSet
    const raw_ptrs = try allocator.alloc(?*const anyopaque, count);
    defer allocator.free(raw_ptrs);
    c.CFSetGetValues(device_set, raw_ptrs.ptr);

    var devices = try allocator.alloc(Device, count);
    var valid: usize = 0;

    for (raw_ptrs) |ptr| {
        if (ptr) |p| {
            const dev_ref: c.IOHIDDeviceRef = @constCast(@ptrCast(@alignCast(p)));

            // Try to open the device
            if (c.IOHIDDeviceOpen(dev_ref, c.kIOHIDOptionsTypeNone) == c.kIOReturnSuccess) {
                devices[valid] = .{ .ref = dev_ref };
                valid += 1;
            }
        }
    }

    return devices[0..valid];
}

/// Find and open the first available FIDO2 device.
pub fn openFirst(allocator: std.mem.Allocator) !Device {
    const devices = try enumerate(allocator);
    if (devices.len == 0) return Error.NoDeviceFound;

    // Return first, close the rest
    const first = devices[0];
    for (devices[1..]) |*dev| {
        dev.close();
    }
    allocator.free(devices);
    return first;
}
