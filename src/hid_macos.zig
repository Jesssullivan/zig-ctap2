/// macOS USB HID transport via IOKit.
///
/// Enumerates FIDO2 devices (USB HID usage page 0xF1D0), opens them,
/// and provides read/write for 64-byte CTAPHID packets.
///
/// IMPORTANT: The IOHIDManagerRef must stay alive for the lifetime of
/// any IOHIDDeviceRef obtained from it. Each Device retains both.

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

const FIDO_USAGE_PAGE: u32 = 0xF1D0;
const FIDO_USAGE: u32 = 0x01;

/// A handle to an open FIDO2 HID device.
/// Owns both the device ref and the manager that created it.
pub const Device = struct {
    ref: c.IOHIDDeviceRef,
    manager: c.IOHIDManagerRef,
    report_buf: [64]u8 = std.mem.zeroes([64]u8),
    report_ready: bool = false,

    pub var last_ioreturn: c_int = 0;

    pub fn write(self: *Device, packet: *const [64]u8) Error!void {
        if (self.ref == null) return Error.WriteFailed;
        const ptr: [*c]const u8 = @ptrCast(packet);
        const result = c.IOHIDDeviceSetReport(
            self.ref,
            1, // kIOHIDReportTypeOutput
            0,
            ptr,
            @as(c.CFIndex, 64),
        );
        last_ioreturn = @intCast(result);
        if (result != 0) return Error.WriteFailed;
    }

    pub fn read(self: *Device, timeout_ms: u32) Error![64]u8 {
        if (self.ref == null) return Error.ReadFailed;
        self.report_ready = false;

        const mode = c.CFStringCreateWithCString(null, "com.zigctap2.hid.read", c.kCFStringEncodingUTF8);
        defer c.CFRelease(mode);

        c.IOHIDDeviceRegisterInputReportCallback(self.ref, &self.report_buf, 64, &reportCallback, @ptrCast(self));
        c.IOHIDDeviceScheduleWithRunLoop(self.ref, c.CFRunLoopGetCurrent(), mode);

        const timeout_sec: f64 = @as(f64, @floatFromInt(timeout_ms)) / 1000.0;
        const run_result = c.CFRunLoopRunInMode(mode, timeout_sec, @intFromBool(true));

        c.IOHIDDeviceUnscheduleFromRunLoop(self.ref, c.CFRunLoopGetCurrent(), mode);

        if (run_result == c.kCFRunLoopRunTimedOut or !self.report_ready) {
            return Error.Timeout;
        }
        return self.report_buf;
    }

    pub fn close(self: *Device) void {
        if (self.ref != null) {
            _ = c.IOHIDDeviceClose(self.ref, 0);
            c.CFRelease(@ptrCast(self.ref));
            self.ref = null;
        }
        if (self.manager != null) {
            _ = c.IOHIDManagerClose(self.manager, 0);
            c.CFRelease(self.manager);
            self.manager = null;
        }
    }
};

fn reportCallback(
    context: ?*anyopaque, _: c.IOReturn, _: ?*anyopaque,
    _: c.IOHIDReportType, _: u32, _: [*c]u8, _: c.CFIndex,
) callconv(.c) void {
    if (context) |ctx| {
        const dev: *Device = @ptrCast(@alignCast(ctx));
        dev.report_ready = true;
        c.CFRunLoopStop(c.CFRunLoopGetCurrent());
    }
}

pub fn enumerate(allocator: std.mem.Allocator) ![]Device {
    const manager = c.IOHIDManagerCreate(c.kCFAllocatorDefault, 0);
    if (manager == null) return Error.NoDeviceFound;

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
    const matching = c.CFDictionaryCreate(null, @ptrCast(&keys), @ptrCast(&values), 2,
        &c.kCFTypeDictionaryKeyCallBacks, &c.kCFTypeDictionaryValueCallBacks);
    defer c.CFRelease(matching);

    c.IOHIDManagerSetDeviceMatching(manager, matching);
    _ = c.IOHIDManagerOpen(manager, 0);

    const device_set = c.IOHIDManagerCopyDevices(manager);
    if (device_set == null) { c.CFRelease(manager); return &[0]Device{}; }
    defer c.CFRelease(device_set);

    const count: usize = @intCast(c.CFSetGetCount(device_set));
    if (count == 0) { c.CFRelease(manager); return &[0]Device{}; }

    const raw_ptrs = try allocator.alloc(?*const anyopaque, count);
    defer allocator.free(raw_ptrs);
    c.CFSetGetValues(device_set, raw_ptrs.ptr);

    var devices = try allocator.alloc(Device, count);
    var valid: usize = 0;

    for (raw_ptrs) |ptr| {
        if (ptr) |p| {
            const dev_ref: c.IOHIDDeviceRef = @constCast(@ptrCast(@alignCast(p)));
            if (c.IOHIDDeviceOpen(dev_ref, 0) == 0) {
                c.CFRetain(@ptrCast(dev_ref));
                devices[valid] = .{ .ref = dev_ref, .manager = manager };
                valid += 1;
            }
        }
    }

    if (valid == 0) {
        c.CFRelease(manager);
        allocator.free(devices);
        return &[0]Device{};
    }

    return devices[0..valid];
}

pub fn openFirst(allocator: std.mem.Allocator) !Device {
    const devices = try enumerate(allocator);
    if (devices.len == 0) return Error.NoDeviceFound;
    const first = devices[0];
    for (devices[1..]) |*dev| { dev.close(); }
    allocator.free(devices);
    return first;
}
