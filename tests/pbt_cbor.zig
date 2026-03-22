/// Property-based tests for CBOR encoder/decoder roundtrips.
///
/// Uses a fixed PRNG seed for reproducibility. Each property runs 1000 iterations
/// with randomly generated inputs to verify encode/decode invariants.

const std = @import("std");
const cbor = @import("cbor");

const ITERATIONS: usize = 1000;
const SEED: u64 = 0xDEAD_BEEF_CAFE_F00D;

// ─── Helpers ────────────────────────────────────────────────

fn makeRng(seed: u64) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(seed);
}

/// Generate a random u64 with bias toward interesting boundary values.
fn randomUint(rng: *std.Random.DefaultPrng) u64 {
    const r = rng.random();
    // 20% chance of a boundary value
    if (r.intRangeAtMost(u8, 0, 4) == 0) {
        const boundaries = [_]u64{
            0, 1, 23, 24, 255, 256, 65535, 65536,
            0xFFFFFFFF, 0x100000000, std.math.maxInt(u64),
        };
        return boundaries[r.intRangeAtMost(usize, 0, boundaries.len - 1)];
    }
    return r.int(u64);
}

/// Fill a buffer with random bytes and return a slice of random length up to `max_len`.
fn randomBytes(rng: *std.Random.DefaultPrng, buf: []u8, max_len: usize) []u8 {
    const r = rng.random();
    const len = r.intRangeAtMost(usize, 0, max_len);
    const slice = buf[0..len];
    r.bytes(slice);
    return slice;
}

/// Generate a random text string (printable ASCII for simplicity).
fn randomText(rng: *std.Random.DefaultPrng, buf: []u8, max_len: usize) []u8 {
    const r = rng.random();
    const len = r.intRangeAtMost(usize, 0, max_len);
    for (buf[0..len]) |*b| {
        b.* = r.intRangeAtMost(u8, 0x20, 0x7E); // printable ASCII
    }
    return buf[0..len];
}

// ─── Property: unsigned integer roundtrip ───────────────────

test "property: uint encode/decode roundtrip" {
    var rng = makeRng(SEED);
    var enc_buf: [16]u8 = undefined;

    for (0..ITERATIONS) |_| {
        const val = randomUint(&rng);

        var enc = cbor.Encoder.init(&enc_buf);
        try enc.encodeUint(val);

        var dec = cbor.Decoder.init(enc.written());
        const decoded = try dec.decodeUint();

        try std.testing.expectEqual(val, decoded);
        // All bytes consumed
        try std.testing.expectEqual(@as(usize, 0), dec.remaining());
    }
}

// ─── Property: byte string roundtrip ────────────────────────

test "property: byte string encode/decode roundtrip" {
    var rng = makeRng(SEED +% 1);
    var data_buf: [1024]u8 = undefined;
    var enc_buf: [1024 + 16]u8 = undefined;

    for (0..ITERATIONS) |_| {
        const data = randomBytes(&rng, &data_buf, 1024);

        var enc = cbor.Encoder.init(&enc_buf);
        try enc.encodeByteString(data);

        var dec = cbor.Decoder.init(enc.written());
        const decoded = try dec.decodeByteString();

        try std.testing.expectEqualSlices(u8, data, decoded);
        try std.testing.expectEqual(@as(usize, 0), dec.remaining());
    }
}

// ─── Property: text string roundtrip ────────────────────────

test "property: text string encode/decode roundtrip" {
    var rng = makeRng(SEED +% 2);
    var text_buf: [512]u8 = undefined;
    var enc_buf: [512 + 16]u8 = undefined;

    for (0..ITERATIONS) |_| {
        const text = randomText(&rng, &text_buf, 512);

        var enc = cbor.Encoder.init(&enc_buf);
        try enc.encodeTextString(text);

        var dec = cbor.Decoder.init(enc.written());
        const decoded = try dec.decodeTextString();

        try std.testing.expectEqualSlices(u8, text, decoded);
        try std.testing.expectEqual(@as(usize, 0), dec.remaining());
    }
}

// ─── Property: nested map encode then skip ──────────────────

test "property: nested map encode/skip roundtrip" {
    var rng = makeRng(SEED +% 3);
    var enc_buf: [4096]u8 = undefined;
    var val_buf: [256]u8 = undefined;

    for (0..ITERATIONS) |_| {
        const r = rng.random();
        const entry_count = r.intRangeAtMost(usize, 1, 5);

        var enc = cbor.Encoder.init(&enc_buf);
        try enc.beginMap(entry_count);

        // Write entries with integer keys and random value types
        for (0..entry_count) |i| {
            try enc.encodeUint(@intCast(i + 1));

            const val_type = r.intRangeAtMost(u8, 0, 3);
            switch (val_type) {
                0 => try enc.encodeUint(randomUint(&rng)),
                1 => {
                    const data = randomBytes(&rng, &val_buf, 64);
                    try enc.encodeByteString(data);
                },
                2 => {
                    const text = randomText(&rng, &val_buf, 64);
                    try enc.encodeTextString(text);
                },
                3 => try enc.encodeBool(r.boolean()),
                else => unreachable,
            }
        }

        // Append a sentinel after the map
        try enc.encodeUint(0xCAFE);

        // Decode: read map header, skip all entries, then read sentinel
        var dec = cbor.Decoder.init(enc.written());
        const map_len = try dec.decodeMapHeader();
        try std.testing.expectEqual(entry_count, map_len);

        for (0..entry_count) |_| {
            try dec.skipValue(); // key
            try dec.skipValue(); // value
        }

        // Sentinel must be reachable after skipping
        const sentinel = try dec.decodeUint();
        try std.testing.expectEqual(@as(u64, 0xCAFE), sentinel);
        try std.testing.expectEqual(@as(usize, 0), dec.remaining());
    }
}

// ─── Property: arbitrary value encode/decode identity ───────

test "property: encode then decode produces original value" {
    var rng = makeRng(SEED +% 4);
    var enc_buf: [2048]u8 = undefined;
    var val_buf: [256]u8 = undefined;

    for (0..ITERATIONS) |_| {
        const r = rng.random();
        const val_type = r.intRangeAtMost(u8, 0, 4);

        var enc = cbor.Encoder.init(&enc_buf);

        switch (val_type) {
            0 => {
                // Unsigned integer
                const val = randomUint(&rng);
                try enc.encodeUint(val);
                var dec = cbor.Decoder.init(enc.written());
                try std.testing.expectEqual(val, try dec.decodeUint());
            },
            1 => {
                // Byte string
                const data = randomBytes(&rng, &val_buf, 256);
                try enc.encodeByteString(data);
                var dec = cbor.Decoder.init(enc.written());
                try std.testing.expectEqualSlices(u8, data, try dec.decodeByteString());
            },
            2 => {
                // Text string
                const text = randomText(&rng, &val_buf, 256);
                try enc.encodeTextString(text);
                var dec = cbor.Decoder.init(enc.written());
                try std.testing.expectEqualSlices(u8, text, try dec.decodeTextString());
            },
            3 => {
                // Boolean
                const val = r.boolean();
                try enc.encodeBool(val);
                // Decode manually: true=0xF5, false=0xF4
                const encoded = enc.written();
                try std.testing.expectEqual(@as(usize, 1), encoded.len);
                const expected: u8 = if (val) 0xF5 else 0xF4;
                try std.testing.expectEqual(expected, encoded[0]);
            },
            4 => {
                // Null
                try enc.encodeNull();
                const encoded = enc.written();
                try std.testing.expectEqual(@as(usize, 1), encoded.len);
                try std.testing.expectEqual(@as(u8, 0xF6), encoded[0]);
            },
            else => unreachable,
        }
    }
}
