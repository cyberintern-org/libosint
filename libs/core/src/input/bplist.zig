// libosint - Library for the Cyberintern OSINT project
// Copyright (C) 2025 Wojciech Mączka - Cyberintern
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
// USA

//! Parsing of binary property lists as specified by Apple.
const std = @import("std");

// PLIST DEFINITION

/// Struct representing a parsed binary plist
pub const Plist = struct {
    /// Allocator used to allocate the offset and object table arrays
    allocator: std.mem.Allocator,

    /// Array storing the parsed objects,
    /// each object is optional, as it can be null in the original plist
    objects: std.ArrayList(?NsObject),

    /// Copied data of the plist
    string_bytes: std.ArrayList(u8),

    /// Deinitialize the plist, freeing the objects and string bytes arrays
    pub fn deinit(self: *Plist) void {
        self.objects.deinit();
        self.string_bytes.deinit();
    }
};

/// Tagged union representing the different types of objects in a plist
pub const NsObject = union(enum) {
    ns_number_b: bool,
    ns_number_i: i64,
    ns_number_r: f64,
    ns_date: f64,
    ns_data: []const u8,
};

/// UNIX timestamp of 2001-01-01 00:00:00 UTC, the Core Data epoch
pub const cf_epoch = 978307200.0;

// PLIST PARSING

/// Internal struct storing the intermediate state of the parsing process
const Parser = struct {
    allocator: std.mem.Allocator,

    data: []const u8,
    offset_table: []const u64,
    object_table: std.ArrayList(?NsObject),
    string_bytes: std.ArrayList(u8),

    ref_size: u8,
};

/// Parse a binary plist from the given data
///
/// For format specification see:
/// [opensource-apple/CF](https://github.com/opensource-apple/CF/blob/master/CFBinaryPList.c)
pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Plist {
    var parser = Parser{
        .allocator = allocator,
        .data = try parseHeader(data),
    };

    const trailer = try parseTrailer(parser.data);

    parser.offset_table = allocator.alloc(u64, trailer.num_objects); // length controled by the number of objects defined in the trailer
    parser.object_table = std.ArrayList(?NsObject).initCapacity(allocator, trailer.num_objects); // same as above
    parser.string_bytes = std.ArrayList(u8).initCapacity(allocator, parser.data.len); // at most the same size as the input data
    parser.ref_size = trailer.ref_size;

    defer allocator.free(parser.offset_table);
    errdefer parser.object_table.deinit();
    errdefer parser.string_bytes.deinit();

    for (0..trailer.num_objects) |i| {
        const offset = trailer.offset_table_offset + i * trailer.offset_size;
        parser.offset_table[i] = try parseUInt(parser.data[offset .. offset + trailer.offset_size]);
    }

    return Plist{
        .allocator = allocator,
        .objects = parser.object_table,
        .string_bytes = parser.string_bytes,
    };
}

fn parseHeader(data: []const u8) ![]const u8 {
    var offset = 0;

    // Skip the BOM if present
    if (data.len > 3 and data[0] == 0xEF and data[1] == 0xBB and data[2] == 0xBF) {
        offset = 3;
    }

    // Skip whitespace
    while (offset < data.len and (data[offset] == ' ' or data[offset] == '\n' or data[offset] == '\r' or data[offset] == '\t')) : (offset += 1) {}

    // Check for the bplist header
    if (data.len - offset < 8 or !std.mem.eql(u8, data[offset .. offset + 6], "bplist")) {
        return error.PlistMalformed;
    }

    // Take only the valid bplist
    return data[offset..];
}

fn parseTrailer(data: []const u8) !struct { offset_size: u8, ref_size: u8, num_objects: u64, top_object_id: u64, offset_table_offset: u64 } {
    if (data.len < 32) {
        return error.PlistMalformed;
    }

    // Final 32 bytes of the bplist form the trailer
    const trailer = data[(data.len - 32)..];

    return .{
        // 6 null bytes
        .offset_size = trailer[6],
        .ref_size = trailer[7],
        .num_objects = try parseUInt(trailer[8..16]),
        .top_object_id = try parseUInt(trailer[16..24]),
        .offset_table_offset = try parseUInt(trailer[24..32]),
    };
}

fn parseObject(p: *Parser, object_id: u64) !?NsObject {
    const offset = p.offset_table[object_id];
    const type_byte = parseTypeByte(p.data[offset]);

    return switch (type_byte.obj_type) {
        0x0 => switch (type_byte.obj_info) {
            0x0 => null, // [0000][0000] | null object
            0x8 => NsObject{ .ns_number_b = false }, // [0000][1000] | NSNumber type bool = false
            0x9 => NsObject{ .ns_number_b = true }, // [0000][1001] | NSNumber type bool = true

            0xC => null, // TODO: URL with no base URL
            0xD => null, // TODO: URL with base URL
            0xE => null, // TODO: 16-bit UUID

            0xF => null, // [0000][1111] | fill byte
            else => error.PlistMalformed,
        },
        0x1 => { // [0001][0nnn] ... | NSNumber type integer of 2^nnn big-endian bytes,
            const len = parseLen(type_byte.obj_info);

            std.debug.assert(p.data.len >= offset + 1 + len);

            const data = p.data[(offset + 1)..(offset + 1 + len)];
            return NsObject{ .ns_number_i = try parseInt(data) };
        },
        0x2 => { // [0010][0nnn] ... | NSNumber type real of 2^nnn big-endian bytes,
            const len = parseLen(type_byte.obj_info);

            std.debug.assert(p.data.len >= offset + 1 + len);

            const data = p.data[(offset + 1)..(offset + 1 + len)];
            return NsObject{ .ns_number_i = try parseFloat(data) };
        },
        0x3 => { // [0011][0011] ... | NSDate object, 8 bytes of big-endian float
            if (type_byte.obj_info != 0x3) {
                return error.PlistMalformed;
            }

            std.debug.assert(p.data.len >= offset + 1 + 8);

            const data = p.data[(offset + 1)..(offset + 1 + 8)];
            return NsObject{ .ns_date = try parseFloat(data) + cf_epoch };
        },
        0x4 => { // [0100][nnnn] ?[int] ... | NSData object, nnnn number of bytes unless nnnn == 1111, then NSNumber int follows, followed by bytes
            const lenOffset = try parseLenOffset(p.data[offset..], type_byte.obj_info);

            std.debug.assert(p.data.len >= offset + lenOffset.offset + lenOffset.len);

            const data = p.data[(offset + lenOffset.offset)..(offset + lenOffset.offset + lenOffset.len)];
            return NsObject{ .ns_data = data };
        },
        else => error.PlistMalformed,
    };
}

fn parseTypeByte(type_byte: u8) struct { obj_type: u8, obj_info: u8 } {
    const obj_type = (type_byte & 0xF0) >> 4; // top 4 bits, always specifies the type
    const obj_info = type_byte & 0x0F; // bottom 4 bits, specifies the type or provides additional info
    return .{ .obj_type = obj_type, .obj_info = obj_info };
}

fn parseLen(object_info: u8) u64 {
    return 1 << object_info; // 2^object_info
}

fn parseLenOffset(data: []const u8, objectInfo: u8) !struct { len: u64, offset: u64 } {
    // 2 options:
    // 1. [type][length] data... - length is objectInfo
    // 2. [type][0xF] [NSNumber] data... - length is the NSNumber encoded integer

    if (objectInfo != 0xF) {
        return .{ .len = objectInfo, .offset = 1 };
    }

    std.debug.assert(data.len > 1);

    // Parse NSNumber encoded integer
    const intTypeByte = parseTypeByte(data[1]);
    const intLength = parseLen(intTypeByte.obj_info);

    // Integer NSNumber's object type is 0x1
    if (intTypeByte.obj_type != 0x1) {
        return error.PlistMalformed;
    }

    std.debug.assert(data.len >= 2 + intLength);

    return .{ .len = try parseInt(data[2..(2 + intLength)]), .offset = 2 + intLength };
}

// DATA PARSING

fn parseUInt(data: []const u8) !u64 {
    return switch (data.len) {
        1 => std.mem.readInt(u8, data[0..1], .big),
        2 => std.mem.readInt(u16, data[0..2], .big),
        4 => std.mem.readInt(u32, data[0..4], .big),
        8 => std.mem.readInt(u64, data[0..8], .big),
        else => error.PlistMalformed, // has to be a power of 2 <= 8
    };
}

fn parseInt(data: []const u8) !i64 {
    return switch (data.len) {
        1 => std.mem.readInt(i8, data[0..1], .big),
        2 => std.mem.readInt(i16, data[0..2], .big),
        4 => std.mem.readInt(i32, data[0..4], .big),
        8 => std.mem.readInt(i64, data[0..8], .big),
        16 => parseInt(data[8..]), // only the lower 8 bytes are used
        else => error.PlistMalformed, // has to be a power of 2 <= 16
    };
}

fn parseFloat(data: []const u8) !f64 {
    return switch (data.len) {
        4 => {
            const v: f32 = @bitCast(std.mem.readInt(i32, data[0..4], .big));
            return v;
        },
        8 => @bitCast(std.mem.readInt(i64, data[0..8], .big)),
        else => error.PlistMalformed, // only 4-bits (single-precision) and 8-bits (double-precision) are supported
    };
}

// TEST SUITE

test "integer parsing" {
    const types = [_]type{ i8, i16, i32, i64 };

    inline for (types) |T| {
        const min = std.math.minInt(T);
        const max = std.math.maxInt(T);
        const step: T = @divExact(max + 1, 2);

        var i: T = min;
        var buf: [@sizeOf(T)]u8 = undefined;

        while (i <= max) {
            std.mem.writeInt(T, &buf, i, .big);
            try std.testing.expectEqual(i, try parseInt(&buf));

            if (i == max) {
                break;
            }

            i +|= step;
        }
    }
}

test "128-bit integer parsing" {
    const min = std.math.minInt(i64);
    const max = std.math.maxInt(i64);
    const step = @divExact(max + 1, 2);

    var i: i64 = min;
    var buf: [16]u8 = undefined;

    while (i <= max) {
        std.mem.writeInt(i64, buf[8..16], i, .big);
        try std.testing.expectEqual(i, try parseInt(&buf));

        if (i == max) {
            break;
        }

        i +|= step;
    }
}

test "invalid size integer error" {
    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    _ = parseInt(&data) catch |err| {
        try std.testing.expectEqual(err, error.PlistMalformed);
    };
}

test "unsigned integer parsing" {
    const types = [_]type{ u8, u16, u32, u64 };

    inline for (types) |T| {
        const min = std.math.minInt(T);
        const max = std.math.maxInt(T);
        const step: T = @divExact(max + 1, 2);

        var i: T = min;
        var buf: [@sizeOf(T)]u8 = undefined;

        while (i <= max) {
            std.mem.writeInt(T, &buf, i, .big);
            try std.testing.expectEqual(i, try parseUInt(&buf));

            if (i == max) {
                break;
            }

            i +|= step;
        }
    }
}

test "single-precision float parsing" {
    const values = [_]f32{ 0.0, 1.0, -1.0, 3.14, -3.14, 1.0 / 3.0, -1.0 / 3.0 };

    for (values) |f| {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(i32, &buf, @bitCast(f), .big);
        try std.testing.expectEqual(f, try parseFloat(&buf));
    }
}

test "double-precision float parsing" {
    const values = [_]f64{ 0.0, 1.0, -1.0, 3.14, -3.14, 1.0 / 3.0, -1.0 / 3.0 };
    for (values) |f| {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(i64, &buf, @bitCast(f), .big);
        try std.testing.expectEqual(f, try parseFloat(&buf));
    }
}
