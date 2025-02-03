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

// PUB DEFINITIONS

/// Struct representing a parsed binary plist
pub const Plist = struct {
    /// Allocator used to allocate the offset and object table arrays
    allocator: std.mem.Allocator,

    /// Array storing the parsed objects,
    /// each object is optional, as it can be null in the original plist
    objects: []?NsObject,

    /// Copied data of the plist
    string_bytes: std.ArrayList(u8),

    /// Pointer to the root object of the plist
    top: *?NsObject,

    /// Deinitialize the plist, freeing the objects and string bytes arrays
    pub fn deinit(self: *Plist) void {
        Parser.deinitObjectTable(self.allocator, self.objects);
        self.allocator.free(self.objects);
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
    ns_string: []const u8,
    uid: u64,
    ns_array: []*?NsObject,
    ns_dict: std.StringHashMap(*?NsObject),
};

/// UNIX timestamp of 2001-01-01 00:00:00 UTC, the Core Data epoch
pub const cf_epoch = 978307200.0;

// PARSING

/// Internal struct storing the intermediate state of the parsing process
const Parser = struct {
    allocator: std.mem.Allocator,

    data: []const u8,
    offset_table: []u64,
    object_table: []?NsObject,
    string_bytes: std.ArrayList(u8),

    ref_size: u8,

    pub fn deinit(self: *Parser) void {
        deinitObjectTable(self.allocator, self.object_table);
        self.allocator.free(self.offset_table);
        self.string_bytes.deinit();
    }

    pub fn deinitObjectTable(allocator: std.mem.Allocator, table: []?NsObject) void {
        for (table) |obj| {
            if (obj == null) {
                continue;
            }

            switch (obj.?) {
                .ns_dict => |dict| {
                    @constCast(&dict).deinit();
                },
                .ns_array => |arr| {
                    allocator.free(arr);
                },
                else => {},
            }
        }
    }
};

/// Parse a binary plist from the given data
///
/// For format specification see:
/// [opensource-apple/CF](https://github.com/opensource-apple/CF/blob/master/CFBinaryPList.c)
pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Plist {
    const valid_data = try parseHeader(data);
    const trailer = try parseTrailer(valid_data);

    var parser = Parser{
        .allocator = allocator,
        .data = valid_data,
        .offset_table = try allocator.alloc(u64, trailer.num_objects), // length controled by the number of objects defined in the trailer
        .object_table = try allocator.alloc(?NsObject, trailer.num_objects), // same as above
        .string_bytes = try std.ArrayList(u8).initCapacity(allocator, valid_data.len), // at most the same size as the input data
        .ref_size = trailer.ref_size,
    };

    defer allocator.free(parser.offset_table);
    errdefer parser.deinit();

    for (0..trailer.num_objects) |i| {
        const offset = trailer.offset_table_offset + i * trailer.offset_size;
        parser.offset_table[i] = try parseUInt(parser.data[offset .. offset + trailer.offset_size]);
        parser.object_table[i] = null;
    }

    parser.object_table[trailer.top_object_id] = try parseObject(&parser, trailer.top_object_id) orelse null;

    return Plist{
        .allocator = allocator,
        .objects = parser.object_table,
        .string_bytes = parser.string_bytes,
        .top = &parser.object_table[trailer.top_object_id],
    };
}

fn parseHeader(data: []const u8) ![]const u8 {
    var offset: u8 = 0;

    // Skip the BOM if present
    if (data.len > 3 and data[0] == 0xEF and data[1] == 0xBB and data[2] == 0xBF) {
        offset = 3;
    }

    // Skip whitespace
    while (offset < data.len and (data[offset] == ' ' or data[offset] == '\n' or data[offset] == '\r' or data[offset] == '\t')) : (offset += 1) {}

    // Check for the bplist header
    if (data.len - offset < 6 or !std.mem.eql(u8, data[offset .. offset + 6], "bplist")) {
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
    if (object_id >= p.offset_table.len) {
        return error.PlistMalformed;
    }

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

            if (p.data.len < offset + 1 + len) {
                return error.PlistMalformed;
            }

            const data = p.data[(offset + 1)..(offset + 1 + len)];
            return NsObject{ .ns_number_i = try parseInt(data) };
        },
        0x2 => { // [0010][0nnn] ... | NSNumber type real of 2^nnn big-endian bytes,
            const len = parseLen(type_byte.obj_info);

            if (p.data.len < offset + 1 + len) {
                return error.PlistMalformed;
            }

            const data = p.data[(offset + 1)..(offset + 1 + len)];
            return NsObject{ .ns_number_r = try parseFloat(data) };
        },
        0x3 => { // [0011][0011] ... | NSDate object, 8 bytes of big-endian float
            if (type_byte.obj_info != 0x3) {
                return error.PlistMalformed;
            }

            if (p.data.len < offset + 1 + 8) {
                return error.PlistMalformed;
            }

            const data = p.data[(offset + 1)..(offset + 1 + 8)];
            return NsObject{ .ns_date = try parseFloat(data) + cf_epoch };
        },
        0x4 => { // [0100][nnnn] ?[int] ... | NSData object, nnnn number of bytes, unless nnnn == 1111, then the length is the NSNumber int that follows
            const data = try parseRawData(p.data[offset..], type_byte.obj_info);
            const idx = p.string_bytes.items.len;

            p.string_bytes.appendSliceAssumeCapacity(data);
            return NsObject{ .ns_data = p.string_bytes.items[idx..] };
        },
        0x5, 0x7 => { // ([0101]/[0111])[nnnn] ?[int] ... | ASCII/UTF-8 string, nnnn number of bytes, unless nnnn == 1111, then the length is the NSNumber int that follows
            const data = try parseRawData(p.data[offset..], type_byte.obj_info);
            const idx = p.string_bytes.items.len;

            p.string_bytes.appendSliceAssumeCapacity(data);
            return NsObject{ .ns_string = p.string_bytes.items[idx..] };
        },
        0x6 => { // [0110][nnnn] ?[int] ... | UTF-16Be string, nnnn number of bytes, unless nnnn == 1111, then the length is the NSNumber int that follows
            const data = try parseRawData(p.data[offset..], type_byte.obj_info);
            var idx = p.string_bytes.items.len;

            try p.string_bytes.appendSlice(data);

            const aligned_ptr: []align(2) u8 = @alignCast(p.string_bytes.items[idx..]);

            var data_u16: []u16 = std.mem.bytesAsSlice(u16, aligned_ptr[0..]);

            for (0..data_u16.len) |i| {
                data_u16[i] = std.mem.bigToNative(u16, data_u16[i]);
            }

            idx = p.string_bytes.items.len;
            try std.unicode.utf16LeToUtf8ArrayList(&p.string_bytes, data_u16);

            return NsObject{ .ns_string = p.string_bytes.items[idx..] };
        },
        0x8 => { // [1000][nnnn] ... | UID
            const len = parseLen(type_byte.obj_info);

            if (p.data.len < offset + 1 + len) {
                return error.PlistMalformed;
            }

            const data = p.data[(offset + 1)..(offset + 1 + len)];
            return NsObject{ .uid = try parseUInt(data) };
        },
        0xA, 0xB, 0xC => { // ([1010]/[1011]/[1100])[nnnn] ?[int] ... | NSArray/NSOrderedSet/NSSet, nnnn number of objects, unless nnnn == 1111, then the length is the NSNumber int that follows
            const lenOffset = try parseLenOffset(p.data[offset..], type_byte.obj_info);
            const arr: []*?NsObject = try p.allocator.alloc(*?NsObject, lenOffset.len);
            errdefer p.allocator.free(arr);

            for (0..lenOffset.len) |i| {
                const obj_id = try parseRef(p.data[offset + lenOffset.offset ..], i, p.ref_size);
                p.object_table[obj_id] = try parseObject(p, obj_id);
                arr[i] = &p.object_table[obj_id];
            }

            return NsObject{ .ns_array = arr };
        },
        0xD => { // [1101][nnnn] ?[int] ... | NSDictionary, nnnn number of key-value pairs, unless nnnn == 1111, then the length is the NSNumber int that follows
            const lenOffset = try parseLenOffset(p.data[offset..], type_byte.obj_info);

            var dict = std.StringHashMap(*?NsObject).init(p.allocator);
            errdefer dict.deinit();

            _ = try dict.ensureTotalCapacity(@intCast(lenOffset.len));

            for (0..lenOffset.len) |i| {
                const key_id = try parseRef(p.data[(offset + lenOffset.offset)..], 2 * i, p.ref_size);
                const val_id = try parseRef(p.data[(offset + lenOffset.offset)..], 2 * i + 1, p.ref_size);

                const key = try parseObject(p, key_id);
                const val = try parseObject(p, val_id);

                p.object_table[key_id] = key;
                p.object_table[val_id] = val;

                if (key == null) {
                    continue;
                }

                const v = &p.object_table[val_id];

                switch (key.?) {
                    .ns_string => |k| {
                        dict.putAssumeCapacity(k, v);
                    },
                    .ns_number_i => |num| {
                        const len = std.fmt.count("{}", .{num});

                        const buf = p.string_bytes.addManyAsSliceAssumeCapacity(len);
                        const k = std.fmt.bufPrintIntToSlice(buf, num, 10, .lower, .{});

                        dict.putAssumeCapacity(k, v);
                    },
                    else => {},
                }
            }

            return NsObject{ .ns_dict = dict };
        },
        else => error.PlistMalformed,
    };
}

fn parseTypeByte(type_byte: u8) struct { obj_type: u8, obj_info: u8 } {
    const obj_type = (type_byte & 0xF0) >> 4; // top 4 bits, always specifies the type
    const obj_info = type_byte & 0x0F; // bottom 4 bits, specifies the type or provides additional info
    return .{ .obj_type = obj_type, .obj_info = obj_info };
}

inline fn parseLen(object_info: u8) u64 {
    const len: u64 = 1;
    return len <<| object_info; // 2^object_info
}

fn parseLenOffset(data: []const u8, object_info: u8) !struct { len: u64, offset: u64 } {
    // 2 options:
    // 1. [type][length] data... - length is objectInfo
    // 2. [type][0xF] [NSNumber] data... - length is the NSNumber encoded integer

    if (object_info != 0xF) {
        return .{ .len = object_info, .offset = 1 };
    }

    if (data.len < 2) {
        return error.PlistMalformed;
    }

    // Parse NSNumber encoded integer
    const int_type_byte = parseTypeByte(data[1]);
    const int_len = parseLen(int_type_byte.obj_info);

    // Integer NSNumber's object type is 0x1
    if (int_type_byte.obj_type != 0x1) {
        return error.PlistMalformed;
    }

    if (data.len < 2 + int_len) {
        return error.PlistMalformed;
    }

    return .{ .len = try parseUInt(data[2..(2 + int_len)]), .offset = 2 + int_len };
}

fn parseRawData(data: []const u8, object_info: u8) ![]const u8 {
    const lenOffset = try parseLenOffset(data, object_info);

    if (data.len < lenOffset.offset + lenOffset.len) {
        return error.PlistMalformed;
    }

    return data[lenOffset.offset .. lenOffset.offset + lenOffset.len];
}

fn parseRef(data: []const u8, idx: usize, ref_size: u8) !u64 {
    const start = idx * ref_size;
    const end = start + ref_size;
    return try parseUInt(data[start..end]);
}

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

test "header BOM and whitespace ommision" {
    const data = [_]u8{ 0xEF, 0xBB, 0xBF, ' ', ' ', ' ', '\n', 'b', 'p', 'l', 'i', 's', 't' };
    const valid_data = try parseHeader(data[0..]);

    try std.testing.expectEqualStrings(valid_data, "bplist");
}

test "trailer parsing" {
    const data = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xCB,
    };

    const trailer = try parseTrailer(data[0..]);

    try std.testing.expectEqual(trailer.offset_size, 2);
    try std.testing.expectEqual(trailer.ref_size, 1);
    try std.testing.expectEqual(trailer.num_objects, 63);
    try std.testing.expectEqual(trailer.top_object_id, 0);
    try std.testing.expectEqual(trailer.offset_table_offset, 971);
}

test "type byte parsing" {
    const type_byte = parseTypeByte(0x12);

    try std.testing.expectEqual(type_byte.obj_type, 0x1);
    try std.testing.expectEqual(type_byte.obj_info, 0x2);
}

test "length calculation" {
    try std.testing.expectEqual(parseLen(0x0), 1);
    try std.testing.expectEqual(parseLen(0x1), 2);
    try std.testing.expectEqual(parseLen(0x2), 4);
    try std.testing.expectEqual(parseLen(0x3), 8);
}

test "length offset calculation" {
    const data = [_]u8{ 0x5F, 0x10, 0x26 };
    const type_byte = parseTypeByte(data[0]);

    const lenOffset = try parseLenOffset(data[0..], type_byte.obj_info);

    try std.testing.expectEqual(lenOffset.len, 38);
    try std.testing.expectEqual(lenOffset.offset, 3);
}

test "ASCII string parsing" {
    const data = [_]u8{
        0x5F, 0x10, 0x16, 0x41, 0x70, 0x70, 0x6C, 0x65, 0x50,
        0x61, 0x73, 0x73, 0x63, 0x6F, 0x64, 0x65, 0x4B, 0x65,
        0x79, 0x62, 0x6F, 0x61, 0x72, 0x64, 0x73,
    };
    var objs = [_]?NsObject{null};
    var offset_table = [_]u64{0};

    var parser = Parser{
        .allocator = std.heap.page_allocator,
        .data = data[0..],
        .object_table = objs[0..],
        .offset_table = offset_table[0..],
        .string_bytes = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, 26),
        .ref_size = 1,
    };

    const obj = try parseObject(&parser, 0);

    try std.testing.expectEqualStrings(obj.?.ns_string, "ApplePasscodeKeyboards");
}

test "UTF-16Be string parsing" {
    const data = [_]u8{
        0x6F, 0x10, 0x2C, 0x00, 0x41, 0x00, 0x70, 0x00,
        0x70, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x50, 0x00,
        0x61, 0x00, 0x73, 0x00, 0x73, 0x00, 0x63, 0x00,
        0x6F, 0x00, 0x64, 0x00, 0x65, 0x00, 0x4B, 0x00,
        0x65, 0x00, 0x79, 0x00, 0x62, 0x00, 0x6F, 0x00,
        0x61, 0x00, 0x72, 0x00, 0x64, 0x00, 0x73,
    };
    var objs = [_]?NsObject{null};
    var offset_table = [_]u64{0};

    var parser = Parser{
        .allocator = std.heap.page_allocator,
        .data = data[0..],
        .object_table = objs[0..],
        .offset_table = offset_table[0..],
        .string_bytes = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, 44),
        .ref_size = 1,
    };

    const obj = try parseObject(&parser, 0);

    try std.testing.expectEqualStrings(obj.?.ns_string, "ApplePasscodeKeyboards");
}
