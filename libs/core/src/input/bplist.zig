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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
// USA

//! Parsing of binary property lists as specified by Apple.
const std = @import("std");

/// Struct representing a parsed binary plist
pub const Plist = struct {
    /// Arena allocator for the plist, used for all allocations
    arena: *std.heap.ArenaAllocator,

    /// The raw data of the plist
    data: []const u8,

    /// Array storing the offsets of each object in the data
    offsetTable: []const u64,

    /// Array storing the parsed objects,
    /// each object is optional, as it can be null in the original plist
    objectTable: []const ?NSObject,

    pub fn deinit(self: *Plist) void {
        self.arena.deinit();
    }
};

/// Tagged union representing the different types of objects in a plist
pub const NSObject = union(enum) {};

/// Parse a binary plist from the given data
///
/// For format specification see:
/// [opensource-apple/CF](https://github.com/opensource-apple/CF/blob/master/CFBinaryPList.c)
pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Plist {
    var plist = Plist{
        .arena = try allocator.create(std.heap.ArenaAllocator),
        .data = data,
    };

    errdefer allocator.destroy(plist.arena);
    plist.arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer plist.arena.deinit();

    return plist;
}

fn parseUInt(data: []const u8) !u64 {
    std.debug.assert(data != null and data.len > 0);

    return switch (data.len) {
        1, 2, 4 => try parseInt(data), // unsigned integers are the same as signed
        8 => try parseInt(data) & 0xFFFFFFFF, // convert to unsigned
        else => error.PlistMalformed, // has to be a power of 2 <= 8
    };
}

fn parseInt(data: []const u8) !i64 {
    std.debug.assert(data != null and data.len > 0);

    return switch (data.len) {
        1 => data[0],
        2 => std.mem.readInt(i16, data, .big),
        4 => std.mem.readInt(i32, data, .big),
        8 => std.mem.readInt(i64, data, .big),
        16 => std.mem.readInt(i64, data[8..], .big), // only the lower 8 bytes are used
        else => error.PlistMalformed, // has to be a power of 2 <= 16
    };
}

fn parseDouble(data: []const u8) !f64 {
    std.debug.assert(data != null and data.len > 0);

    return switch (data.len) {
        4, 8 => @floatFromInt(parseInt(data)), // read as int and convert
        else => error.PlistMalformed, // only 4-bits (single-precsion) and 8-bits (double-precision) are supported
    };
}
