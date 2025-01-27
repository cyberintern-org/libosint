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
