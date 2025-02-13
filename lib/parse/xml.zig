// libosint - Library for the Cyberintern OSINT project
// Copyright (C) 2025 Wojciech Mączka - Cybernetic Internationale
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
//
// This file incorporates work covered by the following copyright and
// permission notice:
// Copyright (C) 2024 Meghan Denny - https://github.com/nektro
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! XML document parsing conforming to the XML 1.0 specification.
//!
//! For more information see:
//! [XML 1.0 specification](https://www.w3.org/TR/xml/)
const std = @import("std");

// PUB DEFINITIONS

/// Structure representing an XML document
/// document ::= prolog element Misc*
/// prolog ::= XMLDecl? Misc* (doctypedecl Misc*)?
pub const Document = struct {
    arena: std.heap.ArenaAllocator,

    /// Array storing the parsed nodes
    nodes: std.MultiArrayList(Node),

    pub fn deinit(self: *@This()) void {
        self.nodes.deinit(self.arena.child_allocator);
        self.arena.deinit();
    }
};

/// Tagged union representing different types of objects in a XML document
pub const Node = union(enum) {
    xml_declaration: XmlDeclaration,
    comment: []const u8,
    pi: ProcessingInstruction,
};

pub const XmlDeclaration = struct {
    version: [2]u8,
    encoding: []const u8,
    standalone: bool,
};

pub const ProcessingInstruction = struct {
    target: []const u8,
    data: []const u8,
};

/// Low-level struct storing the intermediate state of the parsing process
pub const Parser = struct {
    reader: std.io.AnyReader,
    temp: std.ArrayList(u8),
    cursor: usize = 0,
    end: bool = false,
    prev_state: State = State.xml_declaration,
    state: State = State.xml_declaration,

    pub fn init(allocator: std.mem.Allocator, reader: std.io.AnyReader) Parser {
        return Parser{
            .reader = reader,
            .temp = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *@This()) void {
        self.temp.deinit();
    }

    pub fn parseNext(self: *@This(), allocator: std.mem.Allocator) !?Node {
        state_loop: while (true) {
            switch (self.state) {
                State.xml_declaration => {
                    const decl = try self.parseXmlDeclaration(allocator);
                    if (decl != null) {
                        return Node{ .xml_declaration = decl.? };
                    }
                    self.prev_state = State.xml_declaration;
                    self.state = State.misc;
                    continue :state_loop;
                },
                State.misc => {
                    const misc = try self.parseMisc(allocator);
                    if (misc == null) {
                        break;
                    }
                    switch (misc.?) {
                        .comment => return Node{ .comment = misc.?.comment },
                        .pi => return Node{ .pi = misc.?.pi },
                        .s => continue :state_loop,
                    }
                },
            }
        }

        return null;
    }

    /// XMLDecl ::= '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
    /// VersionInfo ::= S 'version' Eq ("'" VersionNum "'" | '"' VersionNum '"')
    /// VersionNum ::= '1.' [0-9]+
    /// EncodingDecl ::= S 'encoding' Eq ('"' EncName '"' | "'" EncName "'")
    /// EncName ::= [A-Za-z] ([A-Za-z0-9._] | '-')*
    /// SDDecl ::= S 'standalone' Eq ('"' ('yes' | 'no') '"' | "'" ('yes' | 'no') "'")
    fn parseXmlDeclaration(self: *@This(), allocator: std.mem.Allocator) !?XmlDeclaration {
        if (!try self.eat("<?xml")) {
            return null;
        }

        var version = [_]u8{ 1, 0 };
        var encoding = std.ArrayList(u8).init(allocator);
        errdefer encoding.deinit();
        var standalone = false;

        // VersionInfo
        if (!try self.skipWhitespace()) return error.XmlMalformed;
        if (try self.eat("version")) {
            try self.skipEq();
            const q = try self.skipQuotesStart();
            if (!try self.eat("1.")) return error.XmlMalformed;
            var i: usize = 0;
            while (try self.peek(1)) : (i += 1) {
                switch (self.top()) {
                    '0'...'9' => {
                        version[1] *= 10;
                        version[1] += self.pop() - '0';
                        continue;
                    },
                    else => {
                        if (i == 0) {
                            return error.XmlMalformed;
                        }
                        break;
                    },
                }
            }
            try self.skipQuotesEnd(q);

            if (version[0] != 1 or version[1] != 0) return error.XmlMalformed;
        } else {
            return error.XmlMalformed;
        }

        // EncodingDecl?
        _ = try self.skipWhitespace();
        if (try self.eat("encoding")) {
            try self.skipEq();
            const q = try self.skipQuotesStart();
            if (!try self.peek(1)) return error.XmlMalformed;
            switch (self.top()) {
                'A'...'Z', 'a'...'z' => {
                    try encoding.append(self.pop());
                },
                else => return error.XmlMalformed,
            }
            while (try self.peek(1)) {
                switch (self.top()) {
                    'A'...'Z', 'a'...'z', '0'...'9', '.', '_', '-' => {
                        try encoding.append(self.pop());
                    },
                    else => break,
                }
            }
            try self.skipQuotesEnd(q);
        }

        // SDDecl?
        _ = try self.skipWhitespace();
        if (try self.eat("standalone")) {
            try self.skipEq();
            const q = try self.skipQuotesStart();
            if (try self.eat("yes")) {
                standalone = true;
            } else if (try self.eat("no")) {
                standalone = false;
            } else {
                return error.XmlMalformed;
            }
            try self.skipQuotesEnd(q);
        }

        _ = try self.skipWhitespace();
        if (!try self.eat("?>")) return error.XmlMalformed;

        return XmlDeclaration{
            .version = version,
            .encoding = try encoding.toOwnedSlice(),
            .standalone = standalone,
        };
    }

    /// Misc ::= Comment | PI | S
    fn parseMisc(self: *@This(), allocator: std.mem.Allocator) !?union(enum) { comment: []const u8, pi: ProcessingInstruction, s: void } {
        if (try self.parseComment(allocator)) |c| {
            return .{ .comment = c };
        }
        if (try self.parsePi(allocator)) |pi| {
            return .{ .pi = pi };
        }
        if (try self.skipWhitespace()) {
            return .{ .s = {} };
        }

        return null;
    }

    /// Comment ::= '<!--' ((Char - '-') | ('-' (Char - '-')))* '-->'
    fn parseComment(self: *@This(), allocator: std.mem.Allocator) !?[]const u8 {
        if (!try self.eat("<!--")) {
            return null;
        }

        var comment = std.ArrayList(u8).init(allocator);
        errdefer comment.deinit();

        while (true) {
            if (!try self.peek(3)) {
                return error.XmlMalformed;
            }
            if (try self.eat("-->")) {
                break;
            }
            try comment.append(self.pop());
        }

        return try comment.toOwnedSlice();
    }

    /// PI ::= '<?' PITarget (S (Char* - (Char* '?>' Char*)))? '?>'
    /// PITarget ::= Name - (('X' | 'x') ('M' | 'm') ('L' | 'l'))
    fn parsePi(self: *@This(), allocator: std.mem.Allocator) !?ProcessingInstruction {
        if (!try self.eat("<?")) {
            return null;
        }

        if (try self.eat("xml ") or try self.eat("XML ")) {
            return error.XmlMalformed;
        }

        const target = try self.parseName(allocator) orelse return error.XmlMalformed;
        var data = std.ArrayList(u8).init(allocator);
        errdefer data.deinit();

        while (try self.peek(1)) {
            if (try self.eat("?>")) {
                break;
            }

            try data.append(self.pop());
        }

        return .{
            .target = target,
            .data = try data.toOwnedSlice(),
        };
    }

    /// Name ::= NameStartChar (NameChar)*
    fn parseName(self: *@This(), allocator: std.mem.Allocator) !?[]const u8 {
        var name = std.ArrayList(u8).init(allocator);
        errdefer name.deinit();

        try name.appendSlice(try self.parseNameStartChar() orelse return null);
        while (try self.parseNameChar()) |c| {
            try name.appendSlice(c);
        }

        return try name.toOwnedSlice();
    }

    /// NameStartChar ::= ":" | [A-Z] | "_" | [a-z] | [#xC0-#xD6] | [#xD8-#xF6] | [#xF8-#x2FF] | [#x370-#x37D] | [#x37F-#x1FFF] | [#x200C-#x200D] | [#x2070-#x218F] | [#x2C00-#x2FEF] | [#x3001-#xD7FF] | [#xF900-#xFDCF] | [#xFDF0-#xFFFD] | [#x10000-#xEFFFF]
    fn parseNameStartChar(self: *@This()) !?[]const u8 {
        if (!try self.peek(1)) {
            return null;
        }
        switch (self.top()) {
            ':', 'A'...'Z', '_', 'a'...'z', 0xC0...0xD6, 0xD8...0xF6, 0xF8...0xFF => {
                return self.popM(1);
            },
            else => {},
        }

        if (!try self.peek(2)) {
            return null;
        }
        switch (self.topM(2) orelse 0) {
            0x100...0x2FF, 0x370...0x37D, 0x37F...0x1FFF, 0x200C...0x200D, 0x2070...0x218F, 0x2C00...0x2FEF, 0x3001...0xD7FF, 0xF900...0xFDCF, 0xFDF0...0xFFFD => {
                return self.popM(2);
            },
            else => {},
        }

        if (!try self.peek(3)) {
            return null;
        }
        switch (self.topM(3) orelse 0) {
            0x10000...0xEFFFF => {
                return self.popM(3);
            },
            else => {},
        }

        return null;
    }

    /// NameChar ::= NameStartChar | "-" | "." | [0-9] | #xB7 | [#x0300-#x036F] | [#x203F-#x2040]
    fn parseNameChar(self: *@This()) !?[]const u8 {
        if (!try self.peek(1)) {
            return null;
        }
        switch (self.top()) {
            '-', '.', 0...9, 0xB7 => {
                return self.popM(1);
            },
            else => {},
        }

        if (try self.parseNameStartChar()) |c| {
            return c;
        }

        switch (self.topM(2) orelse 0) {
            0x300...0x36F, 0x203F...0x2040 => {
                return self.popM(2);
            },
            else => {},
        }

        return null;
    }

    /// Eq ::= S? '=' S?
    fn skipEq(self: *@This()) !void {
        _ = try self.skipWhitespace();
        if (!try self.eat("=")) return error.XmlMalformed;
        _ = try self.skipWhitespace();
    }

    /// S ::= (#x20 | #x9 | #xD | #xA)+
    fn skipWhitespace(self: *@This()) !bool {
        var i: usize = 0;
        while (try self.peek(1)) : (i += 1) {
            switch (self.top()) {
                0x20, 0x09, 0x0D, 0x0A => {
                    _ = self.pop();
                    continue;
                },
                else => {
                    return i > 0;
                },
            }
        }

        return error.UnexpectedEndOfStream;
    }

    fn skipQuotesStart(self: *@This()) !u8 {
        if (try self.eat("\"")) {
            return '"';
        }
        if (try self.eat("'")) {
            return '\'';
        }
        return error.XmlMalformed;
    }

    fn skipQuotesEnd(self: *@This(), quote: u8) !void {
        switch (quote) {
            '"' => if (!try self.eat("\"")) return error.XmlMalformed,
            '\'' => if (!try self.eat("'")) return error.XmlMalformed,
            else => unreachable,
        }
    }

    fn available(self: *@This()) usize {
        return self.temp.items.len - self.cursor;
    }

    fn top(self: *@This()) u8 {
        std.debug.assert(self.cursor < self.temp.items.len);
        return self.temp.items[self.cursor];
    }

    fn pop(self: *@This()) u8 {
        const c = self.top();
        self.cursor += 1;
        return c;
    }

    fn topM(self: *@This(), comptime size: usize) ?u21 {
        std.debug.assert(self.cursor + size <= self.temp.items.len);
        return std.unicode.utf8Decode(self.slice()[0..size]) catch return null;
    }

    fn popM(self: *@This(), comptime size: usize) []const u8 {
        const s = self.slice()[0..size];
        self.cursor += size;
        return s;
    }

    fn slice(self: *@This()) []const u8 {
        return self.temp.items[self.cursor..];
    }

    fn eat(self: *@This(), comptime s: []const u8) !bool {
        if (!try self.peek(s.len)) {
            return false;
        }

        if ((s.len == 1 and s[0] != self.temp.items[self.cursor]) or !std.mem.eql(u8, s, self.slice()[0..s.len])) {
            return false;
        }

        self.cursor += s.len;
        return true;
    }

    fn peek(self: *@This(), comptime size: usize) !bool {
        if (self.available() >= size) {
            return true;
        }

        var buf: [std.mem.page_size]u8 = undefined;
        const n = try self.reader.read(buf[0..]);

        if (n == 0) {
            self.end = true;
            return false;
        }

        try self.temp.appendSlice(buf[0..n]);

        if (n < size) {
            return false;
        }

        return true;
    }

    const State = enum {
        misc,
        xml_declaration,
    };
};

// PUB PARSING

pub fn parseFromSlice(allocator: std.mem.Allocator, s: []const u8) !Document {
    var fbs = std.io.fixedBufferStream(s);
    var parser = Parser.init(allocator, fbs.reader().any());
    defer parser.deinit();

    var nodes: std.MultiArrayList(Node) = .{};
    var arena = std.heap.ArenaAllocator.init(allocator);
    const in_ally = arena.allocator();

    try nodes.append(allocator, (try parser.parseNext(in_ally)).?);

    return Document{
        .arena = arena,
        .nodes = nodes,
    };
}

// TEST SUITE

test "high-level parsing" {
    const ally = std.testing.allocator;

    var doc = try parseFromSlice(ally,
        \\<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
        \\ <!-- comment -->
        \\ <?pi data?>
        \\
    );
    defer doc.deinit();

    const decl = doc.nodes.items(.data)[0].xml_declaration;

    try std.testing.expectEqual(1, decl.version[0]);
    try std.testing.expectEqual(0, decl.version[1]);
    try std.testing.expectEqualStrings("UTF-8", decl.encoding);
    try std.testing.expectEqual(true, decl.standalone);
}
