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
    /// Array storing the parsed nodes
    nodes: std.MultiArrayList(Node),

    /// Copied data of the XML document
    string_bytes: std.ArrayList(u8),
};

/// Tagged union representing different types of objects in a XML document
pub const Node = union(enum) {
    xml_declaration: XmlDeclaration,
};

pub const XmlDeclaration = struct {
    version: [2]u8,
    encoding: []const u8,
    standalone: bool,
};

/// Low-level struct storing the intermediate state of the parsing process
pub const Parser = struct {
    allocator: std.mem.Allocator,
    reader: std.io.AnyReader,
    temp: std.ArrayList(u8),
    cursor: usize,
    end: bool,
    state: State,

    pub fn init(allocator: std.mem.Allocator, reader: std.io.AnyReader) Parser {
        return Parser{
            .allocator = allocator,
            .reader = reader,
            .temp = std.ArrayList(u8).init(allocator),
            .cursor = 0,
            .end = false,
            .state = State.prolog_xml_declaration,
        };
    }

    pub fn deinit(self: *@This()) void {
        self.temp.deinit();
    }

    pub fn parseNext(self: *@This()) !Node {
        while (true) {
            switch (self.state) {
                State.prolog_xml_declaration => {
                    const decl = try self.parseXmlDeclaration();
                    if (decl != null) {
                        return Node{ .xml_declaration = decl.? };
                    }
                    return error.XmlMalformed;
                },
            }
        }
    }

    /// XMLDecl := '<?xml' VersionInfo EncodingDecl? SDDecl? S? '?>'
    /// VersionInfo := S 'version' Eq ("'" VersionNum "'" | '"' VersionNum '"')
    /// VersionNum := '1.' [0-9]+
    /// EncodingDecl := S 'encoding' Eq ('"' EncName '"' | "'" EncName "'")
    /// EncName := [A-Za-z] ([A-Za-z0-9._] | '-')*
    /// SDDecl := S 'standalone' Eq ('"' ('yes' | 'no') '"' | "'" ('yes' | 'no') "'")
    fn parseXmlDeclaration(self: *@This()) !?XmlDeclaration {
        if (!try self.eat("<?xml")) {
            return null;
        }

        var version = [_]u8{ 1, 0 };
        var encoding = std.ArrayList(u8).init(self.allocator);
        var standalone = false;

        // VersionInfo
        try self.skipWhitespace(false);
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
        try self.skipWhitespace(true);
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
        try self.skipWhitespace(true);
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

        try self.skipWhitespace(true);
        if (!try self.eat("?>")) return error.XmlMalformed;

        return XmlDeclaration{
            .version = version,
            .encoding = try encoding.toOwnedSlice(),
            .standalone = standalone,
        };
    }

    /// Eq := S? '=' S?
    fn skipEq(self: *@This()) !void {
        try self.skipWhitespace(true);
        if (!try self.eat("=")) return error.XmlMalformed;
        try self.skipWhitespace(true);
    }

    /// S :== (#x20 | #x9 | #xD | #xA)+
    fn skipWhitespace(self: *@This(), optional: bool) !void {
        var i: usize = 0;
        while (try self.peek(1)) : (i += 1) {
            switch (self.top()) {
                0x20, 0x09, 0x0D, 0x0A => {
                    _ = self.pop();
                    continue;
                },
                else => {
                    if (!optional and i == 0) {
                        return error.XmlMalformed;
                    }
                    return;
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
        return self.temp.items[self.cursor];
    }

    fn pop(self: *@This()) u8 {
        const c = self.temp.items[self.cursor];
        self.cursor += 1;
        return c;
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
        prolog_xml_declaration,
    };
};

// PUB PARSING

pub fn parseFromSlice(allocator: std.mem.Allocator, s: []const u8) !Document {
    var fbs = std.io.fixedBufferStream(s);
    var parser = Parser.init(allocator, fbs.reader().any());
    defer parser.deinit();

    var nodes: std.MultiArrayList(Node) = .{};
    var string_bytes = try std.ArrayList(u8).initCapacity(allocator, s.len);

    var node = try parser.parseNext();

    switch (node) {
        Node.xml_declaration => {
            const idx = string_bytes.items.len;
            try string_bytes.appendSlice(node.xml_declaration.encoding);
            allocator.free(node.xml_declaration.encoding);
            node.xml_declaration.encoding = string_bytes.items[idx..];
        },
    }

    try nodes.append(allocator, node);

    return Document{
        .nodes = nodes,
        .string_bytes = string_bytes,
    };
}

test "xml decl" {
    const ally = std.testing.allocator;

    var doc = try parseFromSlice(ally, "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>");
    defer doc.string_bytes.deinit();
    defer doc.nodes.deinit(ally);

    const decl = doc.nodes.items(.data)[0].xml_declaration;

    try std.testing.expectEqual(1, decl.version[0]);
    try std.testing.expectEqual(0, decl.version[1]);
    try std.testing.expectEqualStrings("UTF-8", decl.encoding);
    try std.testing.expectEqual(true, decl.standalone);
}
