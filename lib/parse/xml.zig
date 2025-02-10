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
pub const Document = struct {
    /// Array storing the parsed nodes
    nodes: std.MultiArrayList(Node),

    /// Copied data of the XML document
    string_bytes: std.ArrayList(u8),
};

/// Tagged union representing different types of objects in a XML document
pub const Node = union(enum) {};

/// Low-level struct storing the intermediate state of the parsing process
pub const Parser = struct {};

// PUB PARSING

pub fn parseFromSlice(allocator: std.mem.Allocator, s: []const u8) !Document {}

// INTERNAL PARSING
