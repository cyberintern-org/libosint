const std = @import("std");

pub const scan = @import("scan.zig");

test {
    std.testing.refAllDecls(@This());
}
