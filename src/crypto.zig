const std = @import("std");

/// Returns the SHA-256 digest of bytes.
pub fn sha256(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}
