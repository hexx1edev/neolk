const std = @import("std");
const config = @import("config.zig");
const magic: u32 = 0x58881688;
const header_size = 512;
const Partition = struct {
    name: []const u8,
    dataStart: usize,
    dataSize: usize,
};

const Pattern = struct {
    bytes: []u8,
    exact: []bool,
};

/// Applies or locates configured binary patches.
pub fn patch(init: std.process.Init, device: config.DeviceConfig, action: []const u8) !void {
    if (!std.mem.eql(u8, action, "apply") and !std.mem.eql(u8, action, "search")) return error.InvalidInput;

    const bytes = std.Io.Dir.cwd().readFileAlloc(init.io, device.image.path, init.gpa, .limited(128 * 1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("error: input LK image not found: {s}\n", .{device.image.path});
            return error.InputImageNotFound;
        },
        else => return err,
    };
    defer init.gpa.free(bytes);

    const text = try std.Io.Dir.cwd().readFileAlloc(init.io, "patches.toml", init.gpa, .limited(1024 * 1024));
    defer init.gpa.free(text);

    const parts = try parseParts(init.gpa, bytes);
    defer init.gpa.free(parts);

    var section: ?[]const u8 = null;
    var needle: ?[]const u8 = null;
    var replacement: ?[]const u8 = null;
    var target: ?[]const u8 = null;
    var count: usize = 0;

    var lines = std.mem.splitScalar(u8, text, '\n');

    while (lines.next()) |line| {
        const x = std.mem.trim(u8, line, " \t\r");
        if (x.len > 2 and x[0] == '[' and x[x.len - 1] == ']') {
            count += try entry(init.gpa, bytes, parts, section, needle, replacement, target, action);
            section = x[1 .. x.len - 1];
            needle = null;
            replacement = null;
            target = null;
        } else if (std.mem.startsWith(u8, x, "pattern")) {
            needle = quoted(x);
        } else if (std.mem.startsWith(u8, x, "replacement")) {
            replacement = quoted(x);
        } else if (std.mem.startsWith(u8, x, "target")) {
            target = value(x);
        }
    }

    count += try entry(init.gpa, bytes, parts, section, needle, replacement, target, action);

    if (std.mem.eql(u8, action, "apply")) {
        try std.Io.Dir.cwd().createDirPath(init.io, "build");
        try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "build/lk.patched.img", .data = bytes });
        std.debug.print("applied {d} patch(es)\n", .{count});
    }
}

fn entry(a: std.mem.Allocator, bytes: []u8, parts: []const Partition, name: ?[]const u8, needle_text: ?[]const u8, replacement_text: ?[]const u8, target: ?[]const u8, action: []const u8) !usize {
    const title = name orelse return 0;

    const needle = try parsePattern(a, needle_text orelse return error.InvalidPatch);
    defer a.free(needle.bytes);
    defer a.free(needle.exact);

    const replacement = try parsePattern(a, replacement_text orelse return error.InvalidPatch);
    defer a.free(replacement.bytes);
    defer a.free(replacement.exact);

    if (needle.bytes.len != replacement.bytes.len) return error.InvalidPatch;

    const part = if (target) |label| find(parts, label) orelse return error.PartitionNotFound else null;
    const base = if (part) |p| p.dataStart else 0;
    const region = if (part) |p| bytes[p.dataStart .. p.dataStart + p.dataSize] else bytes;

    const offset = locate(region, needle) orelse {
        std.debug.print("{s}: not found\n", .{title});
        return 0;
    };

    std.debug.print("{s}: image+0x{x}, partition+0x{x}\n", .{ title, base + offset, offset });

    if (std.mem.eql(u8, action, "apply")) {
        @memcpy(bytes[base + offset ..][0..replacement.bytes.len], replacement.bytes);
    }

    return 1;
}

fn parseParts(a: std.mem.Allocator, bytes: []const u8) ![]Partition {
    var out = std.ArrayList(Partition).empty;
    var off: usize = 0;

    while (off + header_size <= bytes.len and read32(bytes, off) == magic) {
        const size: usize = read32(bytes, off + 4);
        const end_name = std.mem.indexOfScalar(u8, bytes[off + 8 .. off + 40], 0) orelse 32;

        const alignment: usize = if (read32(bytes, off + 48) == 0x58891689 and read32(bytes, off + 68) != 0) read32(bytes, off + 68) else 8;
        const end = std.mem.alignForward(usize, off + header_size + size, alignment);

        if (end > bytes.len) return error.InvalidImage;

        // `bytes` outlives the returned partition list, so partition names can
        // borrow from the input image instead of allocating one copy per entry.
        try out.append(a, .{
            .name = bytes[off + 8 .. off + 8 + end_name],
            .dataStart = off + header_size,
            .dataSize = size,
        });

        if (read32(bytes, off + 64) == 1) break;

        off = end;
    }

    if (out.items.len == 0) return error.InvalidImage;
    return out.toOwnedSlice(a);
}

fn parsePattern(a: std.mem.Allocator, text: []const u8) !Pattern {
    var bytes = std.ArrayList(u8).empty;
    var exact = std.ArrayList(bool).empty;
    var it = std.mem.tokenizeAny(u8, text, " \t");

    while (it.next()) |token| {
        if (std.mem.eql(u8, token, "??")) {
            try bytes.append(a, 0);
            try exact.append(a, false);
        } else {
            try bytes.append(a, try std.fmt.parseInt(u8, token, 16));
            try exact.append(a, true);
        }
    }

    return .{ .bytes = try bytes.toOwnedSlice(a), .exact = try exact.toOwnedSlice(a) };
}

fn locate(bytes: []const u8, needle: Pattern) ?usize {
    if (needle.bytes.len == 0 or needle.bytes.len > bytes.len) return null;

    for (0..bytes.len - needle.bytes.len + 1) |at| {
        for (needle.bytes, needle.exact, 0..) |byte, exact, i| {
            if (exact and bytes[at + i] != byte) break;
            if (i == needle.bytes.len - 1) return at;
        }
    }

    return null;
}

fn read32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn find(parts: []const Partition, name: []const u8) ?Partition {
    for (parts) |part| {
        if (std.mem.eql(u8, part.name, name)) return part;
    }

    return null;
}

fn value(line: []const u8) ?[]const u8 {
    const at = std.mem.indexOfScalar(u8, line, '=') orelse return null;
    return std.mem.trim(u8, line[at + 1 ..], " \t\r");
}

fn quoted(line: []const u8) ?[]const u8 {
    const text = value(line) orelse return null;

    if (text.len < 2 or text[0] != '"' or text[text.len - 1] != '"') return null;
    return text[1 .. text.len - 1];
}
