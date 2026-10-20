const std = @import("std");
const crypto = @import("crypto.zig");

const magic: u32 = 0x58881688;
const header_size = 512;

const Part = struct {
    start: usize,
    data_start: usize,
    data_size: usize,
    end: usize,
    name: []const u8,
    alignment: usize,
    extended: bool,
};

const Tlv = struct {
    tag: u8,
    start: usize,
    value_start: usize,
    value_len: usize,
    end: usize,
};

const CertFields = struct {
    header_oid: []const u8,
    image_oid: []const u8,
    header_hash: [32]u8,
    image_hash: [32]u8,
};

/// Applies lkpatcher's `override` cert-bypass strategy and writes <stem>-signed.<ext>.
pub fn run(init: std.process.Init, filename: []const u8, mode: []const u8) !void {
    if (!std.mem.eql(u8, mode, "override")) return error.UnsupportedBypassMode;

    const source = try std.Io.Dir.cwd().readFileAlloc(init.io, filename, init.gpa, .limited(256 * 1024 * 1024));
    defer init.gpa.free(source);

    const parts = try parseParts(init.gpa, source);
    defer init.gpa.free(parts);

    var replacements = std.AutoHashMap(usize, []u8).init(init.gpa);
    defer {
        var values = replacements.valueIterator();
        while (values.next()) |value| init.gpa.free(value.*);
        replacements.deinit();
    }

    for (parts, 0..) |part, index| {
        if (std.mem.startsWith(u8, part.name, "cert")) continue;

        const cert_index = secondCertificate(parts, index) orelse continue;
        const cert = parts[cert_index];

        const fields = parseCert(source[cert.data_start .. cert.data_start + cert.data_size]) orelse continue;
        const header_hash = crypto.sha256(source[part.start .. part.start + header_size]);
        const image_hash = hashPadded(source[part.data_start .. part.data_start + part.data_size]);

        if (std.mem.eql(u8, &fields.header_hash, &header_hash) and std.mem.eql(u8, &fields.image_hash, &image_hash)) {
            continue;
        }
        const replacement = try buildOverride(init.gpa, fields, header_hash, image_hash, source[cert.data_start .. cert.data_start + cert.data_size]);

        try replacements.put(cert_index, replacement);
        std.debug.print("cert bypass override: {s} cert2 {d} -> {d} bytes\n", .{ part.name, cert.data_size, replacement.len });
    }

    const output = try signedName(init.gpa, filename);
    defer init.gpa.free(output);

    if (replacements.count() == 0) {
        try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = output, .data = source });
        std.debug.print("sign: no modified, parseable cert2 partitions; copied {s}\n", .{output});
        return;
    }

    var rebuilt = std.ArrayList(u8).empty;
    defer rebuilt.deinit(init.gpa);
    for (parts, 0..) |part, index| {
        if (replacements.get(index)) |data| {
            var header: [header_size]u8 = undefined;
            @memcpy(&header, source[part.start .. part.start + header_size]);
            std.mem.writeInt(u32, header[4..8], @intCast(data.len), .little);

            if (part.extended) std.mem.writeInt(u32, header[72..76], @intCast(@as(u64, data.len) >> 32), .little);

            try rebuilt.appendSlice(init.gpa, &header);
            try rebuilt.appendSlice(init.gpa, data);
            const padding = paddingFor(data.len, part.alignment);
            try rebuilt.appendNTimes(init.gpa, 0, padding);
        } else {
            try rebuilt.appendSlice(init.gpa, source[part.start..part.end]);
        }
    }

    try rebuilt.appendSlice(init.gpa, source[parts[parts.len - 1].end..]);
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = output, .data = rebuilt.items });
    std.debug.print("sign: wrote {s}\n", .{output});
}

fn parseParts(a: std.mem.Allocator, source: []const u8) ![]Part {
    var list = std.ArrayList(Part).empty;
    var offset: usize = 0;
    while (offset + header_size <= source.len and read32(source, offset) == magic) {
        const data_size: usize = read32(source, offset + 4);
        const extended = read32(source, offset + 48) == 0x58891689;

        const full_size: usize = if (extended) data_size | (@as(usize, read32(source, offset + 72)) << 32) else data_size;
        const alignment: usize = if (extended and read32(source, offset + 68) != 0) read32(source, offset + 68) else 8;
        const data_start = offset + header_size;
        const end = data_start + full_size + paddingFor(full_size, alignment);

        if (end > source.len) return error.InvalidImage;

        const end_name = std.mem.indexOfScalar(u8, source[offset + 8 .. offset + 40], 0) orelse 32;
        try list.append(a, .{ .start = offset, .data_start = data_start, .data_size = full_size, .end = end, .name = source[offset + 8 .. offset + 8 + end_name], .alignment = alignment, .extended = extended });
        if (extended and read32(source, offset + 64) == 1) break;

        offset = end;
    }

    if (list.items.len == 0) return error.InvalidImage;
    return list.toOwnedSlice(a);
}

fn secondCertificate(parts: []const Part, index: usize) ?usize {
    var found: usize = 0;
    var at = index + 1;
    while (at < parts.len and std.mem.startsWith(u8, parts[at].name, "cert")) : (at += 1) {
        found += 1;
        if (found == 2) return at;
    }
    return null;
}

fn parseCert(raw: []const u8) ?CertFields {
    const outer = tlv(raw, 0) orelse return null;
    if (outer.tag != 0x30 or outer.end != raw.len) return null;

    const inner = tlv(raw, outer.value_start) orelse return null;
    if (inner.tag != 0x30) return null;
    var nodes: [15]Tlv = undefined;
    var at = inner.value_start;

    for (0..nodes.len) |index| {
        nodes[index] = tlv(raw, at) orelse return null;
        at = nodes[index].end;
    }

    if (nodes[9].tag != 0x06 or nodes[10].tag != 0x03 or nodes[13].tag != 0x06 or nodes[14].tag != 0x03) {
        return null;
    }

    const image_hash = bitStringHash(raw, nodes[10]) orelse return null;
    const header_hash = bitStringHash(raw, nodes[14]) orelse return null;

    return .{
        .header_oid = raw[nodes[13].start..nodes[13].end],
        .image_oid = raw[nodes[9].start..nodes[9].end],
        .header_hash = header_hash,
        .image_hash = image_hash,
    };
}

fn bitStringHash(raw: []const u8, node: Tlv) ?[32]u8 {
    if (node.value_len != 33 or raw[node.value_start] != 0) return null;

    var hash: [32]u8 = undefined;
    @memcpy(&hash, raw[node.value_start + 1 .. node.end]);

    return hash;
}

fn buildOverride(a: std.mem.Allocator, fields: CertFields, header_hash: [32]u8, image_hash: [32]u8, original: []const u8) ![]u8 {
    var content = std.ArrayList(u8).empty;
    defer content.deinit(a);
    try content.appendSlice(a, fields.header_oid);
    try appendBitString(&content, a, header_hash);
    try content.appendSlice(a, fields.image_oid);
    try appendBitString(&content, a, image_hash);

    var out = std.ArrayList(u8).empty;

    defer out.deinit(a);
    try out.append(a, 0xa0);
    try appendDerLength(&out, a, content.items.len);
    try out.appendSlice(a, content.items);
    try out.appendSlice(a, original);

    return out.toOwnedSlice(a);
}

fn appendBitString(out: *std.ArrayList(u8), a: std.mem.Allocator, hash: [32]u8) !void {
    try out.appendSlice(a, &.{ 0x03, 0x21, 0x00 });
    try out.appendSlice(a, &hash);
}

fn appendDerLength(out: *std.ArrayList(u8), a: std.mem.Allocator, length: usize) !void {
    if (length < 0x80) return out.append(a, @intCast(length));
    var bytes: [8]u8 = undefined;
    var count: usize = 0;
    var value = length;

    while (value != 0) : (value >>= 8) {
        bytes[7 - count] = @intCast(value & 0xff);
        count += 1;
    }

    try out.append(a, 0x80 | @as(u8, @intCast(count)));
    try out.appendSlice(a, bytes[8 - count ..]);
}

fn tlv(raw: []const u8, start: usize) ?Tlv {
    if (start + 2 > raw.len) return null;

    var at = start + 1;
    const first = raw[at];
    at += 1;

    var length: usize = 0;

    if (first < 0x80) length = first else {
        const count = first & 0x7f;
        if (count == 0 or count > 8 or at + count > raw.len) return null;
        for (raw[at .. at + count]) |byte| length = (length << 8) | byte;
        at += count;
    }

    if (at + length > raw.len) return null;

    return .{ .tag = raw[start], .start = start, .value_start = at, .value_len = length, .end = at + length };
}

fn hashPadded(data: []const u8) [32]u8 {
    const padding = (16 - data.len % 16) % 16;

    if (padding == 0) return crypto.sha256(data);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);

    const zeroes = [_]u8{0} ** 15;
    hasher.update(zeroes[0..padding]);

    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    return digest;
}

fn paddingFor(length: usize, alignment: usize) usize {
    return if (alignment == 0) 0 else (alignment - length % alignment) % alignment;
}

fn read32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn signedName(a: std.mem.Allocator, filename: []const u8) ![]u8 {
    const dot = std.mem.lastIndexOfScalar(u8, filename, '.') orelse return std.fmt.allocPrint(a, "{s}-signed", .{filename});
    return std.fmt.allocPrint(a, "{s}-signed{s}", .{ filename[0..dot], filename[dot..] });
}
