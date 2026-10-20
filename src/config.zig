const std = @import("std");
const Init = std.process.Init;

pub const System = struct {
    virtualBase: ?[]const u8 = null,
    loadAddr: ?u64 = null,
    printf: ?u64 = null,
    malloc: ?u64 = null,
};

pub const Loader = struct {
    injectPoint: ?u64 = null,
    storageOffset: ?u64 = null,
};

pub const DeviceConfig = struct {
    name: []const u8,
    bypass: ?[]const u8,
    image: struct { path: []const u8 },
    system: System,
    loader: Loader,
};

pub const PayloadConfig = struct {
    name: []const u8,
    injectPoint: u64,
};

/// Loads the scalar device configuration.
pub fn load(init: Init) !DeviceConfig {
    const text = try std.Io.Dir.cwd().readFileAlloc(init.io, "device.toml", init.arena.allocator(), .limited(1024 * 1024));
    var section: []const u8 = "";
    var result = DeviceConfig{ .name = "", .bypass = null, .image = .{ .path = "" }, .system = .{}, .loader = .{} };

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |rawLine| {
        const line = std.mem.trim(u8, rawLine, " \t\r");
        if (line.len > 2 and line[0] == '[' and line[line.len - 1] == ']') {
            section = line[1 .. line.len - 1];
            continue;
        }

        const equals = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..equals], " \t");
        const value = std.mem.trim(u8, line[equals + 1 ..], " \t\r");
        const string = unquote(value);

        if (std.mem.eql(u8, section, "device") and std.mem.eql(u8, key, "name")) {
            result.name = string;
        } else if (std.mem.eql(u8, section, "device") and std.mem.eql(u8, key, "bypass")) {
            result.bypass = string;
        } else if (std.mem.eql(u8, section, "image") and std.mem.eql(u8, key, "path")) {
            result.image.path = string;
        } else if (std.mem.eql(u8, section, "system.bl2_ext")) {
            if (std.mem.eql(u8, key, "virtual_base")) result.system.virtualBase = string;
            if (std.mem.eql(u8, key, "load_addr")) result.system.loadAddr = parse(value);
            if (std.mem.eql(u8, key, "printf")) result.system.printf = parse(value);
            if (std.mem.eql(u8, key, "malloc")) result.system.malloc = parse(value);
        } else if (std.mem.eql(u8, section, "loader.bl2_ext")) {
            if (std.mem.eql(u8, key, "inject_point")) result.loader.injectPoint = parse(value);
            if (std.mem.eql(u8, key, "storage_offset")) result.loader.storageOffset = parse(value);
        }
    }

    if (result.name.len == 0 or result.image.path.len == 0) return error.InvalidConfig;
    return result;
}

/// Loads the currently supported payload configuration.
pub fn loadPayload(init: Init, name: []const u8) !PayloadConfig {
    const path = try std.fmt.allocPrint(init.arena.allocator(), "{s}/payload.toml", .{name});
    const text = try std.Io.Dir.cwd().readFileAlloc(init.io, path, init.arena.allocator(), .limited(1024 * 1024));
    var section: []const u8 = "";
    var injectPoint: ?u64 = null;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |rawLine| {
        const line = std.mem.trim(u8, rawLine, " \t\r");
        if (line.len > 2 and line[0] == '[' and line[line.len - 1] == ']') {
            section = line[1 .. line.len - 1];
            continue;
        }

        const equals = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..equals], " \t");
        const value = std.mem.trim(u8, line[equals + 1 ..], " \t\r");
        if (std.mem.eql(u8, section, name) and std.mem.eql(u8, key, "inject_point")) injectPoint = parse(value);
    }

    return .{ .name = name, .injectPoint = injectPoint orelse return error.InvalidPayloadConfig };
}

fn unquote(value: []const u8) []const u8 {
    if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') return value[1 .. value.len - 1];
    return value;
}

fn parse(value: []const u8) ?u64 {
    return std.fmt.parseInt(u64, unquote(value), 0) catch null;
}
