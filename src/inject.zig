const std = @import("std");
const config = @import("config.zig");
const payloadBuilder = @import("payload.zig");

const magic: u32 = 0x58881688;
const header_size = 512;
const loader_capacity = 1168;

/// Injects the AArch64 mapper entry into the reserved bl2_ext window.
pub fn run(init: std.process.Init, device: config.DeviceConfig) !void {
    const source = std.Io.Dir.cwd().readFileAlloc(init.io, "build/lk.patched.img", init.gpa, .limited(128 * 1024 * 1024)) catch |patched_err| switch (patched_err) {
        error.FileNotFound => std.Io.Dir.cwd().readFileAlloc(init.io, device.image.path, init.gpa, .limited(128 * 1024 * 1024)) catch |image_err| switch (image_err) {
            error.FileNotFound => {
                std.debug.print("error: neither build/lk.patched.img nor input LK image exists: {s}\n", .{device.image.path});
                return error.InputImageNotFound;
            },
            else => return image_err,
        },
        else => return patched_err,
    };
    defer init.gpa.free(source);

    const header = findPartition(source, "bl2_ext") orelse return error.PartitionNotFound;
    const hook_offset: usize = @intCast(device.loader.injectPoint orelse return error.MissingInjectPoint);
    const loader_offset: usize = @intCast(device.loader.storageOffset orelse return error.MissingStorageOffset);
    const hook = header + header_size + hook_offset;
    const loader = header + header_size + loader_offset;

    const payload = try config.loadPayload(init, payloadBuilder.name);
    const load_addr = device.system.loadAddr orelse return error.MissingLoadAddress;
    const virtual_base = if (device.system.virtualBase) |text| std.fmt.parseInt(u64, text, 0) catch return error.InvalidVirtualBase else 0;
    const payload_offset: usize = @intCast(payload.injectPoint);

    if (payload_offset >= loader_capacity) return error.InvalidPayloadConfig;
    if (hook + 4 > source.len or loader + loader_capacity > source.len) return error.InvalidImage;

    const original_instruction = std.mem.readInt(u32, source[hook..][0..4], .little);
    const runtime_hook = virtual_base + load_addr + hook_offset;
    const original_target = decodeBranchLink(original_instruction, runtime_hook) orelse {
        std.debug.print("injection point image+0x{x} contains 0x{x}, not an AArch64 BL\n", .{ hook, original_instruction });
        return error.HookIsNotBranchLink;
    };

    const runtime_loader = virtual_base + load_addr + loader_offset;
    const payload_bytes = try payloadBuilder.build(init, device, payload, runtime_loader, original_target);
    defer init.gpa.free(payload_bytes);

    for (source[loader .. loader + loader_capacity]) |byte| if (byte != 0) return error.LoaderWindowOccupied;
    if (payload_bytes.len > loader_capacity) return error.PayloadTooLarge;

    @memcpy(source[loader..][0..payload_bytes.len], payload_bytes);
    const instruction = a64BranchLink(hook, loader) orelse return error.BranchOutOfRange;
    std.mem.writeInt(u32, source[hook..][0..4], instruction, .little);

    try std.Io.Dir.cwd().createDirPath(init.io, "build");
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "build/lk.injected.img", .data = source });
    std.debug.print("injected image+0x{x} -> loader_on_{s} image+0x{x}; original target 0x{x}; loader/payload ({d} bytes) image+0x{x}\n", .{ hook, payload.name, loader, original_target, payload_bytes.len, loader });
}

fn findPartition(bytes: []const u8, wanted: []const u8) ?usize {
    var offset: usize = 0;
    while (offset + header_size <= bytes.len and std.mem.readInt(u32, bytes[offset..][0..4], .little) == magic) {
        const size: usize = std.mem.readInt(u32, bytes[offset + 4 ..][0..4], .little);
        const name_end = std.mem.indexOfScalar(u8, bytes[offset + 8 .. offset + 40], 0) orelse 32;

        if (std.mem.eql(u8, bytes[offset + 8 .. offset + 8 + name_end], wanted)) return offset;

        const alignment: usize = if (std.mem.readInt(u32, bytes[offset + 48 ..][0..4], .little) == 0x58891689 and std.mem.readInt(u32, bytes[offset + 68 ..][0..4], .little) != 0) std.mem.readInt(u32, bytes[offset + 68 ..][0..4], .little) else 8;
        offset = std.mem.alignForward(usize, offset + header_size + size, alignment);
    }
    return null;
}

fn a64BranchLink(source: usize, target: usize) ?u32 {
    const delta: i64 = @as(i64, @intCast(target)) - @as(i64, @intCast(source));

    if (@mod(delta, 4) != 0) return null;

    const words = @divTrunc(delta, 4);
    if (words < -(1 << 25) or words >= (1 << 25)) return null;
    return 0x94000000 | (@as(u32, @bitCast(@as(i32, @intCast(words)))) & 0x03ffffff);
}

fn decodeBranchLink(instruction: u32, source: u64) ?u64 {
    if (instruction & 0xfc000000 != 0x94000000) return null;

    const raw: i64 = @intCast(instruction & 0x03ffffff);
    const words = if ((raw & (1 << 25)) != 0) raw - (1 << 26) else raw;
    return @as(u64, @bitCast(@as(i64, @bitCast(source)) + words * 4));
}
