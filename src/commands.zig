const std = @import("std");
const config = @import("config.zig");
const image = @import("image.zig");
const project = @import("project.zig");
const inject = @import("inject.zig");
const payloadBuilder = @import("payload.zig");
const signer = @import("sign.zig");

pub const version = "0.1.0";

pub fn help() void {
    std.debug.print("neolk {s}\n\n  patch <apply|search>\n  inject\n  build\n  sign <filename> [override]\n  setup-ide\n  clean\n  version\n", .{version});
}

pub fn usage() error{InvalidInput} {
    std.debug.print("error: invalid command arguments\n", .{});
    return error.InvalidInput;
}

pub fn run(init: std.process.Init, command: []const u8, first: ?[]const u8, second: ?[]const u8) !void {
    if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help")) return help();
    if (std.mem.eql(u8, command, "version")) return std.debug.print("neolk {s}\n", .{version});

    if (std.mem.eql(u8, command, "clean")) return project.clean(init.io);
    if (std.mem.eql(u8, command, "setup-ide")) return project.setupIde(init.io);

    if (std.mem.eql(u8, command, "patch")) return image.patch(init, try config.load(init), first orelse return usage());
    if (std.mem.eql(u8, command, "sign")) return signer.run(init, first orelse return usage(), second orelse "override");
    if (std.mem.eql(u8, command, "inject")) return inject.run(init, try config.load(init));

    if (std.mem.eql(u8, command, "build")) {
        const device = try config.load(init);
        try image.patch(init, device, "apply");

        const injected = try payloadBuilder.anyPresent(init);
        if (injected) {
            try inject.run(init, device);
        } else {
            std.debug.print("build: no payloads configured; skipped loader build and injection\n", .{});
        }

        const artifact = if (injected) "build/lk.injected.img" else "build/lk.patched.img";
        const final_source = if (device.bypass) |mode| blk: {
            try signer.run(init, artifact, mode);
            break :blk if (injected) "build/lk.injected-signed.img" else "build/lk.patched-signed.img";
        } else artifact;

        const final_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, final_source, init.gpa, .limited(256 * 1024 * 1024));
        defer init.gpa.free(final_bytes);

        try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "build/lk.final.img", .data = final_bytes });
        std.debug.print("build: wrote build/lk.final.img\n", .{});
        return;
    }
    return usage();
}
