const std = @import("std");
const commands = @import("commands.zig");

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();

    _ = args.next();

    const command = args.next() orelse {
        commands.help();
        return;
    };

    const first = args.next();
    const second = args.next();

    if (args.next() != null) return commands.usage();

    try commands.run(init, command, first, second);
}
