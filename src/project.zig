const std = @import("std");

/// Removes a workspace's generated artifacts.
pub fn clean(io: std.Io) !void {
    std.Io.Dir.cwd().deleteTree(io, "build") catch |err| {
        if (err != error.FileNotFound) return err;
    };

    std.debug.print("cleaned build\n", .{});
}

/// Writes clangd metadata for the example payload.
pub fn setupIde(io: std.Io) !void {
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = "compile_commands.json",
        .data = "[{\"directory\":\".\",\"command\":\"zig cc -target aarch64-freestanding -ffreestanding -Iframework -c my_payload/main.c\",\"file\":\"my_payload/main.c\"}]\n",
    });

    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = ".clangd",
        .data = "CompileFlags:\n  CompilationDatabase: .\n",
    });

    std.debug.print("wrote compile_commands.json and .clangd\n", .{});
}
