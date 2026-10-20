const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe = b.addExecutable(.{ .name = "neolk", .root_module = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize }) });
    const toml_dep = b.dependency("toml", .{ .target = target, .optimize = optimize });
    exe.root_module.addImport("toml", toml_dep.module("toml"));
    b.installArtifact(exe);
    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    const step = b.step("run", "Run neolk");
    step.dependOn(&run.step);
}
