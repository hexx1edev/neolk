const std = @import("std");
const config = @import("config.zig");

pub const name = "my_payload";

/// Returns whether the currently supported payload is configured in this workspace.
/// A workspace without this file is patch-only and must not install the loader.
pub fn anyPresent(init: std.process.Init) !bool {
    const file = std.Io.Dir.cwd().openFile(init.io, "my_payload/payload.toml", .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    file.close(init.io);
    return true;
}

/// Builds the generic C loader, generated hook wrapper, and C payload in WSL.
pub fn build(init: std.process.Init, device: config.DeviceConfig, payload: config.PayloadConfig, runtime_address: u64, original_target: u64) ![]u8 {
    try std.Io.Dir.cwd().createDirPath(init.io, "build");
    const script = try std.fmt.allocPrint(
        init.gpa,
        "ENTRY(loader_on_{s})\nSECTIONS {{\n  . = 0x{x};\n  .text : {{ build/neolk-loader-generated.o(.text.entry) build/neolk-loader.o(.text*) build/neolk-loader-generated.o(.text*) }}\n  ASSERT(. <= 0x{x}, \"loader is larger than the payload offset\")\n  . = 0x{x};\n  .payload : {{ build/neolk-payload.o(.text*) }}\n  .rodata : {{ *(.rodata*) }}\n  .data : {{ *(.data*) }}\n  /DISCARD/ : {{ *(.eh_frame*) *(.comment*) *(.note*) }}\n}}\n",
        .{ payload.name, runtime_address, runtime_address + payload.injectPoint, runtime_address + payload.injectPoint },
    );
    defer init.gpa.free(script);
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "build/neolk-payload.ld", .data = script });

    const source = try std.fmt.allocPrint(init.gpa, "{s}/main.c", .{payload.name});
    defer init.gpa.free(source);
    const printf_define = try std.fmt.allocPrint(init.gpa, "-DNEOLK_PRINTF_ADDRESS=0x{x}", .{device.system.printf orelse return error.MissingPrintfAddress});
    defer init.gpa.free(printf_define);
    const generated = try std.fmt.allocPrint(
        init.gpa,
        "#include <loader.h>\nextern neolk_word neolk_payload_main(neolk_word, neolk_word, neolk_word, neolk_word, neolk_word, neolk_word, neolk_word, neolk_word);\nconst struct neolk_payload neolk_payloads[] = {{ {{ \"{s}\", neolk_payload_main }} }};\nconst unsigned long long neolk_payload_count = 1;\n__attribute__((section(\".text.entry\"))) neolk_word loader_on_{s}(neolk_word x0, neolk_word x1, neolk_word x2, neolk_word x3, neolk_word x4, neolk_word x5, neolk_word x6, neolk_word x7) {{ return loader_run_payload(\"{s}\", (neolk_call)0x{x}ULL, x0, x1, x2, x3, x4, x5, x6, x7); }}\n",
        .{ payload.name, payload.name, payload.name, original_target },
    );
    defer init.gpa.free(generated);
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = "build/neolk-loader-generated.c", .data = generated });
    const elf = "build/neolk-loader.elf";
    const flat = "build/neolk-loader.bin";
    try run(init, &.{ "clang", "--target=aarch64-none-elf", "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-mcmodel=large", "-nostdlib", "-I", "framework", printf_define, "-Dmain=neolk_payload_main", "-c", source, "-o", "build/neolk-payload.o" });
    try run(init, &.{ "clang", "--target=aarch64-none-elf", "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-mcmodel=large", "-nostdlib", "-I", "framework", printf_define, "-c", "framework/loader.c", "-o", "build/neolk-loader.o" });
    try run(init, &.{ "clang", "--target=aarch64-none-elf", "-ffreestanding", "-fno-builtin", "-fno-pic", "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-mcmodel=large", "-nostdlib", "-I", "framework", "-c", "build/neolk-loader-generated.c", "-o", "build/neolk-loader-generated.o" });
    try run(init, &.{ "ld.lld", "-T", "build/neolk-payload.ld", "-o", elf, "build/neolk-loader.o", "build/neolk-loader-generated.o", "build/neolk-payload.o" });
    try run(init, &.{ "llvm-objcopy", "-O", "binary", elf, flat });
    return try std.Io.Dir.cwd().readFileAlloc(init.io, flat, init.gpa, .limited(16 * 1024 * 1024));
}

fn run(init: std.process.Init, argv: []const []const u8) !void {
    const cwd = try std.Io.Dir.cwd().realPathFileAlloc(init.io, ".", init.gpa);
    defer init.gpa.free(cwd);
    const wsl_argv = try std.mem.concat(init.gpa, []const u8, &.{ &.{ "wsl.exe", "--cd", cwd, "--" }, argv });
    defer init.gpa.free(wsl_argv);
    const result = try std.process.run(init.gpa, init.io, .{ .argv = wsl_argv });
    defer init.gpa.free(result.stdout);
    defer init.gpa.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) return error.PayloadBuildFailed;
}
