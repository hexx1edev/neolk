# neolk

neolk is an LK(Little Kernel) surgery toolkit, that implements: binary patching framework, arbitrary code payload execution.
The loader for payloads and payloads are written in C, the toolkit is written in Zig 0.16.0.

## Building neolk

Run `zig build` and that's all - executable will wait for you in `zig-out` directory.

## Creating project

To create a new device project, make a `device.toml` file, refer to `template` directory for example project with simple patch and payload.

## Building project

To build project install `clang, lld, llvm tools` and `neolk` obvivously(it should be available in PATH).  
Run `neolk build`, final lk executable will be located in `build\lk.final.img`

## License

The project is licensed under GNU GPLv3.