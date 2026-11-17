# neolk

neolk is a MediaTek LK tinkering framework, written in Rust.

## Features

- [x] Binary patches
- [x] Re-signing LK subimages using MediaTek security exploits
- [ ] Arbitrary payload execution

## Building

Build project with `cargo build`.

## Usage

Create new device project(see example in `template`), run neolk in project root.  
neolk will read device config, apply patches and re-sign LK image if needed.  
Final LK image is placed in `build/lk.img`.

## License

No license at all, do whatever you want!