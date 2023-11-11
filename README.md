# okbuild

![test-build](https://github.com/krscott/okbuild/actions/workflows/test-build.yml/badge.svg)

Header-only C library for bootstrapping a project build from only a compiler.

## Usage

Create a `build.c` file for your build script and include `okbuild.h`.

See [`build_example.c`](build_example.c) for an example build script.


### Example: Bootstrapping with gcc
```sh
gcc build.c -o build && ./build rebuild
```

### Example: Bootstrapping with msvc

```cmd
vcvars64.bat && cl build.c && build.exe rebuild
```

### Example: Bootstrapping with clang
```sh
clang -o build build.c && ./build rebuild
```

### Example: Bootstrapping with zig cc
```sh
zig cc -D__zig_cc__ -o build build.c && ./build rebuild
```
```cmd
zig cc -D__zig_cc__ -o build.exe build.c && build.exe rebuild
```

## Why?

Experimentation, fun, and because I really don't like cmake.

I stole this idea from [tsoding](https://github.com/tsoding/nobuild), but wanted something a
little more "idiomatic".
