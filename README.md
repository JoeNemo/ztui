# ztui — z/OS TUI Tools

Interactive terminal tools for z/OS over SSH.  No TSO, no ISPF, no 3270 — just a Unix terminal.

## Tools

| Tool | Description |
|------|-------------|
| `nczst` | Job status (like SDSF ST) |
| `nczda` | Display active address spaces (like SDSF DA) |
| `nczlog` | SYSLOG browser |
| `nczps` | Process viewer (USS) |
| `nczdisp` | MVS DISPLAY command browser |
| `nctso` | Interactive TSO command session |

## Building

Requires z/OS with:
- `xlclang` / `xlclang++`
- zopen `ncurses` and `zoslib`

```sh
git submodule update --init
cd build
./build.sh
```

## Dependencies

- [zowe-common-c](https://github.com/zowe/zowe-common-c) — z/OS common libraries (git submodule in `deps/`)

## License

EPL-2.0.  See individual source files.
