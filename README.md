# letmove_msi_ws

Two Rust crates:

- `bof/` — `no_std` Beacon Object File (`letmove_msi.o`) for Cobalt Strike, using DCOM MsiServer + CreateCustomActionServer + SQLInstallDriverEx to install an ODBC driver on a local or remote host.
- `driver/` — sample ODBC driver DLL (`odbcpivot.dll`) exporting `ConfigDriver`.

Both crates deliberately avoid string overlap with prior public art.

## Build

```bash
# BoF (needs boflink + cargo-make)
cd bof && cargo make

# Driver (cross-compile from Linux/macOS)
rustup target add x86_64-pc-windows-gnu
cargo build -p odbcpivot --release --target x86_64-pc-windows-gnu
```

Artifacts:
- `bof/out/letmove_msi.x64.o` (and `letmove_msi.x86.o`)
- `target/x86_64-pc-windows-gnu/release/odbcpivot.dll`

## BoF usage (Cobalt Strike aggressor)

Argument layout — 7 wide strings in order, empty string for absent fields:

```
letmove_msi <local|remote> <host> <domain> <user> <pass> <driver> <dll>
```

- `mode`: `local` | `remote`
- `host`: target hostname (required for `remote`)
- `domain` / `user` / `pass`: alternate credentials (empty = current)
- `driver`: ODBC driver name to register
- `dll`: full target-side path to the driver DLL (place `odbcpivot.dll` there first)

## Driver behaviour

`ConfigDriver` collects the current process token context and appends one line per field to a log file. Path is `%PROGRAMDATA%\odbcpivot.dat` by default; override at compile time with `ODBCPIVOT_LOG`.

## License

MIT.
