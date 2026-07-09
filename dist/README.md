# Prebuilt Artifacts

Built from the current `master`. Rebuild from source with `cargo make` (bof) and `cargo build -p odbcpivot --release --target x86_64-pc-windows-gnu` (driver) if you want to verify.

## Files

| File | Target | Purpose |
|---|---|---|
| `letmove_msi.x64.o` | x86_64 COFF | BoF for x64 Beacon |
| `letmove_msi.x86.o` | i686 COFF | BoF for x86 Beacon |
| `odbcpivot.dll` | x86_64 PE | Sample ODBC driver payload with `ConfigDriver` export |

## SHA-256

Regenerate with `shasum -a 256 *`.
