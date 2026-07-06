# msi_lateral_mv → Rust BoF Port

**Date:** 2026-07-06
**Status:** Design approved, awaiting implementation plan

## Goal

Port the [werdhaihai/msi_lateral_mv](https://github.com/werdhaihai/msi_lateral_mv) BoF (C, ~1300 LoC across `bof/`) to a Rust `no_std` BoF built on the [joaoviictorti/rustbof](https://github.com/joaoviictorti/rustbof) template. The DLL payload (`sqldriverdll/`) is out of scope and remains C/C++.

The port preserves the underlying technique: use the MSI Server COM object over DCOM to install/configure an ODBC driver whose custom action executes an attacker-supplied DLL on a local or remote host, optionally under alternate or domain credentials.

## Non-Goals

- No port of `sqldriverdll/`.
- No new capability beyond the C original (no additional lateral-movement primitives, no persistence, no bundled loader).
- No Cobalt Strike aggressor script rewrite; usage snippet documented in README only.

## Layout

Standalone crate placed at `LetMoveMSI/msi_lateral_mv_rs/`:

```
msi_lateral_mv_rs/
├── Cargo.toml           # crate-type = ["staticlib"]
├── Makefile.toml        # cargo-make → boflink → .o
├── rust-toolchain.toml  # nightly
├── README.md            # usage + build
└── src/
    ├── lib.rs           # #[rustbof::main] entry, arg dispatch
    ├── args.rs          # DataParser wrapper → Args
    ├── com.rs           # IUnknown/IDispatch/IMsiServer vtables + GUIDs
    ├── auth.rs          # COAUTHIDENTITY/COAUTHINFO builder + CoSetProxyBlanket
    ├── msi.rs           # port of msilat.c orchestration
    └── utils.rs         # wide-string, GUID gen, HRESULT format
```

Dependencies (`Cargo.toml`):
- `rustbof` — git = "https://github.com/joaoviictorti/rustbof"
- `windows-sys` 0.59 with features: `Win32_Foundation`, `Win32_System_Com`, `Win32_System_Ole`, `Win32_System_Rpc`, `Win32_System_Variant`, `Win32_Security_Authentication_Identity`

Release profile mirrors rustbof examples: `opt-level = "z"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`, `lto = true`.

## Argument Interface

Simplified from the C original's six positional variants to a single subcommand form:

```
letmove_msi <local|remote> [host] [--domain D] [--user U --pass P] <driver> <dll>
```

Parsed as wide strings via `DataParser::get_wstr()`. Mapping to internal enums:

```rust
enum Mode { Local, Remote(WString) }
enum Creds { Current, Alt { user, pass }, Domain { domain, user, pass } }
struct Args { mode: Mode, creds: Creds, driver: WString, dll: WString }
```

Rules:
- `remote` requires `host` (first positional after mode).
- `--user` and `--pass` must appear together; `--domain` requires both.
- Missing/malformed → `eprintln!` usage + return.

**Why:** the C variant matrix (6 signatures × positional-only) is awkward to invoke from operator scripts. Flag-based parsing is friendlier and only affects the argument-decoding layer; the underlying MSI/DCOM logic is unchanged.

## Data Flow

`lib.rs::main`:

1. Parse `Args` (or bail with usage).
2. `CoInitialize(NULL)`.
3. `auth::build(&creds)` → `COAUTHINFO` (`pAuthIdentityData = NULL` for `Current`).
4. `CoInitializeSecurity(..., PKT_INTEGRITY, IMPERSONATE, &sole_auth_list, EOAC_NONE, ...)`.
5. `CoCreateInstanceEx(CLSID_MsiServer, NULL, CLSCTX_LOCAL_SERVER|CLSCTX_REMOTE_SERVER, server_info?, 1, &MULTI_QI[IID_IMsiServer])` → `*mut IMsiServer` (an `IUnknown`).
6. If remote: `SetupAuthOnParentIUnknownCastToIID(pMsiServer, &auth, IID_IMsiServer)` — i.e. `pMsiServer->QueryInterface` then `CoSetProxyBlanket` on the returned pointer — → `pMsiServerAuthd`.
7. `msi::get_custom_action_server(pMsiServerAuthd, &auth)` → `pMsiCustomAction`:
   - `LoadLibraryW("msi.dll")` → `GetProcAddress("DllGetClassObject")` → `IClassFactory` for `CLSID_MSIRemoteApi` → `CreateInstance(IID_IMsiRemoteAPI)` → fake `pRemApi`.
   - Cast `pMsiServerAuthd` to `IMsiConfigurationManager` and call `CreateCustomActionServer(icac64Impersonated, fakePid=4, pRemApi, envBlock, envSize, 0, cookie, &cookieSize, &pMsiAction, &outServerPid, FALSE)`.
   - `SetupAuthOnParentIUnknownCastToIID(pMsiAction, &auth, IID_IMsiCustomAction)` → `pAuthedAction`.
8. `msi::install_driver(pAuthedAction, driver, dll)`:
   - Split `dll` path into directory + filename via `PathFindFileNameW` + `PathRemoveFileSpecW`.
   - Build ODBC driver-info block: three NUL-terminated wide sections `<drivername>\0Driver=<file>\0Setup=<file>\0\0`.
   - `pAuthedAction->SQLInstallDriverEx(len, driver_info, path_in, path_out, 256, &path_out_len, 2 /* ODBC_INSTALL_COMPLETE */, &usage_count, &raw_rc)`.
   - `pAuthedAction->SQLConfigDriver(1 /* ODBC_INSTALL_DRIVER */, drivername, NULL, msg_buf, 256, &msg_len, &config_rc)`.
   - On failure: `pAuthedAction->SQLInstallerError(1, &err_code, err_msg, 256, &err_msg_len)` and print.
9. Release chain: `pAuthedAction`, `pMsiServerAuthd`, free auth buffers, `CoUninitialize`.

## COM Bindings

Raw `#[repr(C)]` vtables in `com.rs`, mirroring `bof/msilat.h`:

```rust
#[repr(C)] pub struct IUnknownVtbl { QueryInterface, AddRef, Release }
#[repr(C)] pub struct IMsiConfigurationManagerVtbl { unk: IUnknownVtbl, /* pad slots + */ CreateCustomActionServer }
#[repr(C)] pub struct IMsiCustomActionVtbl { unk: IUnknownVtbl, /* pad slots + */ SQLInstallDriverEx, SQLConfigDriver, SQLInstallerError }
#[repr(C)] pub struct IClassFactoryVtbl { unk: IUnknownVtbl, CreateInstance, LockServer }
```

GUIDs as `const GUID` copied verbatim from the C source: `CLSID_MsiServer`, `IID_IMsiServer`, `CLSID_MSIRemoteApi`, `IID_IMsiRemoteAPI`, `IID_IMsiCustomAction`, `IID_IClassFactory`. No `windows` crate — kept lean for `no_std` and small COFF footprint. `windows-sys` supplies the flat APIs (`CoCreateInstanceEx`, `CoSetProxyBlanket`, `CoInitializeSecurity`, `LoadLibraryW`, `GetProcAddress`, `GetEnvironmentStringsW`, `PathFindFileNameW`, `PathRemoveFileSpecW`).

## Auth Building

`auth.rs::build(&Creds)` returns owned wide-string buffers plus initialized structs. Layout matches `bof/comstuff.c`:

- `COAUTHIDENTITY { User, UserLength, Domain, DomainLength, Password, PasswordLength, Flags=SEC_WINNT_AUTH_IDENTITY_UNICODE }`.
- `COAUTHINFO { dwAuthnSvc=RPC_C_AUTHN_WINNT, pAuthIdentityData=&auth_id, dwImpersonationLevel=RPC_C_IMP_LEVEL_IMPERSONATE, dwAuthnLevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, ... }`.
- `COSERVERINFO { pwszName=host, pAuthInfo=&auth_info }` for `Remote`; for `Local` alt-user, `pwszName=NULL` still uses `pAuthInfo`.

Ownership held by a struct returned from `build()` so wide buffers outlive the COM call.

## Error Handling

Small macro in `utils.rs`:

```rust
macro_rules! hr_check {
    ($hr:expr, $ctx:literal) => {
        let _hr = $hr;
        if _hr < 0 { eprintln!("[!] {} failed: 0x{:08X}", $ctx, _hr as u32); return; }
    };
}
```

No `?` operator (would require custom `Error` + `From` impls). Manual `Release()` before every early return in the COM path; encapsulated via a small `ComPtr` newtype whose `Drop` calls `Release`, so control-flow exits clean up automatically.

## Testing

BoF context is not conducive to unit testing (`no_std`, resolved at load time, side-effectful COM calls). Verification is manual:

- Build: `cargo make` produces `letmove_msi.o`.
- Sanity: `llvm-objdump -h letmove_msi.o` shows expected COFF sections and no unresolved externs beyond Beacon-resolvable imports.
- Functional: load in a Cobalt Strike / Havoc lab against a Windows target with MSI service running; verify DLL executes on target (both local alt-user and remote paths).

## Build & Release

- `cargo make` (default task) → `boflink` link → `target/.../letmove_msi.o`.
- README documents: prerequisites (nightly, boflink, cargo-make), build command, argument syntax, DLL-placement caveat inherited from upstream.
- License: MIT (matches upstream posture; single `LICENSE` file at crate root).

## Out of Scope / Deferred

- Payload DLL port to Rust.
- OPSEC hardening (indirect syscalls, string obfuscation) beyond what rustbof gives.
- Aggressor/CNA integration script.
- Windows on ARM64 target.

## Open Questions

None at design time; DISPID name strings and exact `InstallProduct` argument encoding will be lifted verbatim from `bof/msilat.c` during implementation.
