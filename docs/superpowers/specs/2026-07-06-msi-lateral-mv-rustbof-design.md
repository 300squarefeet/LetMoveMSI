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
2. `CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)`.
3. `auth::build(&creds)` → `Option<(COAUTHIDENTITY, COAUTHINFO, COSERVERINFO)>` (None for `Current`).
4. `CoCreateInstanceEx(CLSID_MsiServer, NULL, CLSCTX_LOCAL_SERVER|CLSCTX_REMOTE_SERVER, server_info, 1 MULTI_QI[IID_IDispatch])` → `*mut IDispatch`.
5. If alt/domain: `CoSetProxyBlanket(disp, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, &auth_id, EOAC_DEFAULT)`.
6. `msi::install(disp, &driver, &dll)` — orchestrates the MSI Server call sequence.
7. `disp->Release()`; `CoUninitialize()`.

`msi.rs::install` mirrors `bof/msilat.c` step-for-step, invoking `IDispatch::Invoke` for each MSI Server method (OpenDatabase → CreateRecord → StringData set → InstallProduct) with property string `ACTION=INSTALL ODBCDRIVER=<name> DLLPATH=<path>` (exact tokenisation lifted from the C source during implementation). DISPIDs resolved via `GetIDsOfNames` on first use and cached in locals.

## COM Bindings

Raw `#[repr(C)]` vtables in `com.rs`:

```rust
#[repr(C)] pub struct IUnknownVtbl { QueryInterface, AddRef, Release }
#[repr(C)] pub struct IDispatchVtbl { unk: IUnknownVtbl, GetTypeInfoCount, GetTypeInfo, GetIDsOfNames, Invoke }
#[repr(C)] pub struct IMsiServerVtbl { disp: IDispatchVtbl /* only Invoke used */ }
```

GUIDs as `const GUID` (CLSID_MsiServer `000C101C-0000-0000-C000-000000000046`, IID_IDispatch `00020400-0000-0000-C000-000000000046`). No `windows` crate — kept lean for `no_std` and small COFF footprint.

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
