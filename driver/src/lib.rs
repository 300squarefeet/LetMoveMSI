#![no_std]
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    CloseHandle, FALSE, HANDLE, LocalFree, TRUE,
};
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_ELEVATION,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER, TokenElevation,
    TokenIntegrityLevel, TokenStatistics, TokenUser,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_ALWAYS,
    WriteFile,
};
use windows_sys::Win32::System::Memory::{
    GetProcessHeap, HEAP_ZERO_MEMORY, HeapAlloc, HeapFree,
};
use windows_sys::Win32::System::SystemServices::SECURITY_MANDATORY_LOW_RID;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
};
use windows_sys::Win32::UI::Shell::SHGetFolderPathW;

// Compile-time overridable log path. Windows-style, wide-encoded at runtime.
const LOG_ENV_DEFAULT: &str = "%PROGRAMDATA%\\odbcpivot.dat";
const LOG_PATH_ASCII: &str = match option_env!("ODBCPIVOT_LOG") {
    Some(s) => s,
    None => LOG_ENV_DEFAULT,
};

// Integrity-level thresholds (windows-sys does not always export High/Medium).
const IL_LOW: u32 = 0x1000;
const IL_MEDIUM: u32 = 0x2000;
const IL_HIGH: u32 = 0x3000;

#[inline]
fn invalid_handle() -> HANDLE {
    // INVALID_HANDLE_VALUE == (HANDLE)-1
    -1isize as *mut c_void
}

unsafe fn wide(s: &str, out: &mut [u16]) -> usize { unsafe {
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
                    expanded[idx] = folder[j];
                    idx += 1;
                    j += 1;
                }
            }
            i += b"%PROGRAMDATA%".len();
        } else {
            expanded[idx] = bytes[i] as u16;
            idx += 1;
            i += 1;
        }
    }
    let n = idx.min(out.len() - 1);
    for k in 0..n {
        out[k] = expanded[k];
    }
    out[n] = 0;
    n
}}

unsafe fn write_all(h: HANDLE, buf: &[u8]) { unsafe {
    let mut w: u32 = 0;
    let _ = WriteFile(h, buf.as_ptr(), buf.len() as u32, &mut w, null_mut());
}}

fn fmt_line(out: &mut [u8], line: &str) -> usize {
    let bytes = line.as_bytes();
    let n = bytes.len().min(out.len().saturating_sub(1));
    out[..n].copy_from_slice(&bytes[..n]);
    out[n] = b'\n';
    n + 1
}

// Minimal wide -> ascii stripping (ASCII assumption for log content).
unsafe fn wide_to_ascii(w: *const u16, out: &mut [u8]) -> usize { unsafe {
    if w.is_null() {
        return 0;
    }
    let mut i = 0;
    while i < out.len() {
        let c = *w.add(i);
        if c == 0 {
            break;
        }
        out[i] = (c & 0xff) as u8;
        i += 1;
    }
    i
}}

unsafe fn append_line(msg: &str) { unsafe {
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
    if h.is_null() || h == invalid_handle() {
        return;
    }
    let mut buf = [0u8; 512];
    let n = fmt_line(&mut buf, msg);
    write_all(h, &buf[..n]);
    CloseHandle(h);
}}

fn integrity_tag(rid: u32) -> &'static str {
    if rid >= IL_HIGH {
        "hi"
    } else if rid >= IL_MEDIUM {
        "med"
    } else if rid >= IL_LOW {
        "lo"
    } else if rid >= SECURITY_MANDATORY_LOW_RID as u32 {
        "lo"
    } else {
        "unt"
    }
}

unsafe fn collect_and_log() { unsafe {
    // We build small ASCII lines; each line goes through append_line.
    let mut token: HANDLE = null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
        return;
    }

    // Token user SID -> sid= line.
    let mut sz: u32 = 0;
    GetTokenInformation(token, TokenUser, null_mut(), 0, &mut sz);
    if sz > 0 {
        let p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz as usize) as *mut TOKEN_USER;
        if !p.is_null()
            && GetTokenInformation(token, TokenUser, p as *mut c_void, sz, &mut sz) != FALSE
        {
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
                LocalFree(sid_w as *mut _);
            }
            HeapFree(GetProcessHeap(), 0, p as *mut _);
        }
    }

    // elev=
    let mut el: TOKEN_ELEVATION = core::mem::zeroed();
    let mut szel = core::mem::size_of::<TOKEN_ELEVATION>() as u32;
    if GetTokenInformation(
        token,
        TokenElevation,
        &mut el as *mut _ as *mut c_void,
        szel,
        &mut szel,
    ) != FALSE
    {
        append_line(if el.TokenIsElevated != 0 {
            "elev=y"
        } else {
            "elev=n"
        });
    }

    // sess=
    let mut st: TOKEN_STATISTICS = core::mem::zeroed();
    let mut szst = core::mem::size_of::<TOKEN_STATISTICS>() as u32;
    if GetTokenInformation(
        token,
        TokenStatistics,
        &mut st as *mut _ as *mut c_void,
        szst,
        &mut szst,
    ) != FALSE
    {
        let mut buf = [0u8; 48];
        let n = u32_hex_pair(
            &mut buf,
            b"sess=",
            st.AuthenticationId.HighPart as u32,
            st.AuthenticationId.LowPart,
        );
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
        let p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, szi as usize)
            as *mut TOKEN_MANDATORY_LABEL;
        if !p.is_null()
            && GetTokenInformation(token, TokenIntegrityLevel, p as *mut c_void, szi, &mut szi)
                != FALSE
        {
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
}}

fn u32_hex_pair(out: &mut [u8], prefix: &[u8], hi: u32, lo: u32) -> usize {
    let mut i = 0;
    for &c in prefix {
        out[i] = c;
        i += 1;
    }
    i += write_hex8(&mut out[i..], hi);
    i += write_hex8(&mut out[i..], lo);
    i
}

fn u32_dec(out: &mut [u8], prefix: &[u8], mut n: u32) -> usize {
    let mut i = 0;
    for &c in prefix {
        out[i] = c;
        i += 1;
    }
    if n == 0 {
        out[i] = b'0';
        i += 1;
    } else {
        let mut tmp = [0u8; 10];
        let mut t = 0;
        while n > 0 {
            tmp[t] = b'0' + (n % 10) as u8;
            n /= 10;
            t += 1;
        }
        while t > 0 {
            t -= 1;
            out[i] = tmp[t];
            i += 1;
        }
    }
    i
}

fn il_line(out: &mut [u8], tag: &str, rid: u32) -> usize {
    let mut i = 0;
    let head = b"il=";
    for &c in head {
        out[i] = c;
        i += 1;
    }
    for &c in tag.as_bytes() {
        out[i] = c;
        i += 1;
    }
    out[i] = b'(';
    i += 1;
    i += write_hex8(&mut out[i..], rid);
    out[i] = b')';
    i += 1;
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
fn on_panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
