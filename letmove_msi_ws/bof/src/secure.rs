use core::ptr::{null, null_mut};
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::System::Com::{
    CoInitializeSecurity, CoSetProxyBlanket, COAUTHIDENTITY, COAUTHINFO,
    EOAC_DEFAULT, EOAC_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
    RPC_C_IMP_LEVEL_IMPERSONATE, SOLE_AUTHENTICATION_INFO,
    SOLE_AUTHENTICATION_LIST,
};
use windows_sys::Win32::System::Rpc::{
    RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, SEC_WINNT_AUTH_IDENTITY_UNICODE,
};

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
        null_mut(), -1, null(), null(),
        b.auth_info.dwAuthnLevel, b.auth_info.dwImpersonationLevel,
        &sal as *const _ as *const _, EOAC_NONE as u32, null(),
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
        RPC_C_AUTHN_WINNT as u32, RPC_C_AUTHZ_NONE as u32, null(),
        b.auth_info.dwAuthnLevel, b.auth_info.dwImpersonationLevel,
        b.auth_info.pAuthIdentityData as *const _, EOAC_DEFAULT as u32,
    );
    if hr < 0 { ((*(*out).lpVtbl).Release)(out); return Err(hr); }
    Ok(out)
}
