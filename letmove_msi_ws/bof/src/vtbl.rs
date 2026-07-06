use core::ffi::c_void;
use windows_sys::core::{GUID, HRESULT};

// GUIDs — copied from msi_lateral_mv/bof/msilat.h.
// Canonical form: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX -> from_u128(0xXXXXXXXX_XXXX_XXXX_XXXX_XXXXXXXXXXXX)
pub const CLSID_MsiServer:      GUID = GUID::from_u128(0x000c101c_0000_0000_c000_000000000046);
pub const IID_IMsiServer:       GUID = GUID::from_u128(0x000c101c_0000_0000_c000_000000000046);
pub const CLSID_MSIRemoteApi:   GUID = GUID::from_u128(0x000c1035_0000_0000_c000_000000000046);
pub const IID_IMsiRemoteAPI:    GUID = GUID::from_u128(0x000C1033_0000_0000_C000_000000000046);
pub const IID_IMsiCustomAction: GUID = GUID::from_u128(0x000c1025_0000_0000_c000_000000000046);
pub const IID_IClassFactory:    GUID = GUID::from_u128(0x00000001_0000_0000_C000_000000000046);

// icacCustomActionContext::icac64Impersonated = 1 (msilat.h).
pub const ICAC64_IMPERSONATED: u32 = 1;

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

// IMsiConfigurationManagerVtbl — 16 total slots (msilat.h).
// Slots 1-3: IUnknown (base)
// Slots 4-15: reserved (InstallFinalize, SetLastUsedSource, Reboot, DoInstall,
//   IsServiceInstalling, RegisterUser, RemoveRunOnceEntry, CleanupTempPackages,
//   SourceListClearByType, SourceListAddSource, SourceListClearLastUsed,
//   RegisterCustomActionServer)
// Slot 16: CreateCustomActionServer
#[repr(C)]
pub struct IMsiConfigurationManagerVtbl {
    pub base: IUnknownVtbl,
    pub _reserved04_InstallFinalize:            *const c_void,
    pub _reserved05_SetLastUsedSource:          *const c_void,
    pub _reserved06_Reboot:                     *const c_void,
    pub _reserved07_DoInstall:                  *const c_void,
    pub _reserved08_IsServiceInstalling:        *const c_void,
    pub _reserved09_RegisterUser:               *const c_void,
    pub _reserved10_RemoveRunOnceEntry:         *const c_void,
    pub _reserved11_CleanupTempPackages:        *const c_void,
    pub _reserved12_SourceListClearByType:      *const c_void,
    pub _reserved13_SourceListAddSource:        *const c_void,
    pub _reserved14_SourceListClearLastUsed:    *const c_void,
    pub _reserved15_RegisterCustomActionServer: *const c_void,
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
}
#[repr(C)] pub struct IMsiConfigurationManager { pub lpVtbl: *const IMsiConfigurationManagerVtbl }

// IMsiCustomActionVtbl — 40 total slots (msilat.h).
// Slots 1-3:   IUnknown (base)
// Slots 4-9:   reserved (PrepareDLLCustomAction, RunDLLCustomAction, FinishDLLCustomAction,
//              RunScriptAction, QueryPathOfRegTypeLib, ProcessTypeLibrary)
// Slot 10:     SQLInstallDriverEx
// Slot 11:     SQLConfigDriver
// Slots 12-17: reserved (SQLRemoveDriver, SQLInstallTranslatorEx, SQLRemoveTranslator,
//              SQLConfigDataSource, SQLInstallDriverManager, SQLRemoveDriverManager)
// Slot 18:     SQLInstallerError
// Slots 19-40: reserved (URTMakeFusionFullPath, URTCarryingNDP, URTUnloadFusionBinaries,
//              URTAddAssemblyInstallComponent, URTIsAssemblyInstalled, URTProvideGlobalAssembly,
//              URTCommitAssemblies, URTUninstallAssembly, URTGetAssemblyCacheItem,
//              URTCreateAssemblyFileStream, URTWriteAssemblyBits, URTCommitAssemblyStream,
//              URTGetFusionPath, URTAreAssembliesEqual, URTQueryAssembly, LoadEmbeddedDLL,
//              CallInitDLL, CallMessageDLL, CallShutdownDLL, UnloadEmbeddedDLL,
//              SetNewClientProcess, SetRemoteAPI)
#[repr(C)]
pub struct IMsiCustomActionVtbl {
    pub base: IUnknownVtbl,
    pub _reserved04_PrepareDLLCustomAction:      *const c_void,
    pub _reserved05_RunDLLCustomAction:          *const c_void,
    pub _reserved06_FinishDLLCustomAction:       *const c_void,
    pub _reserved07_RunScriptAction:             *const c_void,
    pub _reserved08_QueryPathOfRegTypeLib:       *const c_void,
    pub _reserved09_ProcessTypeLibrary:          *const c_void,
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
    pub _reserved12_SQLRemoveDriver:             *const c_void,
    pub _reserved13_SQLInstallTranslatorEx:      *const c_void,
    pub _reserved14_SQLRemoveTranslator:         *const c_void,
    pub _reserved15_SQLConfigDataSource:         *const c_void,
    pub _reserved16_SQLInstallDriverManager:     *const c_void,
    pub _reserved17_SQLRemoveDriverManager:      *const c_void,
    pub SQLInstallerError: unsafe extern "system" fn(
        this: *mut IMsiCustomAction, iError: u16, pfErrorCode: *mut u32,
        szErrorMsg: *mut u16, cbErrorMsgMax: u16, pcbErrorMsg: *mut u16,
    ) -> HRESULT,
    pub _reserved19_URTMakeFusionFullPath:       *const c_void,
    pub _reserved20_URTCarryingNDP:              *const c_void,
    pub _reserved21_URTUnloadFusionBinaries:     *const c_void,
    pub _reserved22_URTAddAssemblyInstallComponent: *const c_void,
    pub _reserved23_URTIsAssemblyInstalled:      *const c_void,
    pub _reserved24_URTProvideGlobalAssembly:    *const c_void,
    pub _reserved25_URTCommitAssemblies:         *const c_void,
    pub _reserved26_URTUninstallAssembly:        *const c_void,
    pub _reserved27_URTGetAssemblyCacheItem:     *const c_void,
    pub _reserved28_URTCreateAssemblyFileStream: *const c_void,
    pub _reserved29_URTWriteAssemblyBits:        *const c_void,
    pub _reserved30_URTCommitAssemblyStream:     *const c_void,
    pub _reserved31_URTGetFusionPath:            *const c_void,
    pub _reserved32_URTAreAssembliesEqual:       *const c_void,
    pub _reserved33_URTQueryAssembly:            *const c_void,
    pub _reserved34_LoadEmbeddedDLL:             *const c_void,
    pub _reserved35_CallInitDLL:                 *const c_void,
    pub _reserved36_CallMessageDLL:              *const c_void,
    pub _reserved37_CallShutdownDLL:             *const c_void,
    pub _reserved38_UnloadEmbeddedDLL:           *const c_void,
    pub _reserved39_SetNewClientProcess:         *const c_void,
    pub _reserved40_SetRemoteAPI:                *const c_void,
}
#[repr(C)] pub struct IMsiCustomAction { pub lpVtbl: *const IMsiCustomActionVtbl }
