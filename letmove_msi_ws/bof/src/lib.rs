#![no_std]

mod argv;
mod vtbl;

use rustbof::println;

#[rustbof::main]
fn main(args: *mut u8, len: usize) {
    let Some(a) = argv::parse(args, len) else { return };
    let m = match a.mode { argv::Mode::Local => "local", argv::Mode::Remote => "remote" };
    println!("argv ok mode={}", m);
    let _ = a;
}
