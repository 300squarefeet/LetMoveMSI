use rustbof::data::DataParser;
use rustbof::eprintln;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode { Local, Remote }

pub struct Args {
    pub host:   Option<*const u16>,
    pub domain: Option<*const u16>,
    pub user:   Option<*const u16>,
    pub pass:   Option<*const u16>,
    pub driver: *const u16,
    pub dll:    *const u16,
}

// Adaptation: rustbof::data::DataParser has no `get_wstr()`. The wire protocol
// packs each wide string via Beacon's `Z` type (length-prefixed UTF-16LE with
// null terminator). `get_bytes()` returns the payload as &[u8]; we reinterpret
// the pointer as *const u16. Empty payload -> null pointer.
fn get_wstr(p: &mut DataParser) -> *const u16 {
    let bytes = p.get_bytes();
    if bytes.is_empty() { return core::ptr::null(); }
    bytes.as_ptr() as *const u16
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
    let mode_s = get_wstr(&mut p);
    let host   = get_wstr(&mut p);
    let domain = get_wstr(&mut p);
    let user   = get_wstr(&mut p);
    let pass   = get_wstr(&mut p);
    let driver = get_wstr(&mut p);
    let dll    = get_wstr(&mut p);

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
        host: opt(host), domain: opt(domain), user: opt(user), pass: opt(pass),
        driver, dll,
    })
}
