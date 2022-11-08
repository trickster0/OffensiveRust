#[macro_export]
macro_rules! obf {
    ($s:expr) => {{
        static HASH: u32 = $crate::obf::dbj2_hash_str($s);
        HASH
    }};
}

pub const fn dbj2_hash_str(arg: &str) -> u32 {
    dbj2_hash(arg.as_bytes())
}

pub const fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];
        if cur == 0 {
            iter += 1;
            continue;
        }
        if cur >= ('a' as u8) {
            cur -= 0x20;
        }
        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    return hsh;
}
