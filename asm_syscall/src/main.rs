#![feature(asm)]

fn main() {
    let rax:u64;
    unsafe {
        asm!(
            "push rbx",
            "xor rbx, rbx",
            "xor rax, rax",
            "mov rbx, qword ptr gs:[0x60]",
            "mov rax,rbx",
            "pop rbx",
            out("rax") rax,
        );
    }
    println!("PEB Address: 0x{:x}",rax);
}
