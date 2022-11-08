fn main() {
    let kernel32 = "KERNEL32.DLL".as_bytes();
    println!("KERNEL32.DLL: {:#x}", hash(kernel32));

    let ntdll = "ntdll.dll".as_bytes();
    println!("ntdll.dll: {:#x}", hash(ntdll));

    let load_library_a = "LoadLibraryA".as_bytes();
    println!("LoadLibraryA: {:#x}", hash(load_library_a));

    let get_proc_address = "GetProcAddress".as_bytes();
    println!("GetProcAddress: {:#x}", hash(get_proc_address));

    let virtual_alloc = "VirtualAlloc".as_bytes();
    println!("VirtualAlloc: {:#x}", hash(virtual_alloc));

    let virtual_protect = "VirtualProtect".as_bytes();
    println!("VirtualProtect: {:#x}", hash(virtual_protect));

    let flush_instruction_cache = "FlushInstructionCache".as_bytes();
    println!(
        "FlushInstructionCache: {:#x}",
        hash(flush_instruction_cache)
    );

    let virtual_free = "VirtualFree".as_bytes();
    println!("VirtualFree: {:#x}", hash(virtual_free));

    let exit_thread = "ExitThread".as_bytes();
    println!("ExitThread: {:#x}", hash(exit_thread));

    let say_hello = "SayHello".as_bytes();
    println!("SayHello: {:#x}", hash(say_hello));
}

//credits: janoglezcampos / @httpyxel / yxel
pub fn hash(buffer: &[u8]) -> u32 {
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
