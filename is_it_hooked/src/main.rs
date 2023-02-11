use winapi::{
    um::{
        memoryapi::ReadProcessMemory,
        libloaderapi::{LoadLibraryA,GetProcAddress},
        processthreadsapi::GetCurrentProcess,
    }, 
    shared::minwindef::LPVOID,
    ctypes::c_void,
};
use std::ptr;

fn main() {    
    if is_it_hooked("NtAllocateVirtualMemory") {
        // Use unhooking <https://github.com/trickster0/OffensiveRust/tree/master/Unhooking>
        println!("[?] Use unhooking <https://github.com/trickster0/OffensiveRust/tree/master/Unhooking>");
    }
}

/// Function to detecting hooked syscalls
fn is_it_hooked(api_name: &str) -> bool {
    // <https://github.com/TheD1rkMtr/UnhookingPatch/blob/main/PatchingAPI/src/PatchingAPI.cpp#L73>
    // BOOL isItHooked(LPVOID addr) {
    //     BYTE stub[] = "\x4c\x8b\xd1\xb8";
    //     if (memcmp(addr, stub, 4) != 0)
    //         return TRUE;
    //     return FALSE;
    // }
    unsafe {
        let modu = format!("{}{}{}{}{}.dll{}","n","t","d","l","l","\0");
        let handle = LoadLibraryA(modu.as_ptr() as *const i8);
        let mthd = format!("{}\0",api_name);
        let mini = GetProcAddress(handle, mthd.as_str().as_ptr() as *const i8);
        let mut reader: [u8; 4] = *b"\x00\x00\x00\x00";
        // <https://learn.microsoft.com/fr-fr/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory>
        let _status = ReadProcessMemory(
            GetCurrentProcess(),
            mini as *mut c_void,
            &mut reader as *mut _ as LPVOID,
            4,
            ptr::null_mut()
        );
        // Interesting functions/syscalls, starting with Nt|Zw, before hooking, start with opcodes: 4c 8b d1 b8
        // <https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions>
        let stub: &[u8; 4] = b"\x4C\x8B\xD1\xB8";
        if &reader != stub {
            // If &reader start with (233 == E9) opcode for near jump
            println!("[!] {} hooked. {:02x?}", &api_name, reader);
            return true
        }
        else {
            println!("[+] {} not hooked. {:02x?}", &api_name, reader);
            return false
        }
    }
}