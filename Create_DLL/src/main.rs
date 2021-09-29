#![cfg(windows)]
use std::ptr::null_mut;
use winapi::um::winuser::MessageBoxA;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]

pub extern "C" fn popit() {
    unsafe {MessageBoxA(null_mut(),"Rust DLL Test\0".as_ptr() as *const i8,"Rust DLL Test\0".as_ptr() as *const i8,0x00004000);}
}


//#[no_mangle]
//#[allow(non_snake_case, unused_variables)]
// fn DllMain(
//     dll_module: HINSTANCE,
//     call_reason: DWORD,
//     reserved: LPVOID)
//     -> BOOL
// {
//     const DLL_PROCESS_ATTACH: DWORD = 1;
//     const DLL_PROCESS_DETACH: DWORD = 0;

//     match call_reason {
//         DLL_PROCESS_ATTACH => popit(),
//         DLL_PROCESS_DETACH => (),
//         _ => ()
//     }
//     TRUE
// }
