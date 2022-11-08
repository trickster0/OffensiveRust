use std::ffi::c_void;
use windows_sys::Win32::{
    Foundation::{BOOL, HINSTANCE},
    System::SystemServices::DLL_PROCESS_ATTACH,
    UI::WindowsAndMessaging::MessageBoxA,
};

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _module: HINSTANCE,
    call_reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH {
        MessageBoxA(
            0 as _,
            "Rust DLL injected!\0".as_ptr() as _,
            "Rust DLL\0".as_ptr() as _,
            0x0,
        );

        1
    } else {
        1
    }
}

#[no_mangle]
#[allow(non_snake_case)]
fn SayHello(user_data: *mut c_void, user_data_len: u32) {
    let user_data_slice =
        unsafe { core::slice::from_raw_parts(user_data as *const u8, user_data_len as _) };
    let user_data = std::str::from_utf8(user_data_slice).unwrap();
    let message = format!("Hello from {}", user_data);

    unsafe {
        MessageBoxA(
            0 as _,
            message.as_ptr() as _,
            "SayHello!\0".as_ptr() as _,
            0x0,
        );
    }
}
