use std::ffi::CString;
use winapi::{
    um::{
        winuser::MessageBoxA, 
    },
    shared::{
        windef::HWND, 
        minwindef::{
            UINT
        }, 
        ntdef::LPCSTR
    }
};
use detour::static_detour;

static_detour! {
    static MsgBox: unsafe extern "system" fn(HWND, LPCSTR, LPCSTR, UINT) -> i32;
}


fn main() {
    unsafe {
        MsgBox.initialize(MessageBoxA, |hwnd, lp_text, lp_caption, u_type| {
            println!("Hooked MessageBoxA");
                MsgBox.call(hwnd, lp_text, lp_caption, u_type)
        });
        MessageBoxA(0 as HWND, CString::new("Before").unwrap().as_ptr(), CString::new("Before").unwrap().as_ptr(), 0);
        MsgBox.enable();
        MessageBoxA(0 as HWND, CString::new("After").unwrap().as_ptr(), CString::new("After").unwrap().as_ptr(), 0);
        MsgBox.disable();
    }
}
