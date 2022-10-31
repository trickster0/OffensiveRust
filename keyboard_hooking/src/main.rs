use std::ptr::null_mut;

use windows::Win32::{
    UI::{
        WindowsAndMessaging::{
            SetWindowsHookExW,
            UnhookWindowsHookEx,
            GetMessageW, 
            CallNextHookEx, 
            HHOOK, 
            KBDLLHOOKSTRUCT,
            WM_KEYDOWN,
            WH_KEYBOARD_LL
        }
    },
    Foundation::{
        LRESULT,
        LPARAM,
        WPARAM,
        HINSTANCE,
        HWND
    }
};

static mut HOOK_ID: HHOOK = HHOOK(0);

fn main() {
    unsafe {
        match SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_keyboard), HINSTANCE(0), 0) {
            Ok(hook_id) => {
                HOOK_ID = hook_id;

                while GetMessageW(null_mut(), HWND(0), 0, 0).as_bool() {
                    // Do some stuff here.
                }
                UnhookWindowsHookEx(hook_id);
            }
            Err(err) => {
                eprintln!("Failed to SetWindowsHookEx: {}", err);
            }
        }
    }
}

unsafe extern "system" fn hook_keyboard(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if wparam.0 as u32 == WM_KEYDOWN {
        let info: *mut KBDLLHOOKSTRUCT = std::mem::transmute(lparam);
        let char_written = char::from_u32((*info).vkCode).unwrap();
        
        println!("Character written: {}", char_written);
    }
    return CallNextHookEx(HOOK_ID, code, wparam, lparam);
}
