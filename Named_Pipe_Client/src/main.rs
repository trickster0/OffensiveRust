use winapi::um::winnt::{HANDLE,LPCSTR,GENERIC_READ,GENERIC_WRITE};
use winapi::um::fileapi::{CreateFileA,OPEN_EXISTING,ReadFile};
use std::ptr::null_mut;

fn main() {
    unsafe { 
        let mut bytes_read : u32 = 0;
        let mut buffer_read = vec![0u8;1024];
        let pipe_name : LPCSTR = "\\\\.\\pipe\\rusttestpipe\0".as_ptr() as *const i8;
        let clientpipe : HANDLE = CreateFileA(pipe_name,GENERIC_READ | GENERIC_WRITE,0,null_mut(),OPEN_EXISTING,0,null_mut());
        ReadFile(clientpipe,buffer_read.as_mut_ptr() as  *mut winapi::ctypes::c_void,buffer_read.len() as u32,&mut bytes_read,null_mut());
        println!("{}",String::from_utf8_lossy(&mut buffer_read));
    }
}


