use winapi::um::winbase::CreateNamedPipeA;
use winapi::um::winnt::{HANDLE,LPCSTR};
use winapi::um::namedpipeapi::ConnectNamedPipe;
use winapi::um::fileapi::WriteFile;
use winapi::um::winbase::{PIPE_ACCESS_DUPLEX,PIPE_TYPE_MESSAGE};
use std::ptr::null_mut;

fn main() {
    let mut bytes_written : u32 = 0;
    let message = "RUST IS GOOD FOR OFFSEC\0" ;
    let pipe_name : LPCSTR = "\\\\.\\pipe\\rusttestpipe\0".as_ptr() as *const i8;
    let server_pipe : HANDLE = unsafe {CreateNamedPipeA(pipe_name,PIPE_ACCESS_DUPLEX,PIPE_TYPE_MESSAGE,1,2048,2048,0,null_mut())};
    unsafe {ConnectNamedPipe(server_pipe,null_mut())};
    println!("Sending message to Pipe");
    unsafe {WriteFile(server_pipe,message.as_ptr() as *const winapi::ctypes::c_void,message.len() as u32,&mut bytes_written,null_mut())};
}

