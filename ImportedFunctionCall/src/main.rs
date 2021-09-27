extern crate winapi;
extern crate kernel32;
use winapi::um::processthreadsapi::{OpenProcess,GetCurrentProcess};
use winapi::um::fileapi::{CreateFileA,CREATE_ALWAYS};
use winapi::um::winnt::{PROCESS_ALL_ACCESS,GENERIC_ALL,FILE_ATTRIBUTE_NORMAL,HANDLE};
use std::ptr::null_mut;


fn main() {

 unsafe {
   let minidump: extern "stdcall" fn(HANDLE, u32, HANDLE, u32,*const (),*const (),*const ());
   let hndls = OpenProcess(PROCESS_ALL_ACCESS,0,1234);
   let modu = "dbghelp.dll\0";
   let handle = kernel32::LoadLibraryA(modu.as_ptr() as *const i8);
   let mthd = "MiniDumpWriteDump\0";
   let mini = kernel32::GetProcAddress(handle, mthd.as_ptr() as *const i8);
   minidump = std::mem::transmute(mini);
   let path = "C:\\Users\\Public\\test.dmp\0";
   let fd = CreateFileA(path.as_ptr() as _,GENERIC_ALL,0,null_mut(),CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,null_mut());
   minidump(GetCurrentProcess(),1234,fd,0x00000002,null_mut(),null_mut(),null_mut())
 }
}
