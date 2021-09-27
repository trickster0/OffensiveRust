extern crate ntapi;
use ntapi::ntmmapi::NtAllocateVirtualMemory;
use ntapi::ntpsapi::NtCurrentProcess;
use std::ptr::null_mut;
use ntapi::winapi::ctypes::c_void;

fn main() {

 unsafe {
  let mut allocstart : *mut c_void = null_mut();
  let mut seize : usize = 150;
  NtAllocateVirtualMemory(NtCurrentProcess,&mut allocstart,0,&mut seize, 0x00003000, 0x40);
 }

}
