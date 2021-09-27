extern crate winapi;
use winapi::um::processthreadsapi::{OpenProcessToken,GetCurrentProcess};
use winapi::um::winnt::{HANDLE,TOKEN_ADJUST_PRIVILEGES,TOKEN_QUERY,LUID_AND_ATTRIBUTES,SE_PRIVILEGE_ENABLED,TOKEN_PRIVILEGES};
use std::ptr::null_mut;
use std::mem::size_of;
use winapi::shared::ntdef::LUID;
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::winbase::LookupPrivilegeValueA;

fn main() {
   unsafe{
        let mut h_token: HANDLE = 0 as _;
        OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,&mut h_token);
        let privs = LUID_AND_ATTRIBUTES {Luid: LUID { LowPart: 0, HighPart: 0,},Attributes: SE_PRIVILEGE_ENABLED,};
        let mut tp = TOKEN_PRIVILEGES {PrivilegeCount: 1,Privileges: [privs ;1],};
        let privilege = "SeDebugPrivilege\0";
        let _ = LookupPrivilegeValueA(null_mut(),privilege.as_ptr() as *const i8,&mut tp.Privileges[0].Luid,);
        let _ = AdjustTokenPrivileges(h_token,0,&mut tp,size_of::<TOKEN_PRIVILEGES>() as _,null_mut(),null_mut());
  }
}
