use std::{ptr::null_mut, intrinsics::transmute};
use ntapi::ntpsapi::PPS_ATTRIBUTE_LIST;
use winapi::{um::{winnt::{ACCESS_MASK, GENERIC_ALL}, processthreadsapi::GetCurrentProcess}, shared::{ntdef::{PHANDLE, POBJECT_ATTRIBUTES, HANDLE, PVOID, NTSTATUS, NT_SUCCESS}, minwindef::ULONG, basetsd::SIZE_T}, ctypes::c_void};

mod parallel_syscalls;

// Function to call
type NtCreateThreadEx = unsafe extern "system" fn(
    ThreadHandle: PHANDLE, 
    DesiredAccess: ACCESS_MASK, 
    ObjectAttributes: POBJECT_ATTRIBUTES, 
    ProcessHandle: HANDLE, 
    StartRoutine: PVOID, 
    Argument: PVOID, 
    CreateFlags: ULONG, 
    ZeroBits: SIZE_T, 
    StackSize: SIZE_T, 
    MaximumStackSize: SIZE_T, 
    AttributeList: PPS_ATTRIBUTE_LIST
) -> NTSTATUS;


fn main() {

    // Dynamically get the base address of a fresh copy of ntdll.dll using mdsec's technique
    let ptr_ntdll = parallel_syscalls::get_module_base_address("ntdll.dll");

    if ptr_ntdll.is_null() {
        panic!("Pointer to ntdll is null");
    }

    //get function address
    let nt_create_thread_ex_address = parallel_syscalls::get_function_address(ptr_ntdll, "NtCreateThreadEx");

    //build system call stub
    //let nt_create_thread_ex = parallel_syscalls::build_syscall_stub(syscall_nt_create_thread_ex as u32);
    
    // Convert to function pointer
    let nt_create_thread_ex = unsafe { transmute::<_, NtCreateThreadEx>(nt_create_thread_ex_address) };
    let mut thread_handle : *mut c_void = null_mut();

    // Call the function pointer in the memory region
    let status = unsafe { nt_create_thread_ex(&mut thread_handle, GENERIC_ALL, null_mut(), GetCurrentProcess(), null_mut(), null_mut(), 0, 0, 0, 0, null_mut()) };

    if !NT_SUCCESS(status) {
        panic!("Failed to call NtCreateThreadEx");
    }

    println!("[+] Thread Handle: {:?} and Status: {:?}", thread_handle, status);
}