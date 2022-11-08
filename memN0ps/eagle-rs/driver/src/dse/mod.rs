use core::{ptr::{null_mut}, ffi::CStr};
use alloc::{string::{String, ToString}, collections::BTreeMap};
use bstr::ByteSlice;
use kernel_alloc::nt::{ExAllocatePool, ExFreePool};
use winapi::{shared::{ntdef::{NT_SUCCESS}}, ctypes::c_void, um::winnt::{RtlZeroMemory, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_EXPORT_DIRECTORY}};

use crate::{includes::SystemInformationClass, includes::SystemModuleInformation, includes::ZwQuerySystemInformation};

pub fn get_module_base(module_name: &[u8]) -> *mut c_void {

    let mut bytes = 0;

    // Get buffer size
    let _status = unsafe { ZwQuerySystemInformation(
        SystemInformationClass::SystemModuleInformation,
            null_mut(),
            0,
            &mut bytes
        ) 
    };

    /* Error check will fail and that is intentional to get the buffer size
    if !NT_SUCCESS(status) {
        log::error!("[-] 1st ZwQuerySystemInformation failed {:?}", status);
        return null_mut();
    } */

    let module_info = unsafe { 
        ExAllocatePool(kernel_alloc::nt::PoolType::NonPagedPool, bytes as usize) as *mut SystemModuleInformation 
    };

    if module_info.is_null() {
        log::error!("[-] ExAllocatePool failed");
        return null_mut();
    }

    unsafe { RtlZeroMemory( module_info as *mut c_void, bytes as usize) };

    let status = unsafe { ZwQuerySystemInformation(
        SystemInformationClass::SystemModuleInformation,
        module_info as *mut c_void,
        bytes,
        &mut bytes) 
    };

    if !NT_SUCCESS(status) {
        log::info!("[-] 2nd ZwQuerySystemInformation failed {:#x}", status);
        return null_mut();
    }


    let mut p_module: *mut c_void = null_mut();
    log::info!("Module count: {:?}", unsafe { (*module_info).modules_count as usize });

    for i in unsafe { 0..(*module_info).modules_count as usize } {

        let image_name = unsafe { (*module_info).modules[i].image_name };
        let image_base = unsafe { (*module_info).modules[i].image_base };

        //log::info!("[+] Module name: {:?} and module base: {:?}", image_name.as_bstr(), image_base);

        if let Some(_) = image_name.find(module_name) {
            //log::info!("[+] Module name: {:?} and module base: {:?}", image_name, image_base);
            p_module = image_base;
            break;
        }
    }

    unsafe { ExFreePool(module_info as u64) };

    return p_module;
}


pub fn get_gci_options_address() -> Option<*mut c_void> {

    #[allow(unused_assignments)]
    let mut g_ci_options = null_mut();

    
    let module_base = get_module_base(b"CI.dll");
    let ci_initialize_ptr = get_function_address(module_base, "CiInitialize") as *mut c_void;

    let func_slice: &[u8] = unsafe { 
        core::slice::from_raw_parts(ci_initialize_ptr as *const u8, 0x89) //mov rbx,qword ptr [rsp+30h] : (after call    CI!CipInitialize)
    };

    //before: call    CI!CipInitialize
    let needle = [
        0x8b, 0xcd,       // mov ecx,ebp
    ];

    if let Some(y) = func_slice.windows(needle.len()).position(|x| *x == needle) {
        let position = y + 3;
        let offset_slice = &func_slice[position..position + 4]; //u32::from_le_bytes takes 4 slices
        let offset = u32::from_le_bytes(offset_slice.try_into().unwrap());

        //log::info!("Offset: {:#x}", offset);
        let new_base = unsafe { ci_initialize_ptr.cast::<u8>().offset((position + 4) as isize) };
        //log::info!("new_base: {:?}", new_base);
        let c_ip_initialize = unsafe { new_base.cast::<u8>().offset(offset as isize) };
        log::info!("c_ip_initialize: {:?}", c_ip_initialize);

        
        // Inside CI!CipInitialize

        let needle = [
            0x49, 0x8b, 0xe9, // mov rbp,r9
        ];

        let c_ip_initialize_slice: &[u8] = unsafe { 
            core::slice::from_raw_parts(c_ip_initialize as *const u8, 0x21) //mov     rbx,r8 : (after mov     dword ptr [CI!g_CiOptions])
        };

        if let Some(i) = c_ip_initialize_slice.windows(needle.len()).position(|x| *x == needle) {
            let position = i + 5;
            
            let offset_slice = &c_ip_initialize_slice[position..position + 4]; //u32::from_le_bytes takes 4 slices
            let offset = u32::from_le_bytes(offset_slice.try_into().unwrap());
            let new_offset = 0xffffffff00000000 + offset as u64;
            log::info!("Offset: {:#x}", offset);


            let new_base = unsafe { c_ip_initialize.cast::<u8>().offset((position + 4) as isize) };
            g_ci_options = unsafe { new_base.cast::<u8>().offset(new_offset as isize) };

            log::info!("g_CiOptions: {:?}", g_ci_options);

            return Some(g_ci_options as *mut c_void);
        }
    }
    return None;
}

pub fn get_function_address(module: *mut c_void, function_name: &str) -> usize {
    let mut function_ptr = 0;

    //Get the names and addresses of functions the dll
    for (name, addr) in unsafe { get_module_exports(module).unwrap() } {
        if name == function_name {
            //log::info!("[+] Function: {:?} Address {:#x}", name, addr);
            function_ptr = addr;
            break;
        }
    }

    return function_ptr;
}

/// Retrieves all function and addresses from the specfied modules
unsafe fn get_module_exports(module_base: *mut c_void) -> Option<BTreeMap<String, usize>> {
    let mut exports = BTreeMap::new();
    let dos_header = *(module_base as *mut IMAGE_DOS_HEADER);

    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        log::info!("Error: get_module_exports failed, DOS header is invalid");
        return None;
    }
    
    let nt_header =
        (module_base as usize + dos_header.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

    if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
        log::info!("Error: get_module_exports failed, NT header is invalid");
        return None;
    }

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
    return Some(exports);
}

/*
0: kd> u CI!CiInitialize
CI!CiInitialize:
fffff800`5a673400 48895c2408      mov     qword ptr [rsp+8],rbx
fffff800`5a673405 48896c2410      mov     qword ptr [rsp+10h],rbp
fffff800`5a67340a 4889742418      mov     qword ptr [rsp+18h],rsi
fffff800`5a67340f 57              push    rdi
fffff800`5a673410 4883ec20        sub     rsp,20h
fffff800`5a673414 498bd9          mov     rbx,r9
fffff800`5a673417 498bf8          mov     rdi,r8
fffff800`5a67341a 488bf2          mov     rsi,rdx
0: kd> u
CI!CiInitialize+0x1d:
fffff800`5a67341d 8be9            mov     ebp,ecx
fffff800`5a67341f e8e46b0800      call    CI!wil_InitializeFeatureStaging (fffff800`5a6fa008)
fffff800`5a673424 e8ff6d0800      call    CI!_security_init_cookie (fffff800`5a6fa228)
fffff800`5a673429 488b0d5848ffff  mov     rcx,qword ptr [CI!wil_details_featureChangeNotification (fffff800`5a667c88)]
fffff800`5a673430 4885c9          test    rcx,rcx
fffff800`5a673433 7414            je      CI!CiInitialize+0x49 (fffff800`5a673449)
fffff800`5a673435 4c8b15b4ccffff  mov     r10,qword ptr [CI!_imp_RtlUnregisterFeatureConfigurationChangeNotification (fffff800`5a6700f0)]
fffff800`5a67343c e8ff33eafe      call    nt!RtlUnregisterFeatureConfigurationChangeNotification (fffff800`59516840)
0: kd> u
CI!CiInitialize+0x41:
fffff800`5a673441 4883253f48ffff00 and     qword ptr [CI!wil_details_featureChangeNotification (fffff800`5a667c88)],0
fffff800`5a673449 4c8bcb          mov     r9,rbx
fffff800`5a67344c 4c8bc7          mov     r8,rdi
fffff800`5a67344f 488bd6          mov     rdx,rsi
fffff800`5a673452 8bcd            mov     ecx,ebp
fffff800`5a673454 e8bb080000      call    CI!CipInitialize (fffff800`5a673d14)
fffff800`5a673459 488b5c2430      mov     rbx,qword ptr [rsp+30h]
fffff800`5a67345e 488b6c2438      mov     rbp,qword ptr [rsp+38h]
*/

/*
0: kd> u CI!CipInitialize
CI!CipInitialize:
fffff800`5a673d14 48895c2408      mov     qword ptr [rsp+8],rbx
fffff800`5a673d19 48896c2410      mov     qword ptr [rsp+10h],rbp
fffff800`5a673d1e 4889742418      mov     qword ptr [rsp+18h],rsi
fffff800`5a673d23 57              push    rdi
fffff800`5a673d24 4154            push    r12
fffff800`5a673d26 4156            push    r14
fffff800`5a673d28 4883ec40        sub     rsp,40h
fffff800`5a673d2c 498be9          mov     rbp,r9
0: kd> u
CI!CipInitialize+0x1b:
fffff800`5a673d2f 890d8346ffff    mov     dword ptr [CI!g_CiOptions (fffff800`5a6683b8)],ecx
fffff800`5a673d35 498bd8          mov     rbx,r8
fffff800`5a673d38 488bf2          mov     rsi,rdx
fffff800`5a673d3b 448bf1          mov     r14d,ecx
fffff800`5a673d3e 4c8b15cbc3ffff  mov     r10,qword ptr [CI!_imp_PsGetCurrentProcess (fffff800`5a670110)]
fffff800`5a673d45 e866677cfe      call    nt!PsGetCurrentProcess (fffff800`58e3a4b0)
fffff800`5a673d4a 488905a746ffff  mov     qword ptr [CI!g_CiSystemProcess (fffff800`5a6683f8)],rax
fffff800`5a673d51 813be8000000    cmp     dword ptr [rbx],0E8h

*/