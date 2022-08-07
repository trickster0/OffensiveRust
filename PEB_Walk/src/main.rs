use core::arch::asm;
use windows_sys::Win32::UI::WindowsAndMessaging::MB_OK;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::PEB;
use windows_sys::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_DATA_DIRECTORY};
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
mod types;

#[inline]
#[cfg(target_pointer_width = "64")]
pub unsafe fn __readgsqword(offset: types::DWORD) -> types::DWORD64 {
    let out: u64;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}

fn get_module_base_addr(module_name: &str) -> HINSTANCE {
    unsafe {
        let peb_offset: *const u64 = __readgsqword(0x60)  as *const u64;
        let rf_peb: *const PEB = peb_offset as * const PEB;
        let peb = *rf_peb;

        let mut p_ldr_data_table_entry: *const LDR_DATA_TABLE_ENTRY = (*peb.Ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut p_list_entry = &(*peb.Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;

        loop {
            let buffer = std::slice::from_raw_parts(
                (*p_ldr_data_table_entry).FullDllName.Buffer,
                (*p_ldr_data_table_entry).FullDllName.Length as usize / 2);
            let dll_name = String::from_utf16_lossy(buffer);
            if dll_name.to_lowercase().starts_with(module_name) {
                let module_base: HINSTANCE = (*p_ldr_data_table_entry).Reserved2[0] as HINSTANCE;
                return module_base;
            }
            if p_list_entry == (*peb.Ldr).InMemoryOrderModuleList.Blink {
                println!("Module not found!");
                return 0;
            }
            p_list_entry = (*p_list_entry).Flink;
            p_ldr_data_table_entry = (*p_list_entry).Flink as *const LDR_DATA_TABLE_ENTRY;
        }
    }
}

fn get_proc_addr(module_handle: HINSTANCE, function_name: &str) -> FARPROC {
    let mut address_array: types::UINT_PTR;
    let mut name_array: types::UINT_PTR;
    let mut name_ordinals: types::UINT_PTR;
    let nt_headers: *const IMAGE_NT_HEADERS64;
    let data_directory: *const IMAGE_DATA_DIRECTORY;
    let export_directory: *const IMAGE_EXPORT_DIRECTORY;
    let dos_headers: *const IMAGE_DOS_HEADER;
    unsafe {
        dos_headers = module_handle as *const IMAGE_DOS_HEADER;
        nt_headers = (module_handle as u64 + (*dos_headers).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
        data_directory = (&(*nt_headers).OptionalHeader.DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
        export_directory = (module_handle as u64 + (*data_directory).VirtualAddress as u64) as *const IMAGE_EXPORT_DIRECTORY;
        address_array = (module_handle as u64 + (*export_directory).AddressOfFunctions as u64) as types::UINT_PTR;
        name_array = (module_handle as u64 + (*export_directory).AddressOfNames as u64) as types::UINT_PTR;
        name_ordinals = (module_handle as u64 + (*export_directory).AddressOfNameOrdinals as u64) as types::UINT_PTR;
        loop {
            let name_offest: u32 = *(name_array as *const u32);
            let current_function_name = std::ffi::CStr::from_ptr(
                (module_handle as u64 + name_offest as u64) as *const i8
            ).to_str().unwrap();

            if current_function_name == function_name {
                address_array = address_array + (*(name_ordinals as *const u16) as u64 * (std::mem::size_of::<types::DWORD>() as u64));
                let fun_addr: FARPROC = std::mem::transmute(module_handle as u64 + *(address_array as *const u32) as u64);
                return fun_addr;
            }
            name_array = name_array + std::mem::size_of::<types::DWORD>() as u64;
            name_ordinals = name_ordinals + std::mem::size_of::<u16>() as u64;
        }
    }
}


fn main() {
    unsafe{
        println!("[+] Getting base address of kernel32.dll");
        let kernel32_base_address: HINSTANCE = get_module_base_addr("kernel32.dll");

        println!("[+] Dynamically resolving LoadLibraryA");
        let dn_load_library_a: types::LoadLibraryA = std::mem::transmute(get_proc_addr(kernel32_base_address, "LoadLibraryA"));

        println!("[+] Load user32.dll");
        dn_load_library_a("user32.dll\0".as_ptr());

        println!("[+] Getting base address of user32.dll");
        let user32_base_address: HINSTANCE = get_module_base_addr("user32.dll");

        println!("[+] Dynamically resolve MessageBoxA");
        let dn_message_box_a: types::MessageBoxA = std::mem::transmute(get_proc_addr(user32_base_address, "MessageBoxA"));

        dn_message_box_a(0, "Resolved dynamically\0".as_ptr(), "MessageBoxA\0".as_ptr(), MB_OK);
    }
}
