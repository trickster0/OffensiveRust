use core::{ptr::{slice_from_raw_parts, null_mut}, mem::size_of, intrinsics::copy_nonoverlapping};
use alloc::{string::String};
use common::CallBackInformation;
use kernel_alloc::nt::{ExAllocatePool};
use winapi::{shared::{ntdef::{HANDLE, BOOLEAN, NTSTATUS, NT_SUCCESS}, ntstatus::{STATUS_SUCCESS}}, km::wdm::{PEPROCESS}, um::winnt::RtlZeroMemory, ctypes::c_void};
use crate::includes::{PSCreateNotifyInfo, AuxKlibInitialize, AuxKlibQueryModuleInformation, AuxModuleExtendedInfo, strlen};

#[allow(non_snake_case)]
pub type PcreateProcessNotifyRoutineEx = extern "system" fn(process: PEPROCESS, process_id: HANDLE, create_info: *mut PSCreateNotifyInfo);
//type PcreateProcessNotifyRoutine = extern "system" fn(ParentId: HANDLE, ProcessId: HANDLE, Create: BOOLEAN);
//type PcreateThreadNotifyRoutine = extern "system" fn(ProcessId: HANDLE, ThreadId: HANDLE, Create: BOOLEAN);
//type PloadImageNotifyRoutine = extern "system" fn(FullImageName: PUNICODE_STRING, ProcessId: HANDLE , ImageInfo: *mut IMAGE_INFO);

extern "system" {
    #[allow(non_snake_case)]
    pub fn PsSetCreateProcessNotifyRoutineEx(notify_routine: PcreateProcessNotifyRoutineEx, remove: BOOLEAN) -> NTSTATUS;    
    //pub fn PsSetCreateProcessNotifyRoutine(notify_routine: PcreateProcessNotifyRoutine, remove: BOOLEAN) -> NTSTATUS;    
    //pub fn PsSetCreateThreadNotifyRoutine(notify_routine: PcreateThreadNotifyRoutine) -> NTSTATUS;
    //pub fn PsSetLoadImageNotifyRoutine(notify_routine: PloadImageNotifyRoutine) -> NTSTATUS;
}

#[allow(non_snake_case)]
pub extern "system" fn process_create_callback(_process: PEPROCESS, process_id: HANDLE, create_info: *mut PSCreateNotifyInfo) {
    if !create_info.is_null() {
        let file_open = unsafe { (*create_info).param0.param0.file_open_available };

        if file_open != 0 {
            let p_str = unsafe { *(*create_info).image_file_name };
            let slice = unsafe { &*slice_from_raw_parts(p_str.Buffer, p_str.Length as usize / 2) } ;
            let process_name = String::from_utf16(slice).unwrap();
            let process_id = process_id as u32;
            log::info!("Process Created: {:?} ({:?})", process_name, process_id);
        }
    }
}

/*
PsSetCreateProcessNotifyRoutineEx: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
PsSetCreateProcessNotifyRoutine: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine
PsSetCreateThreadNotifyRoutine: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine
PsSetLoadImageNotifyRoutine: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine

PcreateProcessNotifyRoutineEx: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine_ex
PcreateProcessNotifyRoutine: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine
PcreateThreadNotifyRoutine: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_thread_notify_routine
PloadImageNotifyRoutine: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pload_image_notify_routine
*/


/*
AuxKlibInitialize: https://docs.microsoft.com/en-us/windows/win32/devnotes/auxklibinitialize-func
AuxKlibQueryModuleInformation: https://docs.microsoft.com/en-us/windows/win32/devnotes/auxklibquerymoduleinformation-func
*/

/// Return a pointer and number of loaded modules
pub fn get_loaded_modules() -> Option<(*mut AuxModuleExtendedInfo, u32)> {
    let status = unsafe { AuxKlibInitialize() };

    if !NT_SUCCESS(status) {
        log::error!("Failed to call AuxKlibInitialize ({:#x})", status);
        return None;
    }

    let mut buffer_size: u32 = 0;

    let status = unsafe { AuxKlibQueryModuleInformation(&mut buffer_size, size_of::<AuxModuleExtendedInfo>() as u32, null_mut()) };

    if !NT_SUCCESS(status) {
        log::error!("1st AuxKlibQueryModuleInformation failed ({:#x})", status);
        return None;
    }

    let mod_ptr = unsafe { ExAllocatePool(kernel_alloc::nt::PoolType::NonPagedPool, buffer_size as usize) as *mut c_void };

    if mod_ptr.is_null() {
        return None;
    }

    unsafe { RtlZeroMemory(mod_ptr, buffer_size as usize) };

    let status = unsafe { AuxKlibQueryModuleInformation(&mut buffer_size, size_of::<AuxModuleExtendedInfo>() as u32, mod_ptr) };

    if !NT_SUCCESS(status) {
        log::error!("2nd AuxKlibQueryModuleInformation failed ({:#x})", status);
        return None;
    }

    let number_of_modules = buffer_size / size_of::<AuxModuleExtendedInfo>() as u32;
    let module = mod_ptr as *mut AuxModuleExtendedInfo;

    log::info!("Address of Modules: {:?}, Number of Modules: {:?}", module, number_of_modules);

    return Some((module, number_of_modules));
}

/// Search the loaded modules (kernel callbacks)
pub fn search_loaded_modules(modules: *mut AuxModuleExtendedInfo, number_of_modules: u32, module_info: *mut CallBackInformation) -> NTSTATUS {
    
    for i  in 0..number_of_modules {
        let start_address = unsafe { (*modules.offset(i as isize)).basic_info.image_base };
        let image_size = unsafe { (*modules.offset(i as isize)).image_size };
        
        let end_address = start_address as u64 + image_size as u64;
        let raw_pointer = unsafe { *(((*module_info).pointer &  0xfffffffffffffff8) as *mut u64) };

        if raw_pointer > start_address as u64 && raw_pointer < end_address {
            let dst = unsafe { (*module_info).module_name.as_mut() };

            let src = unsafe { 
                (*modules.offset(i as isize)).full_path_name.as_mut_ptr().offset((*modules.offset(i as isize)).file_name_offset as isize)
            };

            unsafe { copy_nonoverlapping(src, dst.as_mut_ptr(), strlen(src as *const i8)) };
            break;
        }
    }

    return STATUS_SUCCESS;
}