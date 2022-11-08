#![no_std]

extern crate alloc;
use winapi::{um::winioctl::{FILE_DEVICE_UNKNOWN, METHOD_NEITHER, FILE_ANY_ACCESS}};

macro_rules! CTL_CODE {
    ($DeviceType:expr, $Function:expr, $Method:expr, $Access:expr) => {
        ($DeviceType << 16) | ($Access << 14) | ($Function << 2) | $Method
    }
}

pub const IOCTL_PROCESS_READ_REQUEST: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS);
pub const IOCTL_PROCESS_WRITE_REQUEST: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS);
pub const IOCTL_PROCESS_PROTECT_REQUEST: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS);
pub const IOCTL_PROCESS_UNPROTECT_REQUEST: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS);
pub const IOCTL_PROCESS_TOKEN_PRIVILEGES_REQUEST: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS);
pub const IOCTL_PROCESS_HIDE_REQUEST: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS);

pub const IOCTL_CALLBACKS_ENUM_REQUEST: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS);
pub const IOCTL_CALLBACKS_ZERO_REQUEST: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS);

pub const IOCTL_DSE_ENABLE_DISABLE_REQUEST: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x808, METHOD_NEITHER, FILE_ANY_ACCESS);

pub const IOCTL_DRIVER_HIDE_REQUEST: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER, FILE_ANY_ACCESS);
pub const IOCTL_DRIVER_ENUM_REQUEST: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x810, METHOD_NEITHER, FILE_ANY_ACCESS);


#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TargetProcess {
    pub process_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CallBackInformation {
    pub module_name: [u8; 256],
    pub pointer: u64,
}

/* 
impl Default for CallBackInformation {
    fn default() -> Self {
        Self {
            module_name: [0u8; 256],
            pointer: 0,
        }
    }
}*/

pub struct TargetCallback {
    pub index: u32
}

pub struct DriverSignatureEnforcement {
    pub address: u64,
    pub is_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct ModuleInformation {
    pub module_base: usize,
    pub module_name: [u16; 256],
}