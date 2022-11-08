use winapi::{km::wdm::PEPROCESS, shared::ntdef::NT_SUCCESS, um::winnt::PACCESS_TOKEN};

use crate::includes::{PsLookupProcessByProcessId, ObfDereferenceObject, PsReferencePrimaryToken, PsDereferencePrimaryToken};

#[derive(Debug, Clone)]
pub struct Process {
    pub eprocess: PEPROCESS,
}

impl Process {
    pub fn by_id(process_id: u64) -> Option<Self> {
        let mut process = core::ptr::null_mut();

        let status = unsafe { PsLookupProcessByProcessId(process_id as _, &mut process) };
        if NT_SUCCESS(status) {
            Some(Self { eprocess: process })
        } else {
            None
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.eprocess.is_null() {
            unsafe { ObfDereferenceObject(self.eprocess as _) }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Token {
    pub token: PACCESS_TOKEN,
}

impl Token {
    pub fn by_token(eprocess: PEPROCESS) -> Option<Self> {

        let token = unsafe { PsReferencePrimaryToken(eprocess) };
        if !token.is_null() {
            Some(Self { token })
        } else {
            None
        }
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        if !self.token.is_null() {
            unsafe { PsDereferencePrimaryToken(self.token) }
        }
    }
}