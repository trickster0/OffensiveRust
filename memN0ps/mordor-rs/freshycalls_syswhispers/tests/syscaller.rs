#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use freshycalls_syswhispers::syscall_resolve::get_process_id_by_name;
    use freshycalls_syswhispers::syscall;
    use ntapi::{winapi::shared::ntdef::{OBJECT_ATTRIBUTES, HANDLE, NT_SUCCESS}, ntapi_base::CLIENT_ID};
    use windows_sys::Win32::System::{Threading::{PROCESS_VM_READ, PROCESS_VM_WRITE}};

    #[test]
    fn test_open_process() {
        env_logger::init();

        let mut oa = OBJECT_ATTRIBUTES::default();

        let process_id = get_process_id_by_name("notepad.exe");
        let mut process_handle = process_id as HANDLE;

        let mut ci = CLIENT_ID {
            UniqueProcess: process_handle,
            UniqueThread: null_mut(),
        };

        let status = unsafe {
            syscall!(
                "NtOpenProcess",
                &mut process_handle,
                PROCESS_VM_WRITE | PROCESS_VM_READ,
                &mut oa,
                &mut ci
            )
        };

        assert_eq!(NT_SUCCESS(status), true);
    }
}