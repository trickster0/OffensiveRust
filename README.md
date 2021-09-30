<p align="center">
    <img height="500" alt="OffensiveRust" src="https://github.com/trickster0/OffensiveRust/raw/master/offensiverust.png">
</p>

# OffensiveRust

My experiments in weaponizing [Rust](https://www.rust-lang.org/) for implant development and general offensive operations.

## Table of Contents

- [OffensiveRust](#offensiverust)
  * [Why Rust?](#why-rust)
  * [Examples in this repo](#examples-in-this-repo)
  * [Compiling the examples](#compiling-the-examples-in-this-repo)
  * [Compiling the examples in this repo](#Compiling-the-examples-in-this-repo)
  * [Cross Compiling](#cross-compiling)
  * [Optimizing executables for size](#optimizing-executables-for-size)
  * [Pitfalls I found myself falling into](#pitfalls-i-found-myself-falling-into)
  * [Interesting Rust Libraries](#interesting-Rust-libraries)
  * [Opsec](#Opsec)
  * [Other projects I have have made in Rust](#Other-projects-I-have-made-in-Rust)

## Why Rust?

- It is faster than languages like C/C++
- It is multi-purpose language, bearing excellent communities
- It has an amazing inbuilt dependency build management called Cargo
- It is LLVM based which makes it a very good candidate for bypassing static AV detection
- Super easy cross compilation to Windows from *nix/MacOS, only requires you to install the `mingw` toolchain, although certain libraries cannot be compiled successfully in other OSes.

## Examples in this repo

| File | Description |
| ---  | --- |
| [Allocate_With_Syscalls](../master/Allocate_With_Syscalls/src/main.rs) | It uses NTDLL functions directly with the ntapi Library |
| [Create_DLL](../master/Create_DLL/src/main.rs) | Creates DLL and pops up a msgbox, Rust does not fully support this so things might get weird since Rust DLL do not have a main function |
| [DeviceIoControl](../master/DeviceIoControl/src/main.rs) | Opens driver handle and executing DeviceIoControl |
| [EnableDebugPrivileges](../master/EnableDebugPrivileges/src/main.rs) | Enable SeDebugPrivilege in the current process |
| [Exec_Shellcode_In_Memory](../master/Exec_Shellcode_In_Memory/src/main.rs) | Executes shellcode directly in memory by casting pointer |
| [Execute_With_CMD](../master/Execute_Without_Create_Process/src/main.rs) | Executes cmd by passing a command via Rust |
| [ImportedFunctionCall](../master/ImportedFunctionCall/src/main.rs) | It imports minidump from dbghelp and executes it |
| [Kernel_Driver_Exploit](../master/Kernel_Driver_Exploit/src/main.rs) | Kernel Driver exploit for a simple buffer overflow |
| [Named_Pipe_Client](../master/Named_Pipe_Client/src/main.rs) | Named Pipe Client |
| [Named_Pipe_Server](../master/Named_Pipe_Server/src/main.rs) | Named Pipe Server |
| [Process_Injection_CreateThread](../master/Process_Injection_CreateThread/src/main.rs) | Process Injection in remote process with CreateRemoteThread |
| [Unhooking](../master/Unhooking/src/main.rs) | Unhooking calls|
| [asm_syscall](../master/asm_syscall/src/main.rs) | Obtaining PEB address via asm |
| [base64_system_enum](../master/base64_system_enum/src/main.rs) | Base64 encoding/decoding strings |
| [http-https-requests](../master/http-https-requests/src/main.rs) | HTTP/S requests by ignoring cert check for GET/POST |
| [patch_etw](../master/patch_etw/src/main.rs) | Patch ETW |
| [ppid_spoof](../master/ppid_spoof/src/main.rst) | Spoof parent process for created process |
| [tcp_ssl_client](../master/tcp_ssl_client/src/main.rs) | TCP client with SSL that ignores cert check (Requires openssl and perl to be installed for compiling) | 
| [tcp_ssl_server](../master/tcp_ssl_server/src/main.rs) | TCP Server, with port parameter(Requires openssl and perl to be installed for compiling) |
| [wmi_execute](../master/wmi_execute/src/main.rs) | Executes WMI query to obtain the AV/EDRs in the host|

## Compiling the examples in this repo

This repository does not provide binaries, you're gonna have to compile them yourself.

This repo was compiled in Windows 10 so I would stick to it. As mentioned OpenSSL binaries will have depencency issues that will require OpenSSL and perl to be installed.
For the TCP SSL client/server I recommend static build due to dependencies on the hosts you will execute the binaries.
For creating a project, execute:  
`cargo new <name>`
This will automatically create the structured project folders with:

```bash  
project
├── Cargo.toml
└── src
    └── main.rs
```

Cargo.toml is the file that contains the dependencies and the configuration for the compilation.
main.rs is the main file that will be compiled along with any potential directories that contain libraries.

For compiling the project, go into the project directory and execute:  
`cargo build`

This will use your default toolchain.
If you want to build the final "release" version execute:  
`cargo build --release`

For static binaries, in terminal before the build command execute:  
`"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"`  
`set RUSTFLAGS=-C target-feature=+crt-static`


[Install Rust](https://www.rust-lang.org/tools/install) Simply download the binary and install.



The easiest place to find the dependencies or [Crates](https://crates.io/) as they are called.

## Cross Compiling

Cross-Compiling requires to follow the instructions [here](https://rust-lang.github.io/rustup/cross-compilation.html)
By installing different toolchains, you can cross compile with the below command  
`cargo build --target <toolchain>`

## Optimizing executables for size

This [repo](https://github.com/johnthagen/min-sized-rust) contains a lot of configuration options and ideas about reducing the file size.
Static binaries are usually quite big.

## Pitfalls I found myself falling into

Careful of \0 bytes, do not forget them for strings in memory, it spent a lot of my time but windbg always helped resolving it.


## Interesting Rust libraries

-WINAPI  
-[WINAPI2](https://github.com/MauriceKayser/rs-winapi2)  
-Windows  

## OPSEC

-Even though Rust has good advantages it is quite difficult to get used to it and it ain't very intuitive.  
-Shellcode generation is another issue due to LLVM. I have found a few ways to approach this.  
[Donut](https://github.com/TheWover/donut) sometimes does generate shellcode that works but not all the time.  
In general, for shellcode generation the tools that are made should be made to host all code in .text segment,
which leads to this amazing [repo](https://github.com/b1tg/rust-windows-shellcode).
There is a shellcode sample in this project that can show you how to structure and code anything you would like to be possible 
to work via shellcode afterwards.  In addition, this project also has a shellcode generator that grabs the .text segment of a binary and
and dumps the shellcode after executing some patches.
This project grabs from a specific location the binary so I made a fork that receives the path of the binary as an argument [here](https://github.com/trickster0/rust-windows-shellcode-custom).

## Other projects I have have made in Rust

-[UDPlant](https://github.com/trickster0/UDPlant) - Basically a UDP reverse shell
-[EDR Detector](https://github.com/trickster0/EDR_Detector) - Detects the EDRs of the installed system according to the .sys files installed
-[Lenum](https://github.com/trickster0/Lenum) - A simple unix enumeration tool
