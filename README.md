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
  * [Projects in Rust that can be hepfull ](#Projects-in-Rust-that-can-be-hepfull )

## Why Rust?

- It is faster than languages like C/C++
- It is multi-purpose language, bearing excellent communities
- It has an amazing inbuilt dependency build management called Cargo
- It is LLVM based which makes it a very good candidate for bypassing static AV detection
- Super easy cross compilation to Windows from *nix/MacOS, only requires you to install the `mingw` toolchain, although certain libraries cannot be compiled successfully in other OSes.

## Examples in this repo

| File                                                                                                   | Description                                                                                                                                                                              |
|--------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Allocate_With_Syscalls](../master/Allocate_With_Syscalls/src/main.rs)                                 | It uses NTDLL functions directly with the ntapi Library                                                                                                                                  |
| [Create_DLL](../master/Create_DLL/src/lib.rs)                                                          | Creates DLL and pops up a msgbox, Rust does not fully support this so things might get weird since Rust DLL do not have a main function                                                  |
| [DeviceIoControl](../master/DeviceIoControl/src/main.rs)                                               | Opens driver handle and executing DeviceIoControl                                                                                                                                        |
| [EnableDebugPrivileges](../master/EnableDebugPrivileges/src/main.rs)                                   | Enable SeDebugPrivilege in the current process                                                                                                                                           |
| [Shellcode_Local_inject](../master/Shellcode_Local_inject/src/main.rs)                                 | Executes shellcode directly in local process by casting pointer                                                                                                                          |
| [Execute_With_CMD](../master/Execute_Without_Create_Process/src/main.rs)                               | Executes cmd by passing a command via Rust                                                                                                                                               |
| [ImportedFunctionCall](../master/ImportedFunctionCall/src/main.rs)                                     | It imports minidump from dbghelp and executes it                                                                                                                                         |
| [Kernel_Driver_Exploit](../master/Kernel_Driver_Exploit/src/main.rs)                                   | Kernel Driver exploit for a simple buffer overflow                                                                                                                                       |
| [Named_Pipe_Client](../master/Named_Pipe_Client/src/main.rs)                                           | Named Pipe Client                                                                                                                                                                        |
| [Named_Pipe_Server](../master/Named_Pipe_Server/src/main.rs)                                           | Named Pipe Server                                                                                                                                                                        |
| [PEB_Walk](../master/PEB_Walk/src/main.rs)                                                             | Dynamically resolve and invoke Windows APIs                                                                                                                                              |
| [Process_Injection_CreateThread](../master/Process_Injection_CreateThread/src/main.rs)                 | Process Injection in running process with CreateThread                                                                                                                                   |
| [Process_Injection_CreateRemoteThread](../master/Process_Injection_CreateRemoteThread/src/main.rs)     | Process Injection in remote process with CreateRemoteThread                                                                                                                              |
| [Process_Injection_Self_EnumSystemGeoID](../master/Process_Injection_Self_EnumSystemGeoID/src/main.rs) | Self injector that uses the EnumSystemsGeoID API call to run shellcode.                                                                                                                  |
| [Unhooking](../master/Unhooking/src/main.rs)                                                           | Unhooking calls                                                                                                                                                                          |
| [asm_syscall](../master/asm_syscall/src/main.rs)                                                       | Obtaining PEB address via asm                                                                                                                                                            |
| [base64_system_enum](../master/base64_system_enum/src/main.rs)                                         | Base64 encoding/decoding strings                                                                                                                                                         |
| [http-https-requests](../master/http-https-requests/src/main.rs)                                       | HTTP/S requests by ignoring cert check for GET/POST                                                                                                                                      |
| [patch_etw](../master/patch_etw/src/main.rs)                                                           | Patch ETW                                                                                                                                                                                |
| [ppid_spoof](../master/ppid_spoof/src/main.rs)                                                         | Spoof parent process for created process                                                                                                                                                 |
| [tcp_ssl_client](../master/tcp_ssl_client/src/main.rs)                                                 | TCP client with SSL that ignores cert check (Requires openssl and perl to be installed for compiling)                                                                                    |
| [tcp_ssl_server](../master/tcp_ssl_server/src/main.rs)                                                 | TCP Server, with port parameter(Requires openssl and perl to be installed for compiling)                                                                                                 |
| [wmi_execute](../master/wmi_execute/src/main.rs)                                                       | Executes WMI query to obtain the AV/EDRs in the host                                                                                                                                     |
| [Windows.h+ Bindings](../master/bindings.rs)                                                           | This file contains structures of Windows.h plus complete customized LDR,PEB,etc.. that are undocumented officially by Microsoft, add at the top of your file include!("../bindings.rs"); |
| [UUID_Shellcode_Execution](../master/UUID_Shellcode_Execution/src/main.rs)                             | Plants shellcode from UUID array into heap space and uses `EnumSystemLocalesA` Callback in order to execute the shellcode.                                                               |
| [AMSI Bypass](../master/amsi_bypass/src/main.rs)                                                       | AMSI Bypass on Local Process                                                                                                                                                             |
| [Injection_AES_Loader](../master/Injection_AES_Loader/src/main.rs)                                     | NtTestAlert Injection with AES decryption                                                                                                                                                |
| [Litcrypt_String_Encryption](../master/Litcrypt_String_Encryption/src/main.rs)                         | Using the [Litcrypt](https://github.com/anvie/litcrypt.rs) crate to encrypt literal strings at rest and in memory to defeat static AV.                                                   |
| [Api Hooking](../master/apihooking/src/main.rs)                                                        | Api Hooking using detour library                                                                                                                                                         |
| [memfd_create](../master/memfd_create/src/main.rs)                                                     | Execute payloads from memory using the memfd_create technique (For Linux)                                                                                                                |
| [RC4_Encryption](../master/Injection_Rc4_Loader/src/main.rs)                                           | RC4 Decrypted shellcode                                                                                                                                                                  |
| [Steal Token](../master/token_manipulation/src/main.rs) | Steal Token From Process|
| [Keyboard Hooking](../master/keyboard_hooking/src/main.rs) | Keylogging by hooking keyboard with SetWindowsHookEx |
| [memN0ps arsenal: shellcode_runner_classic-rs](https://github.com/memN0ps/arsenal-rs/blob/main/shellcode_runner_classic-rs/src/main.rs) | Classic shellcode runner/injector using `ntapi`                                                                                                                                                       |
| [memN0ps arsenal: dll_injector_classic-rs](https://github.com/memN0ps/arsenal-rs/blob/main/dll_injector_classic-rs/inject/src/main.rs)  | Classic DLL Injection using `windows-sys`                                                                                                                                                          |
| [memN0ps arsenal: module_stomping-rs](https://github.com/memN0ps/arsenal-rs/blob/main/module_stomping-rs/src/main.rs)                   | Module Stomping / Module Overloading / DLL Hollowing using `windows-sys`                                                                                                                                                              |
| [memN0ps arsenal: obfuscate_shellcode-rs](https://github.com/memN0ps/arsenal-rs/blob/main/obfuscate_shellcode-rs/src/main.rs)           | Simple shellcode XOR and AES obfuscator                                                                                                                                                                 |
| [memN0ps arsenal: process_hollowing-rs](https://github.com/memN0ps/arsenal-rs/blob/main/process_hollowing-rs/src/main.rs)               | Process Hollowing using `ntapi`                                                                                                                                                      |
| [memN0ps arsenal: rdi-rs](https://github.com/memN0ps/arsenal-rs/blob/main/rdi-rs/reflective_loader/src/loader.rs)                                  | Reflective DLL Injection using `windows-sys`                                                                                                                                                         |
| [memN0ps: eagle-rs](https://github.com/memN0ps/eagle-rs/blob/master/driver/src/lib.rs)                                                    | Rusty Rootkit: Windows Kernel Driver in Rust for Red Teamers using `winapi` and `ntapi`                                                                                                                                                       |
| [memN0ps: psyscalls-rs](https://github.com/memN0ps/psyscalls-rs/blob/main/parallel_syscalls/src/parallel_syscalls.rs)                                   | Rusty Parallel Syscalls library using `winapi`                                                                                                                                                      |
| [memN0ps: mmapper-rs](https://github.com/memN0ps/mmapper-rs/blob/main/loader/src/lib.rs)                                               | Rusty Manual Mapper using `winapi`                                                                                                                                   |
| [memN0ps: srdi-rs](https://github.com/memN0ps/srdi-rs/blob/main/reflective_loader/src/lib.rs)                                           | Rusty Shellcode Reflective DLL Injection using `windows-sys`                                                                                                                                               |
| [memN0ps: mordor-rs - freshycalls_syswhispers](https://github.com/memN0ps/mordor-rs/blob/main/freshycalls_syswhispers/tests/syscaller.rs)                 | Rusty FreshyCalls / SysWhispers1 / SysWhispers2 / SysWhispers3 library using `windows-sys`                                                                                                                                               |
| [memN0ps: mordor-rs - hells_halos_tartarus_gate](https://github.com/memN0ps/mordor-rs/blob/main/hells_halos_tartarus_gate/src/lib.rs)             | Rusty Hell's Gate / Halo's Gate / Tartarus' Gate Library using `windows-sys`                                                                                                                                           |
| [memN0ps: pemadness-rs](https://github.com/memN0ps/pemadness-rs/blob/main/pemadness/src/lib.rs)                                                   | Rusty Portable Executable Parsing Library (PE Parsing Library) using `windows-sys`                                                                                                                                                       |
| [memN0ps: mimiRust](https://github.com/memN0ps/mimiRust/blob/main/src/main.rs)                                                          | Mimikatz made in Rust by @ThottySploit. The original author deleted their GitHub account, so it's been uploaded for community use.                                                                                                                                                   |
| [memN0ps and trickster0: ekko-rs](https://github.com/memN0ps/ekko-rs/blob/master/src/ekko.rs)                                                          |  Rusty Ekko - Sleep Obfuscation in Rust using windows-sys.                                                                                                                                                   |


## Compiling the examples in this repo

This repository does not provide binaries, you're gonna have to compile them yourself.  

[Install Rust](https://www.rust-lang.org/tools/install)  
Simply download the binary and install.

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

In case it does not feel easy for you to read my code the way it is written,  
you can also you the below command inside the project directory to format it in a better way  
`cargo fmt`

Certain examples might not compile and give you some error, since it might require a nightly  
build of Rust with the latest features. To install it just do:  
`rustup default nightly`  



The easiest place to find the dependencies or [Crates](https://crates.io/) as they are called.

## Cross Compiling

Cross-Compiling requires to follow the instructions [here](https://rust-lang.github.io/rustup/cross-compilation.html)
By installing different toolchains, you can cross compile with the below command  
`cargo build --target <toolchain>`  

To see the installed toolchains on your system do:  
`rustup toolchain list`  

For checking all the available toolchains you can install in your system do:  
`rustup target list`  

For installing a new toolchain do:  
`rustup target add <toolchain_name>`  


## Optimizing executables for size

This [repo](https://github.com/johnthagen/min-sized-rust) contains a lot of configuration options and ideas about reducing the file size.
Static binaries are usually quite big.

## Pitfalls I found myself falling into

Careful of \0 bytes, do not forget them for strings in memory, I spent a lot of my time but windbg always helped resolving it.


## Interesting Rust libraries

- WINAPI  
- [WINAPI2](https://github.com/MauriceKayser/rs-winapi2)  
- Windows - This is the official Microsoft one that I have not played much with

## OPSEC

- Even though Rust has good advantages it is quite difficult to get used to it and it ain't very intuitive.  
- Shellcode generation is another issue due to LLVM. I have found a few ways to approach this.  
[Donut](https://github.com/TheWover/donut) sometimes does generate shellcode that works but depending on how the project is made, it might not.  
In general, for shellcode generation the tools that are made should be made to host all code in .text segment,
which leads to this amazing [repo](https://github.com/b1tg/rust-windows-shellcode).
There is a shellcode sample in this project that can show you how to structure your code for successfull shellcode generation.  
In addition, this project also has a shellcode generator that grabs the .text segment of a binary and
and dumps the shellcode after executing some patches.  
This project grabs from a specific location the binary so I made a fork that receives the path of the binary as an argument [here](https://github.com/trickster0/rust-windows-shellcode-custom).  
- Even if you remove all debug symbols, rust can still keep references to your home directory in the binary. The only way I've found to remove this is to pass the following flag: `--remap-path-prefix {your home directory}={some random identifier}`. You can use bash variables to get your home directory and generate a random placeholder: `--remap-path-prefix "$HOME"="$RANDOM"`. (By [Yamakadi](https://github.com/yamakadi))
- Although for the above there is another way to remove info about the home directory by adding at the top of Cargo.toml  
`cargo-features = ["strip"]` .  
Since Rust by default leaves a lot of things as strings in the binary, I mostly use this [cargo.toml](../master/cargo.toml) to avoid them and also reduce size  
with build command   
`cargo build --release -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-pc-windows-msvc`
- [Yamakadi] , also pointed out that depending on the imported libraries, stripping is not always consistent on hiding the home directory, so a combination of his solution to remap the path and use teh above cargo would work best. Try to be aware and check your binaries before executing them to your engagements for potential strings that are not stripped properly.

## Other projects I have have made in Rust

- [UDPlant](https://github.com/trickster0/UDPlant) - Basically a UDP reverse shell  
- [EDR Detector](https://github.com/trickster0/EDR_Detector) - Detects the EDRs of the installed system according to the .sys files installed  
- [Lenum](https://github.com/trickster0/Lenum) - A simple unix enumeration tool

## Projects in Rust that can be hepfull 

- [houdini](https://github.com/yamakadi/houdini) - Helps make your executable self-delete
