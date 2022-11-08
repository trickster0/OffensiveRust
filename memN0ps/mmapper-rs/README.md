# Manual Mapper

A manual mapper written in Rust

## USAGE
```
manual_map-rs.exe --process <PROCESS> --url <URL>
```

## Features

* Manual Mappping in Remote process
* Manual Mappping x64 DLLs
* Rebasing image and resolving imports in the local process
* Download DLL remotely (HTTP supported and HTTPS ToDo)
* Manual Mappping in local process (ToDo)
* Manual Mappping in an executable file (ToDo)
* TLS callbacks (ToDo)

## References

* https://github.com/Ben-Lichtman (B3NNY)
* https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes
* https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations
* https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection
* https://andreafortuna.org/2018/09/24/some-thoughts-about-pe-injection/
* https://blog.sevagas.com/PE-injection-explained
* http://www.rohitab.com/discuss/topic/41441-pe-injection-new/
* https://github.com/not-matthias/mmap/
* https://github.com/2vg/blackcat-rs/
* https://github.com/Kudaes/DInvoke_rs/
* https://github.com/zorftw/kdmapper-rs/
* https://github.com/stephenfewer/ReflectiveDLLInjection/
* https://github.com/Zer0Mem0ry/ManualMap
* https://github.com/MrElectrify/mmap-loader-rs/
* https://github.com/seal9055/darksouls3_cheats
* https://guidedhacking.com/threads/manual-mapping-dll-injection-tutorial-how-to-manual-map.10009/
* https://0xrick.github.io/win-internals/pe7/#relocations
* https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
* https://stackoverflow.com/questions/17436668/how-are-pe-base-relocations-build-up
* https://discord.com/invite/rust-lang-community (Rust Programming Language Community Server - Discord)
