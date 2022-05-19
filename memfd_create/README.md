# memfd_create-rs

Load binaries into memory and execute them without touching disk.

MITRE ID: T1620

A simple PoC C code can be found inside `src` folder.

Main program will download the ELF and execute it from memory using the `memfd_create` technique.