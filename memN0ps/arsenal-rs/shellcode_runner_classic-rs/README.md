# Classic Shellcode Runner in Rust

Classic Shellcode in Rust using NTDLL functions directly with the NTAPI library.


## Encoding (XOR)

The shellcode used is a msfvenom payload that is simply XOR encoded:

The shellcode is then decoded in the program at runtime using the following:
```rust
let mut shellcode : Vec<u8> = Vec::with_capacity(buf.len());
for x in &buf {
    shellcode.push(*x ^ 0xBE); //change this byte for different XOR.
}
```

Comment out the appropriate line if you don't want to use any encoding and if you do then make sure you encode your shellcode with the appropriate byte.

## Detections

I had 0 detections on Virus Total but this will change after making the project public, also don't rely 100% on virus total results.

![Detections](./Detections.PNG)

https://www.virustotal.com/gui/file/34d2ad3a0c5d603df03ddca8cdaff47545ab427aa9c32dd60e15764b3615abab?nocache=1


## References and Credits

* https://mr.un1k0d3r.com/ (Including the people in the VIP discord Mr.Un1k0d3r, Waldo-IRC, Ditto, nixfreax)
* https://discord.com/invite/rust-lang-community (Rust Lang Community)
* https://github.com/trickster0/OffensiveRust (Motivated by this repository)
* https://github.com/byt3bl33d3r/OffensiveNim
* https://twitter.com/_RastaMouse and https://twitter.com/Jean_Maes_1994
* https://docs.rs/winapi/0.3.9/winapi/
* https://www.rust-lang.org/learn
