mod ekko;

fn main() {
    //env_logger::init();
    println!("[*] Ekko Sleep Obfuscation by @memN0ps and @trickster0. Full credits to Cracked5pider (@C5pider), Austin Hudson (@SecIdiot), Peter Winter-Smith (@peterwintrsmith)");
    
    let mut key_buf = "1234567890ABCDEF\0".as_bytes().to_vec();
    loop {
        ekko::ekko(4000, &mut key_buf);
    }
}
