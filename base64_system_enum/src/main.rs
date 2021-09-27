use base64;
use whoami;

fn main() {
    let deviceName =base64::encode(&whoami::hostname());
    let userName =base64::encode(&whoami::username());
    let procNamePath = std::env::current_exe();
    println!("Hostname: {}\nEncoded Hostname: {}",whoami::hostname(),deviceName);
    println!("Username: {}\nEncoded Username: {}",whoami::username(),userName);
    println!("Executable Path: {:?}",procNamePath.unwrap());
    println!("Decoded Username: {:?}",String::from_utf8_lossy(&base64::decode("REVTS1RPUC1VNElFMEVF").unwrap()));
}
