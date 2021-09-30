use std::io::{Read, Write};
use std::net;
use std::net::{Ipv4Addr, TcpStream, SocketAddr};
use std::process::{Command, Stdio};
use std::str;
use std::thread;
use std::path::Path;
use openssl::ssl::{SslMethod, SslConnector};
use std::ffi::OsStr;

fn main() {
    let mut build = SslConnector::builder(SslMethod::tls()).unwrap();
    build.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let connector = build.build();
	let addr = Ipv4Addr::new(127,0,0,1);
	let sockettest = SocketAddr::from((addr,4443));
	let convertsocket = sockettest.to_string();
	let convertip = addr.to_string();
    let stream = TcpStream::connect(&convertsocket).unwrap();
    let mut stream = connector.connect(&convertip,stream).unwrap();
    loop {
        let mut recv = [0 as u8; 1024];
        stream.read(&mut recv);
        let my_string = String::from_utf8_lossy(&recv);
        let mut splitted = my_string.split("\r");
        println!("{:?}",splitted.next().unwrap());
        stream.write_all(b"RUST IS GOOD FOR OFFSEC");
    }
}
