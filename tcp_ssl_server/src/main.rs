use std::io;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use openssl::ssl::{SslMethod, SslAcceptor, SslStream, SslFiletype};
use std::sync::Arc;

fn main() {
    let args: Vec<String> = env::args().collect();
    let port = &args[1];
    let mut complete = "0.0.0.0:".to_string();
    complete.push_str(&port);
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_private_key_file("server.key", SslFiletype::PEM).unwrap();
    acceptor.set_certificate_chain_file("server.crt").unwrap(); 
    acceptor.check_private_key().unwrap();
    let acceptor = Arc::new(acceptor.build());
    let listener2 = TcpListener::bind(&complete).unwrap();
    println!("[+] Server listening on port {}",&port);
    for stream2 in listener2.incoming() {
        match stream2 {
            Ok(stream2) => {
                println!("New connection: {}", stream2.peer_addr().unwrap());
                let acceptor = acceptor.clone();
                thread::spawn(move || {
                    let stream2 = acceptor.accept(stream2).unwrap();
                    handle_client(stream2)
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

fn handle_client(mut stream: SslStream<TcpStream>) {
    loop {
        print!("Input: ");
        io::stdout().flush().expect("failed to get it");
        let mut input = String::new();
        io::stdin().read_line(&mut input);
        stream.write(&mut input.as_bytes()).unwrap();
        let mut data = [0 as u8; 100];
        stream.read(&mut data);
        let string = String::from_utf8_lossy(&data);
        println!("{}", string);
    }
}
