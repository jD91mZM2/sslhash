extern crate openssl;
extern crate sslhash;

use openssl::ssl::{SslConnector, SslMethod};
use sslhash::AcceptorBuilder;
use std::io::prelude::*;
use std::net::{TcpStream, TcpListener};
use std::thread;

const TEST_PAYLOAD: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
const IP_TEST1: &str = "localhost:1234";
const IP_TEST2: &str = "localhost:2345";

#[test]
fn test() {
    let (acceptor, hash) = AcceptorBuilder::default().set_cache_dir(None).build().unwrap();

    let thread = thread::spawn(move || {
        let tcp = TcpListener::bind(IP_TEST1).unwrap();
        let (client, _) = tcp.accept().unwrap();
        let mut client = acceptor.accept(client).unwrap();

        let mut buf = [0; 10];
        client.read_exact(&mut buf).unwrap();

        assert_eq!(&buf, TEST_PAYLOAD);
    });

    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    let client = TcpStream::connect(IP_TEST1).unwrap();
    let mut client = sslhash::connect(&connector, client, hash).unwrap();

    client.write_all(TEST_PAYLOAD).unwrap();
    client.flush().unwrap();

    thread.join().unwrap();
}

#[test]
fn invalid_hash() {
    let (acceptor, _) = AcceptorBuilder::default().set_cache_dir(None).build().unwrap();

    let thread = thread::spawn(move || {
        let tcp = TcpListener::bind(IP_TEST2).unwrap();
        let (client, _) = tcp.accept().unwrap();
        assert!(acceptor.accept(client).is_err());
    });

    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    let client = TcpStream::connect(IP_TEST2).unwrap();
    assert!(sslhash::connect(&connector, client, String::from("1234")).is_err());

    thread.join().unwrap();
}
