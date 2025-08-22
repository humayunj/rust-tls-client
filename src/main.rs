use core::hash;
use std::{
    env,
    io::{Read, Write, stdout},
    net::TcpStream,
    os::windows::io::{AsRawSocket, AsSocket},
};

use crate::{
    buffer::Error, http_msg::HttpResponse, tls_stream::TlsStream, utils::hkdf_derive_secret,
};
use crypto::curve25519;
use hkdf::Hkdf;
use sha2::{Digest, Sha384, digest::crypto_common};

mod buffer;
mod client_hello;
mod format;
mod handshake;
mod http_msg;
mod keypair;
mod mockdata;
mod record;
mod server_hello;
mod tls_stream;
mod utils;

fn main() {
    let hostname = String::from("humayun.io");
    let mut stream = TlsStream::connect(&hostname, format!("{}:443", hostname)).unwrap();

    let http_msg = format!(
        "GET / HTTP/1.1\r\nConnection: close\r\nHost: {}\r\n\r\n",
        hostname
    );
    println!("Encoded Request:\n\n{}", &http_msg);

    // send message

    stream.send_data(http_msg.as_bytes().into()).unwrap();

    let mut msg = vec![];
    loop {
        if let Ok(d) = stream.receive_data() {
            msg.extend_from_slice(&d[..]);
        } else {
            break;
        }
    }

    let res = HttpResponse::try_from(&msg[..]).unwrap();
    print!("{}", res);
    print!("{}", &res.to_text());
    println!("HEADERS === ");
    for h in res.headers() {
        println!("{:?}", h);
    }
}
