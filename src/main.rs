use core::hash;
use std::{
    env,
    io::{Read, Write, stdout},
    net::TcpStream,
    os::windows::io::{AsRawSocket, AsSocket},
};

use crate::{buffer::Error, tls_stream::TlsStream, utils::hkdf_derive_secret};
use crypto::curve25519;
use hkdf::Hkdf;
use sha2::{Digest, Sha384, digest::crypto_common};

mod buffer;
mod client_hello;
mod format;
mod handshake;
mod keypair;
mod mockdata;
mod record;
mod server_hello;
mod utils;

mod tls_stream;

fn main() {
    let stream = TlsStream::connect("localhost".into(), "localhost:5252").unwrap();

    println!("\nTERMINATED")
}
