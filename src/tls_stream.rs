use std::{
    fmt::Display,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
};

use crate::{
    buffer::{Buffer, Error},
    client_hello::ClientHello,
    format::{Extention, KeyShareExtention},
    handshake::Handshake,
    keypair::KeyPair,
    record::Record,
    server_hello::ServerHello,
    utils::{concat_bytes_array, gen_session_keys},
};

use rand::{self, RngCore};
use sha2::{Digest, Sha384};
pub struct TlsStream {
    session: Session,
    tcp: TcpStream,
}

struct Session {
    hostname: String,
    keypair: KeyPair,
    server_pubkey: [u8; 32],
    client_handshake: Option<Handshake>,
    server_handshake: Option<Handshake>,
    keys: SessionKeys,
}

impl TlsStream {
    pub fn connect(hostname: String, addr: impl ToSocketAddrs) -> Result<TlsStream, Error> {
        let tcp_stream = TcpStream::connect(addr).unwrap();

        let mut secret: [u8; 32] = [0u8; 32];

        let mut rgn = rand::rng();
        rgn.fill_bytes(&mut secret);

        let kp = KeyPair::from(secret);
        let session = Session {
            keypair: kp,
            server_pubkey: [0u8; 32],
            hostname,
            client_handshake: None,
            server_handshake: None,
            keys: SessionKeys {
                handshake_secret: vec![],
                client_secret: vec![],
                server_secret: vec![],
                client_handshake_key: vec![],
                client_handshake_iv: vec![],
                server_handshake_key: vec![],
                server_handshake_iv: vec![],
            },
        };

        let mut stream = TlsStream {
            session: session,
            tcp: tcp_stream,
        };

        let mut client_hello = ClientHello::new();

        client_hello.client_random = [0u8; 32];
        client_hello.cipher_suits.push(0x1302);
        client_hello.compression_methods.push(0);
        client_hello.exts = stream.build_extentions();

        let client_hs = Handshake::from(client_hello);
        let hs = Buffer::from(&client_hs);

        let rec = Record::new(0x16, hs.vec); // handshake

        stream.send_record(&rec)?;

        let server_hello_b = stream.read_record()?;

        let server_hello = ServerHello::try_from(&server_hello_b)?;
        let server_public_key = server_hello.extract_shared_key().unwrap();

        stream.session.server_pubkey = server_public_key[..].try_into()?;
        let server_hs = Handshake::try_from(&server_hello_b)?;

        if let Ok(keys) = gen_session_keys(
            &stream.session.keypair.private_key,
            &stream.session.server_pubkey,
            Buffer::from(&client_hs).as_bytes(),
            Buffer::from(&server_hs).as_bytes(),
        ) {
            stream.session.keys = keys;
        } else {
            return Err("Failed to generate session keys".into());
        }
        stream.session.server_handshake = Some(server_hs);

        println!("Keys: {}", &stream.session.keys);

        // receive change cipher

        let change_cipher_block = stream.read_record()?;

        println!("{}", change_cipher_block);

        Ok(stream)
    }

    fn build_extentions(&mut self) -> Vec<Extention> {
        vec![
            Extention::new(
                EXTENTION_SNI,
                Self::ext_server_name(self.session.hostname.clone()),
                false,
            ),
            Extention::new(
                EXTENTION_SUPPORTED_KEY_EXCHANGE,
                Vec::from([0x00, 0x02, 0x00, 0x1d]),
                false,
            ),
            Extention::new(
                EXTENTION_SUPPORTED_ALGOS,
                Self::ext_signature_algorithms(&Vec::from([
                    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                ])),
                false,
            ),
            Extention::new(
                EXTENTION_KEY_SHARE,
                Buffer::from(&KeyShareExtention::new(
                    0x1d,
                    Vec::from(&self.session.keypair.public_key),
                ))
                .vec,
                false,
            ),
            Extention::new(EXTENTION_PRESHARED_KEYS, Vec::from([0x01, 0x1]), false),
            Extention::new(
                EXTENTION_SUPPORTED_TLS_VERS,
                Vec::from([0x02, 0x3, 0x4]),
                false,
            ),
        ]
    }

    fn read_record(&mut self) -> Result<Record, Error> {
        let mut record_header: [u8; 5] = [0u8; 5];

        self.tcp.read_exact(&mut record_header)?;

        let record_size = Buffer::from(&Vec::from(record_header))
            .seek(3)?
            .read_u16()?;

        let mut content: Vec<u8> = vec![];
        content.resize(record_size as usize, 0); // zeroes
        self.tcp.read_exact(&mut content[..])?;

        let mut b = Buffer::from(&concat_bytes_array(&record_header, &content[..]));

        Record::try_from(&mut b)
    }

    fn send_record(&mut self, record: &Record) -> Result<(), Error> {
        self.tcp.write(Buffer::from(record).as_bytes())?;
        self.tcp.flush()?;
        Ok(())
    }

    fn ext_signature_algorithms(support_alogrithms: &Vec<u16>) -> Vec<u8> {
        let mut v: Vec<u8> = vec![];

        v.extend_from_slice(&((support_alogrithms.len() * 2) as u16).to_be_bytes()); // bytes of data

        support_alogrithms
            .iter()
            .for_each(|id| v.extend_from_slice(&id.to_be_bytes()));

        v
    }

    fn ext_server_name(host: String) -> Vec<u8> {
        let mut v: Vec<u8> = vec![];

        v.extend_from_slice(&((host.len() + 2 + 1) as u16).to_be_bytes()); // entries size: host size + host length bytes (2) + entry type byte (1)
        v.push(0x00); // Entry Type = DNS HOST
        v.extend_from_slice(&(host.len() as u16).to_be_bytes());
        v.extend_from_slice(&host[..].as_bytes());

        v
    }
}

pub const EXTENTION_SNI: u16 = 0x00;
pub const EXTENTION_SUPPORTED_KEY_EXCHANGE: u16 = 0x0a;
pub const EXTENTION_SUPPORTED_ALGOS: u16 = 0x0d;
pub const EXTENTION_KEY_SHARE: u16 = 0x33;
pub const EXTENTION_PRESHARED_KEYS: u16 = 0x2d;
pub const EXTENTION_SUPPORTED_TLS_VERS: u16 = 0x2b;

pub struct SessionKeys {
    pub handshake_secret: Vec<u8>,

    pub client_secret: Vec<u8>,
    pub server_secret: Vec<u8>,

    pub client_handshake_key: Vec<u8>,
    pub client_handshake_iv: Vec<u8>,

    pub server_handshake_key: Vec<u8>,
    pub server_handshake_iv: Vec<u8>,
}

impl Display for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "::SESSION KEYS::")?;
        writeln!(
            f,
            "HANDSHAKE_SECRET {}",
            hex::encode(&self.handshake_secret)
        )?;
        writeln!(f, "SECRET_SECRET {}", hex::encode(&self.server_secret))?;
        writeln!(f, "CLIENT_SECRET {}", hex::encode(&self.client_secret))?;
        writeln!(
            f,
            "CLIENT_HANDSHAKE_KEY {}",
            hex::encode(&self.client_handshake_key)
        )?;
        writeln!(
            f,
            "CLIENT_HANDSHAKE_IV {}",
            hex::encode(&self.client_handshake_iv)
        )?;
        writeln!(
            f,
            "SERVER_HANDSHAKE_KEY {}",
            hex::encode(&self.server_handshake_key)
        )?;
        writeln!(
            f,
            "SERVER_HANDSHAKE_IV {}",
            hex::encode(&self.server_handshake_iv)
        )?;

        Ok(())
    }
}
