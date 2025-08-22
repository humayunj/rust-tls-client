use std::{
    fmt::Display,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::mpsc::Receiver,
};

use crate::{
    buffer::{Buffer, Error},
    client_hello::ClientHello,
    format::{Extention, KeyShareExtention},
    handshake::Handshake,
    keypair::KeyPair,
    record::{self, Record},
    server_hello::ServerHello,
    utils::{
        build_iv, concat_bytes_array, gen_session_keys, hdkf_expand_label, populate_app_keys,
        unwrap_record, wrap_record,
    },
};

use crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    aes_gcm,
};
use hkdf::hmac::{self, Mac};
use rand::{self, RngCore, rng};
use sha2::{Digest, Sha384};
pub struct TlsStream {
    session: Session,
    tcp: TcpStream,
    app_data: Vec<u8>,
}

pub enum KeysState {
    RAW,
    HANDHSAKE,
    APP,
}
struct Session {
    hostname: String,
    keypair: KeyPair,
    server_pubkey: [u8; 32],
    client_handshake: Option<Handshake>,
    server_handshake: Option<Handshake>,
    keys: SessionKeys,
    server_records_count: u64,
    client_records_count: u64,
    keys_state: KeysState,
}

impl TlsStream {
    pub fn connect(hostname: &String, addr: impl ToSocketAddrs) -> Result<TlsStream, Error> {
        let tcp_stream = TcpStream::connect(addr).unwrap();

        let mut secret: [u8; 32] = [0u8; 32];

        let mut rgn = rand::rng();
        rgn.fill_bytes(&mut secret);

        let kp = KeyPair::from(secret);
        let session = Session {
            keypair: kp,
            server_pubkey: [0u8; 32],
            hostname: hostname.clone(),
            client_handshake: None,
            server_handshake: None,
            server_records_count: 0,
            client_records_count: 0,
            keys: SessionKeys::new(),
            keys_state: KeysState::RAW,
        };

        let mut stream = TlsStream {
            session: session,
            tcp: tcp_stream,
            app_data: vec![],
        };

        let mut client_hello = ClientHello::new();

        client_hello.client_random = [0u8; 32];
        client_hello.cipher_suits.push(0x1302);
        client_hello.compression_methods.push(0);
        client_hello.exts = stream.build_extentions();

        rng().fill_bytes(&mut client_hello.client_random);

        let client_hs = Handshake::from(&client_hello);
        stream.session.client_handshake = Some(Handshake::from(&client_hello));

        let hs = Buffer::from(&client_hs);

        let client_rec = Record::new(0x16, hs.vec); // handshake

        stream.send_record(&client_rec)?;

        let server_hello_rec = stream.read_record()?;

        let server_hello = ServerHello::try_from(&server_hello_rec)?;
        let server_public_key = server_hello.extract_shared_key().unwrap();

        stream.session.server_pubkey = server_public_key[..].try_into()?;
        let server_hs = Handshake::try_from(&server_hello_rec)?;

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
        stream.session.server_handshake = Some(Handshake::try_from(&server_hello_rec)?);

        println!("Keys: {}", &stream.session.keys);

        // receive change cipher

        let change_cipher_block = stream.read_record()?;
        println!("{}", change_cipher_block);

        stream.session.keys_state = KeysState::HANDHSAKE;

        let encrypted_exts = stream.read_record()?;
        println!("{}", encrypted_exts);

        let server_cert = stream.read_record()?;
        println!("{}", server_cert);

        let server_cert_verfy = stream.read_record()?;
        println!("{}", server_cert_verfy);

        let server_handshake_finished_r = stream.read_record()?;
        println!("{}", server_handshake_finished_r);

        let mut hs_content: Vec<u8> = vec![];

        hs_content.extend_from_slice(&client_rec.content[..]);
        hs_content.extend_from_slice(&server_hello_rec.content[..]);
        hs_content.extend_from_slice(&encrypted_exts.content[..]);
        hs_content.extend_from_slice(&server_cert.content[..]);
        hs_content.extend_from_slice(&server_cert_verfy.content[..]);

        let hs_content_digest: _ = sha2::Sha384::digest(&hs_content[..]);

        let finished_hs = Handshake::try_from(&server_handshake_finished_r)?;

        let server_finished_key = hdkf_expand_label(
            &stream.session.keys.server_secret,
            "finished".into(),
            "".as_bytes(),
            48,
        )?;

        let mut hasher: _ = hkdf::hmac::Hmac::<Sha384>::new_from_slice(&server_finished_key[..])?;

        hasher.update(&hs_content_digest);

        let res_hash = hasher.finalize().into_bytes().to_vec();

        if res_hash != finished_hs.content.vec {
            println!(
                "Expect: {} Received: {}",
                hex::encode(&res_hash),
                hex::encode(&finished_hs.content.vec)
            )
        } else {
            println!("Server Handhsake finished")
        };

        println!(
            "server_handshake_finished_r: {}",
            hex::encode(&server_handshake_finished_r.content)
        );
        hs_content.extend_from_slice(&server_handshake_finished_r.content[..]);

        let handshakes_hash: _ = sha2::Sha384::digest(&hs_content[..]);

        populate_app_keys(&mut stream.session.keys, &handshakes_hash[..]);

        println!("New keys: {}", stream.session.keys);

        let client_change_cipher_r = Record {
            record_type: 0x14,
            ver: 0x0303,
            content: vec![1],
        };

        stream.send_record(&client_change_cipher_r)?; // change cipher
        println!("Sent cipher change");

        let client_finished_key = hdkf_expand_label(
            &stream.session.keys.client_secret,
            "finished".into(),
            "".as_bytes(),
            48,
        )?;

        let mut hasher: _ = hkdf::hmac::Hmac::<Sha384>::new_from_slice(&client_finished_key[..])?;

        let hs_content_digest = sha2::Sha384::digest(&hs_content[..]);

        hasher.update(&hs_content_digest[..]);

        let res_hash = hasher.finalize().into_bytes().to_vec();
        println!("Digest: {}", hex::encode(&res_hash));

        let hs = Handshake {
            handshake_type: 0x14, // handhsake finished
            content: Buffer::from(&res_hash),
        };

        stream.wrap_send_handshake_record(&Record {
            record_type: 0x16, // handshake record
            ver: 0x0303,
            content: Buffer::from(&hs).as_bytes().into(),
        })?; // change cipher

        // println!("Sent wrapped verify");

        stream.session.keys_state = KeysState::APP;
        stream.session.server_records_count = 0; // reset records count
        stream.session.client_records_count = 0; // reset records count

        // let ticket_1 = stream.read_record()?;
        // println!("ticket 1 {}", ticket_1);

        // let ticket_2 = stream.read_record()?;
        // println!("ticket 2 {}", ticket_2);

        // send HTTP

        Ok(stream)
    }
    pub fn receive_data(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            let r = self.read_record()?;
            if r.record_type == 0x17 {
                return Ok(r.content);
            }
        }
    }

    pub fn send_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let request = Record::new(0x17, Vec::from(data));

        self.wrap_send_handshake_record(&request)?;

        Ok(())
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

        // println!("HEADER {}", hex::encode(&record_header[..]));
        let mut content: Vec<u8> = vec![];
        content.resize(record_size as usize, 0); // zeroes
        self.tcp.read_exact(&mut content[..])?;

        if record_header[0] == 0x17 {
            // application record
            return self.extract_wrapped_record(&record_header, content);
        }

        let mut b = Buffer::from(&concat_bytes_array(&record_header, &content[..]));

        Record::try_from(&mut b)
    }

    fn send_record(&mut self, record: &Record) -> Result<(), Error> {
        // println!("Sending :{}", hex::encode(Buffer::from(record).as_bytes()));
        self.tcp.write(Buffer::from(record).as_bytes())?;
        self.tcp.flush()?;
        Ok(())
    }

    fn wrap_send_handshake_record(&mut self, record: &Record) -> Result<(), Error> {
        let key = match self.session.keys_state {
            KeysState::HANDHSAKE => {
                println!("Handhsake key found");
                &self.session.keys.client_handshake_key
            }

            _ => {
                println!("app key found");

                &self.session.keys.client_app_key
            }
        };

        let base_iv = match self.session.keys_state {
            KeysState::HANDHSAKE => &self.session.keys.client_handshake_iv,

            _ => &self.session.keys.client_app_iv,
        };

        let record = wrap_record(record, base_iv, self.session.client_records_count, key)?;
        // println!(
        //     "Sending Wrapped: {}",
        //     hex::encode(Buffer::from(&record).as_bytes())
        // );

        self.tcp.write(Buffer::from(&record).as_bytes())?;
        self.tcp.flush()?;

        self.session.client_records_count += 1;
        Ok(())
    }

    /// extract encrypted record and returns decrypted record instance
    fn extract_wrapped_record(
        &mut self,
        record_header: &[u8; 5],
        content: Vec<u8>,
    ) -> Result<Record, Error> {
        let key = match self.session.keys_state {
            KeysState::HANDHSAKE => {
                // println!("Handhsake key found");
                &self.session.keys.server_handshake_key
            }

            _ => {
                // println!("app key found");

                &self.session.keys.server_app_key
            }
        };

        let base_iv = match self.session.keys_state {
            KeysState::HANDHSAKE => &self.session.keys.server_handshake_iv,

            _ => &self.session.keys.server_app_iv,
        };

        let r = unwrap_record(
            base_iv,
            self.session.server_records_count,
            &key,
            record_header,
            content,
        )?;

        self.session.server_records_count += 1;

        Ok(r)
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

    pub client_app_key: Vec<u8>,
    pub client_app_iv: Vec<u8>,

    pub server_app_key: Vec<u8>,
    pub server_app_iv: Vec<u8>,
}

impl SessionKeys {
    pub fn new() -> Self {
        SessionKeys {
            handshake_secret: vec![],
            client_secret: vec![],
            server_secret: vec![],
            client_handshake_key: vec![],
            client_handshake_iv: vec![],
            server_handshake_key: vec![],
            server_handshake_iv: vec![],
            client_app_key: vec![],
            client_app_iv: vec![],
            server_app_key: vec![],
            server_app_iv: vec![],
        }
    }
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
            hex::encode(&self.server_app_iv)
        )?;
        writeln!(f, "CLIENT_APP_KEY {}", hex::encode(&self.client_app_key))?;
        writeln!(f, "CLIENT_APP_IV {}", hex::encode(&self.client_app_iv))?;
        writeln!(f, "SERVER_APP_KEY {}", hex::encode(&self.server_app_key))?;
        writeln!(f, "SERVER_APP_IV {}", hex::encode(&self.server_app_iv))?;

        Ok(())
    }
}
