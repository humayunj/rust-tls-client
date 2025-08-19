use std::alloc::System;

use crypto::digest::Digest;

use crate::{
    buffer::{Buffer, Error},
    format::{Extention, parse_extentions},
    handshake::Handshake,
    record::Record,
};

pub struct ClientHello {
    pub tls_ver: u16,
    pub exts: Vec<Extention>,
    pub cipher_suits: Vec<u16>,
    pub client_random: [u8; 32],
    pub session_id: Vec<u8>,
    pub compression_methods: Vec<u8>,
}

impl ClientHello {
    pub fn new() -> ClientHello {
        ClientHello {
            tls_ver: 0x0303,
            exts: vec![],
            cipher_suits: vec![],
            client_random: [0u8; 32],
            compression_methods: vec![],
            session_id: vec![],
        }
    }

    pub fn add_extention(&mut self, extention: Extention) {
        self.exts.push(extention);
    }

    pub fn add_cipher_suit(&mut self, cipher_id: u16) {
        self.cipher_suits.push(cipher_id);
    }

    pub fn set_client_random(&mut self, client_random: &[u8; 32]) {
        self.client_random = *client_random;
    }
}

impl TryFrom<&mut Buffer> for ClientHello {
    type Error = Error;
    fn try_from(b: &mut Buffer) -> Result<Self, Self::Error> {
        let mut c = ClientHello::new();

        c.tls_ver = b.read_u16()?;
        c.client_random = b.read_n(32)?[..].try_into()?;

        let session_id_bytes = b.read_u8()?;

        c.session_id = b.read_n(session_id_bytes as usize)?;

        let cipher_suites = b.read_u16()? / 2;

        for i in 0..cipher_suites {
            println!("{}", i);
            c.add_cipher_suit(b.read_u16()?);
        }

        let compression_methods_size = b.read_u8()?;
        c.compression_methods = b.read_n(compression_methods_size as usize)?;

        let exts_bytes_len = b.read_u16()?;

        let exts = parse_extentions(b, exts_bytes_len as usize, false)?;

        c.exts = exts;

        Ok(c)
    }
}
impl Into<Buffer> for ClientHello {
    fn into(self) -> Buffer {
        let mut b = Buffer::new();
        b.write_u16(self.tls_ver);
        b.write_n(&self.client_random);
        b.write_u8(self.session_id.len() as u8);
        b.write_n(&self.session_id[..]);

        b.write_u16((self.cipher_suits.len() * 2) as u16);
        b.write_n(
            &self
                .cipher_suits
                .iter()
                .flat_map(|x| x.to_be_bytes())
                .collect::<Vec<u8>>(),
        );

        let compression_methods_size = self.compression_methods.len();
        if compression_methods_size == 0 {
            panic!("atleast one compression method (use null) is required");
        }
        b.write_u8(compression_methods_size as u8);
        for i in self.compression_methods {
            b.write_u8(i);
        }

        b.write_u16(
            self.exts
                .iter()
                .fold(0, |x, ext| x + (Into::<Buffer>::into(ext).len() as u16)),
        );

        // write all extentions data
        self.exts
            .iter()
            .for_each(|ext| b.write_n(&Into::<Buffer>::into(ext).vec[..]));

        b
    }
}

impl TryFrom<&Handshake> for ClientHello {
    type Error = Error;
    fn try_from(h: &Handshake) -> Result<Self, Self::Error> {
        let mut b = Buffer::from(&h.content.vec);

        ClientHello::try_from(&mut b)
    }
}
impl From<ClientHello> for Handshake {
    fn from(value: ClientHello) -> Self {
        Handshake {
            handshake_type: 0x1, // client hello
            content: Into::<Buffer>::into(value),
        }
    }
}

impl TryFrom<&Record> for ClientHello {
    type Error = Error;
    fn try_from(h: &Record) -> Result<Self, Self::Error> {
        ClientHello::try_from(&Handshake::try_from(h).unwrap())
    }
}

#[cfg(test)]
mod tests {

    use crate::buffer::Buffer;
    use crate::client_hello::ClientHello;
    use crate::format::KeyShareExtention;
    use crate::mockdata;
    use crate::*;

    #[test]
    fn parse_client_hello() {
        let mock_data = hex::decode(mockdata::MOCK_CLIENT_RECORD).unwrap();

        // skip 5 bytes

        let v = Vec::from(&mock_data[5..]);
        let mut handshake =
            handshake::Handshake::try_from(&mut Buffer::try_from(&v).unwrap()).unwrap();

        println!("handhsake length {}", handshake.content.len());
        assert_eq!(handshake.handshake_type, 0x01); // client hello
        assert_eq!(handshake.content.len(), 0xF4);

        let c_hello = ClientHello::try_from(&mut handshake.content).unwrap();

        assert_eq!(c_hello.tls_ver, 0x0303);

        assert_eq!(
            c_hello.client_random,
            hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()[..]
        );

        assert_eq!(c_hello.session_id.len(), 32);
        assert_eq!(
            c_hello.session_id,
            hex::decode("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
                .unwrap()
        );
        assert_eq!(c_hello.cipher_suits.len(), 4);
        assert_eq!(c_hello.cipher_suits[..], [0x1302, 0x1303, 0x1301, 0x00ff]);

        assert_eq!(c_hello.exts.len(), 10);

        assert_eq!(
            KeyShareExtention::try_from(c_hello.exts.iter().find(|p| p.id == 0x0033).unwrap())
                .unwrap(),
            KeyShareExtention::new(
                0x001d,
                hex::decode("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254")
                    .unwrap()
            )
        )
    }
}
