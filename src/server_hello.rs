use crypto::digest::Digest;

use crate::{
    buffer::{Buffer, Error},
    format::{Extention, KeyShareExtention, parse_extentions},
    handshake::Handshake,
    record::Record,
};

pub struct ServerHello {
    pub tls_ver: u16,
    pub server_random: [u8; 32],
    pub session_id: Vec<u8>,
    pub selected_cipher_suit: u16,
    pub selected_compression_method: u8,
    pub exts: Vec<Extention>,
}

impl ServerHello {
    pub fn new() -> ServerHello {
        ServerHello {
            tls_ver: 0,
            server_random: [0u8; 32],
            session_id: vec![],
            selected_cipher_suit: 0,
            selected_compression_method: 0,
            exts: vec![],
        }
    }

    pub fn extract_shared_key(&self) -> Option<Vec<u8>> {
        Some(
            KeyShareExtention::try_from(self.exts.iter().find(|p| p.id == 0x0033).unwrap())
                .unwrap()
                .key_data
                .clone(),
        )
    }
}

impl TryFrom<&mut Buffer> for ServerHello {
    type Error = Error;
    fn try_from(b: &mut Buffer) -> Result<Self, Self::Error> {
        let mut s = ServerHello::new();

        s.tls_ver = b.read_u16()?;
        s.server_random = b.read_n(32)?[..].try_into()?;

        let session_id_bytes = b.read_u8()?;

        s.session_id = b.read_n(session_id_bytes as usize)?;

        s.selected_cipher_suit = b.read_u16()?;

        s.selected_compression_method = b.read_u8()?;

        let exts_bytes_len = b.read_u16()?;

        let exts = parse_extentions(b, exts_bytes_len as usize, true)?;

        s.exts = exts;

        Ok(s)
    }
}

impl TryFrom<&Handshake> for ServerHello {
    type Error = Error;
    fn try_from(h: &Handshake) -> Result<Self, Self::Error> {
        let mut b = Buffer::from(&h.content.vec);

        ServerHello::try_from(&mut b)
    }
}

impl TryFrom<&Record> for ServerHello {
    type Error = Error;
    fn try_from(h: &Record) -> Result<Self, Self::Error> {
        ServerHello::try_from(&Handshake::try_from(h).unwrap())
    }
}

#[cfg(test)]
mod tests {

    use sha2::Sha384;

    use crate::buffer::Buffer;
    use crate::client_hello::ClientHello;
    use crate::format::KeyShareExtention;
    use crate::keypair::KeyPair;
    use crate::mockdata::{self, MOCK_CLIENT_RECORD, MOCK_SERVER_RECORD};
    use crate::record::Record;
    use crate::server_hello::ServerHello;
    use crate::utils::{concat_bytes_array, hdkf_expand_label, sha384};
    use crate::*;

    #[test]
    fn parse_server_hello() {
        let mock_data = hex::decode(mockdata::MOCK_SERVER_RECORD).unwrap();

        // skip 5 bytes

        let v = Vec::from(&mock_data[5..]);
        let mut handshake =
            handshake::Handshake::try_from(&mut Buffer::try_from(&v).unwrap()).unwrap();

        assert_eq!(handshake.handshake_type, 0x02); // client hello
        assert_eq!(handshake.content.len(), 0x76);

        let s_hello = ServerHello::try_from(&mut handshake.content).unwrap();

        assert_eq!(s_hello.tls_ver, 0x0303);

        assert_eq!(
            s_hello.server_random,
            hex::decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
                .unwrap()[..]
        );

        assert_eq!(s_hello.session_id.len(), 32);
        assert_eq!(
            s_hello.session_id,
            hex::decode("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
                .unwrap()
        );

        assert_eq!(s_hello.selected_cipher_suit, 0x1302);
        assert_eq!(s_hello.selected_compression_method, 0x0);

        assert_eq!(s_hello.exts.len(), 2);

        assert_eq!(
            KeyShareExtention::try_from(s_hello.exts.iter().find(|p| p.id == 0x0033).unwrap())
                .unwrap(),
            KeyShareExtention::new(
                0x001d,
                hex::decode("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615")
                    .unwrap()
            )
        )
    }

    #[test]
    fn test_keys_gen() {
        let secret: [u8; 32] =
            hex::decode("909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
                .unwrap()[..]
                .try_into()
                .unwrap();
        let kp = KeyPair::from(secret);

        let server_record =
            Record::try_from(&mut Buffer::from(&hex::decode(MOCK_SERVER_RECORD).unwrap())).unwrap();

        let client_record =
            Record::try_from(&mut Buffer::from(&hex::decode(MOCK_CLIENT_RECORD).unwrap())).unwrap();

        let client_hello = ClientHello::try_from(&client_record).unwrap();
        let keyshare = client_hello
            .exts
            .iter()
            .find_map(|k| {
                if k.id == 0x33 {
                    Some(KeyShareExtention::try_from(k).unwrap())
                } else {
                    None
                }
            })
            .unwrap();
        let client_key: [u8; 32] = keyshare.key_data.try_into().unwrap();
        let server_key = kp.private_key;

        let shared_secret = curve25519::curve25519(&server_key, &client_key);
        assert_eq!(
            "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624",
            hex::encode(shared_secret)
        );

        let hello_hash =
            sha384(&concat_bytes_array(&client_record.content[..], &server_record.content[..])[..]);
        assert_eq!(
            "e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd",
            hex::encode(hello_hash)
        );

        let (early_secret, _) = hkdf::Hkdf::<Sha384>::extract(Some(&[0u8; 48]), &[0u8; 48]);
        let early_secret: [u8; 48] = early_secret.try_into().unwrap();

        assert_eq!(
            "7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5",
            hex::encode(early_secret)
        );

        let empty_hash = Sha384::digest("");

        assert_eq!(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            hex::encode(&empty_hash)
        );

        let derived_secret = hdkf_expand_label(&early_secret, "derived", &empty_hash, 48).unwrap();
        assert_eq!(
            "1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b",
            hex::encode(&derived_secret)
        );

        let (handshake_secret, _) =
            hkdf::Hkdf::<Sha384>::extract(Some(&derived_secret[..]), &shared_secret);
        let handshake_secret: [u8; 48] = handshake_secret.try_into().unwrap();

        assert_eq!(
            "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299",
            hex::encode(handshake_secret)
        );

        let client_secret =
            hdkf_expand_label(&handshake_secret, "c hs traffic", &hello_hash, 48).unwrap();
        assert_eq!(
            "db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0",
            hex::encode(&client_secret)
        );

        let server_secret =
            hdkf_expand_label(&handshake_secret, "s hs traffic", &hello_hash, 48).unwrap();
        assert_eq!(
            "23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622",
            hex::encode(&server_secret)
        );

        let server_handshake_key =
            hdkf_expand_label(&server_secret, "key", "".as_bytes(), 32).unwrap();

        assert_eq!(
            "9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f",
            hex::encode(server_handshake_key)
        );
        let server_handhsake_iv =
            hdkf_expand_label(&server_secret, "iv", "".as_bytes(), 12).unwrap();
        assert_eq!("9563bc8b590f671f488d2da3", hex::encode(server_handhsake_iv));

        let client_handshake_key =
            hdkf_expand_label(&client_secret, "key", "".as_bytes(), 32).unwrap();

        assert_eq!(
            "1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69",
            hex::encode(client_handshake_key)
        );
        let client_handhsake_iv =
            hdkf_expand_label(&client_secret, "iv", "".as_bytes(), 12).unwrap();
        assert_eq!("4256d2e0e88babdd05eb2f27", hex::encode(client_handhsake_iv))
    }
    #[test]
    fn test_server_keygen() {
        let secret: [u8; 32] =
            hex::decode("909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
                .unwrap()[..]
                .try_into()
                .unwrap();
        let k = KeyPair::from(secret);
        let pk: [u8; 32] =
            hex::decode("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(k.public_key, pk);
    }
}
