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
impl From<&ClientHello> for Buffer {
    fn from(ch: &ClientHello) -> Buffer {
        let mut b = Buffer::new();
        b.write_u16(ch.tls_ver);
        b.write_n(&ch.client_random);
        b.write_u8(ch.session_id.len() as u8);
        b.write_n(&ch.session_id[..]);

        b.write_u16((ch.cipher_suits.len() * 2) as u16);
        b.write_n(
            &ch.cipher_suits
                .iter()
                .flat_map(|x| x.to_be_bytes())
                .collect::<Vec<u8>>(),
        );

        let compression_methods_size = ch.compression_methods.len();
        if compression_methods_size == 0 {
            panic!("atleast one compression method (use null) is required");
        }
        b.write_u8(compression_methods_size as u8);
        for i in &ch.compression_methods {
            b.write_u8(*i);
        }

        b.write_u16(
            ch.exts
                .iter()
                .fold(0, |x, ext| x + (Into::<Buffer>::into(ext).len() as u16)),
        );

        // write all extentions data
        ch.exts
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
impl From<&ClientHello> for Handshake {
    fn from(value: &ClientHello) -> Self {
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

    use crypto::aead::AeadDecryptor;
    use hkdf::hmac::Mac;

    use crate::buffer::Buffer;
    use crate::client_hello::ClientHello;
    use crate::format::KeyShareExtention;
    use crate::handshake::Handshake;
    use crate::keypair::KeyPair;
    use crate::mockdata::{
        self, MOCK_ENCRYPTED_EXTENTIONS_RECORD, MOCK_ENCRYPTED_SERVER_CERT_RECORD,
        MOCK_ENCRYPTED_SERVER_HS_FINISHED, MOCK_ENCRYPTED_SERVER_VERIFY_RECORD, MOCK_SERVER_RECORD,
    };
    use crate::record::Record;
    use crate::utils::{gen_session_keys, hdkf_expand_label, unwrap_record, wrap_record};
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

    #[test]
    fn test_decrypt() {
        let secret: [u8; 32] =
            hex::decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
                .unwrap()[..]
                .try_into()
                .unwrap();

        let server_public_key: [u8; 32] =
            hex::decode("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615")
                .unwrap()[..]
                .try_into()
                .unwrap();

        let kp = KeyPair::from(secret);

        let mock_client_hello = hex::decode(mockdata::MOCK_CLIENT_RECORD).unwrap();
        let mock_server_hello = hex::decode(mockdata::MOCK_SERVER_RECORD).unwrap();

        let server_handshake = &mock_server_hello[5..];
        let client_handshake = &mock_client_hello[5..];

        let keys = gen_session_keys(
            &kp.private_key,
            &server_public_key,
            &client_handshake,
            &server_handshake,
        )
        .unwrap();

        assert_eq!(
            hex::decode("9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f")
                .unwrap(),
            keys.server_handshake_key
        );
        assert_eq!(
            hex::decode("9563bc8b590f671f488d2da3").unwrap(),
            keys.server_handshake_iv
        );

        let vec = hex::decode(MOCK_ENCRYPTED_EXTENTIONS_RECORD).unwrap();
        let record = Record::try_from(&mut Buffer::from(&vec)).unwrap();

        assert_eq!(record.record_type, 0x17); //application data

        let unrwapped_record = unwrap_record(
            &keys.server_handshake_iv,
            0,
            &keys.server_handshake_key,
            &vec[..5].try_into().unwrap(),
            record.content,
        )
        .unwrap();

        assert_eq!(
            unrwapped_record.content,
            &hex::decode("080000020000").unwrap()[..]
        );
    }

    #[test]
    fn test_encrypt() {
        let secret: [u8; 32] =
            hex::decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
                .unwrap()[..]
                .try_into()
                .unwrap();

        let server_public_key: [u8; 32] =
            hex::decode("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615")
                .unwrap()[..]
                .try_into()
                .unwrap();

        let kp = KeyPair::from(secret);

        let mock_client_hello = hex::decode(mockdata::MOCK_CLIENT_RECORD).unwrap();
        let mock_server_hello = hex::decode(mockdata::MOCK_SERVER_RECORD).unwrap();

        let server_handshake = &mock_server_hello[5..];
        let client_handshake = &mock_client_hello[5..];

        let keys = gen_session_keys(
            &kp.private_key,
            &server_public_key,
            &client_handshake,
            &server_handshake,
        )
        .unwrap();

        assert_eq!(
            hex::decode("9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f")
                .unwrap(),
            keys.server_handshake_key
        );
        assert_eq!(
            hex::decode("9563bc8b590f671f488d2da3").unwrap(),
            keys.server_handshake_iv
        );

        let mut hs_content: Vec<u8> = Vec::new();

        hs_content.extend_from_slice(client_handshake);
        hs_content.extend_from_slice(server_handshake);
        hs_content.extend_from_slice(&hex::decode("080000020000").unwrap());

        hs_content.extend_from_slice(
                &hex::decode("0b00032e0000032a0003253082032130820209a0030201020208155a92adc2048f90300d06092a864886f70d01010b05003022310b300906035504061302555331133011060355040a130a4578616d706c65204341301e170d3138313030353031333831375a170d3139313030353031333831375a302b310b3009060355040613025553311c301a060355040313136578616d706c652e756c666865696d2e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c4803606bae7476b089404eca7b691043ff792bc19eefb7d74d7a80d001e7b4b3a4ae60fe8c071fc73e7024c0dbcf4bdd11d396bba70464a13e94af83df3e10959547bc955fb412da3765211e1f3dc776caa53376eca3aecbec3aab73b31d56cb6529c8098bcc9e02818e20bf7f8a03afd1704509ece79bd9f39f1ea69ec47972e830fb5ca95de95a1e60422d5eebe527954a1e7bf8a86f6466d0d9f16951a4cf7a04692595c1352f2549e5afb4ebfd77a37950144e4c026874c653e407d7d23074401f484ffd08f7a1fa05210d1f4f0d5ce79702932e2cabe701fdfad6b4bb71101f44bad666a11130fe2ee829e4d029dc91cdd6716dbb9061886edc1ba94210203010001a3523050300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030206082b06010505070301301f0603551d23041830168014894fde5bcc69e252cf3ea300dfb197b81de1c146300d06092a864886f70d01010b05000382010100591645a69a2e3779e4f6dd271aba1c0bfd6cd75599b5e7c36e533eff3659084324c9e7a504079d39e0d42987ffe3ebdd09c1cf1d914455870b571dd19bdf1d24f8bb9a11fe80fd592ba0398cde11e2651e618ce598fa96e5372eef3d248afde17463ebbfabb8e4d1ab502a54ec0064e92f7819660d3f27cf209e667fce5ae2e4ac99c7c93818f8b2510722dfed97f32e3e9349d4c66c9ea6396d744462a06b42c6d5ba688eac3a017bddfc8e2cfcad27cb69d3ccdca280414465d3ae348ce0f34ab2fb9c618371312b191041641c237f11a5d65c844f0404849938712b959ed685bc5c5dd645ed19909473402926dcb40e3469a15941e8e2cca84bb6084636a00000").unwrap()[..]
);

        hs_content.extend_from_slice(&hex::decode("0f000104080401005cbb24c0409332daa920bbabbdb9bd50170be49cfbe0a4107fca6ffb1068e65f969e6de7d4f9e56038d67c69c031403a7a7c0bcc8683e65721a0c72cc6634019ad1d3ad265a812615ba36380372084f5daec7e63d3f4933f27227419a611034644dcdbc7be3e74ffac473faaadde8c2fc65f3265773e7e62de33861fa705d19c506e896c8d82f5bcf35fece259b71538115e9c8cfba62e49bb8474f58587b11b8ae317c633e9c76c791d466284ad9c4ff735a6d2e963b59bbca440a307091a1b4e46bcc7a2f9fb2f1c898ecb19918be4121d7e8ed04cd50c9a59e987980107bbbf299c232e7fdbe10a4cfdae5c891c96afdff94b54ccd2bc19d3cdaa6644859c").unwrap());

        // verify
        let server_finished_key =
            hdkf_expand_label(&keys.server_secret, "finished".into(), "".as_bytes(), 48).unwrap();

        let mut hasher: _ =
            hkdf::hmac::Hmac::<Sha384>::new_from_slice(&server_finished_key[..]).unwrap();
        let hs_content_digest: _ = sha2::Sha384::digest(&hs_content[..]);

        hasher.update(&hs_content_digest);

        let res_hash = hasher.finalize().into_bytes().to_vec();

        println!("hmac {}:", hex::encode(res_hash));

        hs_content.extend_from_slice(
            &hex::decode("140000307e30eeccb6b23be6c6ca363992e842da877ee64715ae7fc0cf87f9e5032182b5bb48d1e33f9979055a160c8dbbb1569c").unwrap()[..],
        );

        println!("Client key: {}", hex::encode(&keys.client_secret));
        let client_finished_key =
            hdkf_expand_label(&keys.client_secret, "finished".into(), "".as_bytes(), 48).unwrap();

        let mut hasher: _ =
            hkdf::hmac::Hmac::<Sha384>::new_from_slice(&client_finished_key[..]).unwrap();

        let hs_content_digest = sha2::Sha384::digest(&hs_content[..]);
        hasher.update(&hs_content_digest[..]);

        let res_hash = hasher.finalize().into_bytes().to_vec();
        println!("finsihed Digest: {}", hex::encode(&res_hash));

        assert_eq!(hex::decode("bff56a671b6c659d0a7c5dd18428f58bdd38b184a3ce342d9fde95cbd5056f7da7918ee320eab7a93abd8f1c02454d27").unwrap(),&res_hash[..]);

        let hs = Handshake {
            handshake_type: 0x14, // handhsake finished
            content: Buffer::from(&res_hash),
        };

        // stream.wrap_send_handshake_record(&Record {
        //     record_type: 0x16, // handshake record
        //     ver: 0x0303,
        //     content: Buffer::from(&hs).as_bytes().into(),
        // })?; // change cipher

        let client_hs_finished_digest = hex::decode("bff56a671b6c659d0a7c5dd18428f58bdd38b184a3ce342d9fde95cbd5056f7da7918ee320eab7a93abd8f1c02454d27").unwrap();

        let handshake =
            handshake::Handshake::new(0x14, Buffer::try_from(&client_hs_finished_digest).unwrap());
        let rec = Record::new(0x16, Buffer::from(&handshake).as_bytes().into());

        let wrapped_record = wrap_record(
            &rec,
            &keys.client_handshake_iv,
            0,
            &keys.client_handshake_key,
        )
        .unwrap();

        let vec = Buffer::try_from(wrapped_record).unwrap();
        assert_eq!(
            hex::decode(
                "17030300459ff9b063175177322a46dd9896f3c3bb820ab51743ebc25fdadd53454b73deb54cc7248d411a18bccf657a960824e9a19364837c350a69a88d4bf635c85eb874aebc9dfde8"
            ).unwrap(),
            vec.as_bytes()
        );
    }
}
