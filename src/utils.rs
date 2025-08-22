use crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    aes_gcm, curve25519,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha384};

use crate::{
    buffer::{Buffer, Error},
    handshake::Handshake,
    record::Record,
    tls_stream::SessionKeys,
};

pub fn concat_bytes_array(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    let mut r: Vec<u8> = vec![];

    r.extend_from_slice(b1);
    r.extend_from_slice(b2);

    r
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    sha2::Sha384::digest(data).into()
}

pub fn hdkf_expand_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, Error> {
    let mut info: Vec<u8> = Vec::new();

    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(&format!("tls13 {}", label).as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(&context);

    let mut okm: Vec<u8> = vec![0; length];

    Hkdf::<Sha384>::from_prk(secret)
        .unwrap()
        .expand(&info[..], &mut okm)
        .unwrap();

    Ok(okm)
}

pub fn hkdf_derive_secret(
    secret: &[u8],
    label: &str,
    transcript_msgs: &[u8],
) -> Result<Vec<u8>, Error> {
    let hash = Sha384::digest(transcript_msgs);
    return hdkf_expand_label(secret, label, &hash, 48);
}

pub fn populate_app_keys(keys: &mut SessionKeys, hash: &[u8]) {
    let empty_hash = Sha384::digest("");

    let derived_secret =
        hdkf_expand_label(&keys.handshake_secret, "derived", &empty_hash, 48).unwrap();

    let (master_secret, _) = hkdf::Hkdf::<Sha384>::extract(Some(&derived_secret[..]), &[0u8; 48]);
    let master_secret: [u8; 48] = master_secret.try_into().unwrap();

    let client_secret = hdkf_expand_label(&master_secret, "c ap traffic", &hash, 48).unwrap();

    let server_secret = hdkf_expand_label(&master_secret, "s ap traffic", &hash, 48).unwrap();

    let server_app_key = hdkf_expand_label(&server_secret, "key", "".as_bytes(), 32).unwrap();

    let server_app_iv = hdkf_expand_label(&server_secret, "iv", "".as_bytes(), 12).unwrap();

    let client_app_key = hdkf_expand_label(&client_secret, "key", "".as_bytes(), 32).unwrap();

    let client_app_iv = hdkf_expand_label(&client_secret, "iv", "".as_bytes(), 12).unwrap();

    keys.server_app_key = server_app_key;
    keys.server_app_iv = server_app_iv;
    keys.client_app_key = client_app_key;
    keys.client_app_iv = client_app_iv;
}

pub fn gen_session_keys(
    client_privkey: &[u8; 32],
    server_pubkey: &[u8; 32],
    client_handshake_bytes: &[u8],
    server_handshake_bytes: &[u8],
) -> Result<SessionKeys, Error> {
    let shared_secret = curve25519::curve25519(client_privkey, server_pubkey);

    let hello_hash = sha384(&concat_bytes_array(
        client_handshake_bytes,
        server_handshake_bytes,
    ));

    let (early_secret, _) = Hkdf::<Sha384>::extract(Some(&[0u8; 48]), &[0u8; 48]);
    let early_secret: [u8; 48] = early_secret.try_into().unwrap();

    let empty_hash = Sha384::digest("");

    let derived_secret = hdkf_expand_label(&early_secret, "derived", &empty_hash, 48).unwrap();

    let (handshake_secret, _) =
        hkdf::Hkdf::<Sha384>::extract(Some(&derived_secret[..]), &shared_secret);
    let handshake_secret: [u8; 48] = handshake_secret.try_into().unwrap();

    let client_secret =
        hdkf_expand_label(&handshake_secret, "c hs traffic", &hello_hash, 48).unwrap();

    let server_secret =
        hdkf_expand_label(&handshake_secret, "s hs traffic", &hello_hash, 48).unwrap();

    let server_handshake_key = hdkf_expand_label(&server_secret, "key", "".as_bytes(), 32).unwrap();

    let server_handshake_iv = hdkf_expand_label(&server_secret, "iv", "".as_bytes(), 12).unwrap();

    let client_handshake_key = hdkf_expand_label(&client_secret, "key", "".as_bytes(), 32).unwrap();

    let client_handshake_iv = hdkf_expand_label(&client_secret, "iv", "".as_bytes(), 12).unwrap();

    Ok(SessionKeys {
        handshake_secret: Vec::from(handshake_secret),
        client_secret,
        server_secret,
        client_handshake_key,
        client_handshake_iv,
        server_handshake_key,
        server_handshake_iv,
        client_app_iv: vec![],
        client_app_key: vec![],
        server_app_iv: vec![],
        server_app_key: vec![],
    })
}

// xor least bits
pub fn build_iv(iv: &[u8], seq: u64) -> Vec<u8> {
    let mut new_iv: Vec<u8> = vec![];
    new_iv.extend_from_slice(iv);

    let iv_len = iv.len();
    for i in 0..size_of::<u64>() {
        new_iv[iv_len - 1 - i] ^= ((seq >> (i * 8)) & 0xFF) as u8;
    }
    new_iv
}

pub fn wrap_record(
    record: &Record,
    iv: &[u8],
    records_count: u64,
    secret: &[u8],
) -> Result<Record, Error> {
    let mut new_header = Buffer::new();
    new_header.write_u8(0x17);

    new_header.write_u16(0x0303);

    println!("Content len: {}", record.content.len() + 1 + 16);
    new_header.write_u16((record.content.len() + 1 + 16) as u16); // + 1 for record type + 16 for auth tag 

    let mut new_content = record.content.clone();
    new_content.push(record.record_type);

    println!("new content: {}", hex::encode(&new_content));
    let iv = build_iv(iv, records_count);

    println!("IV: {}", hex::encode(&iv));
    let mut aes = aes_gcm::AesGcm::new(
        crypto::aes::KeySize::KeySize256,
        secret,
        &iv[..],
        new_header.as_bytes(),
    );

    let mut encrypted_content: Vec<u8> = Vec::new();
    encrypted_content.resize(new_content.len(), 0);

    println!("Encrypted contente len: {}", encrypted_content.len());
    let mut tag = [0u8; 16];

    aes.encrypt(&new_content, &mut encrypted_content, &mut tag);

    println!(
        "encrypred content: {} tag len: {}",
        encrypted_content.len(),
        tag.len()
    );
    encrypted_content.extend_from_slice(&tag[..]);

    let record = Record::new(0x17, encrypted_content); // application record

    Ok(record)
}

pub fn unwrap_record(
    base_iv: &[u8],
    records_count: u64,
    secret: &[u8],
    record_header: &[u8; 5],
    content: Vec<u8>,
) -> Result<Record, Error> {
    let encrypted_data = Vec::from(&content[0..content.len() - 16]);
    let auth_tag = Vec::from(&content[content.len() - 16..]);

    let iv = build_iv(base_iv, records_count);

    let mut aes = crypto::aes_gcm::AesGcm::new(
        crypto::aes::KeySize::KeySize256,
        &secret,
        &iv[..],
        &record_header[..],
    );

    let mut out: Vec<u8> = Vec::new();
    out.resize(encrypted_data.len(), 0);

    // println!("content: {}", hex::encode(content));
    let res = aes.decrypt(&encrypted_data, &mut out, &auth_tag[..]);
    if !res {
        return Err("Failed to decrypt record".into());
    }

    let record_type = out[out.len() - 1];

    out.pop().unwrap(); // remove record type

    // construct new header

    let record_tls_ver = 0x0303 as u16;
    let record_size = out.len() as u16;
    let mut new_record = Buffer::new();

    new_record.write_u8(record_type);
    new_record.write_u16(record_tls_ver);
    new_record.write_u16(record_size);

    let mut b = Buffer::from(&concat_bytes_array(&new_record.as_bytes(), &out[..]));
    let r = Record::try_from(&mut b)?;

    Ok(r)
}
