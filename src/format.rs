use std::{
    fmt::{Display, format},
    io::Read,
};

use sha2::digest::Key;

use crate::{
    buffer::{self, Buffer, Error},
    format,
};

// pub fn parse_server_hello(payload: &Vec<u8>, session: &mut Session) -> Result<(), Error> {
//     println!("handhsake {}", hex::encode(&payload));
//     let mut b = Buffer::from(payload);
//     let payload_type = b.read_u8()?;

//     if payload_type != 0x2 {
//         return Err(format!("Mismatched handshake type {}", payload_type).into());
//     }

//     let payload_size = b.read_u24()?;

//     let ver_major = b.read_u8()?;
//     let ver_minor = b.read_u8()?;

//     let server_random = b.read_n(32)?;

//     println!("server random: {}", hex::encode(&server_random));
//     let session_id_size = b.read_u8()?;
//     let session_id = b.read_n(session_id_size.into())?;

//     let selected_cypher_suites = b.read_u16()?;

//     println!(
//         "Selected cypher: 0x{}",
//         hex::encode(&selected_cypher_suites.to_be_bytes())
//     );

//     let compression_method = b.read_u8()?;

//     let ext_length = b.read_u16()?;

//     let exts = parse_extentions(&mut b, ext_length.into(), false)?;

//     exts.iter().try_for_each(|e| -> Result<(), Error> {
//         println!("{}", &e);
//         match e.id {
//             0x33 => {
//                 let mut b = Buffer::from(&e.content);
//                 let key_type = b.read_u16()?;
//                 let key_size = b.read_u16()?;

//                 println!("Key type: 0x{:x}", key_type);
//                 session.server_pubkey = b.read_n(key_size as usize).unwrap().try_into().unwrap();

//                 println!("Key: 0x{}", hex::encode(&session.client_secret));

//                 Ok(())
//             }
//             _ => Ok(()),
//         }
//     })?;
//     Ok(())
// }

pub fn parse_extentions(
    b: &mut Buffer,
    expected_length: usize,
    is_server: bool,
) -> Result<Vec<Extention>, Error> {
    let mut vec: Vec<Extention> = Vec::new();
    let pos = b.pos;
    while b.pos < pos + expected_length {
        // read id
        let id = b.read_u16()?;
        let content_size = b.read_u16()?;
        let content = b.read_n(content_size.into())?;

        vec.push(Extention {
            id,
            content,
            is_server,
        });
    }

    Ok(vec)
}

pub struct Extention {
    pub id: u16,
    pub content: Vec<u8>,
    pub is_server: bool,
}

impl Extention {
    pub fn new(id: u16, content: Vec<u8>, is_server: bool) -> Extention {
        Extention {
            id,
            content,
            is_server,
        }
    }
}

fn get_extention_name(id: u16) -> String {
    match id {
        0x002b => String::from(format!("SupportedVer ({})", "002b")),
        0x0033 => String::from(format!("KeyShare ({})", "0033")),
        x => hex::encode(x.to_be_bytes()),
    }
}

impl TryFrom<&Vec<u8>> for Extention {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Extention, Self::Error> {
        Extention::try_from(Buffer::from(value))
    }
}

impl TryFrom<Buffer> for Extention {
    type Error = Error;
    fn try_from(value: Buffer) -> Result<Extention, Self::Error> {
        let mut b = Buffer::from(value);
        let id = b.read_u16()?;
        let content_length = b.read_u16()?;
        let content = b.read_n(content_length.into())?;

        Ok(Extention {
            id,
            content,
            is_server: false,
        })
    }
}
impl From<&Extention> for Buffer {
    fn from(ext: &Extention) -> Buffer {
        let mut b = Buffer::new();

        b.write_u16(ext.id);
        b.write_u16(ext.content.len() as u16);
        b.write_n(&ext.content);
        b
    }
}

impl Display for Extention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            format!(
                "Extention {{ id: {}, content_size: {} }} ",
                get_extention_name(self.id),
                self.content.len()
            )
            .as_str(),
        )
    }
}

#[derive(Debug)]
pub struct KeyShareExtention {
    pub key_id: u16,
    pub key_data: Vec<u8>,
}

impl KeyShareExtention {
    pub fn new(key_id: u16, key_data: Vec<u8>) -> Self {
        KeyShareExtention { key_id, key_data }
    }
}

impl PartialEq<KeyShareExtention> for KeyShareExtention {
    fn eq(&self, other: &KeyShareExtention) -> bool {
        self.key_id == other.key_id && self.key_data == other.key_data
    }
}

impl TryFrom<&Extention> for KeyShareExtention {
    type Error = Error;

    fn try_from(ext: &Extention) -> Result<Self, Self::Error> {
        if ext.id != 0x0033 {
            return Err("Invalid id type".into());
        }

        let mut content = Buffer::from(&ext.content);
        println!("Content length: {}", content.len());
        let mut keyshare_bytes = 0;
        if ext.is_server == false {
            keyshare_bytes = content.read_u16()?;
        }
        let cpos = content.pos;
        // there can be multiple shared keys, we're only reading first
        let key_id = content.read_u16()?;

        let key_length = content.read_u16()?;
        let key_data = content.read_n(key_length as usize)?;
        let ks = KeyShareExtention { key_id, key_data };

        let epos = content.pos;

        if ext.is_server == false && (epos - cpos) > keyshare_bytes as usize {
            return Err("Multiple keyshare not supported".into());
        }
        Ok(ks)
    }
}

impl From<&KeyShareExtention> for Buffer {
    fn from(value: &KeyShareExtention) -> Self {
        let mut b = Buffer::new();
        b.write_u16((value.key_data.len() + 2 + 2) as u16); // key share data bytes (32 + 2 + 2)
        b.write_u16(value.key_id as u16);
        b.write_u16(value.key_data.len() as u16);
        b.write_n(&value.key_data);
        b
    }
}
