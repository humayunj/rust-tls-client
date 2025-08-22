use std::fmt::Display;

use sha2::Digest;

use crate::buffer::{Buffer, Error};

pub struct Record {
    pub record_type: u8,
    pub ver: u16,
    pub content: Vec<u8>,
}
impl Record {
    pub fn new(rtype: u8, content: Vec<u8>) -> Record {
        Record {
            record_type: rtype,
            ver: 0x303,
            content,
        }
    }

    fn get_type_name(&self) -> String {
        match self.record_type {
            0x14 => "ChangeCipherSpec".to_string(),
            0x16 => "Handshake".to_string(),

            0x17 => "ApplicationData".to_string(),
            _ => hex::encode(self.record_type.to_be_bytes()),
        }
    }
}
impl Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Record<type={}  size={}> {}..{}",
            self.get_type_name(),
            hex::encode((self.content.len() as u16).to_be_bytes()),
            hex::encode(&self.content[..std::cmp::min(self.content.len(), 2)]),
            hex::encode(
                &self.content[self
                    .content
                    .len()
                    .checked_sub(2)
                    .unwrap_or(self.content.len())..]
            )
        )
    }
}

impl TryFrom<&mut Buffer> for Record {
    type Error = Error;

    fn try_from(buff: &mut Buffer) -> Result<Self, Self::Error> {
        let record_type: u8 = buff.read_u8()?;
        let ver = buff.read_u16()?;
        let length = buff.read_u16()?;
        let content = buff.read_n(length as usize)?;
        Ok(Record {
            record_type,
            ver,
            content,
        })
    }
}
impl Into<Buffer> for Record {
    fn into(self) -> Buffer {
        let mut b = Buffer::new();
        b.write_u8(self.record_type);
        b.write_u16(self.ver);
        b.write_u16(self.content.len() as u16);
        b.write_n(&self.content[..]);
        b
    }
}
impl From<&Record> for Buffer {
    fn from(v: &Record) -> Self {
        let mut b = Buffer::new();
        b.write_u8(v.record_type);
        b.write_u16(v.ver);
        b.write_u16(v.content.len() as u16);
        b.write_n(&v.content[..]);
        b
    }
}
impl TryFrom<&Vec<u8>> for Record {
    type Error = Error;
    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let mut b = Buffer::from(value);
        let r: Record = Self::try_from(&mut b)?;

        Ok(r)
    }
}
#[cfg(test)]
mod tests {
    use sha2::Digest;

    use crate::{
        buffer::Buffer,
        mockdata::{MOCK_CLIENT_RECORD, MOCK_SERVER_RECORD},
        record::Record,
    };

    #[test]
    fn parse_client_record() {
        let MOCK_DATA = MOCK_CLIENT_RECORD;
        let mut b = Buffer::from(&hex::decode(MOCK_DATA).unwrap());

        let mut r = Record::try_from(&mut b).unwrap();

        assert_eq!(r.record_type, 0x16);
        assert_eq!(r.ver, 0x0301);
        assert_eq!(r.content.len(), 0x00f8);
    }
    #[test]
    fn parse_server_record() {
        let MOCK_DATA = MOCK_SERVER_RECORD;
        let mut b = Buffer::from(&hex::decode(MOCK_DATA).unwrap());

        sha2::Sha384::digest(&b.as_bytes()[5..]);
    }
}
