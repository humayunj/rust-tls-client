use sha2::Digest;

use crate::{
    buffer::{Buffer, Error},
    record::Record,
};

pub struct Handshake {
    pub handshake_type: u8,
    pub content: Buffer,
}

impl Handshake {
    pub fn sha256(&self) -> [u8; 32] {
        let b: Buffer = self.into();
        sha2::Sha256::digest(b.as_bytes()).into()
    }
}
impl TryFrom<&mut Buffer> for Handshake {
    type Error = Error;

    fn try_from(b: &mut Buffer) -> Result<Self, Self::Error> {
        let h_type = b.read_u8()?;
        let content_size = b.read_u24()?;

        let content = b.read_n(content_size as usize)?;

        Ok(Handshake {
            handshake_type: h_type,
            content: Buffer::from(&content),
        })
    }
}
impl TryFrom<&Record> for Handshake {
    type Error = Error;

    fn try_from(r: &Record) -> Result<Self, Self::Error> {
        let mut b = Buffer::from(&r.content);
        let h_type = b.read_u8()?;
        let content_size = b.read_u24()?;

        let content = b.read_n(content_size as usize)?;

        Ok(Handshake {
            handshake_type: h_type,
            content: Buffer::from(&content),
        })
    }
}

impl From<&Handshake> for Buffer {
    fn from(h: &Handshake) -> Self {
        let mut b = Buffer::new();
        b.write_u8(h.handshake_type);
        b.write_u24(h.content.len() as u32);
        b.write_n(h.content.as_bytes());
        b
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        buffer::Buffer,
        mockdata::{MOCK_CLIENT_RECORD, MOCK_SERVER_RECORD},
        *,
    };

    #[test]
    fn parse_client_handhsake() {
        let v = Vec::from(&hex::decode(MOCK_CLIENT_RECORD).unwrap()[5..]);
        let handshake = handshake::Handshake::try_from(&mut Buffer::try_from(&v).unwrap()).unwrap();

        assert_eq!(handshake.handshake_type, 0x01); // client hello
        assert_eq!(handshake.content.len(), 0xF4);
    }
    #[test]

    fn parse_server_handhsake() {
        let v = Vec::from(&hex::decode(MOCK_SERVER_RECORD).unwrap()[5..]);
        let handshake = handshake::Handshake::try_from(&mut Buffer::try_from(&v).unwrap()).unwrap();

        assert_eq!(handshake.handshake_type, 0x02); // server hello
        assert_eq!(handshake.content.len(), 0x76);
    }
}
