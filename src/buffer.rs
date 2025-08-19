use std::{collections::btree_map::Range, io::Write, ops::RangeFull};

pub type Error = Box<dyn std::error::Error>;
pub struct Buffer {
    pub pos: usize,
    pub vec: Vec<u8>,
}

impl Buffer {
    pub fn new() -> Buffer {
        Buffer {
            pos: 0,
            vec: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.vec.len()
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.vec[..]
    }
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        if self.pos == self.vec.len() {
            return Err("end of buffer".into());
        }
        let v = self.vec[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> Result<u16, Error> {
        if self.pos + 1 == self.vec.len() {
            return Err("end of buffer".into());
        }

        let v = (self.vec[self.pos] as u16) << 8 | (self.vec[self.pos + 1] as u16);
        self.pos += 2;
        Ok(v)
    }
    pub fn read_u24(&mut self) -> Result<u32, Error> {
        if self.pos + 2 == self.vec.len() {
            return Err("end of buffer".into());
        }

        let v = (self.vec[self.pos] as u32) << 16
            | (self.vec[self.pos + 1] as u32) << 8
            | (self.vec[self.pos + 2] as u32);
        self.pos += 3;
        Ok(v)
    }

    pub fn read_n(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        if self.pos + n > self.vec.len() {
            return Err("end of buffer".into());
        }

        let mut v: Vec<u8> = vec![];

        v.extend_from_slice(&self.vec[self.pos..self.pos + n]);

        self.pos += n;
        Ok(v)
    }
    pub fn seek(&mut self, pos: usize) -> Result<&mut Self, Error> {
        if self.pos + pos >= self.vec.len() {
            return Err("end of buffer".into());
        }
        self.pos = pos;
        Ok(self)
    }

    pub fn write_u8(&mut self, val: u8) -> () {
        self.vec.push(val);
    }
    pub fn write_u16(&mut self, val: u16) -> () {
        self.vec.extend_from_slice(&val.to_be_bytes());
    }
    pub fn write_u24(&mut self, val: u32) -> () {
        self.write_n(&val.to_be_bytes()[1..]); // not sure it works 
    }

    pub fn write_n(&mut self, val: &[u8]) -> () {
        self.vec.extend_from_slice(&val);
    }
}

impl From<&Vec<u8>> for Buffer {
    fn from(value: &Vec<u8>) -> Self {
        Buffer {
            pos: 0,
            vec: value.clone(),
        }
    }
}
