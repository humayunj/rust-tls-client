use core::fmt;
use std::{fmt::Display, io::BufReader};

use crate::buffer::{Buffer, Error};

#[derive(Debug)]
pub struct HttpHeader {
    name: String,
    value: String,
}
pub struct HttpResponse {
    status_code: u16,
    headers: Vec<HttpHeader>,
    content: Vec<u8>,
}
impl HttpResponse {
    pub fn to_text(&self) -> String {
        String::from_utf8_lossy(&self.content[..]).to_string()
    }
    pub fn headers(&self) -> &[HttpHeader] {
        self.headers.as_slice()
    }
}

impl TryFrom<&[u8]> for HttpResponse {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // extract response header

        let mut pos = 0;
        for i in 0..value.len() - 2 {
            if value[i] == b'\r'
                && value[i + 1] == b'\n'
                && value[i + 2] == b'\r'
                && value[i + 3] == b'\n'
            {
                pos = i
            }
        }

        if pos == 0 {
            return Err("Failed to extract header".into());
        }

        let content = &value[pos + 4..];

        let head = &value[..pos];
        let head_string = String::from_utf8_lossy(head).to_string();
        let mut iter = head_string.lines();

        let status_line: Vec<&str> = iter.next().unwrap().split(" ").collect();

        let status_code = u16::from_str_radix(status_line[1], 10)?;

        let mut headers = vec![];

        for header in iter {
            let (name, val) = header.split_once(":").unwrap();
            headers.push(HttpHeader {
                name: String::from(name),
                value: String::from(val).trim().to_string(),
            })
        }
        Ok(HttpResponse {
            content: Vec::from(content),
            headers,
            status_code,
        })
    }
}

impl fmt::Display for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "HttpResponse<status={} headers_count={} content_len={}",
            self.status_code,
            self.headers.len(),
            self.content.len()
        )
    }
}
