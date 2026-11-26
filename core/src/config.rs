use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
    pub expected_ip: String,
    pub proxy_port: u16,
    pub target_tz: String,
    pub home_dir: PathBuf,
    pub config_dir: PathBuf,
}

impl ShieldConfig {
    pub fn load() -> Self {
        let home_dir = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/Users/Shared"));
        let config_dir = home_dir.join(".config/claude-guard");

        let expected_ip = read_trimmed(&config_dir.join("expected_ip"))
            .unwrap_or_else(|| "未配置".to_string());
        let proxy_port = read_trimmed(&config_dir.join("proxy_port"))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(7897);
        let target_tz = read_trimmed(&config_dir.join("target_tz"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "America/Los_Angeles".to_string());

        Self {
            expected_ip,
            proxy_port,
            target_tz,
            home_dir,
            config_dir,
        }
    }

    pub fn proxy_http_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.proxy_port)
    }

    pub fn proxy_socks_url(&self) -> String {
        format!("socks5h://127.0.0.1:{}", self.proxy_port)
    }

    pub fn is_ip_configured(&self) -> bool {
        !self.expected_ip.is_empty() && self.expected_ip != "未配置"
    }

    pub fn write_cache_json<T: Serialize>(&self, name: &str, value: &T) {
        let _ = fs::create_dir_all(&self.config_dir);
        if let Ok(json) = serde_json::to_string_pretty(value) {
            let tmp = self.config_dir.join(format!(".{}.tmp", name));
            let dst = self.config_dir.join(name);
            if fs::write(&tmp, json).is_ok() {
                let _ = fs::rename(tmp, dst);
            }
        }
    }

    pub fn append_jsonl<T: Serialize>(&self, name: &str, value: &T) {
        let _ = fs::create_dir_all(&self.config_dir);
        let dst = self.config_dir.join(name);
        if let Ok(line) = serde_json::to_string(value) {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(dst) {
                let _ = writeln!(f, "{}", line);
            }
        }
    }
}

pub fn read_trimmed(path: &PathBuf) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn tz_short_and_full(tz: &str) -> (String, String) {
    let city_raw = tz.rsplit('/').next().unwrap_or(tz);
    let full = city_raw.replace('_', " ");
    let short = match full.as_str() {
        "Los Angeles" => "LA",
        "New York" => "NY",
        "San Francisco" => "SF",
        "Chicago" => "CHI",
        "Singapore" => "SG",
        "Hong Kong" => "HK",
        "Tokyo" => "TYO",
        "London" => "LDN",
        "Frankfurt" => "FRA",
        "Amsterdam" => "AMS",
        "Seattle" => "SEA",
        "Dallas" => "DAL",
        "Phoenix" => "PHX",
        "Denver" => "DEN",
        "San Jose" => "SJC",
        "Ashburn" => "IAD",
        "Miami" => "MIA",
        "Toronto" => "YYZ",
        "Sydney" => "SYD",
        _ => "",
    };
    let short_str = if !short.is_empty() {
        short.to_string()
    } else {
        full.chars().take(6).collect()
    };
    (short_str, full)
}
