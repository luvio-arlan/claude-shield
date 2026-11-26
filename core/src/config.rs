use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
    pub expected_ip: String,
    pub proxy_port: u16,
    pub target_tz: String,
    pub hide_original: bool,
    pub home_dir: PathBuf,
    pub config_dir: PathBuf,
}

impl ShieldConfig {
    pub fn load() -> Self {
        let home_dir = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/Users/Shared"));
        Self::from_home(home_dir)
    }

    pub fn from_home(home_dir: PathBuf) -> Self {
        let config_dir = home_dir.join(".config/claude-guard");

        let expected_ip = read_trimmed(&config_dir.join("expected_ip"))
            .unwrap_or_else(|| "未配置".to_string());
        let proxy_port = read_trimmed(&config_dir.join("proxy_port"))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(7897);
        let target_tz = read_trimmed(&config_dir.join("target_tz"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "America/Los_Angeles".to_string());
        let hide_original = read_trimmed(&config_dir.join("hide_original"))
            .map(|s| !matches!(s.to_ascii_lowercase().as_str(), "0" | "false"))
            .unwrap_or(true);

        Self {
            expected_ip,
            proxy_port,
            target_tz,
            hide_original,
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

    /// Append a JSON line while keeping the file bounded to `max_lines` most recent entries.
    pub fn append_jsonl_capped<T: Serialize>(&self, name: &str, value: &T, max_lines: usize) {
        let _ = fs::create_dir_all(&self.config_dir);
        let dst = self.config_dir.join(name);
        let Ok(line) = serde_json::to_string(value) else {
            return;
        };

        if max_lines == 0 {
            return;
        }

        if let Ok(existing) = fs::read_to_string(&dst) {
            let mut lines: Vec<&str> = existing.lines().filter(|l| !l.trim().is_empty()).collect();
            if lines.len() >= max_lines {
                let drop_count = lines.len() + 1 - max_lines;
                lines.drain(0..drop_count);
                let mut rotated = lines.join("\n");
                if !rotated.is_empty() {
                    rotated.push('\n');
                }
                rotated.push_str(&line);
                rotated.push('\n');
                let tmp = self.config_dir.join(format!(".{}.tmp", name));
                if fs::write(&tmp, rotated).is_ok() {
                    let _ = fs::rename(tmp, &dst);
                }
                return;
            }
        }

        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(dst) {
            let _ = writeln!(f, "{}", line);
        }
    }
}

pub fn read_trimmed(path: &Path) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_home(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "claude-shield-cfg-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp home");
        dir
    }

    #[test]
    fn from_home_defaults_and_overrides() {
        let home = temp_home("defaults");
        let cfg = ShieldConfig::from_home(home.clone());
        assert_eq!(cfg.expected_ip, "未配置");
        assert!(!cfg.is_ip_configured());
        assert_eq!(cfg.proxy_port, 7897);
        assert_eq!(cfg.target_tz, "America/Los_Angeles");
        assert!(cfg.hide_original);

        fs::create_dir_all(&cfg.config_dir).expect("mkdir config");
        fs::write(cfg.config_dir.join("expected_ip"), " 45.77.12.34 \n").expect("write ip");
        fs::write(cfg.config_dir.join("proxy_port"), "7890\n").expect("write port");
        fs::write(cfg.config_dir.join("target_tz"), "Asia/Tokyo\n").expect("write tz");
        fs::write(cfg.config_dir.join("hide_original"), "0\n").expect("write hide");

        let reloaded = ShieldConfig::from_home(home.clone());
        assert_eq!(reloaded.expected_ip, "45.77.12.34");
        assert!(reloaded.is_ip_configured());
        assert_eq!(reloaded.proxy_port, 7890);
        assert_eq!(reloaded.target_tz, "Asia/Tokyo");
        assert!(!reloaded.hide_original);

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn tz_short_and_full_maps_known_and_fallback_cities() {
        assert_eq!(
            tz_short_and_full("America/Los_Angeles"),
            ("LA".to_string(), "Los Angeles".to_string())
        );
        assert_eq!(
            tz_short_and_full("Asia/Tokyo"),
            ("TYO".to_string(), "Tokyo".to_string())
        );
        assert_eq!(
            tz_short_and_full("America/Indianapolis"),
            ("Indian".to_string(), "Indianapolis".to_string())
        );
    }

    #[test]
    fn write_cache_and_append_jsonl_capped_rotate_cleanly() {
        let home = temp_home("jsonl");
        let cfg = ShieldConfig::from_home(home.clone());

        cfg.write_cache_json("sample.json", &serde_json::json!({"ok": true}));
        let cached = fs::read_to_string(cfg.config_dir.join("sample.json")).expect("read cache");
        assert!(cached.contains("\"ok\": true"));

        for i in 1..=5 {
            cfg.append_jsonl_capped("history.jsonl", &serde_json::json!({"seq": i}), 3);
        }
        let body = fs::read_to_string(cfg.config_dir.join("history.jsonl")).expect("read jsonl");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"seq\":3"));
        assert!(lines[2].contains("\"seq\":5"));

        let _ = fs::remove_dir_all(&home);
    }
}
