use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    mtime: Option<SystemTime>,
    len: u64,
}

fn file_stamp(path: &Path) -> FileStamp {
    match fs::metadata(path) {
        Ok(m) => FileStamp {
            mtime: m.modified().ok(),
            len: m.len(),
        },
        Err(_) => FileStamp { mtime: None, len: 0 },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigStamps {
    home_dir: PathBuf,
    expected_ip: FileStamp,
    proxy_port: FileStamp,
    target_tz: FileStamp,
    hide_original: FileStamp,
}

impl ConfigStamps {
    fn capture(home_dir: &Path) -> Self {
        let dir = home_dir.join(".config/claude-guard");
        Self {
            home_dir: home_dir.to_path_buf(),
            expected_ip: file_stamp(&dir.join("expected_ip")),
            proxy_port: file_stamp(&dir.join("proxy_port")),
            target_tz: file_stamp(&dir.join("target_tz")),
            hide_original: file_stamp(&dir.join("hide_original")),
        }
    }
}

struct CachedConfigEntry {
    stamps: ConfigStamps,
    cfg: ShieldConfig,
}

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

    /// Mtime-cached configuration loader for hot 3-15s telemetry/defense ticks.
    /// Re-reads disk immediately whenever any of the 4 config files changes.
    pub fn load_cached() -> Self {
        static CACHE: OnceLock<Mutex<Option<CachedConfigEntry>>> = OnceLock::new();
        let home_dir = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/Users/Shared"));
        let stamps = ConfigStamps::capture(&home_dir);
        let cache = CACHE.get_or_init(|| Mutex::new(None));
        if let Ok(guard) = cache.lock() {
            if let Some(ref entry) = *guard {
                if entry.stamps == stamps {
                    return entry.cfg.clone();
                }
            }
        }
        let cfg = Self::from_home(home_dir);
        if let Ok(mut guard) = cache.lock() {
            *guard = Some(CachedConfigEntry {
                stamps,
                cfg: cfg.clone(),
            });
        }
        cfg
    }

    pub fn from_home(home_dir: PathBuf) -> Self {
        let config_dir = home_dir.join(".config/claude-guard");

        let expected_ip = read_trimmed(&config_dir.join("expected_ip"))
            .unwrap_or_else(|| "未配置".to_string());
        let proxy_port = read_trimmed(&config_dir.join("proxy_port"))
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|&p| p > 0)
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

    fn unique_tmp_path(&self, name: &str) -> PathBuf {
        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.config_dir
            .join(format!(".{}.{}.{}.tmp", name, std::process::id(), seq))
    }

    pub fn write_cache_json<T: Serialize>(&self, name: &str, value: &T) {
        let _ = fs::create_dir_all(&self.config_dir);
        if let Ok(json) = serde_json::to_string_pretty(value) {
            let tmp = self.unique_tmp_path(name);
            let dst = self.config_dir.join(name);
            if fs::write(&tmp, json).is_ok() {
                if fs::rename(&tmp, &dst).is_err() {
                    let _ = fs::remove_file(&tmp);
                }
            } else {
                let _ = fs::remove_file(&tmp);
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
                let tmp = self.unique_tmp_path(name);
                if fs::write(&tmp, rotated).is_ok() {
                    if fs::rename(&tmp, &dst).is_err() {
                        let _ = fs::remove_file(&tmp);
                    }
                } else {
                    let _ = fs::remove_file(&tmp);
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
