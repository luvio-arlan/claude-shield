use crate::config::ShieldConfig;
use crate::detect::detect_environment;
use crate::guard::{
    audit_local_defenses, hide_original_claude_app, kill_claude_sessions, kill_pids,
    spawn_hardened_claude_desktop, LaunchDesktopOutcome,
};
use crate::patrol::run_daily_patrol;
use crate::probe::ProbePool;
use crate::purity::run_purity_audit;
use crate::worker::{should_flush_telemetry_cache, telemetry_cache_signature};
use crate::{build_telemetry_payload, evaluate_gate_with_probes};
use std::ffi::{c_char, CStr, CString};
use std::ptr;
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::Instant;

enum EngineJob {
    Telemetry {
        light: bool,
        reset_pool: bool,
        skip_api: bool,
        reply: mpsc::SyncSender<Option<String>>,
    },
    Gate {
        reset_pool: bool,
        reply: mpsc::SyncSender<Option<String>>,
    },
    LaunchDesktop {
        skip_gate: bool,
        verified_ip: Option<String>,
        reply: mpsc::SyncSender<Option<String>>,
    },
    Purity {
        reply: mpsc::SyncSender<Option<String>>,
    },
    Patrol {
        notify: bool,
        auto_kill: bool,
        reply: mpsc::SyncSender<Option<String>>,
    },
    Detect {
        preferred_port: Option<u16>,
        reply: mpsc::SyncSender<Option<String>>,
    },
    ResetPool {
        reply: mpsc::SyncSender<bool>,
    },
    Shutdown,
}

struct FfiEngine {
    tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<EngineJob>>>,
}

impl FfiEngine {
    fn global() -> &'static Self {
        static ENGINE: OnceLock<FfiEngine> = OnceLock::new();
        ENGINE.get_or_init(|| Self {
            tx: Mutex::new(None),
        })
    }

    fn ensure_sender(&self) -> Option<tokio::sync::mpsc::UnboundedSender<EngineJob>> {
        let mut guard = self.tx.lock().ok()?;
        if let Some(ref sender) = *guard {
            if !sender.is_closed() {
                return Some(sender.clone());
            }
        }

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<EngineJob>();
        let spawn_ok = std::thread::Builder::new()
            .name("claude-shield-core-rt".to_string())
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                rt.block_on(async move {
                    let initial_cfg = ShieldConfig::load();
                    let mut pool = ProbePool::new(&initial_cfg);
                    let mut last_cache_sig: Option<String> = None;
                    let mut last_cache_written: Option<Instant> = None;

                    while let Some(job) = rx.recv().await {
                        match job {
                            EngineJob::Telemetry {
                                light,
                                reset_pool,
                                skip_api,
                                reply,
                            } => {
                                let cfg = ShieldConfig::load_cached();
                                let net = if light {
                                    pool.probe_light_opts(&cfg, reset_pool, skip_api).await
                                } else {
                                    pool.probe_full(&cfg, reset_pool).await
                                };
                                let defenses = audit_local_defenses(&cfg);
                                let payload = build_telemetry_payload(&cfg, net, defenses);
                                let sig = telemetry_cache_signature(&payload);
                                let now = Instant::now();
                                if !light
                                    || should_flush_telemetry_cache(
                                        last_cache_sig.as_deref(),
                                        &sig,
                                        last_cache_written,
                                        now,
                                    )
                                {
                                    cfg.write_cache_json("last_telemetry.json", &payload);
                                    last_cache_sig = Some(sig);
                                    last_cache_written = Some(now);
                                }
                                let _ = reply.send(serde_json::to_string(&payload).ok());
                            }
                            EngineJob::Gate { reset_pool, reply } => {
                                let cfg = ShieldConfig::load_cached();
                                let t0 = Instant::now();
                                let (proxy, tun, edge) = pool.probe_gate(&cfg, reset_pool).await;
                                let elapsed_ms = t0.elapsed().as_millis() as u64;
                                let gate = evaluate_gate_with_probes(&cfg, proxy, tun, edge, elapsed_ms);
                                let _ = reply.send(serde_json::to_string(&gate).ok());
                            }
                            EngineJob::LaunchDesktop {
                                skip_gate,
                                verified_ip,
                                reply,
                            } => {
                                let cfg = ShieldConfig::load();
                                let mut approved_ip = verified_ip;
                                if !skip_gate {
                                    let t0 = Instant::now();
                                    let (proxy, tun, edge) = pool.probe_gate(&cfg, false).await;
                                    let elapsed_ms = t0.elapsed().as_millis() as u64;
                                    let gate =
                                        evaluate_gate_with_probes(&cfg, proxy, tun, edge, elapsed_ms);
                                    if !gate.ok {
                                        let out = LaunchDesktopOutcome {
                                            ok: false,
                                            already_running: false,
                                            pid: None,
                                            message: gate
                                                .error
                                                .unwrap_or_else(|| "出口 IP 校验未通过".into()),
                                        };
                                        let _ = reply.send(serde_json::to_string(&out).ok());
                                        continue;
                                    }
                                    if !gate.proxy_ip.is_empty() && gate.proxy_ip != "无法连通" {
                                        approved_ip = Some(gate.proxy_ip);
                                    }
                                }
                                tokio::task::spawn_blocking(move || {
                                    let out =
                                        spawn_hardened_claude_desktop(&cfg, approved_ip.as_deref());
                                    let _ = reply.send(serde_json::to_string(&out).ok());
                                });
                            }
                            // Independent long-running jobs spawn concurrently on the same single-threaded
                            // Tokio reactor so they NEVER head-of-line block Telemetry or Gate checks.
                            EngineJob::Purity { reply } => {
                                tokio::spawn(async move {
                                    let cfg = ShieldConfig::load();
                                    let report = run_purity_audit(&cfg).await;
                                    let _ = reply.send(serde_json::to_string(&report).ok());
                                });
                            }
                            EngineJob::Patrol {
                                notify,
                                auto_kill,
                                reply,
                            } => {
                                tokio::spawn(async move {
                                    let cfg = ShieldConfig::load();
                                    let report = run_daily_patrol(&cfg, notify, auto_kill).await;
                                    let _ = reply.send(serde_json::to_string(&report).ok());
                                });
                            }
                            EngineJob::Detect {
                                preferred_port,
                                reply,
                            } => {
                                tokio::spawn(async move {
                                    let cfg = ShieldConfig::load();
                                    let res = detect_environment(&cfg, preferred_port).await;
                                    let _ = reply.send(serde_json::to_string(&res).ok());
                                });
                            }
                            EngineJob::ResetPool { reply } => {
                                let cfg = ShieldConfig::load();
                                pool.reset(&cfg);
                                let _ = reply.send(true);
                            }
                            EngineJob::Shutdown => break,
                        }
                    }
                });
            })
            .is_ok();

        if !spawn_ok {
            return None;
        }
        *guard = Some(tx.clone());
        Some(tx)
    }

    fn shutdown(&self) {
        if let Ok(mut guard) = self.tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(EngineJob::Shutdown);
            }
        }
    }
}

fn into_raw_c_string(opt: Option<String>) -> *mut c_char {
    let Some(s) = opt else {
        return ptr::null_mut();
    };
    let sanitized = if s.as_bytes().contains(&0) {
        s.replace('\0', "")
    } else {
        s
    };
    CString::new(sanitized)
        .map(CString::into_raw)
        .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn claude_shield_telemetry_json(
    light: bool,
    reset_pool: bool,
    skip_api: bool,
) -> *mut c_char {
    let Some(tx) = FfiEngine::global().ensure_sender() else {
        return ptr::null_mut();
    };
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if tx
        .send(EngineJob::Telemetry {
            light,
            reset_pool,
            skip_api,
            reply: reply_tx,
        })
        .is_err()
    {
        return ptr::null_mut();
    }
    into_raw_c_string(reply_rx.recv().ok().flatten())
}

/// Synchronous zero-fork local defense audit (< 1ms directly on caller's background thread).
#[no_mangle]
pub extern "C" fn claude_shield_defenses_json() -> *mut c_char {
    let cfg = ShieldConfig::load_cached();
    let defenses = audit_local_defenses(&cfg);
    into_raw_c_string(serde_json::to_string(&defenses).ok())
}

#[no_mangle]
pub extern "C" fn claude_shield_gate_json(reset_pool: bool) -> *mut c_char {
    let Some(tx) = FfiEngine::global().ensure_sender() else {
        return ptr::null_mut();
    };
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if tx
        .send(EngineJob::Gate {
            reset_pool,
            reply: reply_tx,
        })
        .is_err()
    {
        return ptr::null_mut();
    }
    into_raw_c_string(reply_rx.recv().ok().flatten())
}

#[no_mangle]
pub extern "C" fn claude_shield_purity_json() -> *mut c_char {
    let Some(tx) = FfiEngine::global().ensure_sender() else {
        return ptr::null_mut();
    };
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if tx.send(EngineJob::Purity { reply: reply_tx }).is_err() {
        return ptr::null_mut();
    }
    into_raw_c_string(reply_rx.recv().ok().flatten())
}

#[no_mangle]
pub extern "C" fn claude_shield_patrol_json(notify: bool, auto_kill: bool) -> *mut c_char {
    let Some(tx) = FfiEngine::global().ensure_sender() else {
        return ptr::null_mut();
    };
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if tx
        .send(EngineJob::Patrol {
            notify,
            auto_kill,
            reply: reply_tx,
        })
        .is_err()
    {
        return ptr::null_mut();
    }
    into_raw_c_string(reply_rx.recv().ok().flatten())
}

#[no_mangle]
pub extern "C" fn claude_shield_detect_json(preferred_port: i32) -> *mut c_char {
    let Some(tx) = FfiEngine::global().ensure_sender() else {
        return ptr::null_mut();
    };
    let port_opt = if (1..=65535).contains(&preferred_port) {
        Some(preferred_port as u16)
    } else {
        None
    };
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if tx
        .send(EngineJob::Detect {
            preferred_port: port_opt,
            reply: reply_tx,
        })
        .is_err()
    {
        return ptr::null_mut();
    }
    into_raw_c_string(reply_rx.recv().ok().flatten())
}

#[no_mangle]
pub extern "C" fn claude_shield_hide_original_json() -> *mut c_char {
    let cfg = ShieldConfig::load();
    let actions = hide_original_claude_app(&cfg);
    into_raw_c_string(serde_json::to_string(&actions).ok())
}

/// Launch or focus hardened Claude Desktop in-process.
///
/// # Safety
/// `verified_ip` must either be null or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn claude_shield_launch_desktop_json(
    skip_gate: bool,
    verified_ip: *const c_char,
) -> *mut c_char {
    let ip_opt = if verified_ip.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(verified_ip) }
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    let Some(tx) = FfiEngine::global().ensure_sender() else {
        return ptr::null_mut();
    };
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if tx
        .send(EngineJob::LaunchDesktop {
            skip_gate,
            verified_ip: ip_opt,
            reply: reply_tx,
        })
        .is_err()
    {
        return ptr::null_mut();
    }
    into_raw_c_string(reply_rx.recv().ok().flatten())
}

#[no_mangle]
pub extern "C" fn claude_shield_kill_claude_json(include_cli: bool) -> *mut c_char {
    let cfg = ShieldConfig::load_cached();
    let out = kill_claude_sessions(&cfg, include_cli);
    into_raw_c_string(serde_json::to_string(&out).ok())
}

/// Kill specific comma-separated PIDs using direct POSIX `kill(pid, SIGKILL)`.
///
/// # Safety
/// `csv_pids` must either be null or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn claude_shield_kill_pids_json(csv_pids: *const c_char) -> *mut c_char {
    let pids: Vec<String> = if csv_pids.is_null() {
        Vec::new()
    } else {
        unsafe { CStr::from_ptr(csv_pids) }
            .to_str()
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    };
    let killed = kill_pids(&pids);
    into_raw_c_string(Some(serde_json::json!({ "killed": killed }).to_string()))
}

#[no_mangle]
pub extern "C" fn claude_shield_reset_pool() -> bool {
    let Some(tx) = FfiEngine::global().ensure_sender() else {
        return false;
    };
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if tx.send(EngineJob::ResetPool { reply: reply_tx }).is_err() {
        return false;
    }
    reply_rx.recv().unwrap_or(false)
}

#[no_mangle]
pub extern "C" fn claude_shield_shutdown() {
    FfiEngine::global().shutdown();
}

/// Free a UTF-8 JSON string returned by any `claude_shield_*_json` FFI function.
///
/// # Safety
/// `ptr` must either be null or a pointer previously returned by this library and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn claude_shield_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn ffi_defenses_roundtrip_returns_valid_json_and_frees_cleanly() {
        let raw = claude_shield_defenses_json();
        assert!(!raw.is_null());
        let json = unsafe { CStr::from_ptr(raw) }.to_str().expect("valid utf8").to_string();
        unsafe { claude_shield_free_string(raw) };
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(parsed.get("oauth_locked").is_some());
        assert!(parsed.get("desktop_proxy_bound").is_some());
        assert!(parsed.get("desktop_bypass_locked").is_some());
        assert!(parsed.get("active_cli_pids").is_some());
    }
}
