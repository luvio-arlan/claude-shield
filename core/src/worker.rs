use crate::config::ShieldConfig;
use crate::guard::audit_local_defenses;
use crate::probe::ProbePool;
use crate::{build_telemetry_payload, evaluate_gate_with_probes, TelemetryJson};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const CACHE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Debug, Deserialize)]
struct WorkerRequest {
    id: u64,
    cmd: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    reset_pool: bool,
}

#[derive(Debug, Serialize)]
struct WorkerResponse<T: Serialize> {
    id: u64,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn telemetry_cache_signature(t: &TelemetryJson) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        t.expected_ip,
        t.proxy_port,
        t.target_tz,
        t.proxy.reachable,
        t.proxy.ip,
        t.tun.reachable,
        t.tun.ip,
        t.claude_edge.colo.as_deref().unwrap_or(""),
        t.defenses.oauth_locked,
        t.defenses.original_hidden,
        t.defenses.original_app_exposed,
        t.defenses.sandbox_enabled,
        t.defenses.telemetry_disabled,
        t.defenses.desktop_pid.as_deref().unwrap_or(""),
        t.defenses.desktop_proxy_bound,
        t.defenses.desktop_quic_disabled,
        t.defenses.desktop_webrtc_locked,
        t.defenses.unprotected_cli_pids.join(","),
    )
}

fn should_flush_telemetry_cache(
    prev_sig: Option<&str>,
    new_sig: &str,
    last_written: Option<Instant>,
    now: Instant,
) -> bool {
    if prev_sig != Some(new_sig) {
        return true;
    }
    match last_written {
        Some(ts) => now.saturating_duration_since(ts) >= CACHE_HEARTBEAT_INTERVAL,
        None => true,
    }
}

fn write_response_line<T: Serialize>(resp: &WorkerResponse<T>) -> bool {
    let Ok(line) = serde_json::to_string(resp) else {
        return false;
    };
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if writeln!(handle, "{}", line).is_err() {
        return false;
    }
    handle.flush().is_ok()
}

/// Persistent single-threaded worker reading NDJSON requests on stdin and writing
/// NDJSON responses on stdout. Keeps HTTP/2 + TLS 1.3 connection pools warm across
/// cycles and exits cleanly when the parent process closes stdin.
pub async fn run_worker_loop() {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let _reader = std::thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(text) => {
                    let trimmed = text.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if tx.send(trimmed.to_string()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let initial_cfg = ShieldConfig::load();
    let mut pool = ProbePool::new(&initial_cfg);
    let mut last_cache_sig: Option<String> = None;
    let mut last_cache_written: Option<Instant> = None;

    while let Some(raw_line) = rx.recv().await {
        let req: WorkerRequest = match serde_json::from_str(&raw_line) {
            Ok(r) => r,
            Err(err) => {
                let resp: WorkerResponse<serde_json::Value> = WorkerResponse {
                    id: 0,
                    ok: false,
                    data: None,
                    error: Some(format!("invalid request: {}", err)),
                };
                if !write_response_line(&resp) {
                    break;
                }
                continue;
            }
        };

        let cfg = ShieldConfig::load();
        let wrote = match req.cmd.as_str() {
            "telemetry" => {
                let is_light = req.mode.as_deref() == Some("light");
                let net = if is_light {
                    pool.probe_light(&cfg, req.reset_pool).await
                } else {
                    pool.probe_full(&cfg, req.reset_pool).await
                };
                let defenses = audit_local_defenses(&cfg);
                let payload = build_telemetry_payload(&cfg, net, defenses);
                let sig = telemetry_cache_signature(&payload);
                let now = Instant::now();
                if !is_light
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
                write_response_line(&WorkerResponse {
                    id: req.id,
                    ok: true,
                    data: Some(payload),
                    error: None,
                })
            }
            "defenses" => {
                let defenses = audit_local_defenses(&cfg);
                write_response_line(&WorkerResponse {
                    id: req.id,
                    ok: true,
                    data: Some(defenses),
                    error: None,
                })
            }
            "gate" => {
                let t0 = Instant::now();
                let (proxy, tun, edge) = pool.probe_gate(&cfg, req.reset_pool).await;
                let elapsed_ms = t0.elapsed().as_millis() as u64;
                let gate = evaluate_gate_with_probes(&cfg, proxy, tun, edge, elapsed_ms);
                write_response_line(&WorkerResponse {
                    id: req.id,
                    ok: true,
                    data: Some(gate),
                    error: None,
                })
            }
            "reset_pool" => {
                pool.reset(&cfg);
                write_response_line(&WorkerResponse {
                    id: req.id,
                    ok: true,
                    data: Some(serde_json::json!({ "reset": true })),
                    error: None,
                })
            }
            "ping" => write_response_line(&WorkerResponse {
                id: req.id,
                ok: true,
                data: Some(serde_json::json!({ "pong": true })),
                error: None,
            }),
            other => write_response_line(&WorkerResponse::<serde_json::Value> {
                id: req.id,
                ok: false,
                data: None,
                error: Some(format!("unknown cmd: {}", other)),
            }),
        };

        if !wrote {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_request_deserializes_with_defaults() {
        let req: WorkerRequest =
            serde_json::from_str(r#"{"id":7,"cmd":"telemetry","mode":"light"}"#).expect("parse req");
        assert_eq!(req.id, 7);
        assert_eq!(req.cmd, "telemetry");
        assert_eq!(req.mode.as_deref(), Some("light"));
        assert!(!req.reset_pool);
    }

    #[test]
    fn cache_flush_deduplicates_unchanged_light_snapshots_until_heartbeat() {
        let t0 = Instant::now();
        assert!(should_flush_telemetry_cache(None, "sig-a", None, t0));
        assert!(!should_flush_telemetry_cache(Some("sig-a"), "sig-a", Some(t0), t0 + Duration::from_secs(60)));
        assert!(should_flush_telemetry_cache(Some("sig-a"), "sig-b", Some(t0), t0 + Duration::from_secs(10)));
        assert!(should_flush_telemetry_cache(
            Some("sig-a"),
            "sig-a",
            Some(t0),
            t0 + CACHE_HEARTBEAT_INTERVAL
        ));
    }
}
