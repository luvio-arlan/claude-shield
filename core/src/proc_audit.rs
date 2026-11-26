use crate::guard::{is_candidate_cli_comm, is_genuine_claude_cli_args};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeProcessInspection {
    pub desktop_pid: Option<String>,
    pub desktop_proxy_bound: bool,
    pub desktop_quic_disabled: bool,
    pub desktop_webrtc_locked: bool,
    pub unprotected_cli_pids: Vec<String>,
}

impl Default for ClaudeProcessInspection {
    fn default() -> Self {
        Self {
            desktop_pid: None,
            desktop_proxy_bound: true,
            desktop_quic_disabled: true,
            desktop_webrtc_locked: true,
            unprotected_cli_pids: Vec::new(),
        }
    }
}

pub(crate) fn is_claude_desktop_exec(exec_path: &str) -> bool {
    let base = exec_path.rsplit('/').next().unwrap_or(exec_path);
    base == "Claude"
        && (exec_path == "Claude" || exec_path.ends_with("/Contents/MacOS/Claude"))
}

pub(crate) fn has_expected_proxy_env_entries(envp: &[String], proxy_port: u16) -> bool {
    let upper = format!("HTTP_PROXY=http://127.0.0.1:{}", proxy_port);
    let lower = format!("http_proxy=http://127.0.0.1:{}", proxy_port);
    envp.iter().any(|entry| entry == &upper || entry == &lower)
}

/// Parse Darwin `KERN_PROCARGS2` buffer layout:
/// `[argc: i32][exec_path\0][\0 padding...][argv[0]\0 ... argv[argc-1]\0][envp[0]\0 ... \0]`
pub(crate) fn parse_procargs2(buf: &[u8]) -> Option<(Vec<String>, Vec<String>)> {
    if buf.len() < 4 {
        return None;
    }
    let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if !(1..=65536).contains(&argc) {
        return None;
    }

    let mut pos = 4usize;
    // Skip exec_path C-string
    while pos < buf.len() && buf[pos] != 0 {
        pos += 1;
    }
    if pos >= buf.len() {
        return None;
    }
    // Skip trailing NUL alignment bytes between exec_path and argv[0]
    while pos < buf.len() && buf[pos] == 0 {
        pos += 1;
    }

    let mut args = Vec::with_capacity((argc as usize).min(32));
    for _ in 0..argc {
        if pos >= buf.len() {
            break;
        }
        let start = pos;
        while pos < buf.len() && buf[pos] != 0 {
            pos += 1;
        }
        args.push(String::from_utf8_lossy(&buf[start..pos]).into_owned());
        if pos < buf.len() {
            pos += 1; // skip NUL terminator
        }
    }

    let mut envp = Vec::new();
    while pos < buf.len() {
        if buf[pos] == 0 {
            break;
        }
        let start = pos;
        while pos < buf.len() && buf[pos] != 0 {
            pos += 1;
        }
        if pos > start {
            envp.push(String::from_utf8_lossy(&buf[start..pos]).into_owned());
        }
        if pos < buf.len() {
            pos += 1;
        }
    }

    Some((args, envp))
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::OnceLock;

    const CTL_KERN: i32 = 1;
    const KERN_ARGMAX: i32 = 8;
    const KERN_PROCARGS2: i32 = 49;
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
    const MAX_PROCARGS_CAP: usize = 512 * 1024;
    const FALLBACK_ARGMAX: usize = 262_144;

    extern "C" {
        fn proc_listallpids(buffer: *mut c_void, buffersize: i32) -> i32;
        fn proc_pidpath(pid: i32, buffer: *mut c_void, buffersize: u32) -> i32;
        fn sysctl(
            name: *const i32,
            namelen: u32,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *const c_void,
            newlen: usize,
        ) -> i32;
    }

    fn kern_argmax() -> usize {
        static ARGMAX: OnceLock<usize> = OnceLock::new();
        *ARGMAX.get_or_init(|| {
            let mib = [CTL_KERN, KERN_ARGMAX];
            let mut val: i32 = 0;
            let mut len = std::mem::size_of::<i32>();
            let rc = unsafe {
                sysctl(
                    mib.as_ptr(),
                    2,
                    (&mut val as *mut i32).cast::<c_void>(),
                    &mut len,
                    ptr::null(),
                    0,
                )
            };
            if rc == 0 && val > 4096 {
                (val as usize).min(MAX_PROCARGS_CAP)
            } else {
                FALLBACK_ARGMAX
            }
        })
    }

    pub(super) fn list_all_pids() -> Vec<i32> {
        let estimated = unsafe { proc_listallpids(ptr::null_mut(), 0) };
        if estimated <= 0 {
            return Vec::new();
        }
        let capacity = (estimated as usize).saturating_add(128);
        let mut pids = vec![0i32; capacity];
        let buf_bytes = (capacity.saturating_mul(std::mem::size_of::<i32>())).min(i32::MAX as usize) as i32;
        let actual = unsafe { proc_listallpids(pids.as_mut_ptr().cast::<c_void>(), buf_bytes) };
        if actual <= 0 {
            return Vec::new();
        }
        let count = (actual as usize).min(pids.len());
        pids.truncate(count);
        pids
    }

    pub(super) fn read_pid_path(pid: i32, path_buf: &mut [u8; PROC_PIDPATHINFO_MAXSIZE]) -> Option<&str> {
        let len = unsafe {
            proc_pidpath(
                pid,
                path_buf.as_mut_ptr().cast::<c_void>(),
                PROC_PIDPATHINFO_MAXSIZE as u32,
            )
        };
        if len <= 0 {
            return None;
        }
        let slice = &path_buf[..(len as usize).min(PROC_PIDPATHINFO_MAXSIZE)];
        std::str::from_utf8(slice).ok()
    }

    pub(super) fn read_process_args_and_env(pid: i32, raw_buf: &mut Vec<u8>) -> Option<(Vec<String>, Vec<String>)> {
        let max_size = kern_argmax();
        if raw_buf.len() < max_size {
            raw_buf.resize(max_size, 0);
        }
        let mib = [CTL_KERN, KERN_PROCARGS2, pid];
        let mut len = max_size;
        let rc = unsafe {
            sysctl(
                mib.as_ptr(),
                3,
                raw_buf.as_mut_ptr().cast::<c_void>(),
                &mut len,
                ptr::null(),
                0,
            )
        };
        if rc != 0 || len < 4 {
            return None;
        }
        parse_procargs2(&raw_buf[..len])
    }

    pub fn inspect_claude_processes(proxy_port: u16) -> ClaudeProcessInspection {
        let mut out = ClaudeProcessInspection::default();
        let self_pid = std::process::id() as i32;
        let expected_flag = format!("--proxy-server=http://127.0.0.1:{}", proxy_port);

        let pids = list_all_pids();
        let mut path_buf = [0u8; PROC_PIDPATHINFO_MAXSIZE];
        let mut raw_args_buf: Vec<u8> = Vec::new();

        for pid in pids {
            if pid <= 0 || pid == self_pid {
                continue;
            }
            let Some(exec_path) = read_pid_path(pid, &mut path_buf) else {
                continue;
            };

            if is_claude_desktop_exec(exec_path) {
                if out.desktop_pid.is_none() {
                    out.desktop_pid = Some(pid.to_string());
                    if let Some((args, _)) = read_process_args_and_env(pid, &mut raw_args_buf) {
                        out.desktop_proxy_bound = args.iter().any(|a| a == &expected_flag);
                        out.desktop_quic_disabled = args.iter().any(|a| a == "--disable-quic");
                        out.desktop_webrtc_locked = args
                            .iter()
                            .any(|a| a == "--force-webrtc-ip-handling-policy=disable_non_proxied_udp");
                    } else {
                        out.desktop_proxy_bound = false;
                        out.desktop_quic_disabled = false;
                        out.desktop_webrtc_locked = false;
                    }
                }
                continue;
            }

            if !is_candidate_cli_comm(exec_path) {
                continue;
            }

            let Some((args, envp)) = read_process_args_and_env(pid, &mut raw_args_buf) else {
                continue;
            };
            let args_joined = args.join(" ");
            if !is_genuine_claude_cli_args(exec_path, &args_joined) {
                continue;
            }
            if !envp.is_empty() && !has_expected_proxy_env_entries(&envp, proxy_port) {
                out.unprotected_cli_pids.push(pid.to_string());
            }
        }

        out
    }
}

#[cfg(target_os = "macos")]
pub use macos::inspect_claude_processes;

#[cfg(not(target_os = "macos"))]
pub fn inspect_claude_processes(_proxy_port: u16) -> ClaudeProcessInspection {
    ClaudeProcessInspection::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_procargs2_blob(exec_path: &str, args: &[&str], envp: &[&str], pad_zeros: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(args.len() as i32).to_ne_bytes());
        buf.extend_from_slice(exec_path.as_bytes());
        buf.push(0);
        buf.extend(std::iter::repeat_n(0u8, pad_zeros));
        for a in args {
            buf.extend_from_slice(a.as_bytes());
            buf.push(0);
        }
        for e in envp {
            buf.extend_from_slice(e.as_bytes());
            buf.push(0);
        }
        buf.push(0);
        buf
    }

    #[test]
    fn parse_procargs2_extracts_args_and_env_with_padding() {
        let blob = build_procargs2_blob(
            "/opt/homebrew/bin/node",
            &["node", "/opt/node_modules/@anthropic-ai/claude-code/cli.js", "--resume"],
            &["PATH=/usr/bin", "HTTP_PROXY=http://127.0.0.1:7897", "TZ=America/Los_Angeles"],
            3,
        );
        let (args, envp) = parse_procargs2(&blob).expect("parse valid procargs2");
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "node");
        assert_eq!(args[2], "--resume");
        assert_eq!(envp.len(), 3);
        assert!(has_expected_proxy_env_entries(&envp, 7897));
        assert!(!has_expected_proxy_env_entries(&envp, 7890));
    }

    #[test]
    fn parse_procargs2_rejects_malformed_or_truncated_buffers() {
        assert!(parse_procargs2(&[]).is_none());
        assert!(parse_procargs2(&[0, 0]).is_none());
        assert!(parse_procargs2(&0i32.to_ne_bytes()).is_none());
        assert!(parse_procargs2(&(-1i32).to_ne_bytes()).is_none());
        // Missing NUL after exec_path
        let mut no_nul = 1i32.to_ne_bytes().to_vec();
        no_nul.extend_from_slice(b"/usr/bin/claude");
        assert!(parse_procargs2(&no_nul).is_none());
    }

    #[test]
    fn desktop_exec_matcher_distinguishes_claude_from_shield() {
        assert!(is_claude_desktop_exec("/Applications/Claude.app/Contents/MacOS/Claude"));
        assert!(is_claude_desktop_exec("/Users/u/.local/apps/Claude.app/Contents/MacOS/Claude"));
        assert!(!is_claude_desktop_exec("/Applications/Claude Shield.app/Contents/MacOS/ClaudeShield"));
        assert!(!is_claude_desktop_exec("/usr/local/bin/claude"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_native_proc_audit_reads_self_process_without_fork() {
        let self_pid = std::process::id() as i32;
        let pids = macos::list_all_pids();
        assert!(pids.contains(&self_pid), "proc_listallpids should contain current test pid");

        let mut path_buf = [0u8; 4096];
        let path = macos::read_pid_path(self_pid, &mut path_buf).expect("proc_pidpath for self");
        assert!(!path.is_empty());

        let mut raw = Vec::new();
        let (args, envp) = macos::read_process_args_and_env(self_pid, &mut raw).expect("KERN_PROCARGS2 for self");
        assert!(!args.is_empty());
        assert!(!envp.is_empty());
    }
}
