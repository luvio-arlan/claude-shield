use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Rolling window capacity for real-time calibrated warm 1-RTT samples.
pub const RTT_WINDOW_SIZE: usize = 5;
/// Prune samples older than this when newer samples arrive so the rolling median
/// tracks gradual network drift without stale inertia.
pub const RTT_SAMPLE_MAX_AGE: Duration = Duration::from_secs(60);
/// Floor threshold above which an unconfirmed jump is treated as a suspect
/// idle-reconnect / single-packet retransmit spike.
pub const RECONNECT_SUSPECT_FLOOR_MS: u64 = 550;

/// Compute robust `(warm_rtt_ms, jitter_ms)` from warmed HTTP/2 RTT samples:
/// - With >= 4 samples, trims the single highest outlier spike before taking the median RTT
///   and symmetric half-range `(max - min) / 2` so one proxy/origin micro-stutter does not
///   inflate `±` jitter, while genuinely unstable lines still report high jitter honestly.
/// - With 2-3 samples, uses median/midpoint and symmetric half-range.
pub fn compute_robust_latency(raw_samples: &[u64]) -> Option<(u64, u64)> {
    if raw_samples.is_empty() {
        return None;
    }
    let mut sorted = raw_samples.to_vec();
    sorted.sort_unstable();

    match sorted.as_slice() {
        [a] => Some((*a, 0)),
        [a, b] => {
            let mid = (*a + *b) / 2;
            let half_spread = (*b - *a) / 2;
            Some((mid, half_spread))
        }
        [a, b, c] => {
            let half_spread = (*c - *a) / 2;
            Some((*b, half_spread))
        }
        many => {
            // Trim single highest tail spike (1 of N) to suppress isolated proxy/origin stutters
            let trimmed = &many[..many.len() - 1];
            let median = trimmed[trimmed.len() / 2];
            let half_spread = (trimmed[trimmed.len() - 1] - trimmed[0]) / 2;
            Some((median, half_spread))
        }
    }
}

/// Per-channel real-time RTT estimator using a short time-bounded sliding window
/// plus instant 1-shot confirmation for spikes and step drops.
///
/// Guarantees:
/// - Single-packet retransmits or silent idle HTTP/2 reconnects are confirmed immediately
///   and discarded if the follow-up warm sample is clean (never spiking the UI).
/// - Genuine network degradations or route recoveries confirmed by 2 consecutive warm samples
///   flush the stale window and snap immediately (zero sluggish lag).
/// - Identity changes (exit IP, Cloudflare colo, proxy port) immediately flush old samples.
#[derive(Debug, Default, Clone)]
pub struct ChannelRttTracker {
    identity: Option<String>,
    samples: VecDeque<(Instant, u64)>,
}

impl ChannelRttTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.identity = None;
        self.samples.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn sync_identity(&mut self, identity: &str) {
        if self.identity.as_deref() != Some(identity) {
            self.identity = Some(identity.to_string());
            self.samples.clear();
        }
    }

    fn prune(&mut self, now: Instant) {
        while self.samples.len() > 1 {
            let Some((ts, _)) = self.samples.front() else {
                break;
            };
            if now.saturating_duration_since(*ts) > RTT_SAMPLE_MAX_AGE {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn current_metrics(&self) -> Option<(u64, u64)> {
        if self.samples.is_empty() {
            return None;
        }
        let values: Vec<u64> = self.samples.iter().map(|(_, ms)| *ms).collect();
        compute_robust_latency(&values)
    }

    pub fn baseline_rtt(&self) -> Option<u64> {
        self.current_metrics().map(|(rtt, _)| rtt)
    }

    /// True if `sample_ms` looks like an unconfirmed spike (idle TCP+TLS reconnect or
    /// isolated retransmit stall) relative to the current channel baseline.
    pub fn is_suspect_spike(&self, sample_ms: u64) -> bool {
        match self.baseline_rtt() {
            Some(base) => {
                let ratio_limit = base.saturating_mul(16) / 10;
                let abs_floor = base.saturating_add(120);
                (sample_ms >= RECONNECT_SUSPECT_FLOOR_MS && sample_ms >= abs_floor)
                    || (sample_ms >= ratio_limit && sample_ms >= base.saturating_add(100))
            }
            None => sample_ms >= RECONNECT_SUSPECT_FLOOR_MS,
        }
    }

    /// True if `sample_ms` represents a sharp latency improvement (e.g. congestion cleared
    /// or route recovered) that warrants an immediate confirmation to snap downward.
    pub fn is_step_drop(&self, sample_ms: u64) -> bool {
        match self.baseline_rtt() {
            Some(base) => {
                sample_ms.saturating_add(80) <= base
                    && sample_ms.saturating_mul(10) <= base.saturating_mul(7)
            }
            None => false,
        }
    }

    pub fn needs_confirmation(&self, sample_ms: u64) -> bool {
        self.is_suspect_spike(sample_ms) || self.is_step_drop(sample_ms)
    }

    fn push_sample(&mut self, now: Instant, ms: u64) {
        self.samples.push_back((now, ms.max(1)));
        while self.samples.len() > RTT_WINDOW_SIZE {
            self.samples.pop_front();
        }
        self.prune(now);
    }

    pub fn record_sample(&mut self, now: Instant, sample_ms: u64) {
        self.push_sample(now, sample_ms);
    }

    /// Resolve an anomalous first sample paired with an immediate warm confirmation sample.
    /// Returns `true` if `first_ms` was classified as a transient spike/reconnect and discarded.
    pub fn record_confirmed_pair(&mut self, now: Instant, first_ms: u64, confirm_ms: u64) -> bool {
        let first_ms = first_ms.max(1);
        let confirm_ms = confirm_ms.max(1);

        if self.is_suspect_spike(first_ms) {
            let confirm_much_faster = confirm_ms.saturating_mul(2) < first_ms;
            let confirm_is_spike = self.is_suspect_spike(confirm_ms);
            if !confirm_is_spike || confirm_much_faster {
                // Transient single-packet retransmit or silent idle H2 reconnect:
                // drop the spike completely and record only the clean confirmation sample.
                self.push_sample(now, confirm_ms);
                return true;
            }
            // Genuine degradation confirmed by 2 consecutive warm probes: snap immediately.
            self.samples.clear();
            self.push_sample(now, first_ms);
            self.push_sample(now, confirm_ms);
            return false;
        }

        if self.is_step_drop(first_ms) && self.is_step_drop(confirm_ms) {
            // Genuine route improvement / recovery confirmed: snap down immediately.
            self.samples.clear();
            self.push_sample(now, first_ms);
            self.push_sample(now, confirm_ms);
            return false;
        }

        self.push_sample(now, first_ms);
        self.push_sample(now, confirm_ms);
        false
    }

    /// Populate or recalibrate the tracker from a fresh warm multi-sample burst
    /// (cold start, post-reset bootstrap, or manual full recalibration).
    /// Drops isolated 2x+ tail outliers (such as post-connect slow-start stalls) when
    /// cleaner warm samples exist in the same burst.
    pub fn record_bootstrap_samples(&mut self, now: Instant, raw_samples: &[u64]) {
        if raw_samples.is_empty() {
            return;
        }
        let cleaned: Vec<u64> = raw_samples.iter().map(|&ms| ms.max(1)).collect();
        let min_ms = cleaned.iter().copied().min().unwrap_or(1);
        let mut filtered: Vec<u64> = cleaned
            .iter()
            .copied()
            .filter(|&ms| !(ms >= RECONNECT_SUSPECT_FLOOR_MS && ms >= min_ms.saturating_mul(2)))
            .collect();
        if filtered.is_empty() {
            filtered = cleaned;
        }

        self.samples.clear();
        for ms in filtered.into_iter().take(RTT_WINDOW_SIZE) {
            self.push_sample(now, ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robust_latency_suppresses_single_outlier_spike() {
        assert_eq!(compute_robust_latency(&[315, 464, 319, 324]), Some((319, 4)));
    }

    #[test]
    fn robust_latency_clean_line_reports_tight_jitter() {
        assert_eq!(compute_robust_latency(&[238, 241, 237, 240]), Some((238, 1)));
    }

    #[test]
    fn robust_latency_preserves_genuinely_unstable_jitter() {
        assert_eq!(compute_robust_latency(&[250, 310, 380, 460]), Some((310, 65)));
        assert_eq!(compute_robust_latency(&[306, 414, 405, 317]), Some((317, 49)));
    }

    #[test]
    fn robust_latency_handles_small_sample_counts() {
        assert_eq!(compute_robust_latency(&[]), None);
        assert_eq!(compute_robust_latency(&[210]), Some((210, 0)));
        assert_eq!(compute_robust_latency(&[200, 240]), Some((220, 20)));
        assert_eq!(compute_robust_latency(&[200, 210, 230]), Some((210, 15)));
    }

    #[test]
    fn tracker_discards_transient_reconnect_spike_immediately() {
        let mut t = ChannelRttTracker::new();
        let t0 = Instant::now();
        t.sync_identity("192.220.27.106|LAX|7897");
        t.record_bootstrap_samples(t0, &[293, 291, 294]);
        assert_eq!(t.baseline_rtt(), Some(293));

        // Simulate a 1276ms idle H2 reconnect spike followed by clean 292ms confirmation
        assert!(t.needs_confirmation(1276));
        let discarded = t.record_confirmed_pair(t0 + Duration::from_secs(5), 1276, 292);
        assert!(discarded);
        assert_eq!(t.baseline_rtt(), Some(292));
        assert_eq!(t.current_metrics(), Some((292, 1)));
    }

    #[test]
    fn tracker_snaps_immediately_on_confirmed_degradation_and_recovery() {
        let mut t = ChannelRttTracker::new();
        let t0 = Instant::now();
        t.sync_identity("192.220.27.106|LAX|7897");
        t.record_bootstrap_samples(t0, &[290, 292, 294, 291]);
        assert_eq!(t.baseline_rtt(), Some(291));

        // Genuine degradation confirmed by 2 consecutive warm samples
        assert!(t.needs_confirmation(640));
        let discarded = t.record_confirmed_pair(t0 + Duration::from_secs(5), 640, 620);
        assert!(!discarded);
        assert_eq!(t.baseline_rtt(), Some(630));

        // Genuine recovery back to 290ms confirmed by 2 consecutive warm samples
        assert!(t.needs_confirmation(288));
        t.record_confirmed_pair(t0 + Duration::from_secs(10), 288, 292);
        assert_eq!(t.baseline_rtt(), Some(290));
    }

    #[test]
    fn tracker_bootstrap_drops_cold_slow_start_outlier() {
        let mut t = ChannelRttTracker::new();
        let t0 = Instant::now();
        t.sync_identity("192.220.27.106|LAX|7897");
        t.record_bootstrap_samples(t0, &[1276, 238]);
        assert_eq!(t.baseline_rtt(), Some(238));

        // On genuinely slow line without 2x disparity, keeps both honestly
        t.record_bootstrap_samples(t0 + Duration::from_secs(5), &[820, 840]);
        assert_eq!(t.baseline_rtt(), Some(830));
    }

    #[test]
    fn tracker_flushes_window_on_identity_change() {
        let mut t = ChannelRttTracker::new();
        let t0 = Instant::now();
        t.sync_identity("192.220.27.106|LAX|7897");
        t.record_bootstrap_samples(t0, &[290, 292]);
        assert_eq!(t.baseline_rtt(), Some(291));

        t.sync_identity("45.77.12.34|NRT|7897");
        assert!(t.is_empty());
        assert_eq!(t.baseline_rtt(), None);
    }

    #[test]
    fn tracker_prunes_stale_samples_as_new_ones_arrive() {
        let mut t = ChannelRttTracker::new();
        let t0 = Instant::now();
        t.sync_identity("192.220.27.106|LAX|7897");
        t.record_sample(t0, 240);
        t.record_sample(t0 + Duration::from_secs(1), 242);
        t.record_sample(t0 + Duration::from_secs(70), 280);
        assert_eq!(t.baseline_rtt(), Some(280));
    }
}
