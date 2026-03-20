//! BBR congestion controller with aggressive bandwidth probing and optional
//! speed ceiling.
//!
//! Based on standard BBR (Startup, Drain, ProbeBw, ProbeRtt) with two key
//! differences:
//!
//! - **Aggressive mode** (estimated BW < 50 Mbps): all bandwidth-growth
//!   limiters are disabled — no premature Startup exit, no recovery-based
//!   cwnd reduction, no ProbeRtt.  This lets the controller reach high
//!   bandwidth in ~3 RTTs instead of slowly crawling in ProbeBw.
//! - **Floor rate** (0–50 Mbps, scaled by ack_rate): pacing rate and cwnd
//!   never drop below the adaptive floor, preventing stall when `bw_est`
//!   is zero (common on lossy / GFW-interfered links).  Connections with
//!   < 5% delivery rate get floor = 0 (only min_cwnd survives).
//! - **Speed ceiling** via `Arc<AtomicU64>`: `> 0` enforces an upper bound
//!   (e.g. free-tier speed limit), `== 0` means no ceiling.
//!
//! Above 50 Mbps the controller behaves like standard BBR with soft loss
//! response (`cwnd *= 0.85`) instead of TCP-style recovery halving.
//!
//! ## Pacer integration
//!
//! Quinn's pacer sends at `1.25 × pacing_window / RTT`.
//! We set `pacing_window = rate × RTT × 0.8`, so the actual
//! pacing rate ≈ `rate`.  `window()` provides cwnd headroom.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rand::{Rng, SeedableRng};

use super::bbr_max::bw_estimation::BandwidthEstimation;
use super::bbr_max::min_max::MinMax;
use super::{BASE_DATAGRAM_SIZE, Controller, ControllerFactory, ControllerMetrics};
use crate::connection::RttEstimator;
use crate::{Duration, Instant};

pub(crate) mod bw_estimation;
pub(crate) mod min_max;

// ── Constants ────────────────────────────────────────────────────────────────

/// Below this estimated bandwidth all growth-limiters are disabled so the
/// controller stays in Startup (2.885× gain) until it discovers real capacity.
/// 50 Mbps = 6.25 MB/s.
const AGGRESSIVE_THRESHOLD: u64 = 6_250_000;

/// Minimum sending rate enforced at output regardless of BBR internal state.
/// Prevents pacing stall when `bw_est` drops to zero (common on lossy/GFW links).
const FLOOR_RATE: u64 = AGGRESSIVE_THRESHOLD;

const HIGH_GAIN: f64 = 2.885;
const HIGH_CWND_GAIN: f64 = 2.885;
const PROBE_BW_CWND_GAIN: f64 = 2.0;
const DRAIN_GAIN: f64 = 1.0 / HIGH_GAIN;
const PACING_GAIN_CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
const STARTUP_GROWTH_TARGET: f64 = 1.25;
const ROUNDS_WITHOUT_GROWTH_BEFORE_EXIT: u64 = 3;
const INITIAL_WINDOW: u64 = 200 * BASE_DATAGRAM_SIZE;
const DRAIN_TO_TARGET: bool = true;
const PROBE_RTT_BASED_ON_BDP: bool = true;

// ── Ack-rate adaptive floor ─────────────────────────────────────────────────

/// Below this delivery ratio the connection is considered essentially dead;
/// floor rate drops to zero (only `min_cwnd` survives) and loss events are
/// no longer ignored even in aggressive mode.
const CRITICAL_ACK_RATE: f64 = 0.05;

/// Above this delivery ratio, full floor rate applies.  Between CRITICAL and
/// HEALTHY the floor is linearly interpolated.
const HEALTHY_ACK_RATE: f64 = 0.30;

/// Sliding-window size (seconds) for ack-rate sampling.
const ACK_RATE_SLOTS: usize = 4;

/// Minimum weighted sample volume before ack-rate is trusted.
const ACK_RATE_MIN_SAMPLE: f64 = 30_000.0;

/// Exponential-decay half-life per second for slot weighting.
const ACK_RATE_DECAY: f64 = 0.5;

// ── Mode ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

// ── Ack-rate slot ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct AckRateSlot {
    timestamp_secs: i64,
    ack_bytes: u64,
    loss_bytes: u64,
}

// ── AckAggregation ───────────────────────────────────────────────────────────

#[derive(Debug, Copy, Clone, Default)]
struct AckAggregationState {
    max_ack_height: MinMax,
    aggregation_epoch_start_time: Option<Instant>,
    aggregation_epoch_bytes: u64,
}

impl AckAggregationState {
    fn update_ack_aggregation_bytes(
        &mut self,
        newly_acked_bytes: u64,
        now: Instant,
        round: u64,
        max_bandwidth: u64,
    ) -> u64 {
        let expected_bytes_acked = max_bandwidth
            * now
                .saturating_duration_since(self.aggregation_epoch_start_time.unwrap_or(now))
                .as_micros() as u64
            / 1_000_000;

        if self.aggregation_epoch_bytes <= expected_bytes_acked {
            self.aggregation_epoch_bytes = newly_acked_bytes;
            self.aggregation_epoch_start_time = Some(now);
            return 0;
        }

        self.aggregation_epoch_bytes += newly_acked_bytes;
        let diff = self.aggregation_epoch_bytes - expected_bytes_acked;
        self.max_ack_height.update_max(round, diff);
        diff
    }
}

// ── BbrMax ───────────────────────────────────────────────────────────────────

/// BBR congestion controller with aggressive probing and optional speed ceiling.
///
/// See module-level docs for design rationale.
#[derive(Debug, Clone)]
pub struct BbrMax {
    speed_limit: Arc<AtomicU64>,

    // ── BBR core state ───────────────────────────────────────────────
    mtu: u64,
    max_bandwidth: BandwidthEstimation,
    acked_bytes: u64,
    mode: Mode,
    is_at_full_bandwidth: bool,
    pacing_gain: f64,
    cwnd_gain: f64,
    last_cycle_start: Option<Instant>,
    current_cycle_offset: u8,
    init_cwnd: u64,
    min_cwnd: u64,
    prev_in_flight: u64,
    exit_probe_rtt_at: Option<Instant>,
    probe_rtt_last_started_at: Option<Instant>,
    min_rtt: Duration,
    smoothed_rtt: Duration,
    exiting_quiescence: bool,
    pacing_rate: u64,
    max_acked_pkt: u64,
    max_sent_pkt: u64,
    cwnd: u64,
    current_round_trip_end: u64,
    round_count: u64,
    bw_at_last_round: u64,
    rounds_wo_bw_gain: u64,
    ack_aggregation: AckAggregationState,
    last_cwnd_reduction: Option<Instant>,
    rng: rand::rngs::StdRng,

    // ── Ack-rate tracking ────────────────────────────────────────────
    ack_rate_slots: [AckRateSlot; ACK_RATE_SLOTS],
    ack_rate: f64,
    base_time: Instant,
}

impl BbrMax {
    fn new(speed_limit: Arc<AtomicU64>, mtu: u16, now: Instant) -> Self {
        let mtu64 = mtu as u64;
        let min_cwnd = 4 * mtu64;
        Self {
            speed_limit,
            mtu: mtu64,
            max_bandwidth: BandwidthEstimation::default(),
            acked_bytes: 0,
            mode: Mode::Startup,
            is_at_full_bandwidth: false,
            pacing_gain: HIGH_GAIN,
            cwnd_gain: HIGH_CWND_GAIN,
            last_cycle_start: None,
            current_cycle_offset: 0,
            init_cwnd: INITIAL_WINDOW,
            min_cwnd,
            prev_in_flight: 0,
            exit_probe_rtt_at: None,
            probe_rtt_last_started_at: None,
            min_rtt: Duration::default(),
            smoothed_rtt: Duration::default(),
            exiting_quiescence: false,
            pacing_rate: 0,
            max_acked_pkt: 0,
            max_sent_pkt: 0,
            cwnd: INITIAL_WINDOW,
            current_round_trip_end: 0,
            round_count: 0,
            bw_at_last_round: 0,
            rounds_wo_bw_gain: 0,
            ack_aggregation: AckAggregationState::default(),
            last_cwnd_reduction: None,
            rng: rand::rngs::StdRng::from_os_rng(),
            ack_rate_slots: Default::default(),
            ack_rate: 1.0,
            base_time: now,
        }
    }

    // ── Threshold helper ─────────────────────────────────────────────

    fn is_below_threshold(&self) -> bool {
        self.max_bandwidth.get_estimate() < AGGRESSIVE_THRESHOLD
    }

    // ── BBR state machine ────────────────────────────────────────────

    fn enter_startup(&mut self) {
        self.mode = Mode::Startup;
        self.pacing_gain = HIGH_GAIN;
        self.cwnd_gain = HIGH_CWND_GAIN;
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = PROBE_BW_CWND_GAIN;
        self.last_cycle_start = Some(now);
        let mut idx = self
            .rng
            .random_range(0..PACING_GAIN_CYCLE.len() as u8 - 1);
        if idx >= 1 {
            idx += 1;
        }
        self.current_cycle_offset = idx;
        self.pacing_gain = PACING_GAIN_CYCLE[idx as usize];
    }

    fn update_gain_cycle(&mut self, now: Instant, in_flight: u64) {
        let mut advance = self
            .last_cycle_start
            .map(|t| now.duration_since(t) > self.min_rtt)
            .unwrap_or(false);

        if self.pacing_gain > 1.0
            && self.prev_in_flight < self.get_target_cwnd(self.pacing_gain)
        {
            advance = false;
        }

        if self.pacing_gain < 1.0 && in_flight <= self.get_target_cwnd(1.0) {
            advance = true;
        }

        if advance {
            self.current_cycle_offset =
                (self.current_cycle_offset + 1) % PACING_GAIN_CYCLE.len() as u8;
            self.last_cycle_start = Some(now);
            if DRAIN_TO_TARGET
                && self.pacing_gain < 1.0
                && (PACING_GAIN_CYCLE[self.current_cycle_offset as usize] - 1.0).abs()
                    < f64::EPSILON
                && in_flight > self.get_target_cwnd(1.0)
            {
                return;
            }
            self.pacing_gain = PACING_GAIN_CYCLE[self.current_cycle_offset as usize];
        }
    }

    fn maybe_exit_startup_or_drain(&mut self, now: Instant, in_flight: u64) {
        if self.mode == Mode::Startup && self.is_at_full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = DRAIN_GAIN;
            self.cwnd_gain = HIGH_CWND_GAIN;
        }
        if self.mode == Mode::Drain && in_flight <= self.get_target_cwnd(1.0) {
            self.enter_probe_bw(now);
        }
    }

    fn is_min_rtt_expired(&self, now: Instant, app_limited: bool) -> bool {
        !app_limited
            && self
                .probe_rtt_last_started_at
                .map(|last| now.saturating_duration_since(last) > Duration::from_secs(10))
                .unwrap_or(true)
    }

    /// Skipped entirely when below aggressive threshold.
    fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: Instant,
        is_round_start: bool,
        in_flight: u64,
        app_limited: bool,
    ) {
        if self.is_below_threshold() {
            return;
        }

        let min_rtt_expired = self.is_min_rtt_expired(now, app_limited);
        if min_rtt_expired && !self.exiting_quiescence && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            self.exit_probe_rtt_at = None;
            self.probe_rtt_last_started_at = Some(now);
        }

        if self.mode == Mode::ProbeRtt {
            match self.exit_probe_rtt_at {
                None => {
                    if in_flight < self.get_probe_rtt_cwnd() + self.mtu {
                        self.exit_probe_rtt_at = Some(now + Duration::from_millis(200));
                    }
                }
                Some(exit_time) if is_round_start && now >= exit_time => {
                    if !self.is_at_full_bandwidth {
                        self.enter_startup();
                    } else {
                        self.enter_probe_bw(now);
                    }
                }
                Some(_) => {}
            }
        }

        self.exiting_quiescence = false;
    }

    /// Skipped entirely when below aggressive threshold — never declares
    /// `is_at_full_bandwidth` so the controller stays in Startup.
    fn check_if_full_bw_reached(&mut self, app_limited: bool) {
        if self.is_below_threshold() {
            return;
        }

        if app_limited {
            return;
        }
        let bw = self.max_bandwidth.get_estimate();
        let target = (self.bw_at_last_round as f64 * STARTUP_GROWTH_TARGET) as u64;
        if bw >= target {
            self.bw_at_last_round = bw;
            self.rounds_wo_bw_gain = 0;
            self.ack_aggregation.max_ack_height.reset();
            return;
        }
        self.rounds_wo_bw_gain += 1;
        if self.rounds_wo_bw_gain >= ROUNDS_WITHOUT_GROWTH_BEFORE_EXIT {
            self.is_at_full_bandwidth = true;
        }
    }

    fn get_target_cwnd(&self, gain: f64) -> u64 {
        let bw = self.max_bandwidth.get_estimate();
        let bdp = self.min_rtt.as_micros() as u64 * bw;
        let cwnd = (gain * bdp as f64 / 1_000_000.0) as u64;
        if cwnd == 0 {
            return self.init_cwnd;
        }
        cwnd.max(self.min_cwnd)
    }

    fn get_probe_rtt_cwnd(&self) -> u64 {
        if PROBE_RTT_BASED_ON_BDP {
            return self.get_target_cwnd(0.75);
        }
        self.min_cwnd
    }

    fn calculate_pacing_rate(&mut self) {
        let bw = self.max_bandwidth.get_estimate();
        if bw == 0 {
            return;
        }
        let target_rate = (bw as f64 * self.pacing_gain) as u64;
        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }
        if self.pacing_rate == 0 && self.min_rtt.as_nanos() != 0 {
            self.pacing_rate =
                BandwidthEstimation::bw_from_delta(self.init_cwnd, self.min_rtt).unwrap_or(0);
            return;
        }
        if self.pacing_rate < target_rate {
            self.pacing_rate = target_rate;
        }
    }

    fn calculate_cwnd(&mut self, bytes_acked: u64, excess_acked: u64) {
        if self.mode == Mode::ProbeRtt {
            return;
        }
        let mut target_window = self.get_target_cwnd(self.cwnd_gain);
        if self.is_at_full_bandwidth {
            target_window += self.ack_aggregation.max_ack_height.get();
        } else {
            target_window += excess_acked;
        }
        if self.is_at_full_bandwidth {
            self.cwnd = target_window.min(self.cwnd + bytes_acked);
        } else if self.cwnd < target_window || self.acked_bytes < self.init_cwnd {
            self.cwnd += bytes_acked;
        }
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    // ── Ack-rate helpers ───────────────────────────────────────────────

    fn current_secs(&self, now: Instant) -> i64 {
        now.checked_duration_since(self.base_time)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn ack_rate_slot_mut(&mut self, secs: i64) -> &mut AckRateSlot {
        let idx = (secs as usize) % ACK_RATE_SLOTS;
        let slot = &mut self.ack_rate_slots[idx];
        if slot.timestamp_secs != secs {
            slot.timestamp_secs = secs;
            slot.ack_bytes = 0;
            slot.loss_bytes = 0;
        }
        slot
    }

    fn update_ack_rate(&mut self, current_secs: i64) {
        let min_ts = current_secs - ACK_RATE_SLOTS as i64;
        let (w_ack, w_total) = self
            .ack_rate_slots
            .iter()
            .filter(|s| s.timestamp_secs >= min_ts && (s.ack_bytes + s.loss_bytes) > 0)
            .fold((0.0f64, 0.0f64), |(wa, wt), s| {
                let age = (current_secs - s.timestamp_secs) as f64;
                let w = ACK_RATE_DECAY.powf(age);
                (
                    wa + s.ack_bytes as f64 * w,
                    wt + (s.ack_bytes + s.loss_bytes) as f64 * w,
                )
            });
        if w_total < ACK_RATE_MIN_SAMPLE {
            self.ack_rate = 1.0;
            return;
        }
        self.ack_rate = (w_ack / w_total).clamp(0.0, 1.0);
    }

    fn is_connection_critical(&self) -> bool {
        self.ack_rate < CRITICAL_ACK_RATE
    }

    // ── Ceiling helpers ──────────────────────────────────────────────

    fn rate_to_cwnd(&self, rate: u64) -> u64 {
        let rtt = self.min_rtt.as_secs_f64();
        if rtt == 0.0 {
            return self.init_cwnd;
        }
        ((rate as f64) * rtt * 2.0).max(self.min_cwnd as f64) as u64
    }

    /// FLOOR_RATE scaled by delivery success (ack_rate):
    ///   ack_rate >= 30%  → full floor
    ///   5% .. 30%        → linear ramp
    ///   < 5%             → 0 (only min_cwnd survives)
    fn effective_floor_rate(&self) -> u64 {
        let ceiling = self.speed_limit.load(Ordering::Relaxed);
        let base_floor = if ceiling > 0 { FLOOR_RATE.min(ceiling) } else { FLOOR_RATE };

        if self.ack_rate >= HEALTHY_ACK_RATE {
            base_floor
        } else if self.ack_rate <= CRITICAL_ACK_RATE {
            0
        } else {
            let t = (self.ack_rate - CRITICAL_ACK_RATE) / (HEALTHY_ACK_RATE - CRITICAL_ACK_RATE);
            (base_floor as f64 * t) as u64
        }
    }

    fn effective_pacing_rate(&self) -> u64 {
        let rate = self.pacing_rate.max(self.effective_floor_rate());
        let ceiling = self.speed_limit.load(Ordering::Relaxed);
        if ceiling > 0 { rate.min(ceiling) } else { rate }
    }
}

// ── Controller trait ─────────────────────────────────────────────────────────

impl Controller for BbrMax {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.max_sent_pkt = last_packet_number;
        self.max_bandwidth.on_sent(now, bytes);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.max_bandwidth
            .on_ack(now, sent, bytes, self.round_count, app_limited);
        self.acked_bytes += bytes;
        self.smoothed_rtt = rtt.get();
        if self.is_min_rtt_expired(now, app_limited) || self.min_rtt > rtt.min() {
            self.min_rtt = rtt.min();
        }
        let secs = self.current_secs(now);
        self.ack_rate_slot_mut(secs).ack_bytes += bytes;
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        let bytes_acked = self.max_bandwidth.bytes_acked_this_window();
        let excess_acked = self.ack_aggregation.update_ack_aggregation_bytes(
            bytes_acked,
            now,
            self.round_count,
            self.max_bandwidth.get_estimate(),
        );
        self.max_bandwidth.end_acks(self.round_count, app_limited);
        if let Some(pkt) = largest_packet_num_acked {
            self.max_acked_pkt = pkt;
        }

        let mut is_round_start = false;
        if bytes_acked > 0 {
            is_round_start = self.max_acked_pkt > self.current_round_trip_end;
            if is_round_start {
                self.current_round_trip_end = self.max_sent_pkt;
                self.round_count += 1;
            }
        }

        // Re-enter aggressive Startup when bandwidth drops below threshold
        if self.is_at_full_bandwidth && self.is_below_threshold() {
            self.is_at_full_bandwidth = false;
            self.rounds_wo_bw_gain = 0;
            self.bw_at_last_round = 0;
            self.enter_startup();
        }

        if self.mode == Mode::ProbeBw {
            self.update_gain_cycle(now, in_flight);
        }

        if is_round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bw_reached(app_limited);
        }

        self.maybe_exit_startup_or_drain(now, in_flight);
        self.maybe_enter_or_exit_probe_rtt(now, is_round_start, in_flight, app_limited);

        self.calculate_pacing_rate();
        self.calculate_cwnd(bytes_acked, excess_acked);

        let secs = self.current_secs(now);
        self.update_ack_rate(secs);

        self.prev_in_flight = in_flight;
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        is_persistent_congestion: bool,
        _is_ecn: bool,
        lost_bytes: u64,
    ) {
        let secs = self.current_secs(now);
        self.ack_rate_slot_mut(secs).loss_bytes += lost_bytes;
        self.update_ack_rate(secs);

        // Below threshold: ignore loss to keep aggressive probing —
        // UNLESS ack_rate is critical, meaning almost nothing gets through.
        if self.is_below_threshold() && !self.is_connection_critical() {
            return;
        }
        // Above threshold / critical: soft loss response
        if self.mode == Mode::Startup && !self.is_connection_critical() {
            return;
        }
        if !is_persistent_congestion {
            if let Some(last) = self.last_cwnd_reduction {
                if now.saturating_duration_since(last) < self.min_rtt {
                    return;
                }
            }
        }
        self.last_cwnd_reduction = Some(now);
        let factor = if is_persistent_congestion { 0.5 } else { 0.85 };
        let floor_cwnd = self.rate_to_cwnd(self.effective_floor_rate());
        self.cwnd = ((self.cwnd as f64 * factor) as u64).max(floor_cwnd).max(self.min_cwnd);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu as u64;
        self.min_cwnd = 4 * self.mtu;
        self.init_cwnd = INITIAL_WINDOW.max(self.min_cwnd);
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    fn window(&self) -> u64 {
        let w = if self.mode == Mode::ProbeRtt {
            self.get_probe_rtt_cwnd()
        } else {
            self.cwnd
        };
        let floor_cwnd = self.rate_to_cwnd(self.effective_floor_rate());
        let result = w.max(floor_cwnd);
        let ceiling = self.speed_limit.load(Ordering::Relaxed);
        if ceiling > 0 { result.min(self.rate_to_cwnd(ceiling)) } else { result }
    }

    fn pacing_window(&self) -> u64 {
        let rate = self.effective_pacing_rate();
        let rtt = self.smoothed_rtt.as_secs_f64();
        if rtt == 0.0 {
            return self.init_cwnd;
        }
        ((rate as f64) * rtt * 0.8).max(self.min_cwnd as f64) as u64
    }

    fn metrics(&self) -> ControllerMetrics {
        let mode_str = match self.mode {
            Mode::Startup => "Startup",
            Mode::Drain => "Drain",
            Mode::ProbeBw => "ProbeBw",
            Mode::ProbeRtt => "ProbeRtt",
        };
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: Some(self.effective_pacing_rate() * 8),
            mode: Some(mode_str),
            bandwidth_estimate: Some(self.max_bandwidth.get_estimate()),
            pacing_gain: Some(self.pacing_gain),
            is_at_full_bandwidth: Some(self.is_at_full_bandwidth),
            round_count: Some(self.round_count),
            ack_rate: Some(self.ack_rate),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

// ── Config ───────────────────────────────────────────────────────────────────

/// Configuration for [`BbrMax`].
///
/// `speed_limit` (bytes/s): `> 0` acts as a speed ceiling (e.g. free-tier
/// cap), `== 0` means no ceiling.  The value can be changed at runtime via
/// the shared `AtomicU64`.
#[derive(Debug, Clone)]
pub struct BbrMaxConfig {
    speed_limit: Arc<AtomicU64>,
}

impl BbrMaxConfig {
    /// Create a config with the given speed ceiling.  `speed_limit` in
    /// bytes/s: `> 0` = ceiling, `== 0` = no ceiling.
    pub fn new(speed_limit: Arc<AtomicU64>) -> Self {
        Self { speed_limit }
    }
}

impl ControllerFactory for BbrMaxConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BbrMax::new(self.speed_limit.clone(), current_mtu, now))
    }
}
