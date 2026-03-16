//! BBR congestion controller with floor rate and soft loss response.
//!
//! Based on standard BBR's bandwidth probing (Startup, Drain, ProbeBw,
//! ProbeRtt) and delivery-rate estimation, with two key differences:
//!
//! - **Soft Recovery**: loss gently reduces cwnd (`×0.85`) instead of
//!   TCP-style halving.  Startup ignores loss entirely so bandwidth
//!   exploration isn't cut short on lossy links.
//! - **Floor rate** (100 Mbps) guarantees a minimum sending rate.
//!   Optional **ceiling** via `AtomicU64`: `> 0` enforces an upper bound
//!   (e.g. free-tier speed limit), `== 0` means no ceiling.
//!
//! ## Pacer integration
//!
//! Quinn's pacer sends at `1.25 × pacing_window / RTT`.
//! We set `pacing_window = rate × RTT × 0.8`, so the actual
//! pacing rate ≈ `rate`.  `window()` provides cwnd headroom
//! derived from `max(bbr_cwnd, floor_cwnd)`.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rand::{Rng, SeedableRng};

use super::bbr::bw_estimation::BandwidthEstimation;
use super::bbr::min_max::MinMax;
use super::{BASE_DATAGRAM_SIZE, Controller, ControllerFactory, ControllerMetrics};
use crate::connection::RttEstimator;
use crate::{Duration, Instant};

// ── Rate bounds ──────────────────────────────────────────────────────────────

/// Minimum sending rate: 100 Mbps = 12.5 MB/s.
const FLOOR_RATE: u64 = 12_500_000;

// ── BBR constants ────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

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

/// BBR congestion controller with rate floor and soft loss response.
///
/// See module-level docs for design rationale.
#[derive(Debug, Clone)]
pub struct BrutalBbr {
    speed_limit: Arc<AtomicU64>,
    probe_enabled: bool,

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
    rng: rand::rngs::StdRng,
}

impl BrutalBbr {
    fn new(speed_limit: Arc<AtomicU64>, mtu: u16, _now: Instant, probe: bool) -> Self {
        let mtu64 = mtu as u64;
        let min_cwnd = 4 * mtu64;
        Self {
            speed_limit,
            probe_enabled: probe,
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
            rng: rand::rngs::StdRng::from_os_rng(),
        }
    }

    // ── BBR state machine ────────────────────────────────────────────────

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

    fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: Instant,
        is_round_start: bool,
        in_flight: u64,
        app_limited: bool,
    ) {
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

    fn check_if_full_bw_reached(&mut self, app_limited: bool) {
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
        } else if (self.cwnd_gain < target_window as f64) || (self.acked_bytes < self.init_cwnd) {
            self.cwnd += bytes_acked;
        }
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    // ── Rate bounds ──────────────────────────────────────────────────────

    fn clamped_rate(&self) -> u64 {
        if !self.probe_enabled {
            return self.speed_limit.load(Ordering::Relaxed);
        }
        let rate = self.pacing_rate.max(FLOOR_RATE);
        let ceiling = self.speed_limit.load(Ordering::Relaxed);
        if ceiling > 0 { rate.min(ceiling) } else { rate }
    }

    fn rate_to_cwnd(&self, rate: u64) -> u64 {
        let rtt = self.min_rtt.as_secs_f64();
        if rtt == 0.0 {
            return self.init_cwnd;
        }
        ((rate as f64) * rtt * 2.0).max(self.min_cwnd as f64) as u64
    }

    fn bbr_window(&self) -> u64 {
        if self.mode == Mode::ProbeRtt {
            return self.get_probe_rtt_cwnd();
        }
        self.cwnd
    }
}

impl Controller for BrutalBbr {
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

        self.prev_in_flight = in_flight;
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        is_persistent_congestion: bool,
        _is_ecn: bool,
        _lost_bytes: u64,
    ) {
        if self.mode == Mode::Startup {
            return;
        }
        let factor = if is_persistent_congestion { 0.5 } else { 0.85 };
        let floor_cwnd = self.rate_to_cwnd(FLOOR_RATE);
        self.cwnd = ((self.cwnd as f64 * factor) as u64).max(floor_cwnd);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu as u64;
        self.min_cwnd = 4 * self.mtu;
        self.init_cwnd = INITIAL_WINDOW.max(self.min_cwnd);
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    fn window(&self) -> u64 {
        if !self.probe_enabled {
            return self.rate_to_cwnd(self.speed_limit.load(Ordering::Relaxed));
        }
        let bbr_win = self.bbr_window();
        let floor_cwnd = self.rate_to_cwnd(FLOOR_RATE);
        let result = bbr_win.max(floor_cwnd);
        let ceiling = self.speed_limit.load(Ordering::Relaxed);
        if ceiling > 0 { result.min(self.rate_to_cwnd(ceiling)) } else { result }
    }

    fn pacing_window(&self) -> u64 {
        let rate = self.clamped_rate();
        let rtt = self.smoothed_rtt.as_secs_f64();
        if rtt == 0.0 {
            return self.init_cwnd;
        }
        ((rate as f64) * rtt * 0.8).max(self.min_cwnd as f64) as u64
    }

    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: Some(self.clamped_rate() * 8),
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

/// Configuration for [`BrutalBbr`].
///
/// `target_rate` (bytes/s): in no-probe (client) mode it is the fixed sending
/// rate.  In probe (server) mode: `> 0` acts as a speed-limit ceiling
/// (e.g. free-tier cap), `== 0` means BBR roams free with only the 100 Mbps
/// floor.  The value can be changed at runtime via `AtomicU64`.
#[derive(Debug, Clone)]
pub struct BrutalBbrConfig {
    target_rate: Arc<AtomicU64>,
    probe: bool,
}

impl BrutalBbrConfig {
    /// Create a probe-mode (server) config.  `target_rate` in bytes/s:
    /// `> 0` = ceiling, `== 0` = no ceiling.
    pub fn new(target_rate: Arc<AtomicU64>) -> Self {
        Self {
            target_rate,
            probe: true,
        }
    }

    /// Create a no-probe (client) config that sends at a fixed `target_rate`.
    pub fn new_no_probe(target_rate: Arc<AtomicU64>) -> Self {
        Self {
            target_rate,
            probe: false,
        }
    }
}

impl ControllerFactory for BrutalBbrConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalBbr::new(
            self.target_rate.clone(),
            current_mtu,
            now,
            self.probe,
        ))
    }
}
