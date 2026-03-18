use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{Controller, ControllerFactory, ControllerMetrics};
use crate::Instant;
use crate::connection::RttEstimator;

const INITIAL_WINDOW: u64 = 64 * 1400;

/// 5-second sliding window for ackRate sampling (matches official Hysteria).
const PKT_INFO_SLOT_COUNT: usize = 5;
/// Require ~50 full-size packets worth of data before trusting the ackRate.
const MIN_SAMPLE_BYTES: u64 = 60_000;
/// Floor for ackRate compensation.  At 0.5 the sender pushes up to 2× target,
/// allowing full throughput delivery even at 50% packet loss.
const MIN_ACK_RATE: f64 = 0.5;

/// Per-second byte counters for ackRate estimation.
#[derive(Clone, Debug, Default)]
struct ByteInfoSlot {
    timestamp_secs: i64,
    ack_bytes: u64,
    loss_bytes: u64,
}

/// Brutal congestion controller with ackRate-based loss compensation.
///
/// Behavioral equivalent of the official Hysteria Brutal sender.
///
/// Official Hysteria has a dedicated pacer at `bps / ackRate` with a generous
/// cwnd of `bps * rtt * 2 / ackRate` that never actually limits throughput.
///
/// Quinn's pacer refills tokens at `1.25 * pacing_window / rtt` and separately
/// caps in-flight at `window`.  We exploit the `pacing_window()` / `window()`
/// split to reproduce the official architecture:
///
///   `window()` = `bps * rtt * 2 / ackRate`  (generous cwnd, never the bottleneck)
///   `pacing_window()` = `bps * rtt * 0.84 / ackRate`
///       → pacer rate = `1.25 * 0.84 * bps / ackRate` = `1.05 × bps / ackRate`
///
/// The 5% overshoot compensates for QUIC per-packet overhead (~44 bytes of
/// header + AEAD tag per ~1400-byte packet ≈ 3.1%), ensuring the *payload*
/// throughput reaches the target rate.
///
/// `target_rate` is in **bytes per second**.
#[derive(Debug)]
pub struct Brutal {
    target_rate: Arc<AtomicU64>,
    rtt: Option<std::time::Duration>,
    mtu: u64,
    slots: [ByteInfoSlot; PKT_INFO_SLOT_COUNT],
    ack_rate: f64,
    base_time: Instant,
}

impl Brutal {
    fn new(target_rate: Arc<AtomicU64>, mtu: u16, now: Instant) -> Self {
        Self {
            target_rate,
            rtt: None,
            mtu: mtu as u64,
            slots: Default::default(),
            ack_rate: 1.0,
            base_time: now,
        }
    }

    fn min_window(&self) -> u64 {
        2 * self.mtu
    }

    fn current_secs(&self, now: Instant) -> i64 {
        now.checked_duration_since(self.base_time)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn slot_mut(&mut self, secs: i64) -> &mut ByteInfoSlot {
        let idx = (secs as usize) % PKT_INFO_SLOT_COUNT;
        let slot = &mut self.slots[idx];
        if slot.timestamp_secs != secs {
            slot.timestamp_secs = secs;
            slot.ack_bytes = 0;
            slot.loss_bytes = 0;
        }
        slot
    }

    fn update_ack_rate(&mut self, current_secs: i64) {
        const DECAY: f64 = 0.5; // half-life: 1 second

        let min_ts = current_secs - PKT_INFO_SLOT_COUNT as i64;
        let (w_ack, w_total) = self
            .slots
            .iter()
            .filter(|s| s.timestamp_secs >= min_ts && (s.ack_bytes + s.loss_bytes) > 0)
            .fold((0.0f64, 0.0f64), |(wa, wt), s| {
                let age = (current_secs - s.timestamp_secs) as f64;
                let w = DECAY.powf(age);
                (
                    wa + s.ack_bytes as f64 * w,
                    wt + (s.ack_bytes + s.loss_bytes) as f64 * w,
                )
            });
        if w_total < MIN_SAMPLE_BYTES as f64 * 0.25 {
            self.ack_rate = 1.0;
            return;
        }
        let rate = w_ack / w_total;
        self.ack_rate = rate.max(MIN_ACK_RATE);
    }

    fn bdp_over_ack_rate(&self) -> Option<f64> {
        let rate = self.target_rate.load(Ordering::Relaxed);
        if rate == 0 {
            return None;
        }
        match self.rtt {
            Some(rtt) if !rtt.is_zero() => {
                Some(rate as f64 * rtt.as_secs_f64() / self.ack_rate)
            }
            _ => None,
        }
    }

    /// cwnd = 2 × BDP / ackRate  (matches official `congestionWindowMultiplier`)
    fn calc_window(&self) -> u64 {
        match self.bdp_over_ack_rate() {
            Some(bdp) => ((bdp * 2.0) as u64).max(self.min_window()),
            None => INITIAL_WINDOW,
        }
    }

    /// pacing_window = 0.84 × BDP / ackRate  →  pacer rate = 1.25 × 0.84 = 1.05 × bps / ackRate
    fn calc_pacing_window(&self) -> u64 {
        match self.bdp_over_ack_rate() {
            Some(bdp) => ((bdp * 0.84) as u64).max(self.min_window()),
            None => INITIAL_WINDOW,
        }
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.rtt = Some(rtt.get());
        let secs = self.current_secs(now);
        self.slot_mut(secs).ack_bytes += bytes;
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        let secs = self.current_secs(now);
        self.update_ack_rate(secs);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _is_ecn: bool,
        lost_bytes: u64,
    ) {
        let secs = self.current_secs(now);
        self.slot_mut(secs).loss_bytes += lost_bytes;
        self.update_ack_rate(secs);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu as u64;
    }

    fn window(&self) -> u64 {
        self.calc_window()
    }

    fn pacing_window(&self) -> u64 {
        self.calc_pacing_window()
    }

    fn metrics(&self) -> ControllerMetrics {
        let rate = self.target_rate.load(Ordering::Relaxed);
        ControllerMetrics {
            congestion_window: self.calc_window(),
            ssthresh: None,
            pacing_rate: Some((rate as f64 / self.ack_rate * 8.0) as u64),
            ..Default::default()
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Brutal {
            target_rate: self.target_rate.clone(),
            rtt: self.rtt,
            mtu: self.mtu,
            slots: self.slots.clone(),
            ack_rate: self.ack_rate,
            base_time: self.base_time,
        })
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the [`Brutal`] congestion controller.
///
/// The `target_rate` (bytes/sec) is a shared atomic so the rate can be adjusted
/// dynamically (e.g. when entering slow-mode) without reconnecting.
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    target_rate: Arc<AtomicU64>,
}

impl BrutalConfig {
    /// Create a new `BrutalConfig` with the given shared target rate (bytes/sec).
    pub fn new(target_rate: Arc<AtomicU64>) -> Self {
        Self { target_rate }
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self.target_rate.clone(), current_mtu, now))
    }
}
