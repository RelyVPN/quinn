use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{Controller, ControllerFactory, ControllerMetrics};
use crate::Instant;
use crate::connection::RttEstimator;

const INITIAL_WINDOW: u64 = 10 * 1200;

/// Brutal congestion controller — sends at a fixed target rate regardless of packet loss.
///
/// `cwnd = target_rate * rtt`, never shrinks below `MIN_WINDOW`.
/// Inspired by the Hysteria project's Brutal sender.
#[derive(Debug)]
pub struct Brutal {
    target_rate_bps: Arc<AtomicU64>,
    rtt: Option<std::time::Duration>,
    mtu: u64,
}

impl Brutal {
    fn new(target_rate_bps: Arc<AtomicU64>, mtu: u16) -> Self {
        Self {
            target_rate_bps,
            rtt: None,
            mtu: mtu as u64,
        }
    }

    fn min_window(&self) -> u64 {
        2 * self.mtu
    }

    fn calc_window(&self) -> u64 {
        let rate = self.target_rate_bps.load(Ordering::Relaxed);
        if rate == 0 {
            return INITIAL_WINDOW;
        }
        match self.rtt {
            Some(rtt) if !rtt.is_zero() => {
                let rtt_secs_f64 = rtt.as_secs_f64();
                let cwnd = (rate as f64 * rtt_secs_f64) as u64;
                cwnd.max(self.min_window())
            }
            _ => INITIAL_WINDOW,
        }
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.rtt = Some(rtt.get());
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _is_ecn: bool,
        _lost_bytes: u64,
    ) {
        // Brutal intentionally ignores congestion signals.
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu as u64;
    }

    fn window(&self) -> u64 {
        self.calc_window()
    }

    fn metrics(&self) -> ControllerMetrics {
        let rate = self.target_rate_bps.load(Ordering::Relaxed);
        ControllerMetrics {
            congestion_window: self.calc_window(),
            ssthresh: None,
            pacing_rate: Some(rate * 8),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Brutal {
            target_rate_bps: self.target_rate_bps.clone(),
            rtt: self.rtt,
            mtu: self.mtu,
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
/// The `target_rate_bps` is a shared atomic so the rate can be adjusted
/// dynamically (e.g. when entering slow-mode) without reconnecting.
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    target_rate_bps: Arc<AtomicU64>,
}

impl BrutalConfig {
    /// Create a new `BrutalConfig` with the given shared target rate (bytes/sec).
    pub fn new(target_rate_bps: Arc<AtomicU64>) -> Self {
        Self { target_rate_bps }
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self.target_rate_bps.clone(), current_mtu))
    }
}
