//! Deterministic semantic liveness guards.
//!
//! A running process is not evidence that its transport or durable pipeline is
//! making progress.  These guards deliberately accept a caller-supplied
//! monotonic time so timeout behavior can be tested without sleeping.

use crate::Result;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProgressState {
    value: u64,
    last_advance_ns: u64,
}

#[derive(Clone, Debug)]
pub struct ProgressWatchdog {
    deadline_ns: u64,
    streams: BTreeMap<String, ProgressState>,
}

impl ProgressWatchdog {
    pub fn new(deadline_ns: u64) -> Result<Self> {
        if deadline_ns == 0 {
            return Err("progress watchdog deadline must be positive".to_owned());
        }
        Ok(Self {
            deadline_ns,
            streams: BTreeMap::new(),
        })
    }

    pub fn observe(&mut self, name: &str, value: u64, now_ns: u64) -> Result<()> {
        if name.trim().is_empty() {
            return Err("progress watchdog stream name must not be empty".to_owned());
        }
        let Some(previous) = self.streams.get_mut(name) else {
            self.streams.insert(
                name.to_owned(),
                ProgressState {
                    value,
                    last_advance_ns: now_ns,
                },
            );
            return Ok(());
        };
        if value < previous.value {
            return Err(format!(
                "progress regressed for {name}: {} -> {value}",
                previous.value
            ));
        }
        if now_ns < previous.last_advance_ns {
            return Err(format!("monotonic watchdog time regressed for {name}"));
        }
        if value > previous.value {
            previous.value = value;
            previous.last_advance_ns = now_ns;
            return Ok(());
        }
        Self::check_one(self.deadline_ns, name, previous, now_ns)
    }

    pub fn check(&self, now_ns: u64) -> Result<()> {
        for (name, state) in &self.streams {
            Self::check_one(self.deadline_ns, name, state, now_ns)?;
        }
        Ok(())
    }

    fn check_one(deadline_ns: u64, name: &str, state: &ProgressState, now_ns: u64) -> Result<()> {
        let age = now_ns
            .checked_sub(state.last_advance_ns)
            .ok_or_else(|| format!("monotonic watchdog time regressed for {name}"))?;
        if age >= deadline_ns {
            return Err(format!(
                "progress stalled for {name}: value={} age_ns={age} deadline_ns={}",
                state.value, deadline_ns
            ));
        }
        Ok(())
    }
}
