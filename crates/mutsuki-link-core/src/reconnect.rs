use crate::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectFailure {
    TemporarilyUnreachable,
    NetworkChanged,
    SleepWake,
    TransportClosed,
    AuthenticationFailed,
    IdentityExpired,
    PairingRevoked,
    ProtocolIncompatible,
    ResourceExhausted,
    Cancelled,
}

impl ReconnectFailure {
    pub const fn is_permanent(self) -> bool {
        matches!(
            self,
            Self::AuthenticationFailed
                | Self::IdentityExpired
                | Self::PairingRevoked
                | Self::ProtocolIncompatible
                | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryLimit {
    pub max_attempts: u32,
    pub max_elapsed_ms: u64,
}

impl RetryLimit {
    pub const fn is_valid(self) -> bool {
        self.max_attempts > 0 && self.max_elapsed_ms > 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExponentialBackoff {
    pub initial_delay_ms: u64,
    pub maximum_delay_ms: u64,
    /// 1,000 means 1x, 2,000 means 2x.
    pub multiplier_per_thousand: u32,
    /// Symmetric delay variation in per-thousand, at most 1,000.
    pub jitter_per_thousand: u16,
    pub limit: RetryLimit,
}

impl ExponentialBackoff {
    pub const fn is_valid(self) -> bool {
        self.initial_delay_ms > 0
            && self.maximum_delay_ms >= self.initial_delay_ms
            && self.multiplier_per_thousand >= 1_000
            && self.jitter_per_thousand <= 1_000
            && self.limit.is_valid()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectPolicy {
    Disabled,
    Immediate(RetryLimit),
    ExponentialBackoff(ExponentialBackoff),
    ApplicationControlled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectStopReason {
    Disabled,
    PermanentFailure(ReconnectFailure),
    AttemptsExhausted,
    DeadlineExceeded,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectAction {
    AttemptAt { unix_ms: u64, attempt: u32 },
    AwaitApplication,
    Stop(ReconnectStopReason),
}

#[derive(Debug)]
pub struct ReconnectController {
    policy: ReconnectPolicy,
    started_unix_ms: Option<u64>,
    attempts: u32,
    cancellation: CancellationToken,
    paused: bool,
}

impl ReconnectController {
    pub fn new(
        policy: ReconnectPolicy,
        cancellation: CancellationToken,
    ) -> Result<Self, &'static str> {
        let valid = match policy {
            ReconnectPolicy::Disabled | ReconnectPolicy::ApplicationControlled => true,
            ReconnectPolicy::Immediate(limit) => limit.is_valid(),
            ReconnectPolicy::ExponentialBackoff(config) => config.is_valid(),
        };
        if !valid {
            return Err("reconnect policy limits must be positive and bounded");
        }
        Ok(Self {
            policy,
            started_unix_ms: None,
            attempts: 0,
            cancellation,
            paused: false,
        })
    }

    pub fn pause(&mut self) {
        self.paused = true;
    }

    pub fn resume(&mut self) {
        self.paused = false;
    }

    pub fn reset(&mut self) {
        self.started_unix_ms = None;
        self.attempts = 0;
    }

    /// `jitter_sample` is injected entropy in `0..=1_000`; core never owns an RNG.
    pub fn after_failure(
        &mut self,
        failure: ReconnectFailure,
        now_unix_ms: u64,
        jitter_sample: u16,
    ) -> ReconnectAction {
        if self.cancellation.is_cancelled() || failure == ReconnectFailure::Cancelled {
            return ReconnectAction::Stop(ReconnectStopReason::Cancelled);
        }
        if failure.is_permanent() {
            return ReconnectAction::Stop(ReconnectStopReason::PermanentFailure(failure));
        }
        if self.paused {
            return ReconnectAction::AwaitApplication;
        }
        let started = *self.started_unix_ms.get_or_insert(now_unix_ms);
        match self.policy {
            ReconnectPolicy::Disabled => ReconnectAction::Stop(ReconnectStopReason::Disabled),
            ReconnectPolicy::ApplicationControlled => ReconnectAction::AwaitApplication,
            ReconnectPolicy::Immediate(limit) => self.schedule(now_unix_ms, started, 0, limit),
            ReconnectPolicy::ExponentialBackoff(config) => {
                let base = exponential_delay(config, self.attempts);
                let delay =
                    jittered_delay(base, config.jitter_per_thousand, jitter_sample.min(1_000));
                self.schedule(now_unix_ms, started, delay, config.limit)
            }
        }
    }

    fn schedule(
        &mut self,
        now_unix_ms: u64,
        started_unix_ms: u64,
        delay_ms: u64,
        limit: RetryLimit,
    ) -> ReconnectAction {
        if self.attempts >= limit.max_attempts {
            return ReconnectAction::Stop(ReconnectStopReason::AttemptsExhausted);
        }
        let elapsed = now_unix_ms.saturating_sub(started_unix_ms);
        if elapsed >= limit.max_elapsed_ms
            || elapsed.saturating_add(delay_ms) > limit.max_elapsed_ms
        {
            return ReconnectAction::Stop(ReconnectStopReason::DeadlineExceeded);
        }
        self.attempts = self.attempts.saturating_add(1);
        ReconnectAction::AttemptAt {
            unix_ms: now_unix_ms.saturating_add(delay_ms),
            attempt: self.attempts,
        }
    }
}

fn exponential_delay(config: ExponentialBackoff, attempt: u32) -> u64 {
    let mut delay = config.initial_delay_ms;
    for _ in 0..attempt {
        delay = delay
            .saturating_mul(u64::from(config.multiplier_per_thousand))
            .saturating_div(1_000)
            .min(config.maximum_delay_ms);
    }
    delay
}

fn jittered_delay(base: u64, jitter: u16, sample: u16) -> u64 {
    if jitter == 0 {
        return base;
    }
    let span = base.saturating_mul(u64::from(jitter)).saturating_div(1_000);
    let offset = span
        .saturating_mul(u64::from(sample))
        .saturating_mul(2)
        .saturating_div(1_000);
    base.saturating_sub(span).saturating_add(offset)
}
