use crate::{ConnectionQuality, EndpointAddress};
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SecurityLevel {
    Plaintext,
    Authenticated,
    AuthenticatedEncrypted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    Local,
    Quic,
    Tcp,
    Custom(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportCandidate {
    pub kind: TransportKind,
    pub endpoint: EndpointAddress,
    /// Lower values are attempted first.
    pub priority: u16,
    pub security: SecurityLevel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptFailure {
    Unreachable,
    TimedOut,
    AuthenticationFailed,
    Incompatible,
    ResourceExhausted,
    Cancelled,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportAttempt {
    pub candidate: TransportCandidate,
    pub failure: AttemptFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallbackPolicy {
    pub minimum_security: SecurityLevel,
    /// When false, a failed authenticated/encrypted candidate prevents any
    /// lower-security candidate even if it still meets `minimum_security`.
    pub allow_security_downgrade: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectionError {
    NoCandidates,
    SecurityDowngrade {
        attempted: SecurityLevel,
        candidate: SecurityLevel,
    },
    Exhausted(Vec<TransportAttempt>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportSelection {
    pub selected: TransportCandidate,
    pub quality: ConnectionQuality,
    pub failures: Vec<TransportAttempt>,
}

#[derive(Debug)]
pub struct FallbackPlan {
    policy: FallbackPolicy,
    pending: VecDeque<TransportCandidate>,
    failures: Vec<TransportAttempt>,
    strongest_attempted: Option<SecurityLevel>,
}

impl FallbackPlan {
    pub fn new(
        mut candidates: Vec<TransportCandidate>,
        policy: FallbackPolicy,
    ) -> Result<Self, SelectionError> {
        candidates.retain(|candidate| candidate.security >= policy.minimum_security);
        candidates.sort_by_key(|candidate| candidate.priority);
        if candidates.is_empty() {
            return Err(SelectionError::NoCandidates);
        }
        Ok(Self {
            policy,
            pending: candidates.into(),
            failures: Vec::new(),
            strongest_attempted: None,
        })
    }

    pub fn next_candidate(&mut self) -> Result<Option<TransportCandidate>, SelectionError> {
        let Some(candidate) = self.pending.pop_front() else {
            return Ok(None);
        };
        if let Some(strongest) = self.strongest_attempted {
            if candidate.security < strongest && !self.policy.allow_security_downgrade {
                return Err(SelectionError::SecurityDowngrade {
                    attempted: strongest,
                    candidate: candidate.security,
                });
            }
        }
        self.strongest_attempted = Some(
            self.strongest_attempted
                .map_or(candidate.security, |current| {
                    current.max(candidate.security)
                }),
        );
        Ok(Some(candidate))
    }

    pub fn record_failure(&mut self, candidate: TransportCandidate, failure: AttemptFailure) {
        self.failures.push(TransportAttempt { candidate, failure });
    }

    pub fn select(
        self,
        selected: TransportCandidate,
        quality: ConnectionQuality,
    ) -> TransportSelection {
        TransportSelection {
            selected,
            quality,
            failures: self.failures,
        }
    }

    pub fn exhausted(self) -> SelectionError {
        SelectionError::Exhausted(self.failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(
        kind: TransportKind,
        priority: u16,
        security: SecurityLevel,
    ) -> TransportCandidate {
        TransportCandidate {
            kind,
            endpoint: EndpointAddress {
                scheme: "test".to_owned(),
                address: format!("{priority}"),
            },
            priority,
            security,
        }
    }

    #[test]
    fn priority_is_explicit_and_failures_are_retained() {
        let local = candidate(TransportKind::Local, 0, SecurityLevel::Authenticated);
        let quic = candidate(
            TransportKind::Quic,
            10,
            SecurityLevel::AuthenticatedEncrypted,
        );
        let mut plan = FallbackPlan::new(
            vec![quic.clone(), local.clone()],
            FallbackPolicy {
                minimum_security: SecurityLevel::Authenticated,
                allow_security_downgrade: true,
            },
        )
        .unwrap();
        assert_eq!(plan.next_candidate().unwrap(), Some(local.clone()));
        plan.record_failure(local, AttemptFailure::Unreachable);
        assert_eq!(plan.next_candidate().unwrap(), Some(quic.clone()));
        let report = plan.select(quic, ConnectionQuality::default());
        assert_eq!(report.failures.len(), 1);
    }

    #[test]
    fn encrypted_failure_cannot_silently_fall_back_to_plaintext() {
        let quic = candidate(
            TransportKind::Quic,
            0,
            SecurityLevel::AuthenticatedEncrypted,
        );
        let tcp = candidate(TransportKind::Tcp, 1, SecurityLevel::Plaintext);
        let mut plan = FallbackPlan::new(
            vec![quic.clone(), tcp],
            FallbackPolicy {
                minimum_security: SecurityLevel::Plaintext,
                allow_security_downgrade: false,
            },
        )
        .unwrap();
        assert_eq!(plan.next_candidate().unwrap(), Some(quic.clone()));
        plan.record_failure(quic, AttemptFailure::AuthenticationFailed);
        assert!(matches!(
            plan.next_candidate(),
            Err(SelectionError::SecurityDowngrade { .. })
        ));
    }
}
