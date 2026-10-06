// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! The core's `ReadSelfNodeLease` effect carries the prior authority's expiry
//! so the shell can bound a renewal readback, and every readback result leaves
//! the core either scheduling a retry or fencing.

use celld_logic::{
    on_event, CasGuard, Config, Effect, Event, Failure, HaltReason, LeaseCasOutcome,
    NodeLeaseRecord, NodeLeaseSpec, OpId, OwnershipOnEvict, State, Timer,
};

const TTL_MS: u64 = 10_000;
const START_MS: u64 = 1_000_000;

fn config() -> Config {
    Config {
        max_resident: 8,
        max_activations: 8,
        max_evictions: 4,
        max_releases: 4,
        max_outbound_websockets: 8,
        ownership_on_evict: OwnershipOnEvict::Sticky,
        require_node_lease: true,
        peer_protocol: 1,
        operation_deadline_ms: None,
        owner_log_recovery_backoff_ms: 100,
        owner_log_recovery_attempts: 3,
        alarm_resident_ms: 1_000,
        idle_evict_ms: None,
        pressure: Default::default(),
    }
}

fn spec() -> NodeLeaseSpec {
    NodeLeaseSpec {
        addr: "127.0.0.1:1".to_string(),
        peer_protocol: 1,
        generation: "gen-1".to_string(),
        resume_generation: None,
        ttl_ms: TTL_MS,
    }
}

fn read_op(effects: &[Effect]) -> (OpId, Option<u64>) {
    let reads: Vec<_> = effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::ReadSelfNodeLease {
                op,
                authority_expires_ms,
            } => Some((*op, *authority_expires_ms)),
            _ => None,
        })
        .collect();
    assert_eq!(reads.len(), 1, "expected one readback in {effects:?}");
    reads[0]
}

fn cas_op(effects: &[Effect]) -> (OpId, CasGuard, NodeLeaseRecord, Option<u64>) {
    let cas: Vec<_> = effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::CasNodeLease {
                op,
                guard,
                record,
                authority_expires_ms,
            } => Some((*op, guard.clone(), record.clone(), *authority_expires_ms)),
            _ => None,
        })
        .collect();
    assert_eq!(cas.len(), 1, "expected one CAS in {effects:?}");
    cas[0].clone()
}

fn renew_timer(effects: &[Effect]) -> Option<(u64, u64)> {
    effects.iter().find_map(|effect| match effect {
        Effect::ScheduleTimer {
            timer: Timer::NodeLeaseRenew { generation },
            at_mono_ms,
        } => Some((*generation, *at_mono_ms)),
        _ => None,
    })
}

fn halted(effects: &[Effect]) -> bool {
    effects
        .iter()
        .any(|effect| matches!(effect, Effect::Halt { .. }))
}

/// A held node at mono 0 with a published expiry of `START_MS + TTL_MS`.
struct Held {
    state: State,
    renew_generation: u64,
    prior_expires_ms: u64,
    /// The record the failed renewal tried to write; set by `renewal_failed`.
    desired: Option<NodeLeaseRecord>,
}

fn held() -> Held {
    let mut state = State::new("n1", config());
    let effects = on_event(
        &mut state,
        Event::StartNodeLease {
            now_ms: START_MS,
            now_mono_ms: 0,
            spec: spec(),
        },
    );
    let (op, authority) = read_op(&effects);
    assert_eq!(authority, None, "initial acquire has no prior authority");
    let effects = on_event(
        &mut state,
        Event::SelfNodeLeaseRead {
            op,
            now_ms: START_MS,
            now_mono_ms: 0,
            result: Ok(None),
        },
    );
    let (op, guard, record, authority) = cas_op(&effects);
    assert_eq!(guard, CasGuard::Absent);
    assert_eq!(authority, None);
    let prior_expires_ms = record.expires_ms;
    let effects = on_event(
        &mut state,
        Event::NodeLeaseCasCompleted {
            op,
            now_mono_ms: 0,
            result: Ok(LeaseCasOutcome::Applied {
                etag: "e1".to_string(),
            }),
            stamped_log_state: None,
        },
    );
    let (renew_generation, _) = renew_timer(&effects).expect("held lease schedules a renewal");
    Held {
        state,
        renew_generation,
        prior_expires_ms,
        desired: None,
    }
}

/// Fire the renewal at a third of the TTL and fail its CAS with `result`.
/// Returns the effects of the CAS completion.
fn renewal_failed(held: &mut Held, result: Result<LeaseCasOutcome, Failure>) -> Vec<Effect> {
    let fired_ms = TTL_MS / 3;
    let effects = on_event(
        &mut held.state,
        Event::TimerFired {
            timer: Timer::NodeLeaseRenew {
                generation: held.renew_generation,
            },
            now_ms: START_MS + fired_ms,
            now_mono_ms: fired_ms,
        },
    );
    let (op, guard, desired, authority) = cas_op(&effects);
    held.desired = Some(desired);
    assert_eq!(guard, CasGuard::Match("e1".to_string()));
    assert_eq!(authority, Some(held.prior_expires_ms));
    on_event(
        &mut held.state,
        Event::NodeLeaseCasCompleted {
            op,
            now_mono_ms: fired_ms + 2_500,
            result,
            stamped_log_state: None,
        },
    )
}

#[test]
fn initial_acquire_readback_has_no_authority() {
    let mut state = State::new("n1", config());
    let effects = on_event(
        &mut state,
        Event::StartNodeLease {
            now_ms: START_MS,
            now_mono_ms: 0,
            spec: spec(),
        },
    );
    assert_eq!(read_op(&effects).1, None);
}

#[test]
fn ambiguous_renewal_readback_carries_prior_expiry() {
    let mut held = held();
    let effects = renewal_failed(&mut held, Err(Failure::Ambiguous));
    assert_eq!(read_op(&effects).1, Some(START_MS + TTL_MS));
}

#[test]
fn rejected_renewal_readback_carries_prior_expiry() {
    let mut held = held();
    let effects = renewal_failed(&mut held, Ok(LeaseCasOutcome::Rejected));
    assert_eq!(read_op(&effects).1, Some(START_MS + TTL_MS));
}

#[test]
fn readback_timeout_failure_schedules_a_retry_not_a_halt() {
    // The shell maps a readback timeout to `Failure::Definite`. The core must
    // answer with a scheduled renewal; the shell owns no retry.
    let mut held = held();
    let effects = renewal_failed(&mut held, Err(Failure::Ambiguous));
    let (op, _) = read_op(&effects);
    let at = TTL_MS / 3 + 2_500 + 2_083;
    let effects = on_event(
        &mut held.state,
        Event::SelfNodeLeaseRead {
            op,
            now_ms: START_MS + at,
            now_mono_ms: at,
            result: Err(Failure::Definite),
        },
    );
    assert!(!halted(&effects), "{effects:?}");
    // Remaining authority is 10_000 - 7_916 = 2_084; the cadence (3_333) does
    // not fit in half of it, so the retry waits a quarter: 521 ms.
    assert_eq!(
        renew_timers(&effects),
        vec![(held.renew_generation, at + 521)]
    );
    assert!(!held.state.is_fenced());

    // Still Held: the retry fires a CAS guarded by the held etag, carrying the
    // unchanged prior authority.
    let retry_at = at + 521;
    let effects = on_event(
        &mut held.state,
        Event::TimerFired {
            timer: Timer::NodeLeaseRenew {
                generation: held.renew_generation,
            },
            now_ms: START_MS + retry_at,
            now_mono_ms: retry_at,
        },
    );
    let (_, guard, _, authority) = cas_op(&effects);
    assert_eq!(guard, CasGuard::Match("e1".to_string()));
    assert_eq!(authority, Some(held.prior_expires_ms));
    assert!(!halted(&effects), "{effects:?}");
}

const READ_AT_MS: u64 = 6_000;

/// Fail the renewal ambiguously, then deliver `record` as the readback at
/// `READ_AT_MS`. `shape` receives the desired record to build the observation.
fn readback_with(
    shape: impl FnOnce(&Held, NodeLeaseRecord) -> NodeLeaseRecord,
) -> (Held, Vec<Effect>) {
    let mut held = held();
    let effects = renewal_failed(&mut held, Err(Failure::Ambiguous));
    let (op, _) = read_op(&effects);
    let desired = held.desired.clone().expect("renewal recorded its record");
    let mut record = shape(&held, desired);
    record.etag = "e2".to_string();
    let effects = on_event(
        &mut held.state,
        Event::SelfNodeLeaseRead {
            op,
            now_ms: START_MS + READ_AT_MS,
            now_mono_ms: READ_AT_MS,
            result: Ok(Some(record)),
        },
    );
    (held, effects)
}

fn halts(effects: &[Effect]) -> Vec<HaltReason> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Halt { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect()
}

fn renew_timers(effects: &[Effect]) -> Vec<(u64, u64)> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::ScheduleTimer {
                timer: Timer::NodeLeaseRenew { generation },
                at_mono_ms,
            } => Some((*generation, *at_mono_ms)),
            _ => None,
        })
        .collect()
}

fn assert_one_renew_no_halt(held: &Held, effects: &[Effect]) -> u64 {
    assert!(halts(effects).is_empty(), "{effects:?}");
    assert!(!held.state.is_fenced());
    let timers = renew_timers(effects);
    assert_eq!(timers.len(), 1, "{effects:?}");
    timers[0].1
}

#[test]
fn readback_matching_desired_completes_the_write_and_renews() {
    let (held, effects) = readback_with(|_, desired| desired);
    let at = assert_one_renew_no_halt(&held, &effects);
    assert!(at > READ_AT_MS, "{at}");
}

#[test]
fn readback_matching_prior_retries_the_renewal() {
    let (held, effects) = readback_with(|held, mut desired| {
        desired.expires_ms = held.prior_expires_ms;
        desired
    });
    // Remaining authority is 4_000; the cadence (3_333) does not fit in half
    // of it, so the retry waits a quarter: 1_000 ms.
    assert_eq!(
        assert_one_renew_no_halt(&held, &effects),
        READ_AT_MS + 1_000
    );
}

#[test]
fn readback_own_zombie_is_adopted_and_renews_now() {
    // Only the expiry moved, by less than the attempt wrote: an earlier
    // ambiguous renewal landed late (#482).
    let (held, effects) = readback_with(|held, mut desired| {
        desired.expires_ms = held.prior_expires_ms + 1_000;
        desired
    });
    // The nudge lane renews 1 ms out, and the adopted anchor (1_000) moves the
    // fence to anchor + ttl.
    assert_eq!(assert_one_renew_no_halt(&held, &effects), READ_AT_MS + 1);
    assert!(
        effects.iter().any(|effect| matches!(
            effect,
            Effect::ScheduleTimer {
                timer: Timer::NodeLeaseFence { .. },
                at_mono_ms,
            } if *at_mono_ms == 1_000 + TTL_MS
        )),
        "{effects:?}"
    );
}

#[test]
fn readback_someone_elses_record_halts_once_with_mismatch() {
    let (held, effects) = readback_with(|_, mut desired| {
        desired.addr = "10.0.0.9:1".to_string();
        desired
    });
    assert_eq!(
        halts(&effects),
        vec![HaltReason::NodeLeaseMismatch],
        "{effects:?}"
    );
    assert!(renew_timers(&effects).is_empty(), "{effects:?}");
    assert!(held.state.is_fenced());
}

#[test]
fn renew_timer_during_readback_does_not_start_a_second_operation() {
    let mut held = held();
    let effects = renewal_failed(&mut held, Err(Failure::Ambiguous));
    let _ = read_op(&effects);
    let effects = on_event(
        &mut held.state,
        Event::TimerFired {
            timer: Timer::NodeLeaseRenew {
                generation: held.renew_generation,
            },
            now_ms: START_MS + 6_000,
            now_mono_ms: 6_000,
        },
    );
    assert!(effects.is_empty(), "{effects:?}");
}

#[test]
fn missing_readback_still_fences() {
    let mut held = held();
    let effects = renewal_failed(&mut held, Err(Failure::Ambiguous));
    let (op, _) = read_op(&effects);
    let effects = on_event(
        &mut held.state,
        Event::SelfNodeLeaseRead {
            op,
            now_ms: START_MS + 6_000,
            now_mono_ms: 6_000,
            result: Ok(None),
        },
    );
    assert!(
        effects.iter().any(|effect| matches!(
            effect,
            Effect::Halt {
                reason: HaltReason::NodeLeaseMissing,
                ..
            }
        )),
        "{effects:?}"
    );
}
