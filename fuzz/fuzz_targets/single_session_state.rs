#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use wc_core::testkit::{SingleSessionHarnessState, SingleSessionStateHarness};
use wc_protocol::{pairing::PairingSymKey, relay::RelayTopic, session::Session};

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_IDS: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    let session_value = value.get("session").unwrap_or(&value);
    let Ok(session) = serde_json::from_value::<Session>(session_value.clone()) else {
        return;
    };
    let update_namespaces = value
        .get("namespaces")
        .and_then(|namespaces| serde_json::from_value(namespaces.clone()).ok())
        .unwrap_or_else(|| session.namespaces.clone());

    exercise_expiry_transition(session.clone());
    exercise_pending_request_state(session.clone(), ids_from(&value, "requestIds"));
    exercise_pending_update_state(
        session.clone(),
        ids_from(&value, "updateIds"),
        update_namespaces,
    );
    exercise_pairing_replacement_state(session.clone());
    exercise_interleaved_runtime_state(session, ids_from(&value, "operationIds"));
});

fn exercise_expiry_transition(session: Session) {
    let topic = session.topic.clone();
    let expiry = session.expiry;
    let mut harness = SingleSessionStateHarness::new_session(session, harness_sym_key());

    if expiry > 0 {
        assert!(harness.take_expired_session_at(expiry - 1).is_none());
        assert!(!harness.is_idle());
    }

    let expired = harness
        .take_expired_session_at(expiry)
        .expect("session expires when now reaches expiry");
    assert_eq!(expired.topic(), &topic);
    assert_eq!(expired.expiry(), expiry);
    assert!(harness.is_idle());
    assert!(harness.take_expired_session_at(expiry).is_none());
}

fn exercise_pending_request_state(session: Session, ids: Vec<u64>) {
    let mut harness = SingleSessionStateHarness::new_session(session, harness_sym_key());

    for request_id in ids.into_iter().take(MAX_IDS) {
        assert!(
            harness
                .mark_session_request_pending(request_id)
                .expect("active session should accept pending request")
        );
        assert!(
            !harness
                .mark_session_request_pending(request_id)
                .expect("duplicate request id should be checked on active session")
        );
        harness
            .complete_session_request(request_id)
            .expect("pending request should complete once");
        assert!(harness.complete_session_request(request_id).is_err());
    }
}

fn exercise_pending_update_state(
    session: Session,
    ids: Vec<u64>,
    update_namespaces: wc_protocol::session::SessionNamespaces,
) {
    let topic = session.topic.clone();
    let mut harness = SingleSessionStateHarness::new_session(session, harness_sym_key());

    for request_id in ids.into_iter().take(MAX_IDS) {
        assert!(harness.complete_session_update(request_id).is_err());
        assert!(
            harness
                .mark_session_update_pending(request_id)
                .expect("active session should accept pending update")
        );
        assert!(
            !harness
                .mark_session_update_pending(request_id)
                .expect("duplicate update id should be checked on active session")
        );
        harness
            .approve_session_update_on(&topic, request_id, update_namespaces.clone())
            .expect("pending update should approve once");
        assert!(harness.complete_session_update(request_id).is_err());
    }
}

fn exercise_pairing_replacement_state(session: Session) {
    let pairing_topic = session.pairing_topic.clone();
    let wrong_pairing_topic = different_topic(&pairing_topic);
    let session_topic = session.topic.clone();
    let mut harness = SingleSessionStateHarness::idle();

    assert_eq!(harness.state(), SingleSessionHarnessState::Idle);
    harness
        .begin_pairing(pairing_topic.clone(), harness_sym_key())
        .expect("idle runtime accepts one pairing topic");
    assert_eq!(harness.state(), SingleSessionHarnessState::Pairing);
    assert!(
        harness
            .begin_pairing(different_topic(&pairing_topic), harness_sym_key())
            .is_err()
    );
    assert!(
        harness
            .adopt_session_from_pairing(&wrong_pairing_topic, session.clone(), harness_sym_key())
            .is_err()
    );
    harness
        .adopt_session_from_pairing(&pairing_topic, session, harness_sym_key())
        .expect("active pairing can be replaced by the approved session");
    assert_eq!(harness.state(), SingleSessionHarnessState::Session);
    assert!(harness.begin_pairing(pairing_topic, harness_sym_key()).is_err());
    assert!(harness.inject_pairing_delete(&wrong_pairing_topic).is_err());
    harness
        .inject_session_delete(&session_topic)
        .expect("session delete clears the active session");
    assert_eq!(harness.state(), SingleSessionHarnessState::Idle);
    assert!(harness.inject_session_delete(&session_topic).is_err());
}

fn exercise_interleaved_runtime_state(session: Session, ids: Vec<u64>) {
    let topic = session.topic.clone();
    let wrong_topic = different_topic(&topic);
    let mut harness = SingleSessionStateHarness::new_session(session, harness_sym_key());

    for (index, request_id) in ids.into_iter().take(MAX_IDS).enumerate() {
        match index % 8 {
            0 => {
                assert!(
                    harness
                        .mark_session_request_pending_on(&wrong_topic, request_id)
                        .is_err()
                );
                let _ = harness
                    .mark_session_request_pending_on(&topic, request_id)
                    .expect("active topic accepts request decisions");
            }
            1 => {
                let _ = harness.complete_session_request_on(&topic, request_id);
                assert!(
                    harness
                        .complete_session_request_on(&wrong_topic, request_id)
                        .is_err()
                );
            }
            2 => {
                assert!(
                    harness
                        .mark_session_update_pending_on(&wrong_topic, request_id)
                        .is_err()
                );
                let _ = harness
                    .mark_session_update_pending_on(&topic, request_id)
                    .expect("active topic accepts update decisions");
            }
            3 => {
                let _ = harness.complete_session_update_on(&topic, request_id);
                assert!(
                    harness
                        .complete_session_update_on(&wrong_topic, request_id)
                        .is_err()
                );
            }
            4 => {
                harness
                    .inject_session_extend(&topic, request_id)
                    .expect("extend mutates active session expiry");
                let _ = harness.take_expired_session_at(request_id);
                if harness.is_idle() {
                    assert_eq!(harness.pending_session_request_count(), 0);
                    assert_eq!(harness.pending_session_update_count(), 0);
                    return;
                }
            }
            5 => {
                assert!(harness.inject_session_extend(&wrong_topic, request_id).is_err());
            }
            6 => {
                if request_id & 1 == 0 {
                    harness
                        .inject_session_delete(&topic)
                        .expect("delete clears active session");
                    assert_eq!(harness.pending_session_request_count(), 0);
                    assert_eq!(harness.pending_session_update_count(), 0);
                    assert!(harness.complete_session_request_on(&topic, request_id).is_err());
                    assert!(harness.complete_session_update_on(&topic, request_id).is_err());
                    return;
                }
            }
            _ => {
                assert!(harness.inject_session_delete(&wrong_topic).is_err());
            }
        }
    }
}

fn ids_from(value: &Value, key: &str) -> Vec<u64> {
    let ids = value
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_u64)
                .take(MAX_IDS)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if ids.is_empty() {
        vec![0, 1, u64::MAX]
    } else {
        ids
    }
}

fn harness_sym_key() -> PairingSymKey {
    PairingSymKey::from_bytes([0x42; 32])
}

fn different_topic(topic: &RelayTopic) -> RelayTopic {
    let alternative = RelayTopic::from_bytes([0x99; 32]);
    if &alternative == topic {
        RelayTopic::from_bytes([0x98; 32])
    } else {
        alternative
    }
}
