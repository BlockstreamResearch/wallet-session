#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use wc_core::testkit::SingleSessionStateHarness;
use wc_protocol::{pairing::PairingSymKey, session::Session};

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

    exercise_expiry_transition(session.clone());
    exercise_pending_request_state(session.clone(), ids_from(&value, "requestIds"));
    exercise_pending_update_state(session, ids_from(&value, "updateIds"));
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

fn exercise_pending_update_state(session: Session, ids: Vec<u64>) {
    let mut harness = SingleSessionStateHarness::new_session(session, harness_sym_key());

    for request_id in ids.into_iter().take(MAX_IDS) {
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
            .complete_session_update(request_id)
            .expect("pending update should complete once");
        assert!(harness.complete_session_update(request_id).is_err());
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
