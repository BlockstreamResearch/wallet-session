#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use wc_protocol::{
    namespaces::{
        is_chain_authorized, is_event_authorized, is_method_authorized,
        validate_approved_namespaces, validate_required_namespaces,
    },
    session::{ProposalNamespaces, SessionNamespaces},
};

const MAX_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    let required_value = value.get("required").unwrap_or(&value);
    let approved_value = value.get("approved").unwrap_or(&value);

    let required = serde_json::from_value::<ProposalNamespaces>(required_value.clone());
    let approved = serde_json::from_value::<SessionNamespaces>(approved_value.clone());

    if let Ok(required) = required.as_ref() {
        let _ = validate_required_namespaces(required);
    }

    if let (Ok(required), Ok(approved)) = (required.as_ref(), approved.as_ref()) {
        let _ = validate_approved_namespaces(required, approved);

        for namespace in approved.values() {
            for account in &namespace.accounts {
                let chain_id = account.chain_id();
                let _ = is_chain_authorized(approved, &chain_id);
                for method in &namespace.methods {
                    let _ = is_method_authorized(approved, &chain_id, method.as_str());
                }
                for event in &namespace.events {
                    let _ = is_event_authorized(approved, &chain_id, event.as_str());
                }
            }
        }
    }
});
