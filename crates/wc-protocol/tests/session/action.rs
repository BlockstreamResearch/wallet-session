use serde_json::json;
use wc_protocol::session::{SessionEventName, SessionMethod};

#[test]
fn parses_live_walletconnect_js_method_and_event_shapes() {
    for value in [
        "eth_sendTransaction",
        "personal_sign",
        "wallet_switchEthereumChain",
        "custom/method",
        "custom:event",
        "custom.event",
        " custom/method ",
        "方法",
    ] {
        assert_eq!(
            SessionMethod::parse(value)
                .expect("method follows JS non-blank string rule")
                .as_str(),
            value
        );
    }

    for value in [
        "accountsChanged",
        "chainChanged",
        "custom/event",
        "custom:event",
        "custom.event",
        " custom/event ",
        "🔥",
    ] {
        assert_eq!(
            SessionEventName::parse(value)
                .expect("event follows JS non-blank string rule")
                .as_str(),
            value
        );
    }
}

#[test]
fn rejects_empty_and_whitespace_like_walletconnect_js() {
    for value in ["", " ", "\t\n"] {
        assert!(
            SessionMethod::parse(value).is_err(),
            "method should reject {value:?}"
        );
        assert!(
            SessionEventName::parse(value).is_err(),
            "event should reject {value:?}"
        );
    }
}

#[test]
fn serde_round_trips_wire_values() {
    let method = SessionMethod::parse("personal_sign").expect("method parses");
    let event = SessionEventName::parse("accountsChanged").expect("event parses");

    assert_eq!(
        serde_json::to_value(&method).expect("serializes"),
        json!("personal_sign")
    );
    assert_eq!(
        serde_json::from_value::<SessionMethod>(json!("personal_sign"))
            .expect("deserializes")
            .as_str(),
        "personal_sign"
    );
    assert_eq!(
        serde_json::to_value(&event).expect("serializes"),
        json!("accountsChanged")
    );
    assert_eq!(
        serde_json::from_value::<SessionEventName>(json!("accountsChanged"))
            .expect("deserializes")
            .as_str(),
        "accountsChanged"
    );
}
