use serde_json::json;
use wc_protocol::session::{Session, SessionTransportType};

const LIVE_WALLET_AUTHENTICATED_SESSION_JSON: &str = r#"{
  "topic": "8262b6adcec43ee7e17a7bf2dfd26dab4cb3c8f89c3ff7393f2b58d0f295e988",
  "acknowledged": true,
  "self": {
    "publicKey": "52520a2d4ac899c9496c44c39d787bf21fe86d5e751dfba95505c5580752ff66",
    "metadata": {
      "name": "wc-rs live auth wallet",
      "description": "Temporary live probe wallet",
      "url": "https://example.com/wallet",
      "icons": [
        ""
      ]
    }
  },
  "peer": {
    "publicKey": "55a7127a90a905c052894ebac4d9226abfd465bfc28b1e668b1633d4f4722b07",
    "metadata": {
      "name": "wc-rs live auth dapp",
      "description": "Temporary live probe for wc_sessionAuthenticate approval",
      "url": "https://example.com/dapp",
      "icons": [
        ""
      ]
    }
  },
  "controller": "55a7127a90a905c052894ebac4d9226abfd465bfc28b1e668b1633d4f4722b07",
  "expiry": 1780470684,
  "authentication": [
    {
      "h": {
        "t": "caip122"
      },
      "p": {
        "iss": "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87",
        "domain": "example.com",
        "aud": "https://example.com/login",
        "version": "1",
        "nonce": "1234567890",
        "iat": "2026-05-27T07:11:24.373Z",
        "statement": "",
        "resources": [
          "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XX19fQ"
        ]
      },
      "s": {
        "t": "eip191",
        "s": "0x5792b0795d84d5247056e1758633fe53f3a150cd0d66148b9bb82310f9adc0e74e54f8073078c8fb9ee2d4e0a9587fe72dea21e005aec83e9813f4031e3f381e1c"
      }
    }
  ],
  "requiredNamespaces": {},
  "optionalNamespaces": {},
  "relay": {
    "protocol": "irn"
  },
  "pairingTopic": "23f45c1d392c4742b1bf607a558a63dd3e8bfbec8fd4564504e86b65a568fd20",
  "namespaces": {
    "eip155": {
      "accounts": [
        "eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"
      ],
      "chains": [
        "eip155:1"
      ],
      "events": [
        "chainChanged",
        "accountsChanged"
      ],
      "methods": [
        "personal_sign"
      ]
    }
  },
  "transportType": "relay"
}"#;

const LIVE_DAPP_AUTHENTICATED_SESSION_JSON: &str = r#"{
  "topic": "8262b6adcec43ee7e17a7bf2dfd26dab4cb3c8f89c3ff7393f2b58d0f295e988",
  "acknowledged": true,
  "self": {
    "publicKey": "55a7127a90a905c052894ebac4d9226abfd465bfc28b1e668b1633d4f4722b07",
    "metadata": {
      "name": "wc-rs live auth dapp",
      "description": "Temporary live probe for wc_sessionAuthenticate approval",
      "url": "https://example.com/dapp",
      "icons": [
        ""
      ]
    }
  },
  "peer": {
    "publicKey": "52520a2d4ac899c9496c44c39d787bf21fe86d5e751dfba95505c5580752ff66",
    "metadata": {
      "name": "wc-rs live auth wallet",
      "description": "Temporary live probe wallet",
      "url": "https://example.com/wallet",
      "icons": [
        ""
      ]
    }
  },
  "controller": "52520a2d4ac899c9496c44c39d787bf21fe86d5e751dfba95505c5580752ff66",
  "expiry": 1780470684,
  "requiredNamespaces": {},
  "optionalNamespaces": {},
  "relay": {
    "protocol": "irn"
  },
  "pairingTopic": "23f45c1d392c4742b1bf607a558a63dd3e8bfbec8fd4564504e86b65a568fd20",
  "namespaces": {
    "eip155": {
      "accounts": [
        "eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"
      ],
      "chains": [
        "eip155:1"
      ],
      "events": [
        "chainChanged",
        "accountsChanged"
      ],
      "methods": [
        "personal_sign"
      ]
    }
  },
  "transportType": "relay"
}"#;

#[test]
fn deserializes_live_wallet_authenticated_session_shape() {
    let session = serde_json::from_str::<Session>(LIVE_WALLET_AUTHENTICATED_SESSION_JSON)
        .expect("wallet authenticated session parses");

    assert_eq!(
        session.topic.as_str(),
        "8262b6adcec43ee7e17a7bf2dfd26dab4cb3c8f89c3ff7393f2b58d0f295e988"
    );
    assert_eq!(
        session.pairing_topic.as_str(),
        "23f45c1d392c4742b1bf607a558a63dd3e8bfbec8fd4564504e86b65a568fd20"
    );
    assert!(session.acknowledged);
    assert_eq!(session.relay.protocol, "irn");
    assert_eq!(
        session.self_participant.metadata.name,
        "wc-rs live auth wallet"
    );
    assert_eq!(session.peer.metadata.name, "wc-rs live auth dapp");
    assert_eq!(session.expiry, 1_780_470_684);
    assert!(!session.is_expired_at(1_700_000_000));
    assert!(session.is_expired_at(1_800_000_000));
    assert_eq!(
        session.namespaces["eip155"].accounts,
        ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"]
    );
    assert_eq!(
        session.authentication.as_ref().map(Vec::len),
        Some(1),
        "wallet-side authenticated session stores CACAO in authentication"
    );
    assert_eq!(session.transport_type, Some(SessionTransportType::Relay));
}

#[test]
fn deserializes_live_dapp_authenticated_session_without_authentication() {
    let session = serde_json::from_str::<Session>(LIVE_DAPP_AUTHENTICATED_SESSION_JSON)
        .expect("dapp authenticated session parses");

    assert_eq!(
        session.self_participant.metadata.name,
        "wc-rs live auth dapp"
    );
    assert_eq!(session.peer.metadata.name, "wc-rs live auth wallet");
    assert!(session.authentication.is_none());
    assert_eq!(session.transport_type, Some(SessionTransportType::Relay));
}

#[test]
fn session_transport_preserves_known_and_unknown_wire_names() {
    assert_eq!(
        serde_json::from_value::<SessionTransportType>(json!("relay")).expect("parses"),
        SessionTransportType::Relay
    );
    assert_eq!(
        serde_json::from_value::<SessionTransportType>(json!("link_mode")).expect("parses"),
        SessionTransportType::LinkMode
    );

    let unknown =
        serde_json::from_value::<SessionTransportType>(json!("future_transport")).expect("parses");

    assert_eq!(
        unknown,
        SessionTransportType::Other("future_transport".to_owned())
    );
    assert_eq!(
        serde_json::to_value(unknown).expect("serializes"),
        json!("future_transport")
    );
}

#[test]
fn serializes_optional_session_fields_when_present() {
    let mut value = serde_json::from_str::<serde_json::Value>(LIVE_DAPP_AUTHENTICATED_SESSION_JSON)
        .expect("dapp authenticated session parses as json");

    value["sessionProperties"] = json!({
        "caip154-mandatory": "true"
    });
    value["scopedProperties"] = json!({
        "eip155:1": {
            "walletService": ["https://example.com"]
        }
    });
    value["sessionConfig"] = json!({
        "disableDeepLink": true
    });
    value["walletPayResult"] = json!([
        {
            "id": "payment-1"
        }
    ]);
    value["transportType"] = json!("link_mode");

    let session = serde_json::from_value::<Session>(value).expect("session parses");
    let serialized = serde_json::to_value(session).expect("serializes");

    assert_eq!(serialized["sessionProperties"]["caip154-mandatory"], "true");
    assert_eq!(
        serialized["scopedProperties"]["eip155:1"]["walletService"],
        json!(["https://example.com"])
    );
    assert_eq!(serialized["sessionConfig"]["disableDeepLink"], true);
    assert_eq!(serialized["walletPayResult"][0]["id"], "payment-1");
    assert_eq!(serialized["transportType"], "link_mode");
}
