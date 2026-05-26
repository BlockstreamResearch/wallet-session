use std::collections::BTreeMap;

use serde_json::json;
use wc_protocol::{
    relay::RelayTopic,
    session::{
        DappMetadata, JsonRpcRequest, ProposalNamespaces, ProposalRequests, Proposer,
        RelayProtocolOptions, SessionProposeParams, SignMethod,
    },
};

const SESSION_PROPOSE_JSON: &str = r#"{
  "id": 1675734656244887,
  "jsonrpc": "2.0",
  "method": "wc_sessionPropose",
  "params": {
    "id": 1675734656244887,
    "pairingTopic": "3c74583111ab5e006b03cbb0f252c667686e9fc01e675dff90aa8b18ec435feb",
    "expiryTimestamp": 1675734962,
    "requiredNamespaces": {
      "eip155": {
        "methods": [
          "eth_sendTransaction",
          "eth_signTransaction",
          "eth_sign",
          "personal_sign",
          "eth_signTypedData"
        ],
        "chains": ["eip155:5"],
        "events": ["chainChanged", "accountsChanged"]
      }
    },
    "optionalNamespaces": {
      "eip155:42161": {
        "methods": ["personal_sign"],
        "events": ["accountsChanged", "chainChanged"]
      }
    },
    "relays": [{"protocol": "irn"}],
    "proposer": {
      "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
      "metadata": {
        "description": "React App for WalletConnect",
        "url": "http://localhost:3000",
        "icons": ["https://avatars.githubusercontent.com/u/37784886"],
        "name": "React App",
        "redirect": {
          "native": "example://wc",
          "universal": "https://example.com/wc",
          "linkMode": true
        }
      }
    }
  }
}"#;

#[test]
fn deserializes_spec_event_shape() {
    let request =
        serde_json::from_str::<JsonRpcRequest<SessionProposeParams>>(SESSION_PROPOSE_JSON)
            .expect("session proposal parses");

    assert!(request.is_session_propose());
    assert_eq!(
        request.params.effective_id(request.id),
        1_675_734_656_244_887
    );
    assert_eq!(
        request.params.effective_expiry_timestamp(),
        Some(1_675_734_962)
    );
    assert_eq!(
        request
            .params
            .pairing_topic
            .as_ref()
            .map(ToString::to_string),
        Some("3c74583111ab5e006b03cbb0f252c667686e9fc01e675dff90aa8b18ec435feb".to_owned())
    );
    assert_eq!(request.params.relays[0].protocol, "irn");
    assert_eq!(request.params.proposer.metadata.name, "React App");
    assert_eq!(
        request.params.required_namespaces["eip155"]
            .chains
            .as_deref(),
        Some(["eip155:5".to_owned()].as_slice())
    );
    assert_eq!(
        request.params.optional_namespaces["eip155:42161"]
            .chains
            .as_ref(),
        None
    );
    assert!(request.params.is_expired_at(1_700_000_000));
}

#[test]
fn deserializes_wire_shape_without_param_id_or_pairing_topic() {
    let value = json!({
        "id": 42,
        "jsonrpc": "2.0",
        "method": "wc_sessionPropose",
        "params": {
            "expiryTimestamp": 99,
            "relays": [{"protocol": "irn", "data": "relay-data"}],
            "proposer": {
                "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
                "metadata": {
                    "name": "Example",
                    "description": "Example dapp",
                    "url": "https://example.com",
                    "icons": []
                }
            },
            "requiredNamespaces": {},
            "optionalNamespaces": {}
        }
    });

    let request =
        serde_json::from_value::<JsonRpcRequest<SessionProposeParams>>(value).expect("parses");

    assert_eq!(request.params.effective_id(request.id), 42);
    assert_eq!(request.params.pairing_topic, None);
    assert_eq!(request.params.relays[0].data.as_deref(), Some("relay-data"));
}

#[test]
fn uses_deprecated_expiry_fallback() {
    let value = json!({
        "id": 7,
        "jsonrpc": "2.0",
        "method": "wc_sessionPropose",
        "params": {
            "expiry": 88,
            "relays": [{"protocol": "irn"}],
            "proposer": {
                "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
                "metadata": {
                    "name": "Example",
                    "description": "Example dapp",
                    "url": "https://example.com",
                    "icons": []
                }
            },
            "requiredNamespaces": {}
        }
    });

    let request =
        serde_json::from_value::<JsonRpcRequest<SessionProposeParams>>(value).expect("parses");

    assert_eq!(request.params.effective_expiry_timestamp(), Some(88));
    assert!(request.params.optional_namespaces.is_empty());
}

#[test]
fn serializes_current_type_names() {
    let request = JsonRpcRequest::new(
        1,
        SignMethod::SessionPropose,
        SessionProposeParams {
            id: Some(1),
            pairing_topic: Some(RelayTopic::from_bytes([0x11; 32])),
            expiry: None,
            expiry_timestamp: Some(2),
            relays: vec![RelayProtocolOptions {
                protocol: "irn".to_owned(),
                data: None,
            }],
            proposer: Proposer {
                public_key: "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207"
                    .to_owned(),
                metadata: DappMetadata {
                    name: "Example".to_owned(),
                    description: "Example dapp".to_owned(),
                    url: "https://example.com".to_owned(),
                    icons: vec![],
                    verify_url: Some("https://verify.example.com".to_owned()),
                    redirect: None,
                },
            },
            required_namespaces: ProposalNamespaces::new(),
            optional_namespaces: ProposalNamespaces::new(),
            session_properties: Some(BTreeMap::from([(
                "caip154-mandatory".to_owned(),
                "true".to_owned(),
            )])),
            scoped_properties: Some(BTreeMap::from([(
                "eip155:1".to_owned(),
                json!({"walletService": ["https://example.com"]}),
            )])),
            attestation: Some("attestation-jwt".to_owned()),
            encrypted_id: Some("encrypted-id".to_owned()),
            requests: Some(ProposalRequests {
                authentication: Some(vec![json!({"chains": ["eip155:1"]})]),
                wallet_pay: Some(json!({"version": "1"})),
            }),
        },
    );

    let value = serde_json::to_value(request).expect("serializes");

    assert_eq!(value["params"]["expiryTimestamp"], 2);
    assert_eq!(
        value["params"]["pairingTopic"],
        "1111111111111111111111111111111111111111111111111111111111111111"
    );
    assert_eq!(
        value["params"]["proposer"]["publicKey"].as_str(),
        Some("a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207")
    );
    assert_eq!(
        value["params"]["proposer"]["metadata"]["verifyUrl"].as_str(),
        Some("https://verify.example.com")
    );
    assert_eq!(
        value["params"]["encryptedId"].as_str(),
        Some("encrypted-id")
    );
    assert!(value["params"].get("expiry").is_none());
}
