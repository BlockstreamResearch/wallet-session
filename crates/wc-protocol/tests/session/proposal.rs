use std::collections::BTreeMap;

use serde_json::json;

use super::{chain_strings, public_key};
use wc_protocol::{
    relay::RelayTopic,
    session::{
        CacaoSignatureType, DappMetadata, JsonRpcError, JsonRpcErrorCode, JsonRpcErrorResponse,
        JsonRpcRequest, JsonRpcResponse, ProposalAuthRequest, ProposalNamespaces, ProposalRequests,
        Proposer, RelayProtocolOptions, SessionProposeErrorResponse, SessionProposeParams,
        SessionProposeResult, SignMethod, session_propose_error_response,
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

const LIVE_SESSION_PROPOSE_APPROVE_JSON: &str = r#"{
  "id": 1779866466221833,
  "jsonrpc": "2.0",
  "result": {
    "relay": {
      "protocol": "irn"
    },
    "responderPublicKey": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337"
  }
}"#;

const LIVE_SESSION_PROPOSE_REJECT_USER_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "error": {
    "message": "User rejected.",
    "code": 5000
  }
}"#;

const LIVE_SESSION_PROPOSE_REJECT_CHAINS_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "error": {
    "message": "User rejected chains.",
    "code": 5001
  }
}"#;

const LIVE_SESSION_PROPOSE_REJECT_METHODS_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "error": {
    "message": "User rejected methods.",
    "code": 5002
  }
}"#;

const LIVE_SESSION_PROPOSE_REJECT_EVENTS_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "error": {
    "message": "User rejected events.",
    "code": 5003
  }
}"#;

const LIVE_SESSION_PROPOSE_UNSUPPORTED_CHAINS_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "error": {
    "message": "Unsupported chains.",
    "code": 5100
  }
}"#;

const LIVE_SESSION_PROPOSE_UNSUPPORTED_METHODS_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "error": {
    "message": "Unsupported methods.",
    "code": 5101
  }
}"#;

const LIVE_SESSION_PROPOSE_UNSUPPORTED_EVENTS_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "error": {
    "message": "Unsupported events.",
    "code": 5102
  }
}"#;

const LIVE_SESSION_PROPOSE_UNSUPPORTED_ACCOUNTS_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "error": {
    "message": "Unsupported accounts.",
    "code": 5103
  }
}"#;

const LIVE_SESSION_PROPOSE_UNSUPPORTED_NAMESPACE_KEY_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "error": {
    "message": "Unsupported namespace key.",
    "code": 5104
  }
}"#;

const LIVE_SESSION_PROPOSE_REJECT_WITH_DATA_JSON: &str = r#"{
  "id": 1779812558761961,
  "jsonrpc": "2.0",
  "error": {
    "message": "User rejected.",
    "code": 5000,
    "data": "wallet rejected proposal"
  }
}"#;

const LIVE_SESSION_PROPOSE_CUSTOM_ERROR_JSON: &str = r#"{
  "id": 1779812558761962,
  "jsonrpc": "2.0",
  "error": {
    "code": 4999,
    "message": "Custom proposal rejection.",
    "data": {
      "reason": "custom object"
    }
  }
}"#;

const LIVE_SESSION_PROPOSE_STRING_ERROR_JSON: &str = r#"{
  "id": 1779812558761963,
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Rejected by wallet"
  }
}"#;

const LIVE_SESSION_PROPOSE_WITH_AUTHENTICATION_JSON: &str = r#"{
  "id": 1780055038877815,
  "jsonrpc": "2.0",
  "method": "wc_sessionPropose",
  "params": {
    "expiryTimestamp": 1780055338,
    "id": 1780055038877815,
    "optionalNamespaces": {
      "eip155": {
        "chains": ["eip155:1"],
        "events": ["accountsChanged"],
        "methods": ["personal_sign"]
      }
    },
    "pairingTopic": "f57feb3b2105286aa72028d51090dc86d6c4caeb10c4342e21ed3f045d53713a",
    "proposer": {
      "metadata": {
        "description": "Live proposal auth subrequest generator for Rust probes",
        "icons": ["https://walletconnect.com/walletconnect-logo.png"],
        "name": "walletconnect-client-poc JS auth proposal harness",
        "url": "https://github.com/BlockstreamResearch/walletconnect-client-poc"
      },
      "publicKey": "19baf2b76e92b5aeaa438520fbcaf78f5045e2d1a63d779d025f9d0502b47966"
    },
    "relays": [{"protocol": "irn"}],
    "requests": {
      "authentication": [
        {
          "aud": "https://example.com/login",
          "chains": ["eip155:1"],
          "domain": "example.com",
          "iat": "2026-05-29T11:43:58.877Z",
          "nonce": "proposal-auth-nonce-001",
          "resources": ["https://example.com/resource/1"],
          "signatureTypes": {"eip155:1": ["eip191"]},
          "statement": "Sign in to Example",
          "type": "caip122",
          "version": "1"
        }
      ]
    },
    "requiredNamespaces": {}
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
    let required_chains = request.params.required_namespaces["eip155"]
        .chains
        .as_deref()
        .expect("required chains");
    assert_eq!(chain_strings(required_chains), ["eip155:5"]);
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
                public_key: public_key(
                    "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
                ),
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
                authentication: Some(vec![
                    serde_json::from_value::<ProposalAuthRequest>(json!({
                        "type": "caip122",
                        "chains": ["eip155:1"],
                        "aud": "https://example.com/login",
                        "domain": "example.com",
                        "version": "1",
                        "nonce": "proposal-auth-nonce-001",
                        "iat": "2026-05-29T11:43:58.877Z",
                        "signatureTypes": {"eip155:1": ["eip191"]}
                    }))
                    .expect("auth request parses"),
                ]),
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

#[test]
fn deserializes_live_proposal_authentication_subrequest_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let request = serde_json::from_str::<JsonRpcRequest<SessionProposeParams>>(
        LIVE_SESSION_PROPOSE_WITH_AUTHENTICATION_JSON,
    )?;

    let auth_requests = request
        .params
        .requests
        .as_ref()
        .and_then(|requests| requests.authentication.as_ref())
        .expect("authentication requests");
    let auth = &auth_requests[0];
    let chain: wc_protocol::caip::Caip2ChainId = "eip155:1".parse()?;

    assert_eq!(auth.auth_payload.kind.as_str(), "caip122");
    assert_eq!(auth.auth_payload.domain, "example.com");
    assert_eq!(auth.auth_payload.aud, "https://example.com/login");
    assert_eq!(auth.auth_payload.nonce, "proposal-auth-nonce-001");
    assert_eq!(auth.auth_payload.chains, vec![chain.clone()]);
    assert_eq!(
        auth.signature_types_for_chain(&chain),
        Some([CacaoSignatureType::Eip191].as_slice())
    );

    let value = serde_json::to_value(&request)?;
    assert_eq!(
        value["params"]["requests"]["authentication"][0]["signatureTypes"]["eip155:1"],
        json!(["eip191"])
    );

    Ok(())
}

#[test]
fn deserializes_live_proposal_approval_result_shape() {
    let response = serde_json::from_str::<JsonRpcResponse<SessionProposeResult>>(
        LIVE_SESSION_PROPOSE_APPROVE_JSON,
    )
    .expect("session proposal approval parses");

    assert_eq!(response.id, 1_779_866_466_221_833);
    assert_eq!(response.result.relay.protocol, "irn");
    assert_eq!(
        response.result.responder_public_key.as_str(),
        "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337"
    );
}

#[test]
fn serializes_proposal_approval_result_wire_shape() {
    let response = JsonRpcResponse::new(
        43,
        SessionProposeResult {
            relay: RelayProtocolOptions {
                protocol: "irn".to_owned(),
                data: Some("relay-data".to_owned()),
            },
            responder_public_key: public_key(
                "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
            ),
        },
    );

    let value = serde_json::to_value(response).expect("serializes");

    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["result"]["relay"]["protocol"], "irn");
    assert_eq!(value["result"]["relay"]["data"], "relay-data");
    assert_eq!(
        value["result"]["responderPublicKey"],
        "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337"
    );
}

#[test]
fn deserializes_live_proposal_rejection_sdk_errors() {
    for (json, code, message) in [
        (
            LIVE_SESSION_PROPOSE_REJECT_USER_JSON,
            JsonRpcErrorCode::UserRejected,
            "User rejected.",
        ),
        (
            LIVE_SESSION_PROPOSE_REJECT_CHAINS_JSON,
            JsonRpcErrorCode::UserRejectedChains,
            "User rejected chains.",
        ),
        (
            LIVE_SESSION_PROPOSE_REJECT_METHODS_JSON,
            JsonRpcErrorCode::UserRejectedMethods,
            "User rejected methods.",
        ),
        (
            LIVE_SESSION_PROPOSE_REJECT_EVENTS_JSON,
            JsonRpcErrorCode::UserRejectedEvents,
            "User rejected events.",
        ),
        (
            LIVE_SESSION_PROPOSE_UNSUPPORTED_CHAINS_JSON,
            JsonRpcErrorCode::UnsupportedChains,
            "Unsupported chains.",
        ),
        (
            LIVE_SESSION_PROPOSE_UNSUPPORTED_METHODS_JSON,
            JsonRpcErrorCode::UnsupportedMethods,
            "Unsupported methods.",
        ),
        (
            LIVE_SESSION_PROPOSE_UNSUPPORTED_EVENTS_JSON,
            JsonRpcErrorCode::UnsupportedEvents,
            "Unsupported events.",
        ),
        (
            LIVE_SESSION_PROPOSE_UNSUPPORTED_ACCOUNTS_JSON,
            JsonRpcErrorCode::UnsupportedAccounts,
            "Unsupported accounts.",
        ),
        (
            LIVE_SESSION_PROPOSE_UNSUPPORTED_NAMESPACE_KEY_JSON,
            JsonRpcErrorCode::UnsupportedNamespaceKey,
            "Unsupported namespace key.",
        ),
    ] {
        let response =
            serde_json::from_str::<SessionProposeErrorResponse>(json).expect("rejection parses");

        assert_eq!(response.id, 1_779_812_558_761_960);
        assert_eq!(response.error.code, code);
        assert_eq!(response.error.message, message);
        assert_eq!(response.error.data, None);
    }
}

#[test]
fn deserializes_live_proposal_rejection_with_data() {
    let response = serde_json::from_str::<SessionProposeErrorResponse>(
        LIVE_SESSION_PROPOSE_REJECT_WITH_DATA_JSON,
    )
    .expect("rejection with data parses");

    assert_eq!(response.id, 1_779_812_558_761_961);
    assert_eq!(response.error.code, JsonRpcErrorCode::UserRejected);
    assert_eq!(response.error.message, "User rejected.");
    assert_eq!(response.error.data, Some(json!("wallet rejected proposal")));
}

#[test]
fn deserializes_live_proposal_rejection_custom_errors() {
    let custom =
        serde_json::from_str::<SessionProposeErrorResponse>(LIVE_SESSION_PROPOSE_CUSTOM_ERROR_JSON)
            .expect("custom error parses");
    let string_error =
        serde_json::from_str::<JsonRpcErrorResponse>(LIVE_SESSION_PROPOSE_STRING_ERROR_JSON)
            .expect("string error parses");

    assert_eq!(custom.error.code, JsonRpcErrorCode::Other(4999));
    assert_eq!(custom.error.message, "Custom proposal rejection.");
    assert_eq!(custom.error.data, Some(json!({"reason": "custom object"})));
    assert_eq!(string_error.error.code, JsonRpcErrorCode::Other(-32000));
    assert_eq!(string_error.error.message, "Rejected by wallet");
    assert_eq!(string_error.error.data, None);
}

#[test]
fn serializes_proposal_rejection_wire_shape() {
    let response = session_propose_error_response(
        1_779_812_558_761_960,
        JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected."),
    );
    let value = serde_json::to_value(response).expect("serializes");
    let live = serde_json::from_str::<serde_json::Value>(LIVE_SESSION_PROPOSE_REJECT_USER_JSON)
        .expect("live fixture parses");

    assert_eq!(value, live);
}

#[test]
fn serializes_proposal_rejection_with_data_wire_shape() {
    let response = session_propose_error_response(
        1_779_812_558_761_961,
        JsonRpcError::with_data(
            JsonRpcErrorCode::UserRejected,
            "User rejected.",
            json!("wallet rejected proposal"),
        ),
    );
    let value = serde_json::to_value(response).expect("serializes");
    let live =
        serde_json::from_str::<serde_json::Value>(LIVE_SESSION_PROPOSE_REJECT_WITH_DATA_JSON)
            .expect("live fixture parses");

    assert_eq!(value, live);
}
