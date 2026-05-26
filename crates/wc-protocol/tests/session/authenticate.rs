use serde_json::json;
use wc_protocol::session::{
    AuthPayload, DappMetadata, JsonRpcRequest, SessionAuthenticateParams, SessionParticipant,
    SignMethod,
};

const LIVE_SESSION_AUTHENTICATE_JSON: &str = r#"{
  "id": 1779815774225716,
  "jsonrpc": "2.0",
  "method": "wc_sessionAuthenticate",
  "params": {
    "authPayload": {
      "type": "caip122",
      "chains": [
        "eip155:1"
      ],
      "statement": "",
      "aud": "https://example.com/login",
      "domain": "example.com",
      "version": "1",
      "nonce": "1234567890",
      "iat": "2026-05-26T17:16:14.225Z",
      "resources": [
        "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XX19fQ"
      ]
    },
    "requester": {
      "publicKey": "351b54461d6075e0bcc0084f3f901cb7cdf4b16135e8ffa46a3a7193c6125b2e",
      "metadata": {
        "name": "wc-rs live auth dapp",
        "description": "Temporary live probe for wc_sessionAuthenticate",
        "url": "https://example.com/dapp",
        "icons": [
          ""
        ]
      }
    },
    "expiryTimestamp": 1779819374
  }
}"#;

#[test]
fn deserializes_live_authenticate_shape() {
    let request = serde_json::from_str::<JsonRpcRequest<SessionAuthenticateParams>>(
        LIVE_SESSION_AUTHENTICATE_JSON,
    )
    .expect("session authenticate parses");

    assert!(request.is_session_authenticate());
    assert_eq!(request.method, SignMethod::SessionAuthenticate);
    assert_eq!(
        request.params.requester.metadata.name,
        "wc-rs live auth dapp"
    );
    assert_eq!(request.params.auth_payload.kind, "caip122");
    assert_eq!(request.params.auth_payload.chains, ["eip155:1"]);
    assert_eq!(request.params.auth_payload.statement.as_deref(), Some(""));
    assert_eq!(request.params.auth_payload.aud, "https://example.com/login");
    assert_eq!(request.params.auth_payload.domain, "example.com");
    assert_eq!(request.params.auth_payload.version, "1");
    assert_eq!(request.params.auth_payload.nonce, "1234567890");
    assert_eq!(request.params.auth_payload.iat, "2026-05-26T17:16:14.225Z");
    assert_eq!(
        request.params.auth_payload.resources,
        ["urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XX19fQ"]
    );
    assert_eq!(request.params.expiry_timestamp, 1_779_819_374);
    assert!(request.params.is_expired_at(1_800_000_000));
}

#[test]
fn serializes_authenticate_request_with_optional_fields() {
    let request = JsonRpcRequest::new(
        21,
        SignMethod::SessionAuthenticate,
        SessionAuthenticateParams {
            requester: SessionParticipant {
                public_key: "351b54461d6075e0bcc0084f3f901cb7cdf4b16135e8ffa46a3a7193c6125b2e"
                    .to_owned(),
                metadata: DappMetadata {
                    name: "Dapp".to_owned(),
                    description: "Dapp".to_owned(),
                    url: "https://example.com/dapp".to_owned(),
                    icons: vec![],
                    verify_url: None,
                    redirect: None,
                },
            },
            auth_payload: AuthPayload {
                kind: "caip122".to_owned(),
                chains: vec!["eip155:1".to_owned()],
                aud: "https://example.com/login".to_owned(),
                domain: "example.com".to_owned(),
                version: "1".to_owned(),
                nonce: "1234567890".to_owned(),
                iat: "2026-05-26T17:16:14.225Z".to_owned(),
                statement: Some("Sign in".to_owned()),
                exp: Some("2026-05-26T18:16:14.225Z".to_owned()),
                nbf: Some("2026-05-26T17:16:14.225Z".to_owned()),
                request_id: Some("request-1".to_owned()),
                resources: vec!["urn:recap:test".to_owned()],
            },
            expiry_timestamp: 1_779_819_374,
        },
    );

    let value = serde_json::to_value(request).expect("serializes");

    assert_eq!(value["method"], "wc_sessionAuthenticate");
    assert_eq!(value["params"]["authPayload"]["type"], "caip122");
    assert_eq!(value["params"]["authPayload"]["requestId"], "request-1");
    assert_eq!(
        value["params"]["authPayload"]["resources"],
        json!(["urn:recap:test"])
    );
    assert_eq!(value["params"]["expiryTimestamp"], 1_779_819_374);
}

#[test]
fn optional_auth_payload_fields_can_be_absent() {
    let value = json!({
        "authPayload": {
            "type": "caip122",
            "chains": ["eip155:1"],
            "aud": "https://example.com/login",
            "domain": "example.com",
            "version": "1",
            "nonce": "1234567890",
            "iat": "2026-05-26T17:16:14.225Z"
        },
        "requester": {
            "publicKey": "351b54461d6075e0bcc0084f3f901cb7cdf4b16135e8ffa46a3a7193c6125b2e",
            "metadata": {
                "name": "Dapp",
                "description": "Dapp",
                "url": "https://example.com/dapp",
                "icons": []
            }
        },
        "expiryTimestamp": 1_779_819_374
    });

    let params = serde_json::from_value::<SessionAuthenticateParams>(value).expect("parses");

    assert_eq!(params.auth_payload.statement, None);
    assert_eq!(params.auth_payload.resources, Vec::<String>::new());
    assert!(!params.is_expired_at(1_700_000_000));
}
