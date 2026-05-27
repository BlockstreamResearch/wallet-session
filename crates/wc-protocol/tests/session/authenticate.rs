use serde_json::json;

use super::{chain, chain_strings, did_pkh};
use wc_protocol::session::{
    AuthPayload, Cacao, CacaoHeader, CacaoHeaderType, CacaoPayload, CacaoSignature,
    CacaoSignatureType, DappMetadata, JsonRpcError, JsonRpcErrorCode, JsonRpcErrorResponse,
    JsonRpcRequest, JsonRpcResponse, SessionAuthenticateParams, SessionAuthenticateResult,
    SessionParticipant, SignMethod,
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

const LIVE_SESSION_AUTHENTICATE_APPROVE_JSON: &str = r#"{
  "id": 1779862258791507,
  "jsonrpc": "2.0",
  "result": {
    "cacaos": [
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
          "iat": "2026-05-27T06:10:58.791Z",
          "statement": "",
          "resources": [
            "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XX19fQ"
          ]
        },
        "s": {
          "t": "eip191",
          "s": "0x5851cc642b66ba30b0073bd3a46c141d46d426eb013465aead257597ca3282a5530db47176d8400e79ac6ed0f8e53ffe87f5d52df421d712be2cbeb02e4768011b"
        }
      }
    ],
    "responder": {
      "publicKey": "977b7da860028df30993e70f25cc6d4f8dd67c4c2e8bb7a84b091a0f9cc37809",
      "metadata": {
        "name": "wc-rs live auth wallet",
        "description": "Temporary live probe wallet",
        "url": "https://example.com/wallet",
        "icons": [
          ""
        ]
      }
    }
  }
}"#;

const LIVE_SESSION_AUTHENTICATE_REJECT_JSON: &str = r#"{
  "id": 1779863175935310,
  "jsonrpc": "2.0",
  "error": {
    "code": 5000,
    "message": "User rejected."
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
    assert_eq!(
        chain_strings(&request.params.auth_payload.chains),
        ["eip155:1"]
    );
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
                chains: vec![chain("eip155:1")],
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

#[test]
fn deserializes_live_authenticate_approve_result_shape() {
    let response = serde_json::from_str::<JsonRpcResponse<SessionAuthenticateResult>>(
        LIVE_SESSION_AUTHENTICATE_APPROVE_JSON,
    )
    .expect("session authenticate approval parses");

    assert_eq!(response.id, 1_779_862_258_791_507);
    assert_eq!(
        response.result.responder.metadata.name,
        "wc-rs live auth wallet"
    );

    let cacao = response.result.cacaos.first().expect("live cacao");
    assert_eq!(cacao.h.kind, CacaoHeaderType::Caip122);
    assert_eq!(
        cacao.p.iss.as_str(),
        "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"
    );
    assert_eq!(cacao.p.domain, "example.com");
    assert_eq!(cacao.p.aud, "https://example.com/login");
    assert_eq!(cacao.p.version, "1");
    assert_eq!(cacao.p.nonce, "1234567890");
    assert_eq!(cacao.p.iat, "2026-05-27T06:10:58.791Z");
    assert_eq!(cacao.p.statement.as_deref(), Some(""));
    assert_eq!(
        cacao.p.resources,
        ["urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XX19fQ"]
    );
    assert_eq!(cacao.s.kind, CacaoSignatureType::Eip191);
    assert!(cacao.s.signature.starts_with("0x"));

    let payload_value = serde_json::to_value(&cacao.p).expect("serializes payload");
    assert!(payload_value.get("chains").is_none());
}

#[test]
fn serializes_authenticate_approve_result_wire_shape() {
    let response = JsonRpcResponse::new(
        42,
        SessionAuthenticateResult {
            responder: SessionParticipant {
                public_key: "wallet-public-key".to_owned(),
                metadata: DappMetadata {
                    name: "Wallet".to_owned(),
                    description: "Wallet".to_owned(),
                    url: "https://example.com/wallet".to_owned(),
                    icons: vec![],
                    verify_url: None,
                    redirect: None,
                },
            },
            cacaos: vec![Cacao {
                h: CacaoHeader {
                    kind: CacaoHeaderType::Caip122,
                },
                p: CacaoPayload {
                    iss: did_pkh("did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"),
                    domain: "example.com".to_owned(),
                    aud: "https://example.com/login".to_owned(),
                    version: "1".to_owned(),
                    nonce: "1234567890".to_owned(),
                    iat: "2026-05-27T06:10:58.791Z".to_owned(),
                    statement: Some(String::new()),
                    exp: None,
                    nbf: None,
                    request_id: None,
                    resources: vec![],
                },
                s: CacaoSignature {
                    kind: CacaoSignatureType::Eip191,
                    signature: "0x00".to_owned(),
                    meta: None,
                },
            }],
        },
    );

    let value = serde_json::to_value(response).expect("serializes");

    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["result"]["cacaos"][0]["h"]["t"], "caip122");
    assert_eq!(value["result"]["cacaos"][0]["s"]["t"], "eip191");
    assert_eq!(value["result"]["cacaos"][0]["p"]["statement"], "");
    assert!(value["result"].get("auths").is_none());
    assert!(value["result"]["cacaos"][0]["p"].get("chains").is_none());
}

#[test]
fn cacao_type_values_preserve_known_and_unknown_wire_names() {
    let value = json!({
        "h": {
            "t": "eip4361"
        },
        "p": {
            "iss": "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87",
            "domain": "example.com",
            "aud": "https://example.com/login",
            "version": "1",
            "nonce": "1234567890",
            "iat": "2026-05-27T06:10:58.791Z"
        },
        "s": {
            "t": "eip1271",
            "s": "0x01",
            "m": "contract-wallet"
        }
    });

    let cacao = serde_json::from_value::<Cacao>(value).expect("parses");

    assert_eq!(cacao.h.kind, CacaoHeaderType::Eip4361);
    assert_eq!(cacao.h.kind.as_str(), "eip4361");
    assert_eq!(cacao.s.kind, CacaoSignatureType::Eip1271);
    assert_eq!(cacao.s.kind.as_str(), "eip1271");
    assert_eq!(cacao.s.meta.as_deref(), Some("contract-wallet"));
    assert_eq!(
        cacao.p.iss.account_id_str(),
        "eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"
    );

    let header = serde_json::from_value::<CacaoHeader>(json!({
        "t": "future-header"
    }))
    .expect("unknown header parses");
    assert_eq!(
        header.kind,
        CacaoHeaderType::Other("future-header".to_owned())
    );
    assert_eq!(
        serde_json::to_value(header).expect("serializes")["t"],
        "future-header"
    );
}

#[test]
fn deserializes_live_authenticate_reject_shape() {
    let response =
        serde_json::from_str::<JsonRpcErrorResponse>(LIVE_SESSION_AUTHENTICATE_REJECT_JSON)
            .expect("session authenticate rejection parses");

    assert_eq!(response.id, 1_779_863_175_935_310);
    assert_eq!(response.error.code, JsonRpcErrorCode::UserRejected);
    assert_eq!(response.error.code.as_i64(), 5000);
    assert_eq!(response.error.message, "User rejected.");
    assert_eq!(response.error.data, None);
}

#[test]
fn serializes_authenticate_reject_wire_shape() {
    let response = JsonRpcErrorResponse::new(
        7,
        JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected."),
    );

    let value = serde_json::to_value(response).expect("serializes");

    assert_eq!(value["id"], 7);
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["error"]["code"], 5000);
    assert_eq!(value["error"]["message"], "User rejected.");
    assert!(value["error"].get("data").is_none());
    assert!(value.get("result").is_none());
}

#[test]
fn error_codes_preserve_known_and_unknown_wire_numbers() {
    assert_eq!(
        JsonRpcErrorCode::from_i64(-32602),
        JsonRpcErrorCode::InvalidParams
    );
    assert_eq!(
        JsonRpcErrorCode::from_i64(10001),
        JsonRpcErrorCode::WcMethodUnsupported
    );
    assert_eq!(
        JsonRpcErrorCode::from_i64(42_000),
        JsonRpcErrorCode::Other(42_000)
    );

    let error = JsonRpcError::with_data(
        JsonRpcErrorCode::Other(42_000),
        "Custom error.",
        json!({
            "source": "test"
        }),
    );

    let value = serde_json::to_value(error).expect("serializes");

    assert_eq!(value["code"], 42_000);
    assert_eq!(value["message"], "Custom error.");
    assert_eq!(value["data"]["source"], "test");

    let parsed = serde_json::from_value::<JsonRpcError>(value).expect("deserializes");
    assert_eq!(parsed.code, JsonRpcErrorCode::Other(42_000));
}
