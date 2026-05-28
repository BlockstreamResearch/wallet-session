use super::{
    approval::{session_proposal_approval_publishes, session_proposal_reject_publish},
    client::{relay_connection_url, validate_pairing_not_expired},
    codec::{
        decode_session_message_data, decode_session_message_data_unchecked,
        decode_session_settle_response_data, decode_subscription_data,
        validate_session_message_payload,
    },
    session_request::{
        session_request_error_publish, session_request_success_publish,
        session_request_validation_error,
    },
    *,
};
use wc_protocol::{
    envelope::{Envelope, EnvelopeEncoding},
    key::{X25519KeyPair, X25519PrivateKey},
    pairing::{PairingSymKey, PairingUri},
    relay::{IrnPublish, IrnSubscriptionData, RelayTopic},
    session::{
        DappMetadata, JsonRpcError, JsonRpcErrorCode, JsonRpcErrorResponse, JsonRpcRequest,
        JsonRpcResponse, RelayProtocolOptions, Session, SessionNamespace, SessionParticipant,
        SessionProposeErrorResponse, SessionProposeParams, SessionProposeResult,
        SessionRequestParams, SessionSettleParams, SessionTransportType, SignMethod,
        session_ack_response,
    },
};

const PAIRING_URI: &str = concat!(
    "wc:1111111111111111111111111111111111111111111111111111111111111111@2",
    "?relay-protocol=irn",
    "&symKey=2222222222222222222222222222222222222222222222222222222222222222",
    "&expiryTimestamp=4102444800"
);

#[test]
fn config_builds_authenticated_relay_url() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = PairingClientConfig::new("project", [7; 32], "subject");
    config.relay_url = "wss://relay.walletconnect.com?existing=1".to_owned();
    config.user_agent = "wc-2/rust-poc/test".to_owned();

    let url = relay_connection_url(&config, 1_700_000_000)?;
    let value = url.as_str();

    assert!(value.starts_with("wss://relay.walletconnect.com/?existing=1&auth="));
    assert!(value.contains("&projectId=project"));
    assert!(value.contains("&ua=wc-2%2Frust-poc%2Ftest"));

    Ok(())
}

#[test]
fn validates_pairing_expiry() -> Result<(), Box<dyn std::error::Error>> {
    let pairing = PairingUri::parse(PAIRING_URI)?;

    validate_pairing_not_expired(&pairing, 4_000_000_000)?;
    let error =
        validate_pairing_not_expired(&pairing, 4_102_444_800).expect_err("expired URI should fail");

    assert!(matches!(error, PairingClientError::PairingExpired { .. }));

    Ok(())
}

#[test]
fn decodes_subscription_data_with_pairing_key() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )?;
    let plaintext = r#"{"id":1,"jsonrpc":"2.0","method":"wc_pairingPing","params":{}}"#;
    let envelope = Envelope::encrypt_type_0(plaintext, &sym_key)?;
    let data = IrnSubscriptionData {
        topic: RelayTopic::from_hex("11".repeat(32))?,
        message: envelope.encode(EnvelopeEncoding::Base64),
        published_at: 1_700_000_000_000,
        tag: Some(1100),
    };

    let received = decode_subscription_data(data, &sym_key)?;

    assert!(received.encoded_message_len() > plaintext.len());
    assert_eq!(received.published_at(), 1_700_000_000_000);
    assert_eq!(received.tag(), Some(1100));
    assert_eq!(received.message().plaintext(), plaintext);
    assert!(matches!(received.payload(), PairingPayload::PairingPing(_)));

    Ok(())
}

#[test]
fn parses_session_proposal_payload() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )?;
    let plaintext = concat!(
        r#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{"#,
        r#""id":1,"pairingTopic":"1111111111111111111111111111111111111111111111111111111111111111","#,
        r#""expiryTimestamp":4102444800,"relays":[{"protocol":"irn"}],"#,
        r#""proposer":{"publicKey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
        r#""metadata":{"name":"Probe Dapp","description":"Probe","url":"https://example.com","icons":[]}},"#,
        r#""requiredNamespaces":{},"optionalNamespaces":{}}}"#
    );
    let data = encrypted_subscription_data(plaintext, &sym_key)?;

    let received = decode_subscription_data(data, &sym_key)?;

    let PairingPayload::SessionProposal(request) = received.payload() else {
        panic!("expected typed session proposal");
    };
    assert_eq!(request.id, 1);
    assert_eq!(request.params.proposer.metadata.name, "Probe Dapp");

    Ok(())
}

#[test]
fn rejects_malformed_known_payload() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )?;
    let plaintext = r#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{}}"#;
    let data = encrypted_subscription_data(plaintext, &sym_key)?;

    let error = decode_subscription_data(data, &sym_key)
        .expect_err("known method with malformed params should fail");

    assert!(matches!(error, PairingClientError::PairingPayload { .. }));

    Ok(())
}

#[test]
fn builds_session_proposal_reject_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )?;
    let subscription = PairingSubscription {
        topic: RelayTopic::from_hex("11".repeat(32))?,
        sym_key: sym_key.clone(),
        subscription_id: "sub-1".to_owned(),
    };

    let publish = session_proposal_reject_publish(
        &subscription,
        7,
        JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected."),
    )?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_PROPOSE_REJECT_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_PROPOSE_REJECT_TAG);
    assert_eq!(publish.prompt, None);

    let envelope = Envelope::decode(&publish.message, EnvelopeEncoding::Base64)?;
    let plaintext = envelope.decrypt(&sym_key)?;
    let response = serde_json::from_str::<SessionProposeErrorResponse>(&plaintext)?;

    assert_eq!(response.id, 7);
    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.error.code, JsonRpcErrorCode::UserRejected);
    assert_eq!(response.error.message, "User rejected.");

    Ok(())
}

#[test]
fn builds_session_proposal_approval_publishes() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )?;
    let subscription = PairingSubscription {
        topic: RelayTopic::from_hex("11".repeat(32))?,
        sym_key: sym_key.clone(),
        subscription_id: "sub-1".to_owned(),
    };
    let proposal = session_proposal_request()?;
    let responder = X25519KeyPair::from_private_key(X25519PrivateKey::from_hex(
        "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
    )?);
    let approval = SessionProposalApproval::new(
        std::collections::BTreeMap::from([(
            "eip155".parse()?,
            SessionNamespace {
                chains: Some(vec!["eip155:1".parse()?]),
                accounts: vec!["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".parse()?],
                methods: vec!["personal_sign".parse()?],
                events: vec!["accountsChanged".parse()?],
            },
        )]),
        wallet_metadata(),
        4_102_444_800,
    );

    let publishes =
        session_proposal_approval_publishes(&subscription, &proposal, approval, &responder, 9)?;

    assert_eq!(publishes.proposal_response.topic, *subscription.topic());
    assert_eq!(
        publishes.proposal_response.ttl,
        SESSION_PROPOSE_RESPONSE_TTL_SECONDS
    );
    assert_eq!(
        publishes.proposal_response.tag,
        SESSION_PROPOSE_RESPONSE_TAG
    );
    assert_eq!(publishes.session_settle.topic, publishes.session_topic);
    assert_eq!(
        publishes.session_settle.ttl,
        SESSION_SETTLE_REQUEST_TTL_SECONDS
    );
    assert_eq!(publishes.session_settle.tag, SESSION_SETTLE_REQUEST_TAG);

    let proposal_response = decrypt_publish::<JsonRpcResponse<SessionProposeResult>>(
        &publishes.proposal_response,
        &sym_key,
    )?;
    assert_eq!(proposal_response.id, proposal.id);
    assert_eq!(
        proposal_response.result.responder_public_key,
        *responder.public_key()
    );

    let settle_request = decrypt_publish::<JsonRpcRequest<SessionSettleParams>>(
        &publishes.session_settle,
        &publishes.session_sym_key,
    )?;
    assert_eq!(settle_request.id, 9);
    assert_eq!(settle_request.method, SignMethod::SessionSettle);
    assert_eq!(
        settle_request.params.controller.public_key,
        *responder.public_key()
    );
    assert_eq!(
        settle_request.params.controller.metadata.name,
        "Rust Wallet"
    );
    assert_eq!(settle_request.params.namespaces["eip155"].accounts.len(), 1);
    assert_eq!(publishes.session.topic, publishes.session_topic);
    assert_eq!(publishes.session.pairing_topic, *subscription.topic());
    assert!(!publishes.session.acknowledged);
    assert_eq!(publishes.session.controller, *responder.public_key());
    assert_eq!(
        publishes.session.self_participant.metadata.name,
        "Rust Wallet"
    );
    assert_eq!(publishes.session.peer.metadata.name, "Probe Dapp");
    assert_eq!(
        publishes.session.transport_type,
        Some(SessionTransportType::Relay)
    );

    Ok(())
}

#[test]
fn acknowledged_session_marks_pending_session_active() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let session_subscription = session_subscription(sym_key)?;
    let mut pending_session = session_from_subscription(&session_subscription)?;
    pending_session.acknowledged = false;
    let approved = ApprovedSession {
        subscription: session_subscription,
        responder_public_key: X25519PrivateKey::from_hex(
            "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
        )?
        .public_key(),
        session_settle_request_id: 9,
        session: pending_session,
        proposal_response_ack: true,
        session_settle_ack: true,
    };
    let response = SessionSettleResponseMessage {
        topic: approved.session_topic().clone(),
        encoded_message_len: 112,
        published_at: 1_779_955_000_000,
        tag: Some(SESSION_SETTLE_RESPONSE_TAG),
        payload: SessionSettleResponsePayload::Success(session_ack_response(9)),
    };

    let acknowledged = approved.acknowledged_session(&response)?;

    assert!(!approved.pending_session().acknowledged);
    assert!(acknowledged.acknowledged);
    assert_eq!(acknowledged.topic, *approved.session_topic());
    assert_eq!(acknowledged.peer.metadata.name, "Probe Dapp");

    Ok(())
}

#[test]
fn acknowledged_session_rejects_settle_error_response() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let session_subscription = session_subscription(sym_key)?;
    let approved = ApprovedSession {
        responder_public_key: X25519PrivateKey::from_hex(
            "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
        )?
        .public_key(),
        session_settle_request_id: 9,
        session: session_from_subscription(&session_subscription)?,
        subscription: session_subscription,
        proposal_response_ack: true,
        session_settle_ack: true,
    };
    let response = SessionSettleResponseMessage {
        topic: approved.session_topic().clone(),
        encoded_message_len: 112,
        published_at: 1_779_955_000_000,
        tag: Some(SESSION_SETTLE_RESPONSE_TAG),
        payload: SessionSettleResponsePayload::Error(JsonRpcErrorResponse::new(
            9,
            JsonRpcError::new(
                JsonRpcErrorCode::SessionSettlementFailed,
                "settlement failed",
            ),
        )),
    };

    assert!(matches!(
        approved
            .acknowledged_session(&response)
            .expect_err("settle error is rejected"),
        PairingClientError::SessionSettleRejected { .. }
    ));

    Ok(())
}

#[test]
fn decodes_session_settle_success_response() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let response = session_ack_response(9);
    let data = encrypted_subscription_data_for_topic(
        &response,
        &sym_key,
        subscription.topic().clone(),
        Some(SESSION_SETTLE_RESPONSE_TAG),
    )?;

    let received = decode_session_settle_response_data(data, &subscription, 9)?;

    assert_eq!(received.topic(), subscription.topic());
    assert_eq!(received.tag(), Some(SESSION_SETTLE_RESPONSE_TAG));
    assert!(matches!(
        received.payload(),
        SessionSettleResponsePayload::Success(response) if response.id == 9
    ));

    Ok(())
}

#[test]
fn decodes_session_settle_error_response() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let response = JsonRpcErrorResponse::new(
        9,
        JsonRpcError::new(
            JsonRpcErrorCode::SessionSettlementFailed,
            "settlement failed",
        ),
    );
    let data = encrypted_subscription_data_for_topic(
        &response,
        &sym_key,
        subscription.topic().clone(),
        Some(SESSION_SETTLE_RESPONSE_TAG),
    )?;

    let received = decode_session_settle_response_data(data, &subscription, 9)?;

    match received.payload() {
        SessionSettleResponsePayload::Error(response) => {
            assert_eq!(response.id, 9);
            assert_eq!(
                response.error.code,
                JsonRpcErrorCode::SessionSettlementFailed
            );
        }
        SessionSettleResponsePayload::Success(response) => {
            panic!("unexpected success payload: {response:?}");
        }
    }

    Ok(())
}

#[test]
fn rejects_session_settle_response_with_wrong_id() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let response = session_ack_response(10);
    let data = encrypted_subscription_data_for_topic(
        &response,
        &sym_key,
        subscription.topic().clone(),
        Some(SESSION_SETTLE_RESPONSE_TAG),
    )?;

    assert!(matches!(
        decode_session_settle_response_data(data, &subscription, 9)
            .expect_err("wrong response id is rejected"),
        PairingClientError::SessionResponseIdMismatch {
            expected: 9,
            actual: 10
        }
    ));

    Ok(())
}

#[test]
fn decodes_authorized_session_request() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = session_request(77, "eip155:1", "personal_sign", Some(4_102_444_700))?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1108),
    )?;

    let received = decode_session_message_data(data, &subscription, &session, 4_000_000_000)?;

    assert_eq!(received.topic(), subscription.topic());
    assert_eq!(received.tag(), Some(1108));
    assert!(received.plaintext_len() > 0);
    match received.payload() {
        SessionPayload::SessionRequest(request) => {
            assert_eq!(request.id, 77);
            assert_eq!(request.params.chain_id.as_str(), "eip155:1");
            assert_eq!(request.params.request.method.as_str(), "personal_sign");
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    Ok(())
}

#[test]
fn rejects_session_message_before_acknowledgement() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let session = session_from_subscription(&subscription)?;
    let request = session_request(77, "eip155:1", "personal_sign", Some(4_102_444_700))?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1108),
    )?;

    assert!(matches!(
        decode_session_message_data(data, &subscription, &session, 4_000_000_000)
            .expect_err("pending session should not receive requests"),
        PairingClientError::SessionNotAcknowledged { .. }
    ));

    Ok(())
}

#[test]
fn rejects_expired_session_message() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    session.expiry = 99;
    let request = session_request(77, "eip155:1", "personal_sign", Some(4_102_444_700))?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1108),
    )?;

    assert!(matches!(
        decode_session_message_data(data, &subscription, &session, 100)
            .expect_err("expired session should reject messages"),
        PairingClientError::SessionExpired {
            expiry_timestamp: 99,
            now_unix_seconds: 100
        }
    ));

    Ok(())
}

#[test]
fn rejects_expired_session_request() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = session_request(77, "eip155:1", "personal_sign", Some(99))?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1108),
    )?;

    assert!(matches!(
        decode_session_message_data(data, &subscription, &session, 100)
            .expect_err("expired request should be rejected"),
        PairingClientError::SessionRequestExpired {
            expiry_timestamp: 99,
            now_unix_seconds: 100
        }
    ));

    Ok(())
}

#[test]
fn rejects_unauthorized_session_request_chain() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = session_request(77, "eip155:137", "personal_sign", Some(4_102_444_700))?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1108),
    )?;

    assert!(matches!(
        decode_session_message_data(data, &subscription, &session, 4_000_000_000)
            .expect_err("unauthorized chain should be rejected"),
        PairingClientError::SessionUnauthorizedChain { chain_id }
            if chain_id.as_str() == "eip155:137"
    ));

    Ok(())
}

#[test]
fn rejects_unauthorized_session_request_method() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = session_request(77, "eip155:1", "eth_sendTransaction", Some(4_102_444_700))?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1108),
    )?;

    assert!(matches!(
        decode_session_message_data(data, &subscription, &session, 4_000_000_000)
            .expect_err("unauthorized method should be rejected"),
        PairingClientError::SessionUnauthorizedMethod { chain_id, method }
            if chain_id.as_str() == "eip155:1" && method.as_str() == "eth_sendTransaction"
    ));

    Ok(())
}

#[test]
fn maps_unauthorized_session_request_method_to_error_response()
-> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = session_request(77, "eip155:1", "eth_sendTransaction", Some(4_102_444_700))?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1108),
    )?;
    let received =
        decode_session_message_data_unchecked(data, &subscription, &session, 4_000_000_000)?;
    let validation_error = validate_session_message_payload(&session, &received, 4_000_000_000)
        .expect_err("unauthorized method should fail validation");
    let response_error = session_request_validation_error(&validation_error)
        .expect("unauthorized method is respondable");
    let publish = session_request_error_publish(&subscription, &received, response_error)?;
    let response: wc_protocol::session::SessionRequestErrorResponse =
        decrypt_publish(&publish, &sym_key)?;

    assert_eq!(response.id, 77);
    assert_eq!(response.error.code, JsonRpcErrorCode::UnauthorizedMethod);
    assert_eq!(response.error.message, "Unauthorized method.");
    assert_eq!(
        response.error.data,
        Some(serde_json::json!({
            "chainId": "eip155:1",
            "method": "eth_sendTransaction",
        }))
    );

    Ok(())
}

#[test]
fn maps_expired_session_request_to_error_response() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = session_request(77, "eip155:1", "personal_sign", Some(99))?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1108),
    )?;
    let received = decode_session_message_data_unchecked(data, &subscription, &session, 100)?;
    let validation_error = validate_session_message_payload(&session, &received, 100)
        .expect_err("expired request should fail validation");
    let response_error = session_request_validation_error(&validation_error)
        .expect("expired request is respondable");
    let publish = session_request_error_publish(&subscription, &received, response_error)?;
    let response: wc_protocol::session::SessionRequestErrorResponse =
        decrypt_publish(&publish, &sym_key)?;

    assert_eq!(response.id, 77);
    assert_eq!(response.error.code, JsonRpcErrorCode::Other(6));
    assert_eq!(response.error.message, "Expired. session request.");
    assert_eq!(
        response.error.data,
        Some(serde_json::json!({
            "expiryTimestamp": 99,
            "nowUnixSeconds": 100,
        }))
    );

    Ok(())
}

#[test]
fn builds_session_request_success_response_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = session_request(77, "eip155:1", "personal_sign", Some(4_102_444_700))?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1108),
    )?;
    let received = decode_session_message_data(data, &subscription, &session, 4_000_000_000)?;

    let publish =
        session_request_success_publish(&subscription, &received, serde_json::json!("0xsigned"))?;
    let response: wc_protocol::session::SessionRequestResponse =
        decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_REQUEST_RESPONSE_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_REQUEST_RESPONSE_TAG);
    assert_eq!(response.id, 77);
    assert_eq!(response.result.as_value(), &serde_json::json!("0xsigned"));

    Ok(())
}

#[test]
fn builds_session_request_error_response_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = session_request(77, "eip155:1", "personal_sign", Some(4_102_444_700))?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1108),
    )?;
    let received = decode_session_message_data(data, &subscription, &session, 4_000_000_000)?;

    let publish = session_request_error_publish(
        &subscription,
        &received,
        JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected request."),
    )?;
    let response: wc_protocol::session::SessionRequestErrorResponse =
        decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_REQUEST_RESPONSE_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_REQUEST_RESPONSE_TAG);
    assert_eq!(response.id, 77);
    assert_eq!(response.error.code, JsonRpcErrorCode::UserRejected);
    assert_eq!(response.error.message, "User rejected request.");

    Ok(())
}

#[test]
fn rejects_session_request_response_for_wrong_topic() -> Result<(), Box<dyn std::error::Error>> {
    let subscription = session_subscription(PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?)?;
    let request = session_request(77, "eip155:1", "personal_sign", Some(4_102_444_700))?;
    let received = SessionReceivedMessage {
        topic: RelayTopic::from_hex("55".repeat(32))?,
        encoded_message_len: 1,
        plaintext_len: 1,
        published_at: 1_779_954_250_000,
        tag: Some(1108),
        payload: SessionPayload::SessionRequest(Box::new(request)),
    };

    assert!(matches!(
        session_request_success_publish(&subscription, &received, serde_json::json!("0xsigned"))
            .expect_err("wrong topic is rejected"),
        PairingClientError::UnexpectedTopic { .. }
    ));

    Ok(())
}

#[test]
fn rejects_non_request_session_response_target() -> Result<(), Box<dyn std::error::Error>> {
    let subscription = session_subscription(PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?)?;
    let received = SessionReceivedMessage {
        topic: subscription.topic().clone(),
        encoded_message_len: 1,
        plaintext_len: 1,
        published_at: 1_779_954_250_000,
        tag: Some(1114),
        payload: SessionPayload::Sign(SignMethod::SessionPing),
    };

    assert!(matches!(
        session_request_error_publish(
            &subscription,
            &received,
            JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected request."),
        )
        .expect_err("non-request payload is rejected"),
        PairingClientError::SessionResponseTargetNotRequest
    ));

    Ok(())
}

fn encrypted_subscription_data(
    plaintext: &str,
    sym_key: &PairingSymKey,
) -> Result<IrnSubscriptionData, Box<dyn std::error::Error>> {
    let envelope = Envelope::encrypt_type_0(plaintext, sym_key)?;
    Ok(IrnSubscriptionData {
        topic: RelayTopic::from_hex("11".repeat(32))?,
        message: envelope.encode(EnvelopeEncoding::Base64),
        published_at: 1_700_000_000_000,
        tag: Some(1100),
    })
}

fn encrypted_subscription_data_for_topic<T>(
    payload: &T,
    sym_key: &PairingSymKey,
    topic: RelayTopic,
    tag: Option<u64>,
) -> Result<IrnSubscriptionData, Box<dyn std::error::Error>>
where
    T: serde::Serialize,
{
    let plaintext = serde_json::to_string(payload)?;
    let envelope = Envelope::encrypt_type_0(&plaintext, sym_key)?;

    Ok(IrnSubscriptionData {
        topic,
        message: envelope.encode(EnvelopeEncoding::Base64),
        published_at: 1_779_954_250_000,
        tag,
    })
}

fn session_subscription(
    sym_key: PairingSymKey,
) -> Result<SessionSubscription, Box<dyn std::error::Error>> {
    Ok(SessionSubscription {
        topic: RelayTopic::from_hex("44".repeat(32))?,
        sym_key,
        subscription_id: "session-sub-1".to_owned(),
    })
}

fn session_from_subscription(
    subscription: &SessionSubscription,
) -> Result<Session, Box<dyn std::error::Error>> {
    let controller = X25519PrivateKey::from_hex(
        "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
    )?
    .public_key();
    let peer = X25519PrivateKey::from_hex(
        "4afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
    )?
    .public_key();

    Ok(Session {
        topic: subscription.topic().clone(),
        pairing_topic: RelayTopic::from_hex("11".repeat(32))?,
        relay: RelayProtocolOptions {
            protocol: "irn".to_owned(),
            data: None,
        },
        expiry: 4_102_444_800,
        acknowledged: false,
        controller: controller.clone(),
        namespaces: std::collections::BTreeMap::from([(
            "eip155".parse()?,
            SessionNamespace {
                chains: Some(vec!["eip155:1".parse()?]),
                accounts: vec!["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".parse()?],
                methods: vec!["personal_sign".parse()?],
                events: vec!["accountsChanged".parse()?],
            },
        )]),
        required_namespaces: std::collections::BTreeMap::new(),
        optional_namespaces: std::collections::BTreeMap::new(),
        session_properties: None,
        scoped_properties: None,
        session_config: None,
        self_participant: SessionParticipant {
            public_key: controller,
            metadata: wallet_metadata(),
        },
        peer: SessionParticipant {
            public_key: peer,
            metadata: DappMetadata {
                name: "Probe Dapp".to_owned(),
                description: "Probe".to_owned(),
                url: "https://example.com".to_owned(),
                icons: vec![],
                verify_url: None,
                redirect: None,
            },
        },
        authentication: None,
        wallet_pay_result: None,
        transport_type: Some(SessionTransportType::Relay),
    })
}

fn session_proposal_request()
-> Result<JsonRpcRequest<SessionProposeParams>, Box<dyn std::error::Error>> {
    let json = concat!(
        r#"{"id":7,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{"#,
        r#""id":7,"pairingTopic":"1111111111111111111111111111111111111111111111111111111111111111","#,
        r#""expiryTimestamp":4102444800,"relays":[{"protocol":"irn"}],"#,
        r#""proposer":{"publicKey":"80dd64bd6e4c3612ff0f5ccbe9282f1f11ba56ada6a2f9740da063d1ed1f2b20","#,
        r#""metadata":{"name":"Probe Dapp","description":"Probe","url":"https://example.com","icons":[]}},"#,
        r#""requiredNamespaces":{"eip155":{"chains":["eip155:1"],"methods":["personal_sign"],"events":["accountsChanged"]}},"#,
        r#""optionalNamespaces":{}}}"#
    );

    serde_json::from_str(json).map_err(Into::into)
}

fn session_request(
    id: u64,
    chain_id: &str,
    method: &str,
    expiry_timestamp: Option<u64>,
) -> Result<JsonRpcRequest<SessionRequestParams>, Box<dyn std::error::Error>> {
    let expiry = expiry_timestamp.map_or_else(String::new, |expiry| {
        format!(r#","expiryTimestamp":{expiry}"#)
    });
    let json = format!(
        r#"{{
            "id": {id},
            "jsonrpc": "2.0",
            "method": "wc_sessionRequest",
            "params": {{
                "chainId": "{chain_id}",
                "request": {{
                    "method": "{method}",
                    "params": ["0x68656c6c6f", "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"]
                    {expiry}
                }}
            }}
        }}"#
    );

    serde_json::from_str(&json).map_err(Into::into)
}

fn wallet_metadata() -> DappMetadata {
    DappMetadata {
        name: "Rust Wallet".to_owned(),
        description: "Rust Wallet".to_owned(),
        url: "https://example.com/wallet".to_owned(),
        icons: vec![],
        verify_url: None,
        redirect: None,
    }
}

fn decrypt_publish<T>(
    publish: &IrnPublish,
    sym_key: &PairingSymKey,
) -> Result<T, Box<dyn std::error::Error>>
where
    T: serde::de::DeserializeOwned,
{
    let envelope = Envelope::decode(&publish.message, EnvelopeEncoding::Base64)?;
    let plaintext = envelope.decrypt(sym_key)?;
    serde_json::from_str(&plaintext).map_err(Into::into)
}
