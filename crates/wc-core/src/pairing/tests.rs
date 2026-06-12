use super::{
    approval::{session_proposal_approval_publishes, session_proposal_reject_publish},
    client::{relay_connection_url, validate_pairing_not_expired},
    codec::{
        decode_session_lifecycle_response_data, decode_session_message_data,
        decode_session_message_data_unchecked, decode_session_settle_response_data,
        decode_subscription_data, validate_session_message_payload,
    },
    pairing_lifecycle::pairing_ping_response_publish,
    session_authenticate::{
        session_authenticate_error_publish, session_authenticate_success_publish,
    },
    session_lifecycle::{
        session_delete_request_publish, session_delete_response_publish,
        session_event_request_publish, session_extend_request_publish,
        session_extend_response_publish, session_ping_response_publish,
        session_update_error_publish, session_update_request_publish,
        session_update_response_publish,
    },
    session_request::{
        session_request_error_publish, session_request_success_publish,
        session_request_validation_error,
    },
    *,
};
use wc_protocol::{
    did::DidPkh,
    dto::pairing::{
        PairingJsonRpcRequest, PairingJsonRpcResponse, PairingMethod, PairingPingParams,
    },
    envelope::{Envelope, EnvelopeEncoding, EnvelopeType},
    key::{
        X25519KeyPair, X25519PrivateKey, derive_shared_sym_key, derive_topic_from_x25519_public_key,
    },
    pairing::{PairingSymKey, PairingUri},
    pairing_message::PairingMessage,
    relay::{IrnPublish, IrnSubscriptionData, RelayTopic},
    session::{
        AuthPayload, Cacao, CacaoHeader, CacaoHeaderType, CacaoPayload, CacaoSignature,
        CacaoSignatureType, CacaoSignatureValue, DappMetadata, JsonRpcError, JsonRpcErrorCode,
        JsonRpcErrorResponse, JsonRpcRequest, JsonRpcResponse, ProposalRequestsResponses,
        RelayProtocolOptions, Session, SessionAuthenticateParams, SessionAuthenticateResult,
        SessionDeleteParams, SessionDeleteResponse, SessionEvent, SessionEventName,
        SessionEventParams, SessionExtendParams, SessionExtendResponse, SessionNamespace,
        SessionParticipant, SessionPingParams, SessionPingResponse, SessionProposeErrorResponse,
        SessionProposeParams, SessionProposeResult, SessionRequestParams, SessionSettleParams,
        SessionTransportType, SessionUpdateParams, SessionUpdateResponse, SignMethod,
        session_ack_response,
    },
    verify::VerifyAttestationHash,
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
fn pairing_client_config_debug_redacts_auth_seed() {
    let seed = RelayAuthSeed::new([7; 32]);
    let config = PairingClientConfig::new("project", seed, "subject");

    let seed_debug = format!("{seed:?}");
    let config_debug = format!("{config:?}");

    assert_eq!(seed_debug, "RelayAuthSeed(<redacted>)");
    assert!(config_debug.contains("RelayAuthSeed(<redacted>)"));
    assert!(!config_debug.contains("[7, 7"));
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
        attestation: Some("verify-jwt".to_owned()),
        encrypted_id: Some("encrypted-id".to_owned()),
    };

    let received = decode_subscription_data(data, &sym_key)?;

    assert!(received.encoded_message_len() > plaintext.len());
    assert_eq!(received.published_at(), 1_700_000_000_000);
    assert_eq!(received.tag(), Some(1100));
    assert_eq!(
        received.verify_jwt_attestation(),
        Some(("verify-jwt", "encrypted-id"))
    );
    assert_eq!(received.message().plaintext(), plaintext);
    assert!(matches!(received.payload(), PairingPayload::PairingPing(_)));

    Ok(())
}

#[test]
fn decodes_session_authenticate_pairing_payload() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )?;
    let request = session_authenticate_request()?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        RelayTopic::from_hex("11".repeat(32))?,
        Some(1116),
    )?;

    let received = decode_subscription_data(data, &sym_key)?;

    let PairingPayload::SessionAuthenticate(request) = received.payload() else {
        panic!("expected session authenticate payload");
    };
    assert_eq!(request.id, 9);
    assert_eq!(request.params.auth_payload.domain, "example.com");
    assert_eq!(received.tag(), Some(1116));

    Ok(())
}

#[test]
fn builds_session_authenticate_error_publish() -> Result<(), Box<dyn std::error::Error>> {
    let pairing_sym_key = PairingSymKey::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )?;
    let subscription = pairing_subscription(pairing_sym_key.clone())?;
    let request = session_authenticate_request()?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &pairing_sym_key,
        subscription.topic().clone(),
        Some(1116),
    )?;
    let received = decode_subscription_data(data, &pairing_sym_key)?;
    let responder = X25519KeyPair::from_private_key(X25519PrivateKey::from_hex(
        "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
    )?);
    let error = JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected.");

    let publish = session_authenticate_error_publish(&subscription, &received, error, &responder)?;
    let response_sym_key = derive_shared_sym_key(
        responder.private_key(),
        &request.params.requester.public_key,
    );
    let envelope = Envelope::decode(&publish.message, EnvelopeEncoding::Base64)?;
    let response: JsonRpcErrorResponse = decrypt_publish(&publish, &response_sym_key)?;

    assert_eq!(
        publish.topic,
        derive_topic_from_x25519_public_key(&request.params.requester.public_key)
    );
    assert_eq!(publish.ttl, SESSION_AUTHENTICATE_REJECT_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_AUTHENTICATE_REJECT_TAG);
    assert_eq!(envelope.envelope_type(), EnvelopeType::Type1);
    assert_eq!(
        envelope.sender_public_key(),
        Some(&responder.public_key().to_bytes())
    );
    assert_eq!(response.id, request.id);
    assert_eq!(response.error.code, JsonRpcErrorCode::UserRejected);

    Ok(())
}

#[test]
fn builds_session_authenticate_success_publish() -> Result<(), Box<dyn std::error::Error>> {
    let pairing_sym_key = PairingSymKey::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )?;
    let subscription = pairing_subscription(pairing_sym_key.clone())?;
    let request = session_authenticate_request()?;
    let data = encrypted_subscription_data_for_topic(
        &request,
        &pairing_sym_key,
        subscription.topic().clone(),
        Some(1116),
    )?;
    let received = decode_subscription_data(data, &pairing_sym_key)?;
    let responder = X25519KeyPair::from_private_key(X25519PrivateKey::from_hex(
        "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
    )?);
    let publish = session_authenticate_success_publish(
        &subscription,
        &received,
        wallet_metadata(),
        vec![auth_cacao()?],
        &responder,
    )?;
    let response_sym_key = derive_shared_sym_key(
        responder.private_key(),
        &request.params.requester.public_key,
    );
    let envelope = Envelope::decode(&publish.message, EnvelopeEncoding::Base64)?;
    let response: JsonRpcResponse<SessionAuthenticateResult> =
        decrypt_publish(&publish, &response_sym_key)?;

    assert_eq!(
        publish.topic,
        derive_topic_from_x25519_public_key(&request.params.requester.public_key)
    );
    assert_eq!(publish.ttl, SESSION_AUTHENTICATE_RESPONSE_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_AUTHENTICATE_RESPONSE_TAG);
    assert_eq!(envelope.envelope_type(), EnvelopeType::Type1);
    assert_eq!(
        envelope.sender_public_key(),
        Some(&responder.public_key().to_bytes())
    );
    assert_eq!(response.id, request.id);
    assert_eq!(response.result.responder.metadata.name, "Rust Wallet");
    assert_eq!(response.result.cacaos.len(), 1);
    assert_eq!(
        response.result.cacaos[0].p.iss.as_str(),
        "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"
    );

    Ok(())
}

#[test]
fn builds_pairing_ping_response_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )?;
    let subscription = pairing_subscription(sym_key.clone())?;
    let request = PairingJsonRpcRequest::new(77, PairingMethod::Ping, PairingPingParams::default());
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1002),
    )?;
    let received = decode_subscription_data(data, &sym_key)?;

    let publish = pairing_ping_response_publish(&subscription, &received)?;
    let response: PairingJsonRpcResponse<bool> = decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, PAIRING_PING_RESPONSE_TTL_SECONDS);
    assert_eq!(publish.tag, PAIRING_PING_RESPONSE_TAG);
    assert_eq!(response.id, 77);
    assert!(response.result);

    Ok(())
}

#[test]
fn pairing_ping_response_rejects_non_ping_message() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "2222222222222222222222222222222222222222222222222222222222222222",
    )?;
    let subscription = pairing_subscription(sym_key.clone())?;
    let proposal = session_proposal_request()?;
    let data = encrypted_subscription_data_for_topic(
        &proposal,
        &sym_key,
        subscription.topic().clone(),
        Some(1100),
    )?;
    let received = decode_subscription_data(data, &sym_key)?;

    assert!(matches!(
        pairing_ping_response_publish(&subscription, &received)
            .expect_err("session proposal is not a pairing ping"),
        PairingClientError::PairingResponseTargetNotPing
    ));

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
    let mut approval = SessionProposalApproval::new(
        approved_eip155_namespaces()?,
        wallet_metadata(),
        4_102_444_800,
    );
    let cacao = auth_cacao()?;
    approval.proposal_requests_responses = Some(ProposalRequestsResponses {
        authentication: Some(vec![cacao.clone()]),
        wallet_pay: Some(vec![serde_json::json!({"id": "payment-1"})]),
    });

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
    assert_eq!(publishes.session.authentication, Some(vec![cacao]));
    assert_eq!(
        publishes
            .session
            .wallet_pay_result
            .as_ref()
            .and_then(|results| results.first())
            .and_then(|result| result.get("id"))
            .and_then(serde_json::Value::as_str),
        Some("payment-1")
    );
    assert!(
        settle_request
            .params
            .proposal_requests_responses
            .as_ref()
            .and_then(|responses| responses.authentication.as_ref())
            .is_some_and(|authentication| authentication.len() == 1)
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
fn decodes_session_request_with_exact_verify_hash() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let plaintext = concat!(
        r#"{"id":7,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"#,
        r#""request":{"method":"personal_sign","params":["0x68656c6c6f","#,
        r#""0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],"#,
        r#""expiryTimestamp":1700000300},"chainId":"eip155:1"}}"#
    );
    let data = encrypted_subscription_data_from_plaintext_for_topic(
        plaintext,
        &sym_key,
        subscription.topic().clone(),
        Some(1108),
    )?;

    let received = decode_session_message_data(data, &subscription, &session, 1_700_000_000)?;

    assert_eq!(received.plaintext_len(), plaintext.len());
    assert_eq!(
        received.verify_attestation_hash().as_str(),
        "c80b3a0b3cea362433fc277cbf54d43b6b277d8f829de423c671e1fe6e6b3797"
    );
    let review = crate::SessionRequestReview::from_message(&received)?;
    assert_eq!(
        review
            .verify_attestation_hash()
            .expect("received message has verify hash")
            .as_str(),
        "c80b3a0b3cea362433fc277cbf54d43b6b277d8f829de423c671e1fe6e6b3797"
    );
    match received.payload() {
        SessionPayload::SessionRequest(request) => {
            assert_eq!(request.id, 7);
            assert_eq!(request.params.chain_id.as_str(), "eip155:1");
            assert_eq!(request.params.request.method.as_str(), "personal_sign");
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    Ok(())
}

#[test]
fn decodes_session_request_with_verify_jwt_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let plaintext = r#"{"id":7,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"personal_sign","params":[]},"chainId":"eip155:1"}}"#;
    let envelope = Envelope::encrypt_type_0(plaintext, &sym_key)?;
    let data = IrnSubscriptionData {
        topic: subscription.topic().clone(),
        message: envelope.encode(EnvelopeEncoding::Base64),
        published_at: 1_700_000_000_000,
        tag: Some(1108),
        attestation: Some("verify-jwt".to_owned()),
        encrypted_id: Some("encrypted-id".to_owned()),
    };

    let received = decode_session_message_data(data, &subscription, &session, 1_700_000_000)?;
    let review = crate::SessionRequestReview::from_message(&received)?;

    assert_eq!(
        received.verify_jwt_attestation(),
        Some(("verify-jwt", "encrypted-id"))
    );
    assert_eq!(
        review.verify_jwt_attestation(),
        Some(("verify-jwt", "encrypted-id"))
    );

    Ok(())
}

#[test]
fn decodes_session_ping() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = JsonRpcRequest::new(88, SignMethod::SessionPing, SessionPingParams::default());
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1114),
    )?;

    let received = decode_session_message_data(data, &subscription, &session, 4_000_000_000)?;

    assert_eq!(received.tag(), Some(1114));
    match received.payload() {
        SessionPayload::SessionPing(request) => {
            assert_eq!(request.id, 88);
            assert_eq!(request.params, SessionPingParams::default());
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    Ok(())
}

#[test]
fn decodes_session_delete() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = JsonRpcRequest::new(
        89,
        SignMethod::SessionDelete,
        SessionDeleteParams::user_disconnected(),
    );
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(1112),
    )?;

    let received = decode_session_message_data(data, &subscription, &session, 4_000_000_000)?;

    assert_eq!(received.tag(), Some(1112));
    match received.payload() {
        SessionPayload::SessionDelete(request) => {
            assert_eq!(request.id, 89);
            assert_eq!(
                request.params.message,
                SessionDeleteParams::USER_DISCONNECTED_MESSAGE
            );
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    Ok(())
}

#[test]
fn decodes_session_update() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = JsonRpcRequest::new(
        90,
        SignMethod::SessionUpdate,
        SessionUpdateParams {
            namespaces: session.namespaces.clone(),
        },
    );
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(SESSION_UPDATE_REQUEST_TAG),
    )?;

    let received = decode_session_message_data(data, &subscription, &session, 4_000_000_000)?;

    assert_eq!(received.tag(), Some(SESSION_UPDATE_REQUEST_TAG));
    match received.payload() {
        SessionPayload::SessionUpdate(request) => {
            assert_eq!(request.id, 90);
            assert_eq!(request.params.namespaces, session.namespaces);
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    Ok(())
}

#[test]
fn decodes_session_extend() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = JsonRpcRequest::new(
        91,
        SignMethod::SessionExtend,
        SessionExtendParams::default(),
    );
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(SESSION_EXTEND_REQUEST_TAG),
    )?;

    let received = decode_session_message_data(data, &subscription, &session, 4_000_000_000)?;

    assert_eq!(received.tag(), Some(SESSION_EXTEND_REQUEST_TAG));
    match received.payload() {
        SessionPayload::SessionExtend(request) => {
            assert_eq!(request.id, 91);
            assert_eq!(request.params, SessionExtendParams::default());
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    Ok(())
}

#[test]
fn decodes_session_event() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = JsonRpcRequest::new(92, SignMethod::SessionEvent, session_event_params()?);
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(SESSION_EVENT_REQUEST_TAG),
    )?;

    let received = decode_session_message_data(data, &subscription, &session, 4_000_000_000)?;

    assert_eq!(received.tag(), Some(SESSION_EVENT_REQUEST_TAG));
    match received.payload() {
        SessionPayload::SessionEvent(request) => {
            assert_eq!(request.id, 92);
            assert_eq!(request.params.chain_id.as_str(), "eip155:1");
            assert_eq!(request.params.event.name.as_str(), "accountsChanged");
        }
        other => panic!("unexpected payload: {other:?}"),
    }

    Ok(())
}

#[test]
fn rejects_unauthorized_session_event() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let request = JsonRpcRequest::new(
        92,
        SignMethod::SessionEvent,
        SessionEventParams {
            event: SessionEvent {
                name: "sessionChanged".parse()?,
                data: serde_json::json!(null),
            },
            chain_id: "eip155:1".parse()?,
        },
    );
    let data = encrypted_subscription_data_for_topic(
        &request,
        &sym_key,
        subscription.topic().clone(),
        Some(SESSION_EVENT_REQUEST_TAG),
    )?;

    assert!(matches!(
        decode_session_message_data(data, &subscription, &session, 4_000_000_000)
            .expect_err("unapproved event should fail"),
        PairingClientError::SessionUnauthorizedEvent { .. }
    ));

    Ok(())
}

#[test]
fn classifies_session_request_as_client_event() -> Result<(), Box<dyn std::error::Error>> {
    let subscription = session_subscription(PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?)?;
    let message = SessionReceivedMessage {
        topic: subscription.topic().clone(),
        encoded_message_len: 1,
        plaintext_len: 1,
        verify_attestation_hash: placeholder_verify_hash(),
        verify_attestation_jwt: None,
        verify_encrypted_id: None,
        published_at: 1_779_954_250_000,
        tag: Some(1108),
        payload: SessionPayload::SessionRequest(Box::new(session_request(
            77,
            "eip155:1",
            "personal_sign",
            Some(4_102_444_700),
        )?)),
    };

    let event = SessionClientEvent::from_message(message);

    assert_eq!(event.topic(), subscription.topic());
    assert!(event.rejection().is_none());
    match event {
        SessionClientEvent::SessionRequest(message) => {
            assert_eq!(message.tag(), Some(1108));
            assert!(matches!(
                message.payload(),
                SessionPayload::SessionRequest(_)
            ));
        }
        other => panic!("unexpected event: {other:?}"),
    }

    Ok(())
}

#[test]
fn classifies_rejected_session_request_as_client_event() -> Result<(), Box<dyn std::error::Error>> {
    let subscription = session_subscription(PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?)?;
    let rejection = SessionRequestRejection {
        topic: subscription.topic().clone(),
        request_id: 77,
        error: JsonRpcError::new(JsonRpcErrorCode::UnauthorizedMethod, "Unsupported method."),
        response_ack: true,
    };

    let event =
        SessionClientEvent::from_outcome(SessionMessageOutcome::Rejected(rejection.clone()));

    assert_eq!(event.topic(), subscription.topic());
    assert_eq!(event.message(), None);
    assert_eq!(event.rejection(), Some(&rejection));
    assert!(matches!(
        event,
        SessionClientEvent::RejectedSessionRequest(_)
    ));

    Ok(())
}

#[test]
fn classifies_unparsed_session_payload_as_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    let subscription = session_subscription(PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?)?;
    let message = SessionReceivedMessage {
        topic: subscription.topic().clone(),
        encoded_message_len: 1,
        plaintext_len: 1,
        verify_attestation_hash: placeholder_verify_hash(),
        verify_attestation_jwt: None,
        verify_encrypted_id: None,
        published_at: 1_779_954_250_000,
        tag: Some(1114),
        payload: SessionPayload::Sign(SignMethod::SessionPing),
    };

    let event = SessionClientEvent::from_message(message);

    assert_eq!(event.topic(), subscription.topic());
    assert!(event.rejection().is_none());
    match event {
        SessionClientEvent::Unsupported(message) => {
            assert!(matches!(message.payload(), SessionPayload::Sign(_)));
        }
        other => panic!("unexpected event: {other:?}"),
    }

    Ok(())
}

#[test]
fn classifies_pairing_proposal_as_client_event() -> Result<(), Box<dyn std::error::Error>> {
    let request = session_proposal_request()?;
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let plaintext = serde_json::to_string(&request)?;
    let envelope = Envelope::encrypt_type_0(&plaintext, &sym_key)?;
    let message = PairingReceivedMessage {
        topic: RelayTopic::from_hex("11".repeat(32))?,
        encoded_message_len: envelope.encode(EnvelopeEncoding::Base64).len(),
        published_at: 1_779_954_250_000,
        tag: Some(1100),
        verify_attestation_jwt: Some("relay-verify-jwt".to_owned()),
        verify_encrypted_id: Some("relay-encrypted-id".to_owned()),
        message: PairingMessage::decode_relay_message(
            wc_protocol::pairing_message::EncryptedRelayEnvelope::new(
                &envelope.encode(EnvelopeEncoding::Base64),
            ),
            &sym_key,
        )?,
        payload: PairingPayload::SessionProposal(Box::new(request)),
    };

    let event = crate::SingleSessionClientEvent::from_pairing_message(message);

    match event {
        crate::SingleSessionClientEvent::SessionProposal(proposal) => {
            assert_eq!(proposal.proposal_id(), 7);
            assert_eq!(proposal.pairing_topic().as_str(), "11".repeat(32));
            assert_eq!(
                proposal.request().params.proposer.metadata.name,
                "Probe Dapp"
            );
            assert_eq!(
                proposal.verify_context().verified.origin,
                "https://example.com"
            );
            assert_eq!(proposal.verify_risk(), crate::VerifyContextRisk::Unknown);
            assert_eq!(
                proposal.verify_jwt_attestation(),
                Some(("relay-verify-jwt", "relay-encrypted-id"))
            );
        }
        other => panic!("unexpected event: {other:?}"),
    }

    Ok(())
}

#[test]
fn classifies_pairing_authenticate_as_client_event() -> Result<(), Box<dyn std::error::Error>> {
    let request = session_authenticate_request()?;
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let plaintext = serde_json::to_string(&request)?;
    let envelope = Envelope::encrypt_type_0(&plaintext, &sym_key)?;
    let message = PairingReceivedMessage {
        topic: RelayTopic::from_hex("11".repeat(32))?,
        encoded_message_len: envelope.encode(EnvelopeEncoding::Base64).len(),
        published_at: 1_779_954_250_000,
        tag: Some(1116),
        verify_attestation_jwt: Some("relay-verify-jwt".to_owned()),
        verify_encrypted_id: Some("relay-encrypted-id".to_owned()),
        message: PairingMessage::decode_relay_message(
            wc_protocol::pairing_message::EncryptedRelayEnvelope::new(
                &envelope.encode(EnvelopeEncoding::Base64),
            ),
            &sym_key,
        )?,
        payload: PairingPayload::SessionAuthenticate(Box::new(request)),
    };

    let event = crate::SingleSessionClientEvent::from_pairing_message(message);

    match event {
        crate::SingleSessionClientEvent::SessionAuthenticate(authenticate) => {
            assert_eq!(authenticate.request_id(), 9);
            assert_eq!(authenticate.pairing_topic().as_str(), "11".repeat(32));
            assert_eq!(
                authenticate.request().params.auth_payload.domain,
                "example.com"
            );
            assert_eq!(
                authenticate.verify_context().verified.origin,
                "https://example.com"
            );
            assert_eq!(
                authenticate.verify_risk(),
                crate::VerifyContextRisk::Unknown
            );
            assert_eq!(
                authenticate.verify_jwt_attestation(),
                Some(("relay-verify-jwt", "relay-encrypted-id"))
            );
        }
        other => panic!("unexpected event: {other:?}"),
    }

    Ok(())
}

#[test]
fn client_config_wraps_pairing_config() {
    let pairing = PairingClientConfig::new("project", [7; 32], "subject");
    let config = crate::SingleSessionClientConfig::new(pairing.clone());

    assert_eq!(config.pairing().project_id, pairing.project_id);
    assert_eq!(
        config.max_queued_events(),
        crate::DEFAULT_SINGLE_SESSION_CLIENT_EVENT_QUEUE_CAPACITY
    );
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
fn builds_session_ping_response_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let received = SessionReceivedMessage {
        topic: subscription.topic().clone(),
        encoded_message_len: 1,
        plaintext_len: 1,
        verify_attestation_hash: placeholder_verify_hash(),
        verify_attestation_jwt: None,
        verify_encrypted_id: None,
        published_at: 1_779_954_250_000,
        tag: Some(1114),
        payload: SessionPayload::SessionPing(JsonRpcRequest::new(
            88,
            SignMethod::SessionPing,
            SessionPingParams::default(),
        )),
    };

    let publish = session_ping_response_publish(&subscription, &received)?;
    let response: SessionPingResponse = decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_PING_RESPONSE_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_PING_RESPONSE_TAG);
    assert_eq!(response.id, 88);
    assert_eq!(response.result, wc_protocol::session::SessionAck);

    Ok(())
}

#[test]
fn builds_session_update_response_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let session = session_from_subscription(&subscription)?;
    let received = SessionReceivedMessage {
        topic: subscription.topic().clone(),
        encoded_message_len: 1,
        plaintext_len: 1,
        verify_attestation_hash: placeholder_verify_hash(),
        verify_attestation_jwt: None,
        verify_encrypted_id: None,
        published_at: 1_779_954_250_000,
        tag: Some(1104),
        payload: SessionPayload::SessionUpdate(JsonRpcRequest::new(
            90,
            SignMethod::SessionUpdate,
            SessionUpdateParams {
                namespaces: session.namespaces,
            },
        )),
    };

    let publish = session_update_response_publish(&subscription, &received)?;
    let response: SessionUpdateResponse = decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_UPDATE_RESPONSE_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_UPDATE_RESPONSE_TAG);
    assert_eq!(response.id, 90);
    assert_eq!(response.result, wc_protocol::session::SessionAck);

    Ok(())
}

#[test]
fn builds_session_update_error_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let session = session_from_subscription(&subscription)?;
    let received = SessionReceivedMessage {
        topic: subscription.topic().clone(),
        encoded_message_len: 1,
        plaintext_len: 1,
        verify_attestation_hash: placeholder_verify_hash(),
        verify_attestation_jwt: None,
        verify_encrypted_id: None,
        published_at: 1_779_954_250_000,
        tag: Some(1104),
        payload: SessionPayload::SessionUpdate(JsonRpcRequest::new(
            92,
            SignMethod::SessionUpdate,
            SessionUpdateParams {
                namespaces: session.namespaces,
            },
        )),
    };

    let publish = session_update_error_publish(
        &subscription,
        &received,
        JsonRpcError::new(
            JsonRpcErrorCode::UserRejected,
            "User rejected session update.",
        ),
    )?;
    let response: JsonRpcErrorResponse = decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_UPDATE_RESPONSE_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_UPDATE_RESPONSE_TAG);
    assert_eq!(response.id, 92);
    assert_eq!(response.error.code, JsonRpcErrorCode::UserRejected);

    Ok(())
}

#[test]
fn builds_session_extend_response_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let received = SessionReceivedMessage {
        topic: subscription.topic().clone(),
        encoded_message_len: 1,
        plaintext_len: 1,
        verify_attestation_hash: placeholder_verify_hash(),
        verify_attestation_jwt: None,
        verify_encrypted_id: None,
        published_at: 1_779_954_250_000,
        tag: Some(1106),
        payload: SessionPayload::SessionExtend(JsonRpcRequest::new(
            91,
            SignMethod::SessionExtend,
            SessionExtendParams::default(),
        )),
    };

    let publish = session_extend_response_publish(&subscription, &received)?;
    let response: SessionExtendResponse = decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_EXTEND_RESPONSE_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_EXTEND_RESPONSE_TAG);
    assert_eq!(response.id, 91);
    assert_eq!(response.result, wc_protocol::session::SessionAck);

    Ok(())
}

#[test]
fn builds_session_delete_response_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let received = SessionReceivedMessage {
        topic: subscription.topic().clone(),
        encoded_message_len: 1,
        plaintext_len: 1,
        verify_attestation_hash: placeholder_verify_hash(),
        verify_attestation_jwt: None,
        verify_encrypted_id: None,
        published_at: 1_779_954_250_000,
        tag: Some(1112),
        payload: SessionPayload::SessionDelete(JsonRpcRequest::new(
            89,
            SignMethod::SessionDelete,
            SessionDeleteParams::user_disconnected(),
        )),
    };

    let publish = session_delete_response_publish(&subscription, &received)?;
    let response: SessionDeleteResponse = decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_DELETE_RESPONSE_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_DELETE_RESPONSE_TAG);
    assert_eq!(response.id, 89);
    assert_eq!(response.result, wc_protocol::session::SessionAck);

    Ok(())
}

#[test]
fn builds_session_delete_request_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;

    let publish = session_delete_request_publish(
        &subscription,
        &session,
        SessionDeleteParams::user_disconnected(),
        103,
        4_000_000_000,
    )?;
    let request: JsonRpcRequest<SessionDeleteParams> = decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_DELETE_REQUEST_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_DELETE_REQUEST_TAG);
    assert_eq!(request.id, 103);
    assert_eq!(request.method, SignMethod::SessionDelete);
    assert_eq!(
        request.params.message,
        SessionDeleteParams::USER_DISCONNECTED_MESSAGE
    );

    Ok(())
}

#[test]
fn builds_session_update_request_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let namespaces = session.namespaces.clone();

    let publish =
        session_update_request_publish(&subscription, &session, &namespaces, 100, 4_000_000_000)?;
    let request: JsonRpcRequest<SessionUpdateParams> = decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_UPDATE_REQUEST_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_UPDATE_REQUEST_TAG);
    assert_eq!(request.id, 100);
    assert_eq!(request.method, SignMethod::SessionUpdate);
    assert_eq!(request.params.namespaces, namespaces);

    Ok(())
}

#[test]
fn builds_session_extend_request_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;

    let publish = session_extend_request_publish(&subscription, &session, 101, 4_000_000_000)?;
    let request: JsonRpcRequest<SessionExtendParams> = decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_EXTEND_REQUEST_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_EXTEND_REQUEST_TAG);
    assert_eq!(request.id, 101);
    assert_eq!(request.method, SignMethod::SessionExtend);
    assert_eq!(request.params, SessionExtendParams::default());

    Ok(())
}

#[test]
fn builds_session_event_request_publish() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let params = session_event_params()?;

    let publish =
        session_event_request_publish(&subscription, &session, &params, 102, 4_000_000_000)?;
    let request: JsonRpcRequest<SessionEventParams> = decrypt_publish(&publish, &sym_key)?;

    assert_eq!(publish.topic, *subscription.topic());
    assert_eq!(publish.ttl, SESSION_EVENT_REQUEST_TTL_SECONDS);
    assert_eq!(publish.tag, SESSION_EVENT_REQUEST_TAG);
    assert_eq!(request.id, 102);
    assert_eq!(request.method, SignMethod::SessionEvent);
    assert_eq!(request.params.chain_id.as_str(), "eip155:1");
    assert_eq!(request.params.event.name.as_str(), "accountsChanged");

    Ok(())
}

#[test]
fn rejects_outbound_session_lifecycle_before_acknowledgement()
-> Result<(), Box<dyn std::error::Error>> {
    let subscription = session_subscription(PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?)?;
    let session = session_from_subscription(&subscription)?;

    assert!(matches!(
        session_update_request_publish(
            &subscription,
            &session,
            &session.namespaces,
            100,
            4_000_000_000,
        )
        .expect_err("pending update should fail"),
        PairingClientError::SessionNotAcknowledged { .. }
    ));
    assert!(matches!(
        session_extend_request_publish(&subscription, &session, 101, 4_000_000_000)
            .expect_err("pending extend should fail"),
        PairingClientError::SessionNotAcknowledged { .. }
    ));
    assert!(matches!(
        session_event_request_publish(
            &subscription,
            &session,
            &session_event_params()?,
            102,
            4_000_000_000,
        )
        .expect_err("pending event should fail"),
        PairingClientError::SessionNotAcknowledged { .. }
    ));
    assert!(matches!(
        session_delete_request_publish(
            &subscription,
            &session,
            SessionDeleteParams::user_disconnected(),
            103,
            4_000_000_000,
        )
        .expect_err("pending delete should fail"),
        PairingClientError::SessionNotAcknowledged { .. }
    ));

    Ok(())
}

#[test]
fn rejects_outbound_unauthorized_session_event() -> Result<(), Box<dyn std::error::Error>> {
    let subscription = session_subscription(PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?)?;
    let mut session = session_from_subscription(&subscription)?;
    session.acknowledged = true;
    let params = SessionEventParams {
        event: SessionEvent {
            name: "sessionChanged".parse()?,
            data: serde_json::json!(null),
        },
        chain_id: "eip155:1".parse()?,
    };

    assert!(matches!(
        session_event_request_publish(&subscription, &session, &params, 102, 4_000_000_000)
            .expect_err("unapproved event should fail"),
        PairingClientError::SessionUnauthorizedEvent { .. }
    ));

    Ok(())
}

#[test]
fn decodes_session_lifecycle_success_response() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let response = session_ack_response(100);
    let data = encrypted_subscription_data_for_topic(
        &response,
        &sym_key,
        subscription.topic().clone(),
        Some(SESSION_UPDATE_RESPONSE_TAG),
    )?;

    let received = decode_session_lifecycle_response_data(data, &subscription, 100)?;

    assert_eq!(received.tag(), Some(SESSION_UPDATE_RESPONSE_TAG));
    match received.payload() {
        SessionLifecycleResponsePayload::Success(response) => {
            assert_eq!(response.id, 100);
            assert_eq!(response.result, wc_protocol::session::SessionAck);
        }
        other @ SessionLifecycleResponsePayload::Error(_) => {
            panic!("unexpected payload: {other:?}")
        }
    }

    Ok(())
}

#[test]
fn decodes_session_lifecycle_error_response() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let response = JsonRpcErrorResponse::new(
        101,
        JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected."),
    );
    let data = encrypted_subscription_data_for_topic(
        &response,
        &sym_key,
        subscription.topic().clone(),
        Some(SESSION_EXTEND_RESPONSE_TAG),
    )?;

    let received = decode_session_lifecycle_response_data(data, &subscription, 101)?;

    assert_eq!(received.tag(), Some(SESSION_EXTEND_RESPONSE_TAG));
    match received.payload() {
        SessionLifecycleResponsePayload::Error(response) => {
            assert_eq!(response.id, 101);
            assert_eq!(response.error.code, JsonRpcErrorCode::UserRejected);
        }
        other @ SessionLifecycleResponsePayload::Success(_) => {
            panic!("unexpected payload: {other:?}")
        }
    }

    Ok(())
}

#[test]
fn rejects_session_lifecycle_response_with_wrong_id() -> Result<(), Box<dyn std::error::Error>> {
    let sym_key = PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?;
    let subscription = session_subscription(sym_key.clone())?;
    let response = session_ack_response(102);
    let data = encrypted_subscription_data_for_topic(
        &response,
        &sym_key,
        subscription.topic().clone(),
        Some(SESSION_UPDATE_RESPONSE_TAG),
    )?;

    assert!(matches!(
        decode_session_lifecycle_response_data(data, &subscription, 100)
            .expect_err("wrong response id should fail"),
        PairingClientError::SessionResponseIdMismatch {
            expected: 100,
            actual: 102
        }
    ));

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
        verify_attestation_hash: placeholder_verify_hash(),
        verify_attestation_jwt: None,
        verify_encrypted_id: None,
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
        verify_attestation_hash: placeholder_verify_hash(),
        verify_attestation_jwt: None,
        verify_encrypted_id: None,
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

#[test]
fn rejects_non_ping_session_response_target() -> Result<(), Box<dyn std::error::Error>> {
    let subscription = session_subscription(PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?)?;
    let received = SessionReceivedMessage {
        topic: subscription.topic().clone(),
        encoded_message_len: 1,
        plaintext_len: 1,
        verify_attestation_hash: placeholder_verify_hash(),
        verify_attestation_jwt: None,
        verify_encrypted_id: None,
        published_at: 1_779_954_250_000,
        tag: Some(1108),
        payload: SessionPayload::SessionRequest(Box::new(session_request(
            77,
            "eip155:1",
            "personal_sign",
            Some(4_102_444_700),
        )?)),
    };

    assert!(matches!(
        session_ping_response_publish(&subscription, &received)
            .expect_err("non-ping payload is rejected"),
        PairingClientError::SessionResponseTargetNotPing
    ));

    Ok(())
}

#[test]
fn rejects_non_delete_session_response_target() -> Result<(), Box<dyn std::error::Error>> {
    let subscription = session_subscription(PairingSymKey::from_hex(
        "3333333333333333333333333333333333333333333333333333333333333333",
    )?)?;
    let received = SessionReceivedMessage {
        topic: subscription.topic().clone(),
        encoded_message_len: 1,
        plaintext_len: 1,
        verify_attestation_hash: placeholder_verify_hash(),
        verify_attestation_jwt: None,
        verify_encrypted_id: None,
        published_at: 1_779_954_250_000,
        tag: Some(1114),
        payload: SessionPayload::SessionPing(JsonRpcRequest::new(
            88,
            SignMethod::SessionPing,
            SessionPingParams::default(),
        )),
    };

    assert!(matches!(
        session_delete_response_publish(&subscription, &received)
            .expect_err("non-delete payload is rejected"),
        PairingClientError::SessionResponseTargetNotDelete
    ));

    Ok(())
}

fn encrypted_subscription_data(
    plaintext: &str,
    sym_key: &PairingSymKey,
) -> Result<IrnSubscriptionData, Box<dyn std::error::Error>> {
    encrypted_subscription_data_from_plaintext_for_topic(
        plaintext,
        sym_key,
        RelayTopic::from_hex("11".repeat(32))?,
        Some(1100),
    )
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
    encrypted_subscription_data_from_plaintext_for_topic(&plaintext, sym_key, topic, tag)
}

fn encrypted_subscription_data_from_plaintext_for_topic(
    plaintext: &str,
    sym_key: &PairingSymKey,
    topic: RelayTopic,
    tag: Option<u64>,
) -> Result<IrnSubscriptionData, Box<dyn std::error::Error>> {
    let envelope = Envelope::encrypt_type_0(plaintext, sym_key)?;

    Ok(IrnSubscriptionData {
        topic,
        message: envelope.encode(EnvelopeEncoding::Base64),
        published_at: 1_779_954_250_000,
        tag,
        attestation: None,
        encrypted_id: None,
    })
}

fn placeholder_verify_hash() -> VerifyAttestationHash {
    VerifyAttestationHash::from_message("{}")
}

fn pairing_subscription(
    sym_key: PairingSymKey,
) -> Result<PairingSubscription, Box<dyn std::error::Error>> {
    Ok(PairingSubscription {
        topic: RelayTopic::from_hex("11".repeat(32))?,
        sym_key,
        subscription_id: "pairing-sub-1".to_owned(),
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

fn session_authenticate_request()
-> Result<JsonRpcRequest<SessionAuthenticateParams>, Box<dyn std::error::Error>> {
    Ok(JsonRpcRequest::new(
        9,
        SignMethod::SessionAuthenticate,
        SessionAuthenticateParams {
            requester: SessionParticipant {
                public_key: X25519PrivateKey::from_hex(
                    "4afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
                )?
                .public_key(),
                metadata: DappMetadata {
                    name: "Authenticate Dapp".to_owned(),
                    description: "Authentication probe".to_owned(),
                    url: "https://example.com".to_owned(),
                    icons: vec!["https://example.com/icon.png".to_owned()],
                    verify_url: None,
                    redirect: None,
                },
            },
            auth_payload: AuthPayload {
                kind: CacaoHeaderType::Caip122,
                chains: vec!["eip155:1".parse()?],
                aud: "https://example.com/login".to_owned(),
                domain: "example.com".to_owned(),
                version: "1".to_owned(),
                nonce: "1234567890".to_owned(),
                iat: "2026-05-28T12:00:00.000Z".to_owned(),
                statement: Some("Sign in to Example".to_owned()),
                exp: None,
                nbf: None,
                request_id: None,
                resources: vec!["urn:recap:eyJhdHQiOnsifX0".to_owned()],
            },
            expiry_timestamp: 4_102_444_800,
        },
    ))
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

fn session_event_params() -> Result<SessionEventParams, Box<dyn std::error::Error>> {
    Ok(SessionEventParams {
        event: SessionEvent {
            name: SessionEventName::parse("accountsChanged")?,
            data: serde_json::json!(["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"]),
        },
        chain_id: "eip155:1".parse()?,
    })
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

fn approved_eip155_namespaces()
-> Result<wc_protocol::session::SessionNamespaces, Box<dyn std::error::Error>> {
    Ok(std::collections::BTreeMap::from([(
        "eip155".parse()?,
        SessionNamespace {
            chains: Some(vec!["eip155:1".parse()?]),
            accounts: vec!["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".parse()?],
            methods: vec!["personal_sign".parse()?],
            events: vec!["accountsChanged".parse()?],
        },
    )]))
}

fn auth_cacao() -> Result<Cacao, Box<dyn std::error::Error>> {
    Ok(Cacao {
        h: CacaoHeader {
            kind: CacaoHeaderType::Caip122,
        },
        p: CacaoPayload {
            iss: DidPkh::parse("did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87")?,
            domain: "example.com".to_owned(),
            aud: "https://example.com/login".to_owned(),
            version: "1".to_owned(),
            nonce: "1234567890".to_owned(),
            iat: "2026-05-28T12:00:00.000Z".to_owned(),
            statement: Some("Sign in to Example".to_owned()),
            exp: None,
            nbf: None,
            request_id: None,
            resources: vec!["urn:recap:eyJhdHQiOnsifX0".to_owned()],
        },
        s: CacaoSignature {
            kind: CacaoSignatureType::Eip191,
            signature: CacaoSignatureValue::from_wire("0x00"),
            meta: None,
        },
    })
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
