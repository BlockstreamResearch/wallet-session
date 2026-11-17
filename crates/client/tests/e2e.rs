use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message as WsMessage,
};
use wallet_session_client::{
    AckPayload, Client, ClientConfig, ClientError, ClientEvent, ClientMessage, IdentityKey, Opaque,
    PairingKey, ProposalPayload, RequestPayload, Role, Seed, SessionState, XChaCha20Poly1305Cipher,
    crypto::{Aad, SealedPayload},
    handshake::{EphemeralKeyPair, decode_public_key},
};
use wallet_session_core::{
    connection::ConnectionQuery,
    crypto::MessageCipher,
    did::DidKey,
    frame::{RelayFrame, RelayFrameBody},
    message::{Ciphertext, Message as Envelope, MessageId, MessageType, Topic},
};
use wallet_session_relay::{
    config::NativeRelayTransportConfig,
    limits::{Limiter, RelayLimitsConfig},
    registry::Registry,
    server::serve,
};

const AUDIENCE: &str = "wss://relay.example.com";

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn sealed_request_response() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run()).await??;
    Ok(())
}

/// Request/response over the relay with real XChaCha20-Poly1305 encryption.
async fn run() -> TestResult {
    let _ = env_logger::builder()
        .is_test(true)
        .parse_default_env()
        .try_init();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(serve(
        listener,
        Arc::new(Registry::new()),
        Arc::new(Limiter::new(RelayLimitsConfig::default())),
        NativeRelayTransportConfig::new(AUDIENCE),
    ));

    let relay_url = format!("ws://{addr}");
    let pairing = PairingKey::random()?;
    let topic = pairing.topic()?;
    let key = *pairing.as_bytes();

    let proposer_config = ClientConfig::new(&relay_url)
        .with_insecure_ws()
        .with_audience(AUDIENCE)
        .with_registration_id("reg-1");
    let responder_config = ClientConfig::new(&relay_url)
        .with_insecure_ws()
        .with_audience(AUDIENCE);

    let mut proposer = Client::connect(
        proposer_config,
        IdentityKey::from_seed(&Seed::from_bytes([1u8; 32])),
        Role::Proposer,
        topic.clone(),
        XChaCha20Poly1305Cipher::new(key)?,
    )
    .await?;
    let mut responder = Client::connect(
        responder_config,
        IdentityKey::from_seed(&Seed::from_bytes([2u8; 32])),
        Role::Responder,
        topic.clone(),
        XChaCha20Poly1305Cipher::new(key)?,
    )
    .await?;

    proposer.wait_session_ready().await?;
    responder.wait_session_ready().await?;

    proposer
        .propose(json!({ "capabilities": ["read"] }))
        .await?;
    match responder.recv().await? {
        ClientMessage::Proposal(payload) => {
            let proposal: serde_json::Value = serde_json::from_slice(&payload.proposal.0)?;
            assert_eq!(proposal, json!({ "capabilities": ["read"] }));
        }
        other => panic!("expected proposal, got {other:?}"),
    }

    responder.approve(json!({ "ok": true })).await?;
    assert!(matches!(proposer.recv().await?, ClientMessage::Approve(_)));

    proposer.wait_session_ready().await?;
    responder.wait_session_ready().await?;
    assert_ne!(proposer.session().topic, topic);
    assert_ne!(responder.session().topic, topic);
    assert_eq!(proposer.session().pairing_topic, topic);
    assert_eq!(responder.session().pairing_topic, topic);

    assert!(matches!(
        responder
            .respond("invalid", Some(json!({})), Some(json!({})))
            .await,
        Err(ClientError::ProtocolViolation(_))
    ));
    assert!(matches!(
        responder.respond("invalid", None, None).await,
        Err(ClientError::ProtocolViolation(_))
    ));

    let request_id = proposer.request(json!({ "method": "get_status" })).await?;
    match responder.recv().await? {
        ClientMessage::Request(payload) => {
            assert_eq!(payload.request_id, request_id);
            let request: serde_json::Value = serde_json::from_slice(&payload.request.0)?;
            assert_eq!(request, json!({ "method": "get_status" }));
        }
        other => panic!("expected request, got {other:?}"),
    }

    responder
        .respond(request_id.clone(), Some(json!({ "result": "ok" })), None)
        .await?;
    match proposer.recv().await? {
        ClientMessage::Response(payload) => {
            assert_eq!(payload.request_id, request_id);
            let response = payload.response.expect("response body");
            let response: serde_json::Value = serde_json::from_slice(&response.0)?;
            assert_eq!(response, json!({ "result": "ok" }));
        }
        other => panic!("expected response, got {other:?}"),
    }

    // The proposer's request was acknowledged by the responder.
    let mut delivered = Vec::new();
    while let Some(ClientEvent::Delivered { id }) = proposer.poll_event() {
        delivered.push(id);
    }
    assert!(
        delivered.iter().any(|id| id.to_string() == request_id),
        "expected a Delivered event for {request_id}, got {delivered:?}"
    );

    // A second request has no response. `next_event` must process the inbound
    // ack itself, without the application calling `recv`.
    let second = proposer
        .request(json!({ "method": "wait_for_ack" }))
        .await?;
    match responder.recv().await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, second),
        other => panic!("expected the second request, got {other:?}"),
    }
    let event = tokio::time::timeout(Duration::from_secs(2), proposer.next_event()).await??;
    assert!(
        matches!(event, ClientEvent::Delivered { ref id } if id.to_string() == second),
        "expected a Delivered event for {second}, got {event:?}"
    );

    // A local disconnect is terminal: later operations fail instead of hanging.
    proposer.disconnect("done", 4000).await?;
    match tokio::time::timeout(Duration::from_secs(2), responder.recv()).await?? {
        ClientMessage::Disconnect(payload) => assert_eq!(payload.code, 4000),
        other => panic!("expected disconnect, got {other:?}"),
    }
    assert_eq!(responder.session().state, SessionState::Disconnected);
    assert!(matches!(proposer.recv().await, Err(ClientError::Closed)));
    assert!(matches!(
        proposer
            .request(json!({ "method": "after_disconnect" }))
            .await,
        Err(ClientError::Closed)
    ));

    Ok(())
}

type RawStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn message_id(label: &str) -> MessageId {
    let mut bytes = [0u8; MessageId::LEN];
    let label = &label.as_bytes()[..label.len().min(MessageId::LEN)];
    bytes[..label.len()].copy_from_slice(label);
    MessageId::from_bytes(bytes)
}

async fn connect_raw(
    relay_url: &str,
    identity: &IdentityKey,
    role: Role,
    topic: &Topic,
) -> Result<RawStream, Box<dyn std::error::Error>> {
    let token = identity.connection_token("e2e-raw", AUDIENCE, Duration::from_secs(60))?;
    let query = ConnectionQuery {
        auth: token,
        role,
        topic: topic.clone(),
        registration_id: None,
    };
    let mut url = url::Url::parse(relay_url)?;
    url.set_query(Some(&serde_urlencoded::to_string(&query)?));
    let (stream, _) = connect_async(url.as_str()).await?;
    Ok(stream)
}

async fn read_raw_frame(stream: &mut RawStream) -> Result<RelayFrame, Box<dyn std::error::Error>> {
    loop {
        match stream.next().await {
            Some(Ok(WsMessage::Text(text))) => return Ok(serde_json::from_str(&text)?),
            Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
            Some(Ok(WsMessage::Close(frame))) => {
                return Err(std::io::Error::other(format!(
                    "relay closed the connection: {frame:?}"
                ))
                .into());
            }
            Some(Ok(_)) => continue,
            Some(Err(error)) => return Err(error.into()),
            None => return Err(std::io::Error::other("relay stream ended").into()),
        }
    }
}

async fn wait_raw_session_ready(stream: &mut RawStream) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let frame = read_raw_frame(stream).await?;
        if matches!(frame.body, RelayFrameBody::SessionReady) {
            return Ok(());
        }
    }
}

fn seal_message(
    topic: &Topic,
    from: DidKey,
    id: MessageId,
    message: &ClientMessage,
    role: Role,
    cipher: &mut XChaCha20Poly1305Cipher,
) -> Result<RelayFrame, Box<dyn std::error::Error>> {
    let ts = unix_now();
    let aad = Aad::new(&id, message.message_type(), topic, &from, ts, role).to_bytes();
    let plaintext = message.to_bytes()?;
    let sealed = cipher.seal(&aad, &plaintext)?;
    let wire = Envelope::new(message.message_type(), from, ts, sealed.nonce, sealed.data);
    Ok(RelayFrame {
        v: 1,
        id,
        topic: topic.clone(),
        body: RelayFrameBody::Message {
            payload: serde_json::to_string(&wire)?,
        },
    })
}

fn open_message(
    frame: &RelayFrame,
    cipher: &XChaCha20Poly1305Cipher,
    receiver_role: Role,
) -> Result<ClientMessage, Box<dyn std::error::Error>> {
    let RelayFrameBody::Message { payload } = &frame.body else {
        return Err("expected a message frame".into());
    };
    let wire: Envelope = serde_json::from_str(payload)?;
    let aad = Aad::new(
        &frame.id,
        wire.kind,
        &frame.topic,
        &wire.from,
        wire.ts,
        receiver_role.counterpart(),
    )
    .to_bytes();
    let bytes = cipher.open(
        &aad,
        &SealedPayload {
            nonce: wire.nonce.clone(),
            data: wire.data.clone(),
        },
    )?;
    Ok(ClientMessage::from_bytes(&bytes)?)
}

fn tamper(frame: RelayFrame) -> Result<RelayFrame, Box<dyn std::error::Error>> {
    let mut frame = frame;
    let RelayFrameBody::Message { payload } = &mut frame.body else {
        return Err("expected a message frame".into());
    };
    let mut wire: Envelope = serde_json::from_str(payload)?;
    let mut bytes = wire.data.as_bytes().to_vec();
    *bytes.first_mut().ok_or("empty ciphertext")? ^= 0x01;
    wire.data = Ciphertext::new(bytes);
    *payload = serde_json::to_string(&wire)?;
    Ok(frame)
}

fn request(request_id: &str) -> ClientMessage {
    ClientMessage::Request(RequestPayload {
        request_id: request_id.to_owned(),
        request: Opaque(
            serde_json::to_vec(&json!({ "method": "get_status" })).expect("request JSON"),
        ),
    })
}

#[tokio::test]
async fn session_topic_requires_the_derived_key() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_session_key()).await??;
    Ok(())
}

/// With a real cipher, the session topic must reject frames sealed with the
/// pairing key or with tampered session ciphertext, and accept a frame sealed
/// with the derived session key.
async fn run_session_key() -> TestResult {
    let _ = env_logger::builder()
        .is_test(true)
        .parse_default_env()
        .try_init();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(serve(
        listener,
        Arc::new(Registry::new()),
        Arc::new(Limiter::new(RelayLimitsConfig::default())),
        NativeRelayTransportConfig::new(AUDIENCE),
    ));

    let relay_url = format!("ws://{addr}");
    let pairing = PairingKey::random()?;
    let topic = pairing.topic()?;
    let key = *pairing.as_bytes();
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        responder_identity,
        Role::Responder,
        topic.clone(),
        XChaCha20Poly1305Cipher::new(key)?,
    )
    .await?;
    let mut pairing_stream =
        connect_raw(&relay_url, &proposer_identity, Role::Proposer, &topic).await?;
    responder.wait_session_ready().await?;
    wait_raw_session_ready(&mut pairing_stream).await?;

    let mut pairing_cipher = XChaCha20Poly1305Cipher::new(key)?;
    let keypair = EphemeralKeyPair::generate();
    let proposal = ClientMessage::Proposal(ProposalPayload {
        ephemeral_public_key: keypair.public_key_encoded(),
        session_expiry: 0,
        proposal: Opaque(serde_json::to_vec(&json!({ "test": true }))?),
    });
    let proposal_frame = seal_message(
        &topic,
        proposer_identity.did(),
        message_id("proposal"),
        &proposal,
        Role::Proposer,
        &mut pairing_cipher,
    )?;
    pairing_stream
        .send(WsMessage::text(serde_json::to_string(&proposal_frame)?))
        .await?;
    assert!(matches!(
        responder.recv().await?,
        ClientMessage::Proposal(_)
    ));

    responder.approve(json!({ "ok": true })).await?;
    let approve_frame = loop {
        let frame = read_raw_frame(&mut pairing_stream).await?;
        let RelayFrameBody::Message { payload } = &frame.body else {
            continue;
        };
        let wire: Envelope = serde_json::from_str(payload)?;
        if wire.kind == MessageType::Approve {
            break frame;
        }
    };
    let approve = open_message(&approve_frame, &pairing_cipher, Role::Proposer)?;
    let ClientMessage::Approve(approve) = approve else {
        return Err("expected approve".into());
    };
    let client_public = decode_public_key(&approve.ephemeral_public_key)?;
    let (session_key, session_topic) = keypair.derive(&client_public)?;
    let session_topic = session_topic.as_topic().clone();

    let ack = ClientMessage::Ack(AckPayload {
        ack_id: approve_frame.id.clone(),
    });
    let ack_frame = seal_message(
        &topic,
        proposer_identity.did(),
        message_id("approve-ack"),
        &ack,
        Role::Proposer,
        &mut pairing_cipher,
    )?;
    pairing_stream
        .send(WsMessage::text(serde_json::to_string(&ack_frame)?))
        .await?;
    match tokio::time::timeout(Duration::from_secs(2), responder.next_event()).await?? {
        ClientEvent::Delivered { id } => assert_eq!(id, approve_frame.id),
        other => panic!("expected approve delivery, got {other:?}"),
    }

    let mut session_cipher = XChaCha20Poly1305Cipher::new(*session_key.as_bytes())?;
    let mut session_stream = connect_raw(
        &relay_url,
        &proposer_identity,
        Role::Proposer,
        &session_topic,
    )
    .await?;
    wait_raw_session_ready(&mut session_stream).await?;
    responder.wait_session_ready().await?;

    // Wrong key: the pairing cipher on the session topic.
    let wrong_key = request("wrong-key");
    let wrong_frame = seal_message(
        &session_topic,
        proposer_identity.did(),
        message_id("wrong-key"),
        &wrong_key,
        Role::Proposer,
        &mut pairing_cipher,
    )?;
    session_stream
        .send(WsMessage::text(serde_json::to_string(&wrong_frame)?))
        .await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), responder.recv())
            .await
            .is_err(),
        "a frame sealed with the pairing key must not be delivered"
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            read_raw_frame(&mut session_stream)
        )
        .await
        .is_err(),
        "a frame sealed with the pairing key must not be acknowledged"
    );

    // Tampered session ciphertext.
    let valid = request("valid-session");
    let valid_frame = seal_message(
        &session_topic,
        proposer_identity.did(),
        message_id("valid-session"),
        &valid,
        Role::Proposer,
        &mut session_cipher,
    )?;
    let tampered = tamper(valid_frame.clone())?;
    session_stream
        .send(WsMessage::text(serde_json::to_string(&tampered)?))
        .await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), responder.recv())
            .await
            .is_err(),
        "a tampered session frame must not be delivered"
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            read_raw_frame(&mut session_stream)
        )
        .await
        .is_err(),
        "a tampered session frame must not be acknowledged"
    );

    // Valid session frame.
    session_stream
        .send(WsMessage::text(serde_json::to_string(&valid_frame)?))
        .await?;
    match responder.recv().await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, "valid-session"),
        other => panic!("expected valid session request, got {other:?}"),
    }
    let ack_frame = read_raw_frame(&mut session_stream).await?;
    match open_message(&ack_frame, &session_cipher, Role::Proposer)? {
        ClientMessage::Ack(payload) => assert_eq!(payload.ack_id, valid_frame.id),
        other => panic!("expected session ack, got {other:?}"),
    }

    Ok(())
}
