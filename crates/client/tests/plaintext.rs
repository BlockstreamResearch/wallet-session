use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message as WsMessage,
};
use wallet_session_client::{
    AckPayload, ApprovePayload, Client, ClientConfig, ClientError, ClientEvent, ClientMessage,
    DisconnectPayload, IdentityKey, Opaque, PairingKey, ProposalPayload, RejectPayload,
    RequestPayload, ResponsePayload, Role, Seed, SessionState,
    handshake::{EphemeralKeyPair, HandshakeError, decode_public_key},
};
use wallet_session_relay::{
    config::NativeRelayTransportConfig,
    limits::{Limiter, RateLimit, RelayLimitsConfig},
    registry::Registry,
    server::serve,
};

use wallet_session_client::crypto::{CipherError, NONCE_LEN, SENDER_PREFIX_LEN, SealedPayload};
use wallet_session_core::{
    connection::ConnectionQuery,
    crypto::MessageCipher,
    did::DidKey,
    frame::{RelayFrame, RelayFrameBody},
    message::{Ciphertext, Message as Envelope, MessageId, MessageType, Nonce, Topic},
};

const AUDIENCE: &str = "wss://relay.example.com";

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Process-unique prefix so two test clients don't share a nonce space.
static PREFIX_SEQ: AtomicU64 = AtomicU64::new(0);

/// Data the test cipher refuses to open, standing in for a bad AEAD tag.
const TAMPERED: &[u8] = b"plaintext-tampered";

/// Test-only passthrough cipher: no encryption, but a valid nonce sequence.
#[derive(Debug, Clone)]
pub struct PlaintextCipher {
    prefix: [u8; SENDER_PREFIX_LEN],
    counter: u64,
}

impl PlaintextCipher {
    /// Build a plaintext cipher with a fresh sender prefix.
    pub fn new() -> Self {
        let sequence = PREFIX_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut prefix = [0u8; SENDER_PREFIX_LEN];
        prefix[SENDER_PREFIX_LEN - 8..].copy_from_slice(&sequence.to_be_bytes());
        Self { prefix, counter: 0 }
    }

    fn nonce(&self) -> Nonce {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..SENDER_PREFIX_LEN].copy_from_slice(&self.prefix);
        nonce[SENDER_PREFIX_LEN..].copy_from_slice(&self.counter.to_be_bytes());
        Nonce::new(nonce.to_vec()).expect("nonce length")
    }
}

impl Default for PlaintextCipher {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageCipher for PlaintextCipher {
    type Sealed = SealedPayload;
    type Error = CipherError;

    fn seal(&mut self, _aad: &[u8], plaintext: &[u8]) -> Result<SealedPayload, CipherError> {
        let nonce = self.nonce();
        self.counter = self.counter.wrapping_add(1);
        Ok(SealedPayload {
            nonce,
            data: Ciphertext::new(plaintext.to_vec()),
        })
    }

    fn open(&self, _aad: &[u8], sealed: &SealedPayload) -> Result<Vec<u8>, CipherError> {
        if sealed.data.as_bytes() == TAMPERED {
            return Err(CipherError::Decrypt);
        }
        Ok(sealed.data.as_bytes().to_vec())
    }

    fn for_key(&self, _key: &[u8; 32]) -> Result<Self, CipherError> {
        Ok(Self::new())
    }
}

#[tokio::test]
async fn plaintext_request_response() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run()).await??;
    Ok(())
}

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

    let proposer_config = ClientConfig::new(&relay_url)
        .with_insecure_ws()
        .with_audience(AUDIENCE)
        .with_registration_id("reg-1");
    let responder_config = ClientConfig::new(&relay_url)
        .with_insecure_ws()
        .with_audience(AUDIENCE);

    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));

    let mut proposer = Client::connect(
        proposer_config,
        proposer_identity,
        Role::Proposer,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut responder = Client::connect(
        responder_config,
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;

    proposer.wait_session_ready().await?;
    responder.wait_session_ready().await?;

    // Relay readiness is not session establishment.
    assert_eq!(proposer.session().state, SessionState::Idle);
    assert_eq!(responder.session().state, SessionState::Idle);

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
            assert_eq!(payload.error, None);
            let response = payload.response.expect("response body");
            let response: serde_json::Value = serde_json::from_slice(&response.0)?;
            assert_eq!(response, json!({ "result": "ok" }));
        }
        other => panic!("expected response, got {other:?}"),
    }

    // Handshake kinds and manual acks are not accepted by generic `send`.
    assert!(matches!(
        proposer
            .send(&ClientMessage::Ack(AckPayload {
                ack_id: message_id("manual-ack")
            }))
            .await,
        Err(ClientError::ProtocolViolation(
            "acknowledgements are sent automatically"
        ))
    ));
    assert!(matches!(
        proposer
            .send(&ClientMessage::Proposal(ProposalPayload {
                ephemeral_public_key: "not-sent".to_owned(),
                session_expiry: 0,
                proposal: Opaque(Vec::new()),
            }))
            .await,
        Err(ClientError::UnexpectedHandshake)
    ));
    assert!(matches!(
        responder.propose(json!({ "not": "allowed" })).await,
        Err(ClientError::ProtocolViolation(
            "only the proposer may propose"
        ))
    ));
    assert!(matches!(
        proposer.approve(json!({ "not": "allowed" })).await,
        Err(ClientError::ProtocolViolation(
            "only the responder may approve"
        ))
    ));

    Ok(())
}

#[tokio::test]
async fn responder_reconnects_within_grace_and_resumes() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_reconnect()).await??;
    Ok(())
}

/// The responder drops abruptly, the proposer keeps going (its proposal is
/// buffered), and the same identity reconnects within the grace window. The
/// buffered proposal is redelivered and the handshake then completes normally.
async fn run_reconnect() -> TestResult {
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
        NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_secs(2)),
    ));

    let relay_url = format!("ws://{addr}");
    let pairing = PairingKey::random()?;
    let topic = pairing.topic()?;

    let proposer_config = ClientConfig::new(&relay_url)
        .with_insecure_ws()
        .with_audience(AUDIENCE)
        .with_registration_id("reg-1");
    let responder_config = ClientConfig::new(&relay_url)
        .with_insecure_ws()
        .with_audience(AUDIENCE);
    let responder_seed = Seed::from_bytes([2u8; 32]);

    let mut proposer = Client::connect(
        proposer_config,
        IdentityKey::from_seed(&Seed::from_bytes([1u8; 32])),
        Role::Proposer,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut responder = Client::connect(
        responder_config.clone(),
        IdentityKey::from_seed(&responder_seed),
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;

    proposer.wait_session_ready().await?;
    responder.wait_session_ready().await?;

    // The responder drops abruptly, without a disconnect message.
    drop(responder);
    // Let the relay observe the drop and reserve the responder's slot.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Sent while the responder is away: the relay buffers it for redelivery.
    proposer
        .propose(json!({ "capabilities": ["read"] }))
        .await?;

    // The same identity reconnects within the grace window.
    let mut responder = Client::connect(
        responder_config,
        IdentityKey::from_seed(&responder_seed),
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;

    responder.wait_session_ready().await?;
    match responder.recv().await? {
        ClientMessage::Proposal(payload) => {
            let proposal: serde_json::Value = serde_json::from_slice(&payload.proposal.0)?;
            assert_eq!(proposal, json!({ "capabilities": ["read"] }));
        }
        other => panic!("expected buffered proposal after reconnect, got {other:?}"),
    }

    responder.approve(json!({ "ok": true })).await?;
    assert!(matches!(proposer.recv().await?, ClientMessage::Approve(_)));
    proposer.wait_session_ready().await?;
    responder.wait_session_ready().await?;

    let request_id = proposer.request(json!({ "method": "get_status" })).await?;
    match responder.recv().await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, request_id),
        other => panic!("expected request after reconnect, got {other:?}"),
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

    Ok(())
}

#[tokio::test]
async fn survivor_is_notified_when_peer_does_not_reconnect() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_expiry()).await??;
    Ok(())
}

/// The responder drops and does not reconnect, so after the grace window the
/// relay tells the survivor, whose `recv` fails with `PeerDisconnected`.
async fn run_expiry() -> TestResult {
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
        NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_millis(200)),
    ));

    let relay_url = format!("ws://{addr}");
    let pairing = PairingKey::random()?;
    let topic = pairing.topic()?;

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
        PlaintextCipher::new(),
    )
    .await?;
    let responder = Client::connect(
        responder_config,
        IdentityKey::from_seed(&Seed::from_bytes([2u8; 32])),
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;

    proposer.wait_session_ready().await?;

    // The responder drops and never reconnects.
    drop(responder);

    let outcome = proposer.recv().await;
    assert!(
        matches!(outcome, Err(ClientError::PeerDisconnected)),
        "expected PeerDisconnected, got {outcome:?}"
    );
    assert_eq!(proposer.session().state, SessionState::Disconnected);
    assert!(
        !proposer.is_ready(),
        "peer disconnection must clear readiness"
    );

    Ok(())
}

#[tokio::test]
async fn peer_return_restores_tracked_sends() -> TestResult {
    tokio::time::timeout(Duration::from_secs(15), run_peer_return()).await??;
    Ok(())
}

/// A peer that returns after the grace window gets another `session_ready`
/// on the survivor's existing socket. Tracked sends must resume even though
/// the survivor never reconnected.
async fn run_peer_return() -> TestResult {
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
        NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_millis(200)),
    ));

    let relay_url = format!("ws://{addr}");
    let pairing = PairingKey::random()?;
    let topic = pairing.topic()?;
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    // The client under test is the survivor; a raw peer plays the wallet.
    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let raw = establish_raw_session(&relay_url, &topic, &mut responder, &proposer_identity).await?;
    let session_topic = raw.topic.clone();
    let mut session_cipher = raw.cipher.clone();

    // The wallet goes away without a local client reconnect.
    drop(raw.session);

    let outcome = responder.recv().await;
    assert!(
        matches!(outcome, Err(ClientError::PeerDisconnected)),
        "expected PeerDisconnected, got {outcome:?}"
    );
    assert!(!responder.is_ready(), "peer loss must clear readiness");

    // It returns on the same session topic; the relay sends a second
    // `session_ready` on the survivor's existing socket.
    let mut session = connect_raw(
        &relay_url,
        &proposer_identity,
        Role::Proposer,
        &session_topic,
    )
    .await?;
    wait_raw_session_ready(&mut session).await?;
    responder.wait_session_ready().await?;

    // A tracked send must now reach the wire without a local reconnect.
    let request_id = responder
        .request(json!({ "method": "after_peer_return" }))
        .await?;
    match read_raw_message(&mut session, &session_cipher).await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, request_id),
        other => panic!("expected request after peer return, got {other:?}"),
    }

    let ack_id = request_id.parse::<MessageId>()?;
    let ack = client_frame(
        &session_topic,
        proposer_identity.did(),
        "peer-return-ack",
        &ClientMessage::Ack(AckPayload { ack_id }),
        &mut session_cipher,
    )?;
    session
        .send(WsMessage::text(serde_json::to_string(&ack)?))
        .await?;
    match tokio::time::timeout(Duration::from_secs(2), responder.next_event()).await?? {
        ClientEvent::Delivered { id } => assert_eq!(id.to_string(), request_id),
        other => panic!("expected delivery after peer return, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn peer_disconnect_survives_a_full_inbox() -> TestResult {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_peer_disconnect_full_inbox(false),
    )
    .await??;
    Ok(())
}

#[tokio::test]
async fn peer_disconnect_survives_the_peer_returning() -> TestResult {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_peer_disconnect_full_inbox(true),
    )
    .await??;
    Ok(())
}

/// `peer_disconnected` is sent once. If it arrives while the application is
/// not draining and the inbox is full, it must still be reported once the
/// application catches up, even if the peer has come back by then.
async fn run_peer_disconnect_full_inbox(peer_returns: bool) -> TestResult {
    let _ = env_logger::builder()
        .is_test(true)
        .parse_default_env()
        .try_init();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    // Filling the inbox takes more than the default per-connection burst.
    let limiter = Arc::new(Limiter::new(RelayLimitsConfig {
        inbound_message_rate: RateLimit {
            burst: 10_000,
            interval: Duration::from_secs(3600),
        },
        ..RelayLimitsConfig::default()
    }));
    tokio::spawn(serve(
        listener,
        Arc::new(Registry::new()),
        limiter,
        NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_millis(50)),
    ));

    let relay_url = format!("ws://{addr}");
    let pairing = PairingKey::random()?;
    let topic = pairing.topic()?;
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut raw =
        establish_raw_session(&relay_url, &topic, &mut responder, &proposer_identity).await?;

    // Overfill the inbox while the application is not driving the client,
    // then leave for longer than the grace window.
    for index in 0..80 {
        let frame = request_frame(
            &raw.topic,
            proposer_identity.did(),
            &format!("full-{index}"),
            &format!("full-{index}"),
            &mut raw.cipher,
        )?;
        raw.session
            .send(WsMessage::text(serde_json::to_string(&frame)?))
            .await?;
    }
    let session_topic = raw.topic.clone();
    drop(raw);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _returned = if peer_returns {
        let mut session = connect_raw(
            &relay_url,
            &proposer_identity,
            Role::Proposer,
            &session_topic,
        )
        .await?;
        wait_raw_session_ready(&mut session).await?;
        Some(session)
    } else {
        None
    };

    // Catch up. The requests that fit are delivered, then the disconnect.
    let mut delivered = 0;
    loop {
        match tokio::time::timeout(Duration::from_secs(2), responder.recv()).await {
            Ok(Ok(ClientMessage::Request(_))) => delivered += 1,
            Ok(Err(ClientError::PeerDisconnected)) => break,
            Ok(other) => panic!("unexpected result: {other:?}"),
            Err(_) => panic!("peer_disconnected was lost"),
        }
    }
    assert!(
        delivered > 0,
        "the requests that fit in the inbox must be delivered first"
    );
    assert_eq!(responder.session().state, SessionState::Disconnected);
    if peer_returns {
        responder.wait_session_ready().await?;
    } else {
        assert!(!responder.is_ready());
    }

    Ok(())
}

#[tokio::test]
async fn inbound_disconnect_is_terminal_and_acked() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_inbound_disconnect_terminal()).await??;
    Ok(())
}

/// A peer's `disconnect` is acknowledged and delivered once, then every
/// later operation observes a terminal client.
async fn run_inbound_disconnect_terminal() -> TestResult {
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
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut raw =
        establish_raw_session(&relay_url, &topic, &mut responder, &proposer_identity).await?;

    // Leave a tracked send outstanding when the peer disconnects.
    let request_id = responder
        .request(json!({ "method": "pending_at_disconnect" }))
        .await?;
    match read_raw_message(&mut raw.session, &raw.cipher).await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, request_id),
        other => panic!("expected pending request, got {other:?}"),
    }

    let disconnect = ClientMessage::Disconnect(DisconnectPayload {
        reason: "peer-bye".to_owned(),
        code: 1000,
        message: String::new(),
    });
    let disconnect = client_frame(
        &raw.topic,
        proposer_identity.did(),
        "peer-disconnect",
        &disconnect,
        &mut raw.cipher,
    )?;
    raw.session
        .send(WsMessage::text(serde_json::to_string(&disconnect)?))
        .await?;

    match responder.recv().await? {
        ClientMessage::Disconnect(payload) => assert_eq!(payload.reason, "peer-bye"),
        other => panic!("expected disconnect, got {other:?}"),
    }
    match read_raw_message(&mut raw.session, &raw.cipher).await? {
        ClientMessage::Ack(payload) => assert_eq!(payload.ack_id, message_id("peer-disconnect")),
        other => panic!("expected disconnect ack, got {other:?}"),
    }

    // Closing reports the outstanding request before the terminal error.
    match tokio::time::timeout(Duration::from_secs(2), responder.next_event()).await?? {
        ClientEvent::Failed { id, .. } => assert_eq!(id.to_string(), request_id),
        other => panic!("expected the pending request to fail, got {other:?}"),
    }
    assert!(matches!(responder.recv().await, Err(ClientError::Closed)));
    assert!(matches!(
        responder
            .request(json!({ "method": "after_disconnect" }))
            .await,
        Err(ClientError::Closed)
    ));

    Ok(())
}

type RawStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Connect to the relay as a raw peer, bypassing `Client`.
async fn connect_raw(
    relay_url: &str,
    identity: &IdentityKey,
    role: Role,
    topic: &Topic,
) -> Result<RawStream, Box<dyn std::error::Error>> {
    let token = identity.connection_token("raw-test", AUDIENCE, Duration::from_secs(60))?;
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

/// Read the next relay frame, ignoring WebSocket control frames.
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

/// Read and decrypt the next application message from the raw peer.
async fn read_raw_message(
    stream: &mut RawStream,
    cipher: &PlaintextCipher,
) -> Result<ClientMessage, Box<dyn std::error::Error>> {
    let frame = read_raw_frame(stream).await?;
    let RelayFrameBody::Message { payload } = frame.body else {
        return Err(std::io::Error::other("expected a message frame").into());
    };
    let wire: Envelope = serde_json::from_str(&payload)?;
    let bytes = cipher.open(
        &[],
        &SealedPayload {
            nonce: wire.nonce,
            data: wire.data,
        },
    )?;
    Ok(ClientMessage::from_bytes(&bytes)?)
}

/// A distinct, valid message id for a test label.
fn message_id(label: &str) -> MessageId {
    let mut bytes = [0u8; MessageId::LEN];
    let label = &label.as_bytes()[..label.len().min(MessageId::LEN)];
    bytes[..label.len()].copy_from_slice(label);
    MessageId::from_bytes(bytes)
}

fn client_frame(
    topic: &Topic,
    from: DidKey,
    id: &str,
    message: &ClientMessage,
    cipher: &mut PlaintextCipher,
) -> Result<RelayFrame, Box<dyn std::error::Error>> {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let plaintext = message.to_bytes()?;
    let sealed = cipher.seal(&[], &plaintext)?;
    let wire = Envelope::new(
        message.message_type(),
        from,
        ts.as_secs(),
        sealed.nonce,
        sealed.data,
    );
    Ok(RelayFrame {
        v: 1,
        id: message_id(id),
        topic: topic.clone(),
        body: RelayFrameBody::Message {
            payload: serde_json::to_string(&wire)?,
        },
    })
}

/// Build a frame carrying arbitrary envelope data, bypassing a real cipher.
fn envelope_frame(
    topic: &Topic,
    from: DidKey,
    id: &str,
    kind: MessageType,
    nonce: [u8; 24],
    data: &[u8],
) -> Result<RelayFrame, Box<dyn std::error::Error>> {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let wire = Envelope::new(
        kind,
        from,
        ts.as_secs(),
        Nonce::new(nonce.to_vec())?,
        Ciphertext::new(data.to_vec()),
    );
    Ok(RelayFrame {
        v: 1,
        id: message_id(id),
        topic: topic.clone(),
        body: RelayFrameBody::Message {
            payload: serde_json::to_string(&wire)?,
        },
    })
}

fn request_frame(
    topic: &Topic,
    from: DidKey,
    id: &str,
    request_id: &str,
    cipher: &mut PlaintextCipher,
) -> Result<RelayFrame, Box<dyn std::error::Error>> {
    client_frame(
        topic,
        from,
        id,
        &ClientMessage::Request(RequestPayload {
            request_id: request_id.to_owned(),
            request: Opaque(serde_json::to_vec(&json!({ "method": "get_status" }))?),
        }),
        cipher,
    )
}

/// Build one application frame of each kind that must never travel on the
/// pairing topic.
fn pairing_application_frames(
    topic: &Topic,
    from: DidKey,
    label: &str,
    cipher: &mut PlaintextCipher,
) -> Result<Vec<RelayFrame>, Box<dyn std::error::Error>> {
    Ok(vec![
        request_frame(
            topic,
            from.clone(),
            &format!("{label}-request"),
            label,
            cipher,
        )?,
        client_frame(
            topic,
            from.clone(),
            &format!("{label}-response"),
            &ClientMessage::Response(ResponsePayload {
                request_id: label.to_owned(),
                response: Some(Opaque(serde_json::to_vec(&json!({ "ok": true }))?)),
                error: None,
            }),
            cipher,
        )?,
        client_frame(
            topic,
            from,
            &format!("{label}-disconnect"),
            &ClientMessage::Disconnect(DisconnectPayload {
                reason: "test".to_owned(),
                code: 1000,
                message: "application traffic on the pairing topic".to_owned(),
            }),
            cipher,
        )?,
    ])
}

/// Read frames until the relay sends `session_ready`.
async fn wait_raw_session_ready(stream: &mut RawStream) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let frame = read_raw_frame(stream).await?;
        if matches!(frame.body, RelayFrameBody::SessionReady) {
            return Ok(());
        }
    }
}

/// A raw proposer connected to both the pairing and session topics.
struct RawSession {
    pairing: RawStream,
    pairing_topic: Topic,
    pairing_cipher: PlaintextCipher,
    approve: RelayFrame,
    session: RawStream,
    cipher: PlaintextCipher,
    topic: Topic,
}

/// Drive a `Client` responder through a handshake with a raw proposer, then
/// return a session-topic connection for the raw proposer.
async fn establish_raw_session(
    relay_url: &str,
    pairing_topic: &Topic,
    responder: &mut Client<PlaintextCipher>,
    proposer_identity: &IdentityKey,
) -> Result<RawSession, Box<dyn std::error::Error>> {
    let mut pairing =
        connect_raw(relay_url, proposer_identity, Role::Proposer, pairing_topic).await?;
    responder.wait_session_ready().await?;
    wait_raw_session_ready(&mut pairing).await?;

    let keypair = EphemeralKeyPair::generate();
    let mut cipher = PlaintextCipher::new();
    let proposal = ClientMessage::Proposal(ProposalPayload {
        ephemeral_public_key: keypair.public_key_encoded(),
        session_expiry: 0,
        proposal: Opaque(serde_json::to_vec(&json!({ "test": true }))?),
    });
    let frame = client_frame(
        pairing_topic,
        proposer_identity.did(),
        "raw-proposal",
        &proposal,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&frame)?))
        .await?;

    match responder.recv().await? {
        ClientMessage::Proposal(_) => {}
        other => return Err(format!("expected proposal, got {other:?}").into()),
    }

    approve_raw_session(
        relay_url,
        pairing,
        pairing_topic,
        responder,
        proposer_identity,
        keypair,
        cipher,
    )
    .await
}

/// Complete the handshake for a raw proposer after its proposal was accepted.
async fn approve_raw_session(
    relay_url: &str,
    mut pairing: RawStream,
    pairing_topic: &Topic,
    responder: &mut Client<PlaintextCipher>,
    proposer_identity: &IdentityKey,
    keypair: EphemeralKeyPair,
    mut cipher: PlaintextCipher,
) -> Result<RawSession, Box<dyn std::error::Error>> {
    responder.approve(json!({ "test": true })).await?;

    let (approve_frame, session_topic) = read_raw_approve(&mut pairing, &cipher, keypair).await?;
    let approve_id = approve_frame.id.clone();

    let ack = ClientMessage::Ack(AckPayload {
        ack_id: approve_id.clone(),
    });
    let ack_frame = client_frame(
        pairing_topic,
        proposer_identity.did(),
        "raw-approve-ack",
        &ack,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&ack_frame)?))
        .await?;

    // Wait until the responder has consumed the ack, which also retires the
    // pairing link. Returning after session_ready alone races with that ack.
    loop {
        match responder.next_event().await? {
            ClientEvent::Delivered { id } if id == approve_id => break,
            ClientEvent::Failed { id, .. } if id == approve_id => {
                return Err("approve was not acknowledged".into());
            }
            _ => {}
        }
    }

    let mut session =
        connect_raw(relay_url, proposer_identity, Role::Proposer, &session_topic).await?;
    wait_raw_session_ready(&mut session).await?;
    responder.wait_session_ready().await?;

    Ok(RawSession {
        pairing,
        pairing_topic: pairing_topic.clone(),
        pairing_cipher: cipher,
        approve: approve_frame,
        session,
        cipher: PlaintextCipher::new(),
        topic: session_topic,
    })
}

/// Read the responder's `approve` on the pairing topic and derive the session
/// topic from it, without acknowledging it.
async fn read_raw_approve(
    pairing: &mut RawStream,
    cipher: &PlaintextCipher,
    keypair: EphemeralKeyPair,
) -> Result<(RelayFrame, Topic), Box<dyn std::error::Error>> {
    loop {
        let frame = read_raw_frame(pairing).await?;
        let RelayFrameBody::Message { payload } = &frame.body else {
            continue;
        };
        let wire: Envelope = serde_json::from_str(payload)?;
        if wire.kind != MessageType::Approve {
            continue;
        }
        let bytes = cipher.open(
            &[],
            &SealedPayload {
                nonce: wire.nonce,
                data: wire.data,
            },
        )?;
        let ClientMessage::Approve(approve) = ClientMessage::from_bytes(&bytes)? else {
            return Err("expected approve payload".into());
        };
        let peer_public = decode_public_key(&approve.ephemeral_public_key)?;
        let (_key, session_topic) = keypair.derive(&peer_public)?;
        return Ok((frame, session_topic.as_topic().clone()));
    }
}

/// Drive `recv` and the raw stream together, requiring neither a delivered
/// message nor a relay frame (such as an ack) before the timeout.
async fn expect_no_delivery_or_ack(
    responder: &mut Client<PlaintextCipher>,
    raw: &mut RawStream,
) -> TestResult {
    let mut receiving = Box::pin(responder.recv());
    let mut incoming = Box::pin(read_raw_frame(raw));
    tokio::select! {
        result = &mut receiving => panic!("unexpected delivery: {result:?}"),
        result = &mut incoming => panic!("unexpected relay frame: {result:?}"),
        _ = tokio::time::sleep(Duration::from_millis(300)) => {}
    }
    Ok(())
}

#[tokio::test]
async fn pending_cap_covers_handshake_messages_and_still_acks() -> TestResult {
    tokio::time::timeout(
        Duration::from_secs(30),
        run_pending_cap_handshake_messages(),
    )
    .await??;
    Ok(())
}

/// Every delivered kind shares the pending cap. Fill it with authenticated
/// handshake messages, then prove the overflowing message is not acknowledged
/// or queued while a later ack is still processed.
async fn run_pending_cap_handshake_messages() -> TestResult {
    let _ = env_logger::builder()
        .is_test(true)
        .parse_default_env()
        .try_init();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    // The cap test needs more than the default per-connection message burst.
    let limiter = Arc::new(Limiter::new(RelayLimitsConfig {
        inbound_message_rate: RateLimit {
            burst: 10_000,
            interval: Duration::from_secs(3600),
        },
        ..RelayLimitsConfig::default()
    }));
    tokio::spawn(serve(
        listener,
        Arc::new(Registry::new()),
        limiter,
        NativeRelayTransportConfig::new(AUDIENCE),
    ));

    let relay_url = format!("ws://{addr}");
    let pairing = PairingKey::random()?;
    let topic = pairing.topic()?;
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE)
            .with_ack_base_delay(Duration::from_secs(60)),
        responder_identity,
        Role::Proposer,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut pairing = connect_raw(&relay_url, &proposer_identity, Role::Responder, &topic).await?;
    responder.wait_session_ready().await?;
    wait_raw_session_ready(&mut pairing).await?;

    // Track one outbound message so a later ack has something to deliver.
    responder
        .propose(json!({ "capabilities": ["read"] }))
        .await?;
    let proposal_id = loop {
        let frame = read_raw_frame(&mut pairing).await?;
        let RelayFrameBody::Message { payload } = frame.body else {
            continue;
        };
        let wire: Envelope = serde_json::from_str(&payload)?;
        if wire.kind == MessageType::Proposal {
            break frame.id;
        }
    };

    let mut cipher = PlaintextCipher::new();

    // Fill the pending queue one round trip at a time, so every ack is
    // observable and the outbox is not overwhelmed by a burst.
    for index in 0..256u32 {
        let reject = ClientMessage::Reject(RejectPayload {
            code: index,
            message: format!("reject {index}"),
        });
        let frame = client_frame(
            &topic,
            proposer_identity.did(),
            &format!("reject-{index}"),
            &reject,
            &mut cipher,
        )?;
        let frame_id = frame.id.clone();
        pairing
            .send(WsMessage::text(serde_json::to_string(&frame)?))
            .await?;

        // Drive the client while waiting for the ack it sends for this frame.
        // A retransmitted proposal is not the ack we are waiting for.
        let ack_id = loop {
            let mut event = Box::pin(responder.next_event());
            let incoming = Box::pin(read_raw_frame(&mut pairing));
            let frame = tokio::select! {
                event = &mut event => {
                    return Err(
                        format!("unexpected event while filling the cap: {event:?}").into(),
                    );
                }
                frame = incoming => frame?,
            };
            let RelayFrameBody::Message { payload } = frame.body else {
                continue;
            };
            let wire: Envelope = serde_json::from_str(&payload)?;
            if wire.kind != MessageType::Ack {
                continue;
            }
            let bytes = cipher.open(
                &[],
                &SealedPayload {
                    nonce: wire.nonce,
                    data: wire.data,
                },
            )?;
            let ClientMessage::Ack(ack) = ClientMessage::from_bytes(&bytes)? else {
                continue;
            };
            break ack.ack_id;
        };
        assert_eq!(ack_id, frame_id);
    }

    // One more authenticated handshake message overflows the cap: it must be
    // dropped before it is recorded or acknowledged.
    let overflow = client_frame(
        &topic,
        proposer_identity.did(),
        "reject-overflow",
        &ClientMessage::Reject(RejectPayload {
            code: 256,
            message: "overflow".into(),
        }),
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&overflow)?))
        .await?;
    let overflow_wait = async {
        loop {
            let mut event = Box::pin(responder.next_event());
            let incoming = Box::pin(read_raw_frame(&mut pairing));
            let frame = tokio::select! {
                event = &mut event => panic!("unexpected event: {event:?}"),
                frame = incoming => frame?,
            };
            let RelayFrameBody::Message { payload } = frame.body else {
                continue;
            };
            let wire: Envelope = serde_json::from_str(&payload)?;
            if wire.kind != MessageType::Ack {
                continue;
            }
            let bytes = cipher.open(
                &[],
                &SealedPayload {
                    nonce: wire.nonce,
                    data: wire.data,
                },
            )?;
            let ClientMessage::Ack(_) = ClientMessage::from_bytes(&bytes)? else {
                continue;
            };
            return Ok::<bool, Box<dyn std::error::Error>>(true);
        }
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(300), overflow_wait)
            .await
            .is_err(),
        "overflowing handshake message must not be acknowledged"
    );

    // Acks are still processed while the pending queue is full.
    let ack = ClientMessage::Ack(AckPayload {
        ack_id: proposal_id.clone(),
    });
    let ack = client_frame(
        &topic,
        proposer_identity.did(),
        "proposal-ack",
        &ack,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&ack)?))
        .await?;
    match tokio::time::timeout(Duration::from_secs(2), responder.next_event()).await?? {
        ClientEvent::Delivered { id } => assert_eq!(id, proposal_id),
        other => panic!("expected delivery of the proposal, got {other:?}"),
    }

    // The queued handshake messages remain deliverable in order.
    for index in 0..256u32 {
        match responder.recv().await? {
            ClientMessage::Reject(payload) => assert_eq!(payload.code, index),
            other => panic!("expected reject {index}, got {other:?}"),
        }
    }

    // The overflowing message was dropped rather than queued.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), responder.recv())
            .await
            .is_err(),
        "the overflowing handshake message must not be queued"
    );

    Ok(())
}

#[tokio::test]
async fn retransmission_is_reacknowledged() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_retransmission()).await??;
    Ok(())
}

/// An identical retransmission must not be delivered twice, but must be
/// acknowledged again.
async fn run_retransmission() -> TestResult {
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

    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let RawSession {
        mut session,
        mut cipher,
        topic: session_topic,
        ..
    } = establish_raw_session(&relay_url, &topic, &mut responder, &proposer_identity).await?;

    let request_id = "raw-request-1";
    let frame = request_frame(
        &session_topic,
        proposer_identity.did(),
        "raw-frame-1",
        request_id,
        &mut cipher,
    )?;
    let text = serde_json::to_string(&frame)?;

    session.send(WsMessage::text(text.clone())).await?;
    match responder.recv().await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, request_id),
        other => panic!("expected request, got {other:?}"),
    }
    match read_raw_message(&mut session, &cipher).await? {
        ClientMessage::Ack(payload) => assert_eq!(payload.ack_id, frame.id),
        other => panic!("expected ack, got {other:?}"),
    }

    // Retransmit the identical envelope. It must not reach the application
    // again, but the responder must send a fresh ack.
    session.send(WsMessage::text(text)).await?;
    let receiving = tokio::spawn(async move { responder.recv().await });
    let ack = tokio::time::timeout(
        Duration::from_secs(2),
        read_raw_message(&mut session, &cipher),
    )
    .await??;
    match ack {
        ClientMessage::Ack(payload) => assert_eq!(payload.ack_id, frame.id),
        other => panic!("expected re-ack, got {other:?}"),
    }
    assert!(
        !receiving.is_finished(),
        "the duplicate must not be delivered to the application again"
    );
    receiving.abort();

    Ok(())
}

#[tokio::test]
async fn pairing_topic_rejects_application_traffic() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_pairing_topic_guard()).await??;
    Ok(())
}

/// Application traffic must not use the pairing key before or after the
/// handshake, and the session topic must keep working.
async fn run_pairing_topic_guard() -> TestResult {
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
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE)
            .with_ack_base_delay(Duration::from_secs(60)),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;

    assert!(matches!(
        responder.request(json!({ "method": "too_early" })).await,
        Err(ClientError::SessionNotActive)
    ));

    let mut raw =
        establish_raw_session(&relay_url, &topic, &mut responder, &proposer_identity).await?;

    // Once the approve has been acknowledged, the pairing link is retired:
    // even an otherwise valid handshake retransmission is no longer re-acked.
    let _ = raw
        .pairing
        .send(WsMessage::text(serde_json::to_string(&raw.approve)?))
        .await;
    let outcome = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            let frame = match read_raw_frame(&mut raw.pairing).await {
                Ok(frame) => frame,
                Err(_) => return Ok::<(), Box<dyn std::error::Error>>(()),
            };
            let RelayFrameBody::Message { payload } = &frame.body else {
                continue;
            };
            let wire: Envelope = serde_json::from_str(payload)?;
            if wire.kind == MessageType::Ack {
                return Err(format!(
                    "the retired pairing link must not acknowledge handshake traffic, got {frame:?}"
                )
                .into());
            }
        }
    })
    .await;
    if let Ok(Err(error)) = outcome {
        panic!("{error}");
    }

    // The pairing key still exists locally, but an application envelope on the
    // pairing topic is rejected even though the session is established.
    let pairing_request = request_frame(
        &raw.pairing_topic,
        proposer_identity.did(),
        "pairing-app-frame",
        "pairing-app-request",
        &mut raw.pairing_cipher,
    )?;
    raw.pairing
        .send(WsMessage::text(serde_json::to_string(&pairing_request)?))
        .await?;
    expect_no_delivery_or_ack(&mut responder, &mut raw.session).await?;

    // The session topic remains usable.
    let session_request = request_frame(
        &raw.topic,
        proposer_identity.did(),
        "session-frame",
        "session-request",
        &mut raw.cipher,
    )?;
    raw.session
        .send(WsMessage::text(serde_json::to_string(&session_request)?))
        .await?;
    match responder.recv().await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, "session-request"),
        other => panic!("expected session request, got {other:?}"),
    }
    match read_raw_message(&mut raw.session, &raw.cipher).await? {
        ClientMessage::Ack(payload) => assert_eq!(payload.ack_id, message_id("session-frame")),
        other => panic!("expected session ack, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn unexpected_approve_preserves_the_handshake() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_unexpected_approve()).await??;
    Ok(())
}

/// A bad `approve` in the wrong handshake state must not discard the peer's
/// proposal, so the real approval can still complete.
async fn run_unexpected_approve() -> TestResult {
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
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut raw = connect_raw(&relay_url, &proposer_identity, Role::Proposer, &topic).await?;
    responder.wait_session_ready().await?;
    wait_raw_session_ready(&mut raw).await?;

    let mut cipher = PlaintextCipher::new();
    let keypair = EphemeralKeyPair::generate();
    let proposal = ClientMessage::Proposal(ProposalPayload {
        ephemeral_public_key: keypair.public_key_encoded(),
        session_expiry: 0,
        proposal: Opaque(serde_json::to_vec(&json!({ "test": true }))?),
    });
    let proposal = client_frame(
        &topic,
        proposer_identity.did(),
        "unexpected-proposal",
        &proposal,
        &mut cipher,
    )?;
    raw.send(WsMessage::text(serde_json::to_string(&proposal)?))
        .await?;
    assert!(matches!(
        responder.recv().await?,
        ClientMessage::Proposal(_)
    ));

    let bad = ClientMessage::Approve(ApprovePayload {
        ephemeral_public_key: EphemeralKeyPair::generate().public_key_encoded(),
        approval: Opaque(serde_json::to_vec(&json!({ "test": true }))?),
    });
    let bad = client_frame(
        &topic,
        proposer_identity.did(),
        "unexpected-approve",
        &bad,
        &mut cipher,
    )?;
    raw.send(WsMessage::text(serde_json::to_string(&bad)?))
        .await?;
    assert!(
        matches!(
            responder.recv().await,
            Err(ClientError::UnexpectedHandshake)
        ),
        "an approve in the wrong state must be rejected"
    );

    // The original PeerProposed state is still intact.
    responder.approve(json!({ "ok": true })).await?;

    Ok(())
}

#[tokio::test]
async fn weak_proposal_is_rejected_without_acking() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_weak_proposal()).await??;
    Ok(())
}

/// A proposal with a low-order public key must not be acknowledged or change
/// the handshake state. A later valid proposal still completes the handshake.
async fn run_weak_proposal() -> TestResult {
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
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut pairing = connect_raw(&relay_url, &proposer_identity, Role::Proposer, &topic).await?;
    responder.wait_session_ready().await?;
    wait_raw_session_ready(&mut pairing).await?;

    let mut cipher = PlaintextCipher::new();
    let weak = ClientMessage::Proposal(ProposalPayload {
        ephemeral_public_key: wallet_session_core::codec::encode(&[0u8; 32]),
        session_expiry: 0,
        proposal: Opaque(serde_json::to_vec(&json!({ "weak": true }))?),
    });
    let weak = client_frame(
        &topic,
        proposer_identity.did(),
        "weak-proposal",
        &weak,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&weak)?))
        .await?;

    assert!(matches!(
        responder.recv().await,
        Err(ClientError::Handshake(HandshakeError::WeakKey))
    ));
    assert_eq!(responder.session().state, SessionState::Idle);

    // The weak proposal must not be acknowledged.
    match tokio::time::timeout(Duration::from_millis(300), read_raw_frame(&mut pairing)).await {
        Err(_) => {}
        Ok(Err(_)) => {}
        Ok(Ok(frame)) => panic!("weak proposal must not be acknowledged: {frame:?}"),
    }

    // A valid proposal still completes the handshake.
    let keypair = EphemeralKeyPair::generate();
    let proposal = ClientMessage::Proposal(ProposalPayload {
        ephemeral_public_key: keypair.public_key_encoded(),
        session_expiry: 0,
        proposal: Opaque(serde_json::to_vec(&json!({ "valid": true }))?),
    });
    let proposal = client_frame(
        &topic,
        proposer_identity.did(),
        "valid-proposal",
        &proposal,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&proposal)?))
        .await?;
    assert!(matches!(
        responder.recv().await?,
        ClientMessage::Proposal(_)
    ));
    assert!(matches!(
        read_raw_message(&mut pairing, &cipher).await?,
        ClientMessage::Ack(_)
    ));

    let mut raw = approve_raw_session(
        &relay_url,
        pairing,
        &topic,
        &mut responder,
        &proposer_identity,
        keypair,
        cipher,
    )
    .await?;

    let request = request_frame(
        &raw.topic,
        proposer_identity.did(),
        "weak-recovery-session",
        "session",
        &mut raw.cipher,
    )?;
    raw.session
        .send(WsMessage::text(serde_json::to_string(&request)?))
        .await?;
    match responder.recv().await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, "session"),
        other => panic!("expected session request, got {other:?}"),
    }
    match read_raw_message(&mut raw.session, &raw.cipher).await? {
        ClientMessage::Ack(payload) => {
            assert_eq!(payload.ack_id, message_id("weak-recovery-session"))
        }
        other => panic!("expected session ack, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn weak_approve_preserves_the_proposal() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_weak_approve()).await??;
    Ok(())
}

/// A low-order `approve` must not be acknowledged or consume the proposal
/// keypair. A later valid approve still completes the handshake.
async fn run_weak_approve() -> TestResult {
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
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut proposer = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        proposer_identity,
        Role::Proposer,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut pairing = connect_raw(&relay_url, &responder_identity, Role::Responder, &topic).await?;
    proposer.wait_session_ready().await?;
    wait_raw_session_ready(&mut pairing).await?;

    proposer
        .propose(json!({ "capabilities": ["read"] }))
        .await?;

    let mut cipher = PlaintextCipher::new();
    let (proposal_id, proposer_public) = loop {
        let frame = read_raw_frame(&mut pairing).await?;
        let proposal_id = frame.id.clone();
        let RelayFrameBody::Message { payload } = frame.body else {
            continue;
        };
        let wire: Envelope = serde_json::from_str(&payload)?;
        if wire.kind != MessageType::Proposal {
            continue;
        }
        let bytes = cipher.open(
            &[],
            &SealedPayload {
                nonce: wire.nonce,
                data: wire.data,
            },
        )?;
        let ClientMessage::Proposal(proposal) = ClientMessage::from_bytes(&bytes)? else {
            return Err("expected proposal payload".into());
        };
        break (
            proposal_id,
            decode_public_key(&proposal.ephemeral_public_key)?,
        );
    };

    let proposal_ack = ClientMessage::Ack(AckPayload {
        ack_id: proposal_id.clone(),
    });
    let proposal_ack = client_frame(
        &topic,
        responder_identity.did(),
        "weak-approve-proposal-ack",
        &proposal_ack,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&proposal_ack)?))
        .await?;
    match proposer.next_event().await? {
        ClientEvent::Delivered { id } => assert_eq!(id, proposal_id),
        other => panic!("expected the proposal acknowledgment, got {other:?}"),
    }

    let weak = ClientMessage::Approve(ApprovePayload {
        ephemeral_public_key: wallet_session_core::codec::encode(&[0u8; 32]),
        approval: Opaque(serde_json::to_vec(&json!({ "ok": false }))?),
    });
    let weak = client_frame(
        &topic,
        responder_identity.did(),
        "weak-approve",
        &weak,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&weak)?))
        .await?;

    assert!(matches!(
        proposer.recv().await,
        Err(ClientError::Handshake(HandshakeError::WeakKey))
    ));
    assert_eq!(proposer.session().state, SessionState::ProposalSent);

    // The weak approve must not be acknowledged.
    match tokio::time::timeout(Duration::from_millis(300), read_raw_frame(&mut pairing)).await {
        Err(_) => {}
        Ok(Err(_)) => {}
        Ok(Ok(frame)) => panic!("weak approve must not be acknowledged: {frame:?}"),
    }

    // A valid approve still completes the handshake with the original keypair.
    let responder_keypair = EphemeralKeyPair::generate();
    let approve = ClientMessage::Approve(ApprovePayload {
        ephemeral_public_key: responder_keypair.public_key_encoded(),
        approval: Opaque(serde_json::to_vec(&json!({ "ok": true }))?),
    });
    let approve = client_frame(
        &topic,
        responder_identity.did(),
        "valid-approve",
        &approve,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&approve)?))
        .await?;
    assert!(matches!(proposer.recv().await?, ClientMessage::Approve(_)));
    assert!(matches!(
        read_raw_message(&mut pairing, &cipher).await?,
        ClientMessage::Ack(_)
    ));

    let (_key, session_topic) = responder_keypair.derive(&proposer_public)?;
    let session_topic = session_topic.as_topic().clone();
    let mut session = connect_raw(
        &relay_url,
        &responder_identity,
        Role::Responder,
        &session_topic,
    )
    .await?;
    wait_raw_session_ready(&mut session).await?;
    proposer.wait_session_ready().await?;

    let request_id = proposer
        .request(json!({ "method": "weak_approve_recovery" }))
        .await?;
    match read_raw_message(&mut session, &cipher).await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, request_id),
        other => panic!("expected session request, got {other:?}"),
    }
    let ack = ClientMessage::Ack(AckPayload {
        ack_id: request_id.parse::<MessageId>()?,
    });
    let ack = client_frame(
        &session_topic,
        responder_identity.did(),
        "weak-approve-session-ack",
        &ack,
        &mut cipher,
    )?;
    session
        .send(WsMessage::text(serde_json::to_string(&ack)?))
        .await?;
    match tokio::time::timeout(Duration::from_secs(2), proposer.next_event()).await?? {
        ClientEvent::Delivered { id } => assert_eq!(id.to_string(), request_id),
        other => panic!("expected delivery after weak approve, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn approve_is_an_implicit_proposal_ack() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_implicit_proposal_ack()).await??;
    Ok(())
}

/// A valid approve proves the peer received the proposal even when the
/// explicit proposal ack was lost.
async fn run_implicit_proposal_ack() -> TestResult {
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
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut proposer = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE)
            .with_ack_base_delay(Duration::from_millis(100))
            .with_ack_max_attempts(1),
        proposer_identity,
        Role::Proposer,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut pairing = connect_raw(&relay_url, &responder_identity, Role::Responder, &topic).await?;
    proposer.wait_session_ready().await?;
    wait_raw_session_ready(&mut pairing).await?;

    proposer
        .propose(json!({ "capabilities": ["read"] }))
        .await?;

    let mut cipher = PlaintextCipher::new();
    let (proposal_id, proposer_public) = loop {
        let frame = read_raw_frame(&mut pairing).await?;
        let proposal_id = frame.id.clone();
        let RelayFrameBody::Message { payload } = frame.body else {
            continue;
        };
        let wire: Envelope = serde_json::from_str(&payload)?;
        if wire.kind != MessageType::Proposal {
            continue;
        }
        let bytes = cipher.open(
            &[],
            &SealedPayload {
                nonce: wire.nonce,
                data: wire.data,
            },
        )?;
        let ClientMessage::Proposal(proposal) = ClientMessage::from_bytes(&bytes)? else {
            return Err("expected proposal payload".into());
        };
        break (
            proposal_id,
            decode_public_key(&proposal.ephemeral_public_key)?,
        );
    };

    // Deliberately do not send the explicit proposal ack.
    let responder_keypair = EphemeralKeyPair::generate();
    let approve = ClientMessage::Approve(ApprovePayload {
        ephemeral_public_key: responder_keypair.public_key_encoded(),
        approval: Opaque(serde_json::to_vec(&json!({ "ok": true }))?),
    });
    let approve = client_frame(
        &topic,
        responder_identity.did(),
        "implicit-approve",
        &approve,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&approve)?))
        .await?;

    assert!(matches!(proposer.recv().await?, ClientMessage::Approve(_)));
    match tokio::time::timeout(Duration::from_secs(2), proposer.next_event()).await?? {
        ClientEvent::Delivered { id } => assert_eq!(id, proposal_id),
        other => panic!("expected the proposal delivery, got {other:?}"),
    }

    // No failure arrives after the retry window.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        proposer.poll_event().is_none(),
        "an approved proposal must not be reported failed"
    );

    let (_key, session_topic) = responder_keypair.derive(&proposer_public)?;
    let session_topic = session_topic.as_topic().clone();
    let mut session = connect_raw(
        &relay_url,
        &responder_identity,
        Role::Responder,
        &session_topic,
    )
    .await?;
    wait_raw_session_ready(&mut session).await?;
    proposer.wait_session_ready().await?;

    Ok(())
}

#[tokio::test]
async fn failed_proposal_returns_to_idle() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_failed_proposal()).await??;
    Ok(())
}

/// An unacknowledged proposal returns the proposer to `Idle` so the
/// application can try again.
async fn run_failed_proposal() -> TestResult {
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
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut proposer = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE)
            .with_ack_base_delay(Duration::from_millis(10))
            .with_ack_max_attempts(0),
        proposer_identity,
        Role::Proposer,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let _pairing = connect_raw(&relay_url, &responder_identity, Role::Responder, &topic).await?;
    proposer.wait_session_ready().await?;

    proposer
        .propose(json!({ "capabilities": ["read"] }))
        .await?;
    match tokio::time::timeout(Duration::from_secs(2), proposer.next_event()).await?? {
        ClientEvent::Failed { .. } => {}
        other => panic!("expected the proposal failure, got {other:?}"),
    }
    assert_eq!(proposer.session().state, SessionState::Idle);
    proposer
        .propose(json!({ "capabilities": ["read"] }))
        .await?;

    Ok(())
}

#[tokio::test]
async fn failed_approve_closes_an_unjoined_session() -> TestResult {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_failed_approve_session_timeout(true),
    )
    .await??;
    Ok(())
}

#[tokio::test]
async fn failed_approve_closes_without_consuming_events() -> TestResult {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_failed_approve_session_timeout(false),
    )
    .await??;
    Ok(())
}

/// When the approve is lost, the responder must not wait forever on a
/// session link the proposer never joins, whether or not the application
/// consumes the approve's `Failed` outcome.
async fn run_failed_approve_session_timeout(consume_events: bool) -> TestResult {
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
        NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_millis(100)),
    ));

    let relay_url = format!("ws://{addr}");
    let pairing = PairingKey::random()?;
    let topic = pairing.topic()?;
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE)
            .with_ack_base_delay(Duration::from_millis(10))
            .with_ack_max_attempts(0)
            .with_session_join_timeout(Duration::from_millis(100)),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut pairing = connect_raw(&relay_url, &proposer_identity, Role::Proposer, &topic).await?;
    responder.wait_session_ready().await?;
    wait_raw_session_ready(&mut pairing).await?;

    let mut cipher = PlaintextCipher::new();
    let keypair = EphemeralKeyPair::generate();
    let proposal = ClientMessage::Proposal(ProposalPayload {
        ephemeral_public_key: keypair.public_key_encoded(),
        session_expiry: 0,
        proposal: Opaque(serde_json::to_vec(&json!({ "test": true }))?),
    });
    let proposal = client_frame(
        &topic,
        proposer_identity.did(),
        "timeout-proposal",
        &proposal,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&proposal)?))
        .await?;
    assert!(matches!(
        responder.recv().await?,
        ClientMessage::Proposal(_)
    ));

    // The approve is sent but never acknowledged. The proposer also never
    // joins the session topic.
    responder.approve(json!({ "ok": true })).await?;

    // The proposer never joins the session topic, so the join window ends the
    // client and the call driving it reports why.
    let error = if consume_events {
        match tokio::time::timeout(Duration::from_secs(2), responder.next_event()).await?? {
            ClientEvent::Failed { .. } => {}
            other => panic!("expected the approve failure, got {other:?}"),
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Err(error) = responder.next_event().await {
                    return error;
                }
            }
        })
        .await?
    } else {
        // Without consuming the outcome the join window still runs: it was
        // armed when the approve went out.
        tokio::time::timeout(Duration::from_secs(5), responder.wait_session_ready())
            .await?
            .expect_err("the session must not become ready")
    };
    assert!(
        matches!(error, ClientError::SessionNotEstablished),
        "unexpected error: {error:?}"
    );
    assert_eq!(responder.session().state, SessionState::Disconnected);
    assert!(matches!(
        responder.recv().await,
        Err(ClientError::SessionNotEstablished)
    ));
    assert!(matches!(
        responder.request(json!({ "method": "no_session" })).await,
        Err(ClientError::SessionNotEstablished)
    ));

    Ok(())
}

#[tokio::test]
async fn acked_approve_still_closes_an_unjoined_session() -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), run_acked_approve_unjoined()).await??;
    Ok(())
}

/// Anyone holding the pairing key can acknowledge our approve. That must not
/// stop the join timeout: only the proposer joining the session topic does.
async fn run_acked_approve_unjoined() -> TestResult {
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
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE)
            .with_ack_base_delay(Duration::from_millis(10))
            .with_ack_max_attempts(1)
            .with_session_join_timeout(Duration::from_millis(100)),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut pairing = connect_raw(&relay_url, &proposer_identity, Role::Proposer, &topic).await?;
    responder.wait_session_ready().await?;
    wait_raw_session_ready(&mut pairing).await?;

    let mut cipher = PlaintextCipher::new();
    let keypair = EphemeralKeyPair::generate();
    let proposal = client_frame(
        &topic,
        proposer_identity.did(),
        "acked-proposal",
        &ClientMessage::Proposal(ProposalPayload {
            ephemeral_public_key: keypair.public_key_encoded(),
            session_expiry: 0,
            proposal: Opaque(serde_json::to_vec(&json!({ "test": true }))?),
        }),
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&proposal)?))
        .await?;
    assert!(matches!(
        responder.recv().await?,
        ClientMessage::Proposal(_)
    ));
    responder.approve(json!({ "ok": true })).await?;

    // Acknowledge the approve, but never join the session topic.
    let (approve, _) = read_raw_approve(&mut pairing, &cipher, keypair).await?;
    let ack = client_frame(
        &topic,
        proposer_identity.did(),
        "acked-approve-ack",
        &ClientMessage::Ack(AckPayload { ack_id: approve.id }),
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&ack)?))
        .await?;

    let error = tokio::time::timeout(Duration::from_secs(5), responder.wait_session_ready())
        .await
        .expect("the join timeout must close the client")
        .expect_err("the session must not become ready");
    assert!(
        matches!(error, ClientError::SessionNotEstablished),
        "unexpected error: {error:?}"
    );

    Ok(())
}

#[tokio::test]
async fn joined_session_survives_the_join_timeout() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_joined_session_timeout()).await??;
    Ok(())
}

/// A failed `approve` only means its acks were lost. If the proposer did join
/// the session topic, the join timeout must not tear the session down, even
/// when the peer happens to be away when the timer fires.
async fn run_joined_session_timeout() -> TestResult {
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
        NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_millis(50)),
    ));

    let relay_url = format!("ws://{addr}");
    let pairing = PairingKey::random()?;
    let topic = pairing.topic()?;
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE)
            .with_ack_base_delay(Duration::from_millis(10))
            .with_ack_max_attempts(0)
            .with_session_join_timeout(Duration::from_millis(200)),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut pairing = connect_raw(&relay_url, &proposer_identity, Role::Proposer, &topic).await?;
    responder.wait_session_ready().await?;
    wait_raw_session_ready(&mut pairing).await?;

    let mut cipher = PlaintextCipher::new();
    let keypair = EphemeralKeyPair::generate();
    let proposal = ClientMessage::Proposal(ProposalPayload {
        ephemeral_public_key: keypair.public_key_encoded(),
        session_expiry: 0,
        proposal: Opaque(serde_json::to_vec(&json!({ "test": true }))?),
    });
    let proposal = client_frame(
        &topic,
        proposer_identity.did(),
        "joined-proposal",
        &proposal,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&proposal)?))
        .await?;
    assert!(matches!(
        responder.recv().await?,
        ClientMessage::Proposal(_)
    ));

    // The proposer reads the approve and joins the session topic, but never
    // acknowledges the approve.
    responder.approve(json!({ "ok": true })).await?;
    let (_approve, session_topic) = read_raw_approve(&mut pairing, &cipher, keypair).await?;
    let mut session = connect_raw(
        &relay_url,
        &proposer_identity,
        Role::Proposer,
        &session_topic,
    )
    .await?;
    wait_raw_session_ready(&mut session).await?;
    responder.wait_session_ready().await?;
    match tokio::time::timeout(Duration::from_secs(2), responder.next_event()).await?? {
        ClientEvent::Failed { .. } => {}
        other => panic!("expected the approve failure, got {other:?}"),
    }

    // The proposer goes away past its grace window and stays away while the
    // join timeout fires. Only `PeerDisconnected` may be reported.
    drop(session);
    let driving = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            match responder.next_event().await {
                Ok(_) | Err(ClientError::PeerDisconnected) => {}
                Err(error) => return error,
            }
        }
    })
    .await;
    if let Ok(error) = driving {
        panic!("the joined session was closed: {error:?}");
    }

    // The proposer returns and the session still carries traffic.
    let mut session = connect_raw(
        &relay_url,
        &proposer_identity,
        Role::Proposer,
        &session_topic,
    )
    .await?;
    wait_raw_session_ready(&mut session).await?;
    responder.wait_session_ready().await?;
    let request_id = responder.request(json!({ "method": "still_here" })).await?;
    match read_raw_message(&mut session, &PlaintextCipher::new()).await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, request_id),
        other => panic!("expected the request, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn pairing_kind_guard_rejects_before_and_between_handshake() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_pairing_kind_guard_stages()).await??;
    Ok(())
}

async fn run_pairing_kind_guard_stages() -> TestResult {
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
    let pairing_key = PairingKey::random()?;
    let topic = pairing_key.topic()?;
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut pairing = connect_raw(&relay_url, &proposer_identity, Role::Proposer, &topic).await?;
    responder.wait_session_ready().await?;
    wait_raw_session_ready(&mut pairing).await?;

    let mut cipher = PlaintextCipher::new();

    // Before any handshake: the pairing key must not carry application traffic.
    for frame in
        pairing_application_frames(&topic, proposer_identity.did(), "guard-before", &mut cipher)?
    {
        pairing
            .send(WsMessage::text(serde_json::to_string(&frame)?))
            .await?;
    }
    expect_no_delivery_or_ack(&mut responder, &mut pairing).await?;
    assert!(responder.session().peer_did.is_none());

    let keypair = EphemeralKeyPair::generate();
    let proposal = ClientMessage::Proposal(ProposalPayload {
        ephemeral_public_key: keypair.public_key_encoded(),
        session_expiry: 0,
        proposal: Opaque(serde_json::to_vec(&json!({ "test": true }))?),
    });
    let proposal = client_frame(
        &topic,
        proposer_identity.did(),
        "guard-proposal",
        &proposal,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&proposal)?))
        .await?;
    assert!(matches!(
        responder.recv().await?,
        ClientMessage::Proposal(_)
    ));
    assert!(matches!(
        read_raw_message(&mut pairing, &cipher).await?,
        ClientMessage::Ack(_)
    ));

    // Between proposal and approve: still only handshake traffic is allowed.
    for frame in pairing_application_frames(
        &topic,
        proposer_identity.did(),
        "guard-between",
        &mut cipher,
    )? {
        pairing
            .send(WsMessage::text(serde_json::to_string(&frame)?))
            .await?;
    }
    expect_no_delivery_or_ack(&mut responder, &mut pairing).await?;

    // The handshake and the session still work after the rejected frames.
    let mut raw = approve_raw_session(
        &relay_url,
        pairing,
        &topic,
        &mut responder,
        &proposer_identity,
        keypair,
        cipher,
    )
    .await?;
    let request = request_frame(
        &raw.topic,
        proposer_identity.did(),
        "guard-session",
        "session",
        &mut raw.cipher,
    )?;
    raw.session
        .send(WsMessage::text(serde_json::to_string(&request)?))
        .await?;
    match responder.recv().await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, "session"),
        other => panic!("expected the session request, got {other:?}"),
    }
    match read_raw_message(&mut raw.session, &raw.cipher).await? {
        ClientMessage::Ack(payload) => assert_eq!(payload.ack_id, message_id("guard-session")),
        other => panic!("expected a session ack, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn pairing_kind_guard_rejects_during_proposer_retirement_window() -> TestResult {
    tokio::time::timeout(
        Duration::from_secs(10),
        run_proposer_retirement_window_guard(),
    )
    .await??;
    Ok(())
}

async fn run_proposer_retirement_window_guard() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(serve(
        listener,
        Arc::new(Registry::new()),
        Arc::new(Limiter::new(RelayLimitsConfig::default())),
        NativeRelayTransportConfig::new(AUDIENCE),
    ));

    let relay_url = format!("ws://{addr}");
    let pairing_key = PairingKey::random()?;
    let topic = pairing_key.topic()?;
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));

    let mut proposer = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        proposer_identity,
        Role::Proposer,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut pairing = connect_raw(&relay_url, &responder_identity, Role::Responder, &topic).await?;
    proposer.wait_session_ready().await?;
    wait_raw_session_ready(&mut pairing).await?;

    proposer
        .propose(json!({ "capabilities": ["read"] }))
        .await?;

    let mut cipher = PlaintextCipher::new();
    let (proposal_id, proposal) = loop {
        let frame = read_raw_frame(&mut pairing).await?;
        let proposal_id = frame.id.clone();
        let RelayFrameBody::Message { payload } = frame.body else {
            continue;
        };
        let wire: Envelope = serde_json::from_str(&payload)?;
        if wire.kind != MessageType::Proposal {
            continue;
        }
        let bytes = cipher.open(
            &[],
            &SealedPayload {
                nonce: wire.nonce,
                data: wire.data,
            },
        )?;
        break (proposal_id, ClientMessage::from_bytes(&bytes)?);
    };
    let ClientMessage::Proposal(proposal) = proposal else {
        return Err("expected proposal payload".into());
    };

    // Acknowledge the proposal so its retry does not race the late request.
    let proposal_ack = ClientMessage::Ack(AckPayload {
        ack_id: proposal_id,
    });
    let proposal_ack = client_frame(
        &topic,
        responder_identity.did(),
        "guard-proposal-ack",
        &proposal_ack,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&proposal_ack)?))
        .await?;

    let keypair = EphemeralKeyPair::generate();
    let approve = ClientMessage::Approve(ApprovePayload {
        ephemeral_public_key: keypair.public_key_encoded(),
        approval: Opaque(serde_json::to_vec(&json!({ "ok": true }))?),
    });
    let approve = client_frame(
        &topic,
        responder_identity.did(),
        "guard-approve",
        &approve,
        &mut cipher,
    )?;
    pairing
        .send(WsMessage::text(serde_json::to_string(&approve)?))
        .await?;
    assert!(matches!(proposer.recv().await?, ClientMessage::Approve(_)));

    let peer_public = decode_public_key(&proposal.ephemeral_public_key)?;
    let (_key, session_topic) = keypair.derive(&peer_public)?;
    let session_topic = session_topic.as_topic().clone();

    // Consume the proposer's ack for the approve. The proposer's pairing link
    // is still inside its retirement window.
    loop {
        let frame = read_raw_frame(&mut pairing).await?;
        let RelayFrameBody::Message { payload } = frame.body else {
            continue;
        };
        let wire: Envelope = serde_json::from_str(&payload)?;
        if wire.kind == MessageType::Ack {
            break;
        }
    }

    // The session is established, but the pairing link still exists. An
    // application envelope must still be rejected by the kind/topic guard.
    for frame in pairing_application_frames(
        &topic,
        responder_identity.did(),
        "guard-retirement",
        &mut cipher,
    )? {
        pairing
            .send(WsMessage::text(serde_json::to_string(&frame)?))
            .await?;
    }
    expect_no_delivery_or_ack(&mut proposer, &mut pairing).await?;

    // The session topic remains usable after the rejected pairing frame.
    let mut session = connect_raw(
        &relay_url,
        &responder_identity,
        Role::Responder,
        &session_topic,
    )
    .await?;
    wait_raw_session_ready(&mut session).await?;
    proposer.wait_session_ready().await?;

    let mut session_cipher = PlaintextCipher::new();
    let request = request_frame(
        &session_topic,
        responder_identity.did(),
        "guard-session",
        "session",
        &mut session_cipher,
    )?;
    session
        .send(WsMessage::text(serde_json::to_string(&request)?))
        .await?;
    match proposer.recv().await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, "session"),
        other => panic!("expected the session request, got {other:?}"),
    }
    match read_raw_message(&mut session, &session_cipher).await? {
        ClientMessage::Ack(payload) => assert_eq!(payload.ack_id, message_id("guard-session")),
        other => panic!("expected a session ack, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn oversized_relay_frame_is_rejected() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_oversized_frame()).await??;
    Ok(())
}

/// A relay that forwards a frame above the client's WebSocket limit must cause
/// a transport failure, not an application delivery.
async fn run_oversized_frame() -> TestResult {
    let _ = env_logger::builder()
        .is_test(true)
        .parse_default_env()
        .try_init();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(serve(
        listener,
        Arc::new(Registry::new()),
        Arc::new(Limiter::new(RelayLimitsConfig {
            inbound_byte_rate: RateLimit {
                burst: 1024 * 1024,
                interval: Duration::from_secs(1),
            },
            ..RelayLimitsConfig::default()
        })),
        NativeRelayTransportConfig::new(AUDIENCE).with_max_incoming_frame_bytes(512 * 1024),
    ));

    let relay_url = format!("ws://{addr}");
    let pairing = PairingKey::random()?;
    let topic = pairing.topic()?;
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut raw =
        establish_raw_session(&relay_url, &topic, &mut responder, &proposer_identity).await?;

    // Two base64 layers (the opaque payload and the envelope ciphertext) put
    // this above 256 KiB on the wire while staying inside the relay's default
    // byte budget.
    let request = ClientMessage::Request(RequestPayload {
        request_id: "oversized".to_owned(),
        request: Opaque(vec![0u8; 200 * 1024]),
    });
    let frame = client_frame(
        &raw.topic,
        proposer_identity.did(),
        "oversized-frame",
        &request,
        &mut raw.cipher,
    )?;
    let text = serde_json::to_string(&frame)?;
    assert!(text.len() > 256 * 1024);
    raw.session.send(WsMessage::text(text)).await?;

    if let Ok(Ok(message)) =
        tokio::time::timeout(Duration::from_millis(500), responder.recv()).await
    {
        panic!("oversized frame was delivered: {message:?}");
    }

    Ok(())
}

#[tokio::test]
async fn recoverable_bad_frames_are_dropped() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_recoverable_bad_frames()).await??;
    Ok(())
}

/// A malformed envelope, a failed AEAD open, and plaintext that is not a client
/// message must not end the receive loop. The next valid message is delivered.
async fn run_recoverable_bad_frames() -> TestResult {
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
    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut raw =
        establish_raw_session(&relay_url, &topic, &mut responder, &proposer_identity).await?;

    let malformed = RelayFrame {
        v: 1,
        id: message_id("malformed-envelope"),
        topic: raw.topic.clone(),
        body: RelayFrameBody::Message {
            payload: "not json".to_owned(),
        },
    };
    raw.session
        .send(WsMessage::text(serde_json::to_string(&malformed)?))
        .await?;

    let bad_plaintext = envelope_frame(
        &raw.topic,
        proposer_identity.did(),
        "bad-plaintext",
        MessageType::Request,
        [11u8; 24],
        b"not a client message",
    )?;
    raw.session
        .send(WsMessage::text(serde_json::to_string(&bad_plaintext)?))
        .await?;

    let bad_tag = envelope_frame(
        &raw.topic,
        proposer_identity.did(),
        "bad-tag",
        MessageType::Request,
        [12u8; 24],
        TAMPERED,
    )?;
    raw.session
        .send(WsMessage::text(serde_json::to_string(&bad_tag)?))
        .await?;

    let invalid_response = ClientMessage::Response(ResponsePayload {
        request_id: "invalid".to_owned(),
        response: Some(Opaque(Vec::new())),
        error: Some(Opaque(Vec::new())),
    });
    let invalid_response = client_frame(
        &raw.topic,
        proposer_identity.did(),
        "invalid-response",
        &invalid_response,
        &mut raw.cipher,
    )?;
    raw.session
        .send(WsMessage::text(serde_json::to_string(&invalid_response)?))
        .await?;

    for (id, nonce, plaintext) in [
        (
            "null-error-response",
            [13u8; 24],
            r#"{"type":"response","requestId":"null-error","response":"AQID","error":null}"#,
        ),
        (
            "null-response-response",
            [14u8; 24],
            r#"{"type":"response","requestId":"null-response","response":null,"error":"BAU"}"#,
        ),
        (
            "empty-response",
            [15u8; 24],
            r#"{"type":"response","requestId":"empty"}"#,
        ),
    ] {
        let frame = envelope_frame(
            &raw.topic,
            proposer_identity.did(),
            id,
            MessageType::Response,
            nonce,
            plaintext.as_bytes(),
        )?;
        raw.session
            .send(WsMessage::text(serde_json::to_string(&frame)?))
            .await?;
    }

    let valid = request_frame(
        &raw.topic,
        proposer_identity.did(),
        "valid-after-bad",
        "valid-request",
        &mut raw.cipher,
    )?;
    raw.session
        .send(WsMessage::text(serde_json::to_string(&valid)?))
        .await?;

    match tokio::time::timeout(Duration::from_secs(2), responder.recv()).await?? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, "valid-request"),
        other => panic!("expected the valid request, got {other:?}"),
    }
    match read_raw_message(&mut raw.session, &raw.cipher).await? {
        ClientMessage::Ack(payload) => assert_eq!(payload.ack_id, message_id("valid-after-bad")),
        other => panic!("expected an ack for the valid request, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn own_and_foreign_identities_are_rejected() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), run_identities()).await??;
    Ok(())
}

/// Frames from the receiver's own identity, and from an identity other than
/// the established counterpart, must not be delivered or acknowledged.
async fn run_identities() -> TestResult {
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

    let responder_identity = IdentityKey::from_seed(&Seed::from_bytes([2u8; 32]));
    let proposer_identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));
    let foreign_identity = IdentityKey::from_seed(&Seed::from_bytes([9u8; 32]));

    let mut responder = Client::connect(
        ClientConfig::new(&relay_url)
            .with_insecure_ws()
            .with_audience(AUDIENCE),
        responder_identity.clone(),
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let RawSession {
        mut session,
        mut cipher,
        topic: session_topic,
        ..
    } = establish_raw_session(&relay_url, &topic, &mut responder, &proposer_identity).await?;

    assert_eq!(responder.session().peer_did, Some(proposer_identity.did()));
    assert_eq!(responder.session().state, SessionState::Active);

    // The receiver's own identity is rejected.
    let own = request_frame(
        &session_topic,
        responder_identity.did(),
        "own-frame",
        "own-request",
        &mut cipher,
    )?;
    session
        .send(WsMessage::text(serde_json::to_string(&own)?))
        .await?;
    expect_no_delivery_or_ack(&mut responder, &mut session).await?;

    // A different sender is rejected because the counterpart is pinned to the
    // proposer that completed the handshake.
    let foreign = request_frame(
        &session_topic,
        foreign_identity.did(),
        "foreign-frame",
        "foreign-request",
        &mut cipher,
    )?;
    session
        .send(WsMessage::text(serde_json::to_string(&foreign)?))
        .await?;
    expect_no_delivery_or_ack(&mut responder, &mut session).await?;
    assert_eq!(responder.session().peer_did, Some(proposer_identity.did()));

    // A later frame from the counterpart proves the rejected frames were
    // skipped rather than merely still queued.
    let after = request_frame(
        &session_topic,
        proposer_identity.did(),
        "after-foreign-frame",
        "after-foreign-request",
        &mut cipher,
    )?;
    session
        .send(WsMessage::text(serde_json::to_string(&after)?))
        .await?;
    match responder.recv().await? {
        ClientMessage::Request(payload) => {
            assert_eq!(payload.request_id, "after-foreign-request");
        }
        other => panic!("expected the post-foreign request, got {other:?}"),
    }
    match read_raw_message(&mut session, &cipher).await? {
        ClientMessage::Ack(payload) => {
            assert_eq!(payload.ack_id, message_id("after-foreign-frame"));
        }
        other => panic!("expected ack for the post-foreign request, got {other:?}"),
    }

    Ok(())
}
