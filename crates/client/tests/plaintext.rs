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
    AckPayload, ApprovePayload, Client, ClientConfig, ClientError, ClientMessage, IdentityKey,
    Opaque, PairingKey, ProposalPayload, RequestPayload, Role, Seed, SessionState,
    handshake::{EphemeralKeyPair, decode_public_key},
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

    fn rekey(&mut self, _key: &[u8; 32]) {
        self.counter = 0;
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
    responder.approve(json!({ "test": true })).await?;

    let (approve_id, approve, approve_frame) = loop {
        let frame = read_raw_frame(&mut pairing).await?;
        let approve_frame = frame.clone();
        let RelayFrameBody::Message { payload } = frame.body else {
            continue;
        };
        let wire: Envelope = serde_json::from_str(&payload)?;
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
        break (frame.id, ClientMessage::from_bytes(&bytes)?, approve_frame);
    };
    let ClientMessage::Approve(approve) = approve else {
        return Err("expected approve payload".into());
    };
    let peer_public = decode_public_key(&approve.ephemeral_public_key)?;
    let (_key, session_topic) = keypair.derive(&peer_public)?;
    let session_topic = session_topic.as_topic().clone();

    let ack = ClientMessage::Ack(AckPayload { ack_id: approve_id });
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
            .with_audience(AUDIENCE),
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
    match tokio::time::timeout(Duration::from_millis(300), read_raw_frame(&mut raw.pairing)).await {
        Err(_) => {}
        Ok(Err(_)) => {}
        Ok(Ok(frame)) => {
            panic!("the retired pairing link must not acknowledge handshake traffic, got {frame:?}")
        }
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
