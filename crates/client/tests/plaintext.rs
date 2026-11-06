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
    Client, ClientConfig, ClientError, ClientMessage, IdentityKey, Opaque, PairingKey,
    RequestPayload, Role, Seed, SessionState,
};
use wallet_session_relay::{
    config::NativeRelayTransportConfig,
    limits::{Limiter, RelayLimitsConfig},
    registry::Registry,
    server::serve,
};

use wallet_session_client::crypto::{CipherError, NONCE_LEN, SENDER_PREFIX_LEN, SealedPayload};
use wallet_session_core::{
    connection::ConnectionQuery,
    crypto::MessageCipher,
    frame::{RelayFrame, RelayFrameBody},
    message::{Ciphertext, Message as Envelope, MessageType, Nonce, Topic},
};

const AUDIENCE: &str = "wss://relay.example.com";

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Process-unique prefix so two test clients don't share a nonce space.
static PREFIX_SEQ: AtomicU64 = AtomicU64::new(0);

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
        .with_audience(AUDIENCE)
        .with_registration_id("reg-1");
    let responder_config = ClientConfig::new(&relay_url).with_audience(AUDIENCE);

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

/// The responder drops abruptly, the proposer keeps going (its request is
/// buffered), and the same identity reconnects within the grace window and
/// resumes the session with the buffered frame redelivered.
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
        .with_audience(AUDIENCE)
        .with_registration_id("reg-1");
    let responder_config = ClientConfig::new(&relay_url).with_audience(AUDIENCE);
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
    let request_id = proposer.request(json!({ "method": "get_status" })).await?;

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
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, request_id),
        other => panic!("expected buffered request after reconnect, got {other:?}"),
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
        .with_audience(AUDIENCE)
        .with_registration_id("reg-1");
    let responder_config = ClientConfig::new(&relay_url).with_audience(AUDIENCE);

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
        ClientConfig::new(&relay_url).with_audience(AUDIENCE),
        responder_identity,
        Role::Responder,
        topic.clone(),
        PlaintextCipher::new(),
    )
    .await?;
    let mut raw = connect_raw(&relay_url, &proposer_identity, Role::Proposer, &topic).await?;

    responder.wait_session_ready().await?;
    let ready = read_raw_frame(&mut raw).await?;
    assert!(matches!(ready.body, RelayFrameBody::SessionReady));

    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let request_id = "raw-request-1";
    let plaintext = ClientMessage::Request(RequestPayload {
        request_id: request_id.to_owned(),
        request: Opaque(serde_json::to_vec(&json!({ "method": "get_status" }))?),
    })
    .to_bytes()?;
    let mut sender = PlaintextCipher::new();
    let sealed = sender.seal(&[], &plaintext)?;
    let wire = Envelope::new(
        MessageType::Request,
        proposer_identity.did(),
        ts.as_secs(),
        sealed.nonce,
        sealed.data,
    );
    let frame = RelayFrame {
        v: 1,
        id: "raw-frame-1".to_owned(),
        topic: topic.clone(),
        body: RelayFrameBody::Message {
            payload: serde_json::to_string(&wire)?,
        },
    };
    let text = serde_json::to_string(&frame)?;

    raw.send(WsMessage::text(text.clone())).await?;
    match responder.recv().await? {
        ClientMessage::Request(payload) => assert_eq!(payload.request_id, request_id),
        other => panic!("expected request, got {other:?}"),
    }
    match read_raw_message(&mut raw, &sender).await? {
        ClientMessage::Ack(payload) => assert_eq!(payload.ack_id, frame.id),
        other => panic!("expected ack, got {other:?}"),
    }

    // Retransmit the identical envelope. It must not reach the application
    // again, but the responder must send a fresh ack.
    raw.send(WsMessage::text(text)).await?;
    let receiving = tokio::spawn(async move { responder.recv().await });
    let ack =
        tokio::time::timeout(Duration::from_secs(2), read_raw_message(&mut raw, &sender)).await??;
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
