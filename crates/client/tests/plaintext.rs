use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use serde_json::json;
use tokio::net::TcpListener;
use wallet_session_client::{
    Client, ClientConfig, ClientError, ClientMessage, IdentityKey, PairingKey, Role, Seed,
    SessionState,
};
use wallet_session_relay::{
    config::NativeRelayTransportConfig,
    limits::{Limiter, RelayLimitsConfig},
    registry::Registry,
    server::serve,
};

use wallet_session_client::crypto::{CipherError, NONCE_LEN, SENDER_PREFIX_LEN, SealedPayload};
use wallet_session_core::{
    crypto::MessageCipher,
    message::{Ciphertext, Nonce},
};

const AUDIENCE: &str = "wss://relay.example.com";

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Process-unique prefix so two test clients don't share a nonce space.
static PREFIX_SEQ: AtomicU64 = AtomicU64::new(0);

/// Test-only passthrough cipher: no encryption, but a valid nonce sequence.
#[derive(Debug)]
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

    let request_id = proposer.request(json!({ "method": "get_status" })).await?;
    match responder.recv().await? {
        ClientMessage::Request {
            request_id: received,
            request,
        } => {
            assert_eq!(received, request_id);
            assert_eq!(request, json!({ "method": "get_status" }));
        }
        other => panic!("expected request, got {other:?}"),
    }

    responder
        .respond(request_id.clone(), Some(json!({ "result": "ok" })), None)
        .await?;
    match proposer.recv().await? {
        ClientMessage::Response {
            request_id: received,
            response,
            error,
        } => {
            assert_eq!(received, request_id);
            assert_eq!(response, Some(json!({ "result": "ok" })));
            assert_eq!(error, None);
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
        ClientMessage::Request {
            request_id: received,
            ..
        } => assert_eq!(received, request_id),
        other => panic!("expected buffered request after reconnect, got {other:?}"),
    }

    responder
        .respond(request_id.clone(), Some(json!({ "result": "ok" })), None)
        .await?;
    match proposer.recv().await? {
        ClientMessage::Response {
            request_id: received,
            response,
            ..
        } => {
            assert_eq!(received, request_id);
            assert_eq!(response, Some(json!({ "result": "ok" })));
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
