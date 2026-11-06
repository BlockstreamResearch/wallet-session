//! Opt-in tests against an already-deployed relay.
//!
//! `cargo test` never touches the network: every test in this file is
//! `#[ignore]`. Run them explicitly:
//!
//! ```text
//! WALLET_SESSION_RELAY_URL=wss://relay.example.com/ \
//! WALLET_SESSION_RELAY_AUDIENCE=wss://relay.example.com \
//!   cargo test -p wallet-session-client --test live_relay -- --ignored --nocapture
//! ```
//!
//! `WALLET_SESSION_RELAY_AUDIENCE` defaults to the relay URL. Set it
//! explicitly when the relay's configured audience differs from the URL used
//! to reach it (for example when a proxy rewrites the host).
//!
//! The tests share one deployment, so they run one at a time. They use random
//! identities and topics, so repeated runs do not collide with each other.

use std::time::{Duration, Instant};

use futures_util::StreamExt;
use serde_json::json;
use tokio::{net::TcpStream, sync::Mutex, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Message, protocol::frame::coding::CloseCode},
};
use url::Url;
use wallet_session_client::{
    Client, ClientConfig, ClientEvent, ClientMessage, IdentityKey, PairingKey, Role, Seed,
    SessionState, XChaCha20Poly1305Cipher,
};
use wallet_session_core::{connection::ConnectionQuery, message::Topic};

/// Connection token lifetime used by the live tests. It is longer than
/// `TEST_TIMEOUT` but shorter than the relay's ten-minute default cap, so the
/// tests still fit deployments that lower the cap.
const TOKEN_TTL: Duration = Duration::from_secs(240);

/// Upper bound for one live test, including connect, reconnect and routing.
const TEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Request/response pairs sent by the long-session test.
const LONG_SESSION_MESSAGES: usize = 50;

/// Pacing between pairs. Each pair produces one request frame from the
/// proposer and two frames from the responder (ack + response), so this stays
/// below the relay's default per-connection inbound message rate.
const LONG_SESSION_INTERVAL: Duration = Duration::from_millis(150);

/// The long session needs more time than a single round trip.
const LONG_SESSION_TIMEOUT: Duration = Duration::from_secs(120);

/// Serialize live tests: a small deployment may have per-source admission
/// limits that a parallel test run would trip.
static LIVE_LOCK: Mutex<()> = Mutex::const_new(());

type TestResult = Result<(), Box<dyn std::error::Error>>;
type LiveClient = Client<XChaCha20Poly1305Cipher>;
type RawStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A deployed relay and the audience its tokens must carry.
struct LiveRelay {
    url: String,
    audience: String,
}

impl LiveRelay {
    fn from_env() -> Self {
        // Show the test's own progress lines and client warnings. Debug logs
        // are opt-in through RUST_LOG because the client's connect debug line
        // contains the connection token.
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default()
                .default_filter_or("live_relay=info,wallet_session_client=warn"),
        )
        .is_test(true)
        .try_init();

        // Raw `connect_async` calls below bypass `Client::connect`, which is
        // where the library normally installs the rustls provider.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let url = std::env::var("WALLET_SESSION_RELAY_URL").unwrap_or_else(|_| {
            panic!(
                "set WALLET_SESSION_RELAY_URL to the deployed relay, for example \
                 wss://relay.example.com/ (live tests are ignored by default)"
            )
        });
        let audience =
            std::env::var("WALLET_SESSION_RELAY_AUDIENCE").unwrap_or_else(|_| url.clone());

        eprintln!("live relay: url={url} audience={audience}");
        Self { url, audience }
    }

    fn config(&self) -> ClientConfig {
        ClientConfig::new(self.url.clone())
            .with_audience(self.audience.clone())
            .with_token_ttl(TOKEN_TTL)
            .with_idle_timeout(Duration::from_secs(30))
            .with_ack_base_delay(Duration::from_millis(250))
            .with_ack_max_attempts(8)
            .with_ping_interval(Duration::from_secs(10))
            .with_pong_timeout(Duration::from_secs(10))
            .with_reconnect_initial_delay(Duration::from_millis(100))
            .with_reconnect_max_delay(Duration::from_millis(500))
            .with_reconnect_max_attempts(3)
    }
}

/// A connected proposer/responder pair plus the material needed to reconnect
/// the responder under the same identity.
struct Pair {
    proposer: LiveClient,
    responder: LiveClient,
    topic: Topic,
    key: [u8; 32],
    responder_seed: Seed,
}

async fn connect_pair(live: &LiveRelay) -> Result<Pair, Box<dyn std::error::Error>> {
    let pairing = PairingKey::random()?;
    let topic = pairing.topic()?;
    let key = *pairing.as_bytes();
    let responder_seed = Seed::random()?;

    let mut proposer = Client::connect(
        live.config().with_registration_id("live-test"),
        IdentityKey::random()?,
        Role::Proposer,
        topic.clone(),
        XChaCha20Poly1305Cipher::new(key)?,
    )
    .await?;
    let mut responder = Client::connect(
        live.config(),
        IdentityKey::from_seed(&responder_seed),
        Role::Responder,
        topic.clone(),
        XChaCha20Poly1305Cipher::new(key)?,
    )
    .await?;

    proposer.wait_session_ready().await?;
    responder.wait_session_ready().await?;

    Ok(Pair {
        proposer,
        responder,
        topic,
        key,
        responder_seed,
    })
}

/// Build a handshake URL with the signed connection query.
fn url_with_query(
    base: &str,
    query: &ConnectionQuery,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut url = Url::parse(base)?;
    url.set_query(Some(&serde_urlencoded::to_string(query)?));
    Ok(url.to_string())
}

/// Open a raw WebSocket connection, bypassing the client's reconnect logic so
/// handshake and close behavior can be asserted directly.
async fn connect_raw(
    live: &LiveRelay,
    identity: &IdentityKey,
    role: Role,
    topic: &Topic,
) -> Result<RawStream, Box<dyn std::error::Error>> {
    let token = identity.connection_token("live-test", &live.audience, TOKEN_TTL)?;
    let query = ConnectionQuery {
        auth: token,
        role,
        topic: topic.clone(),
        registration_id: None,
    };
    let url = url_with_query(&live.url, &query)?;
    let (stream, response) = connect_async(url).await?;

    assert_eq!(
        response.status().as_u16(),
        101,
        "relay did not upgrade the WebSocket handshake"
    );
    Ok(stream)
}

#[tokio::test]
#[ignore = "requires a deployed relay; set WALLET_SESSION_RELAY_URL"]
async fn full_session_round_trip() -> TestResult {
    let _guard = LIVE_LOCK.lock().await;
    let live = LiveRelay::from_env();

    timeout(TEST_TIMEOUT, async {
        let Pair {
            mut proposer,
            mut responder,
            ..
        } = connect_pair(&live).await?;

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

        // The responder acknowledged the request before sending the response,
        // so the delivery event is already queued when the response arrives.
        let mut delivered = Vec::new();
        while let Some(event) = proposer.poll_event() {
            if let ClientEvent::Delivered { id } = event {
                delivered.push(id);
            }
        }
        assert!(
            delivered.contains(&request_id),
            "expected a Delivered event for {request_id}, got {delivered:?}"
        );

        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await
    .expect("live relay test timed out")?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires a deployed relay; set WALLET_SESSION_RELAY_URL"]
async fn long_session_with_100_messages() -> TestResult {
    let _guard = LIVE_LOCK.lock().await;
    let live = LiveRelay::from_env();

    timeout(LONG_SESSION_TIMEOUT, async {
        let Pair {
            mut proposer,
            mut responder,
            ..
        } = connect_pair(&live).await?;

        eprintln!("long session: proposing");
        proposer
            .propose(json!({ "capabilities": ["read"] }))
            .await?;
        match responder.recv().await? {
            ClientMessage::Proposal(payload) => {
                let proposal: serde_json::Value = serde_json::from_slice(&payload.proposal.0)?;
                assert_eq!(proposal, json!({ "capabilities": ["read"] }));
                eprintln!("long session: proposal received");
            }
            other => panic!("expected proposal, got {other:?}"),
        }

        responder.approve(json!({ "ok": true })).await?;
        assert!(matches!(proposer.recv().await?, ClientMessage::Approve(_)));
        eprintln!("long session: approved; starting {LONG_SESSION_MESSAGES} messages");

        // A non-trivial payload also exercises the relay's byte accounting.
        let payload = "x".repeat(512);
        let started_at = Instant::now();
        let mut latencies = Vec::with_capacity(LONG_SESSION_MESSAGES);

        for seq in 1..=LONG_SESSION_MESSAGES {
            let sent_at = Instant::now();
            let request_id = proposer
                .request(json!({
                    "seq": seq,
                    "method": "echo",
                    "data": payload.clone(),
                }))
                .await?;
            eprintln!(
                "[{seq:03}/{LONG_SESSION_MESSAGES}] proposer -> request id={request_id} bytes={}",
                payload.len()
            );

            match responder.recv().await? {
                ClientMessage::Request(message) => {
                    assert_eq!(message.request_id, request_id);
                    let request: serde_json::Value = serde_json::from_slice(&message.request.0)?;
                    assert_eq!(request["seq"].as_u64(), Some(seq as u64));
                    assert_eq!(request["data"].as_str(), Some(payload.as_str()));
                    eprintln!(
                        "[{seq:03}/{LONG_SESSION_MESSAGES}] responder <- request id={}",
                        message.request_id
                    );
                }
                other => panic!("expected request {seq}, got {other:?}"),
            }

            responder
                .respond(
                    request_id.clone(),
                    Some(json!({
                        "seq": seq,
                        "ok": true,
                        "data": payload.clone(),
                    })),
                    None,
                )
                .await?;
            eprintln!("[{seq:03}/{LONG_SESSION_MESSAGES}] responder -> response id={request_id}");

            match proposer.recv().await? {
                ClientMessage::Response(message) => {
                    assert_eq!(message.request_id, request_id);
                    assert_eq!(message.error, None);
                    let response = message.response.expect("response body");
                    let response: serde_json::Value = serde_json::from_slice(&response.0)?;
                    assert_eq!(response["seq"].as_u64(), Some(seq as u64));
                    assert_eq!(response["ok"], json!(true));
                    assert_eq!(response["data"].as_str(), Some(payload.as_str()));
                }
                other => panic!("expected response {seq}, got {other:?}"),
            }

            let mut delivered = false;
            while let Some(event) = proposer.poll_event() {
                if let ClientEvent::Delivered { id } = event
                    && id == request_id
                {
                    delivered = true;
                }
            }
            assert!(
                delivered,
                "no Delivered event for request {seq} ({request_id})"
            );

            let latency = sent_at.elapsed();
            latencies.push(latency);
            eprintln!(
                "[{seq:03}/{LONG_SESSION_MESSAGES}] proposer <- response id={request_id} \
                 delivered=true rtt={latency:?} elapsed={:?}",
                started_at.elapsed()
            );

            tokio::time::sleep(LONG_SESSION_INTERVAL).await;
        }

        let total = started_at.elapsed();
        let sum: Duration = latencies.iter().sum();
        let average = sum / LONG_SESSION_MESSAGES as u32;
        let minimum = latencies.iter().min().copied().unwrap_or_default();
        let maximum = latencies.iter().max().copied().unwrap_or_default();
        eprintln!(
            "long session complete: messages={LONG_SESSION_MESSAGES} total={total:?} \
             avg_rtt={average:?} min_rtt={minimum:?} max_rtt={maximum:?}"
        );

        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await
    .expect("long live relay test timed out")?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires a deployed relay; set WALLET_SESSION_RELAY_URL"]
async fn disconnect_is_delivered_and_acknowledged() -> TestResult {
    let _guard = LIVE_LOCK.lock().await;
    let live = LiveRelay::from_env();

    timeout(TEST_TIMEOUT, async {
        let Pair {
            mut proposer,
            mut responder,
            ..
        } = connect_pair(&live).await?;

        // Prove the session is active before tearing it down.
        let request_id = proposer
            .request(json!({ "method": "before_disconnect" }))
            .await?;
        match responder.recv().await? {
            ClientMessage::Request(payload) => assert_eq!(payload.request_id, request_id),
            other => panic!("expected request before disconnect, got {other:?}"),
        }
        responder
            .respond(request_id.clone(), Some(json!({ "ok": true })), None)
            .await?;
        match proposer.recv().await? {
            ClientMessage::Response(payload) => assert_eq!(payload.request_id, request_id),
            other => panic!("expected response before disconnect, got {other:?}"),
        }

        // Drain delivery events from the request above; the only tracked
        // message left after this point is the disconnect.
        let mut request_delivered = false;
        while let Some(event) = proposer.poll_event() {
            if let ClientEvent::Delivered { id } = event
                && id == request_id
            {
                request_delivered = true;
            }
        }
        assert!(
            request_delivered,
            "pre-disconnect request was not acknowledged"
        );
        eprintln!("disconnect test: session active");

        let proposer_reason = "user closed the pairing";
        let proposer_code = 4000;
        proposer.disconnect(proposer_reason, proposer_code).await?;
        assert_eq!(proposer.session().state, SessionState::Disconnected);
        eprintln!(
            "disconnect test: proposer -> disconnect reason={proposer_reason:?} \
             code={proposer_code}"
        );

        match responder.recv().await? {
            ClientMessage::Disconnect(payload) => {
                assert_eq!(payload.reason, proposer_reason);
                assert_eq!(payload.code, proposer_code);
                assert!(
                    payload.message.is_empty(),
                    "unexpected message: {:?}",
                    payload.message
                );
                eprintln!(
                    "disconnect test: responder <- disconnect reason={:?} code={}",
                    payload.reason, payload.code
                );
            }
            other => panic!("expected disconnect from proposer, got {other:?}"),
        }

        // The responder acknowledges the teardown with its own disconnect.
        let responder_reason = "wallet closed the pairing";
        let responder_code = 4001;
        responder
            .disconnect(responder_reason, responder_code)
            .await?;
        assert_eq!(responder.session().state, SessionState::Disconnected);
        eprintln!(
            "disconnect test: responder -> disconnect reason={responder_reason:?} \
             code={responder_code}"
        );

        // This recv processes the ack for the proposer's disconnect before
        // returning the responder's disconnect frame.
        match proposer.recv().await? {
            ClientMessage::Disconnect(payload) => {
                assert_eq!(payload.reason, responder_reason);
                assert_eq!(payload.code, responder_code);
                assert!(
                    payload.message.is_empty(),
                    "unexpected message: {:?}",
                    payload.message
                );
                eprintln!(
                    "disconnect test: proposer <- disconnect reason={:?} code={}",
                    payload.reason, payload.code
                );
            }
            other => panic!("expected disconnect from responder, got {other:?}"),
        }

        let mut delivered = false;
        while let Some(event) = proposer.poll_event() {
            if let ClientEvent::Delivered { .. } = event {
                delivered = true;
            }
        }
        assert!(
            delivered,
            "proposer did not receive a Delivered event for its disconnect"
        );
        eprintln!("disconnect test: proposer disconnect acknowledged");

        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await
    .expect("disconnect live relay test timed out")?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires a deployed relay; set WALLET_SESSION_RELAY_URL"]
async fn reconnect_resumes_buffered_frames() -> TestResult {
    let _guard = LIVE_LOCK.lock().await;
    let live = LiveRelay::from_env();

    timeout(TEST_TIMEOUT, async {
        let Pair {
            mut proposer,
            responder,
            topic,
            key,
            responder_seed,
        } = connect_pair(&live).await?;

        // Drop the responder without a disconnect message and give the relay
        // time to reserve its slot before the proposer sends.
        drop(responder);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let request_id = proposer.request(json!({ "method": "get_status" })).await?;

        // The same identity reconnects within the deployment's grace window.
        let mut responder = Client::connect(
            live.config(),
            IdentityKey::from_seed(&responder_seed),
            Role::Responder,
            topic.clone(),
            XChaCha20Poly1305Cipher::new(key)?,
        )
        .await?;
        responder.wait_session_ready().await?;

        match responder.recv().await? {
            ClientMessage::Request(payload) => {
                assert_eq!(payload.request_id, request_id);
                let request: serde_json::Value = serde_json::from_slice(&payload.request.0)?;
                assert_eq!(request, json!({ "method": "get_status" }));
            }
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

        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await
    .expect("live relay test timed out")?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires a deployed relay; set WALLET_SESSION_RELAY_URL"]
async fn wrong_audience_is_rejected() -> TestResult {
    let _guard = LIVE_LOCK.lock().await;
    let live = LiveRelay::from_env();

    timeout(TEST_TIMEOUT, async {
        let identity = IdentityKey::random()?;
        let topic = PairingKey::random()?.topic()?;
        let token =
            identity.connection_token("live-test", "wss://wrong-audience.invalid", TOKEN_TTL)?;
        let query = ConnectionQuery {
            auth: token,
            role: Role::Proposer,
            topic,
            registration_id: None,
        };
        let url = url_with_query(&live.url, &query)?;

        let error = connect_async(url)
            .await
            .expect_err("relay accepted a token minted for the wrong audience");
        match error {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                assert_eq!(
                    response.status().as_u16(),
                    400,
                    "relay must answer a bad token with 400 Bad Request"
                );
            }
            other => panic!("expected HTTP 400 for a wrong-audience token, got {other:?}"),
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await
    .expect("live relay test timed out")?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires a deployed relay; set WALLET_SESSION_RELAY_URL"]
async fn role_slot_is_exclusive() -> TestResult {
    let _guard = LIVE_LOCK.lock().await;
    let live = LiveRelay::from_env();

    timeout(TEST_TIMEOUT, async {
        let topic = PairingKey::random()?.topic()?;

        // Occupy the proposer slot with one identity.
        let _first = connect_raw(&live, &IdentityKey::random()?, Role::Proposer, &topic).await?;
        tokio::time::sleep(Duration::from_millis(300)).await;

        // A different identity must not be able to take the same slot.
        let mut second =
            connect_raw(&live, &IdentityKey::random()?, Role::Proposer, &topic).await?;
        let message = timeout(Duration::from_secs(5), second.next())
            .await
            .expect("timed out waiting for the role rejection")
            .expect("relay closed without a close frame")?;

        match message {
            Message::Close(Some(frame)) => {
                assert_eq!(frame.code, CloseCode::Policy);
                assert_eq!(frame.reason.as_str(), "role already taken");
            }
            other => panic!("expected a policy close for the taken role, got {other:?}"),
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await
    .expect("live relay test timed out")?;

    Ok(())
}
