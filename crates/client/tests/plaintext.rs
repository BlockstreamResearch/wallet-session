use std::{sync::Arc, time::Duration};

use serde_json::json;
use tokio::net::TcpListener;
use wallet_session_client::{
    Client, ClientConfig, ClientMessage, IdentityKey, PairingKey, Role, Seed,
};
use wallet_session_relay::{
    connection::NativeRelayTransportConfig, registry::Registry, server::serve,
};

const AUDIENCE: &str = "wss://relay.example.com";

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
    )
    .await?;
    let mut responder = Client::connect(
        responder_config,
        responder_identity,
        Role::Responder,
        topic.clone(),
    )
    .await?;

    proposer.wait_session_ready().await?;
    responder.wait_session_ready().await?;

    proposer.propose(json!({ "chains": ["eip155:1"] })).await?;
    match responder.recv().await? {
        ClientMessage::Proposal { proposal } => {
            assert_eq!(proposal, json!({ "chains": ["eip155:1"] }));
        }
        other => panic!("expected proposal, got {other:?}"),
    }

    responder.approve(json!({ "ok": true })).await?;
    assert!(matches!(
        proposer.recv().await?,
        ClientMessage::Approve { .. }
    ));

    let request_id = proposer.request(json!({ "method": "eth_chainId" })).await?;
    match responder.recv().await? {
        ClientMessage::Request {
            request_id: received,
            request,
        } => {
            assert_eq!(received, request_id);
            assert_eq!(request, json!({ "method": "eth_chainId" }));
        }
        other => panic!("expected request, got {other:?}"),
    }

    responder
        .respond(request_id.clone(), Some(json!({ "result": "0x1" })), None)
        .await?;
    match proposer.recv().await? {
        ClientMessage::Response {
            request_id: received,
            response,
            error,
        } => {
            assert_eq!(received, request_id);
            assert_eq!(response, Some(json!({ "result": "0x1" })));
            assert_eq!(error, None);
        }
        other => panic!("expected response, got {other:?}"),
    }

    Ok(())
}
