//! Local WebSocket tests for the native relay transport.

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};
use tokio_tungstenite::{
    accept_async,
    tungstenite::{
        Message,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use wc_protocol::relay::{
    IrnSubscribe, IrnSubscription, IrnSubscriptionData, RelayJsonRpcRequest, RelayJsonRpcResponse,
    RelayRequest, RelayRpcId, RelayTopic,
};
use wc_transport::{NativeRelayTransport, TransportError};

#[tokio::test]
async fn native_transport_sends_typed_relay_request() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let message = websocket
            .next()
            .await
            .expect("client sends frame")
            .expect("frame is readable");

        match message {
            Message::Text(text) => {
                serde_json::from_str::<serde_json::Value>(&text).expect("request frame is json")
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    });

    let connection = NativeRelayTransport::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    assert_eq!(connection.status(), 101);
    let mut transport = connection.into_transport();

    let topic = RelayTopic::from_bytes([0x11; 32]);
    let request = RelayJsonRpcRequest::new(RelayRpcId::new(7), IrnSubscribe::new(topic));
    transport
        .send_request(&request)
        .await
        .expect("sends request");

    let value = server.await.expect("server task joins");
    assert_eq!(
        value,
        json!({
            "id": 7,
            "jsonrpc": "2.0",
            "method": "irn_subscribe",
            "params": {
                "topic": "1111111111111111111111111111111111111111111111111111111111111111",
            },
        })
    );
}

#[tokio::test]
async fn native_transport_reads_text_and_binary_json_frames() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        websocket
            .send(Message::Text("{\"text\":true}".into()))
            .await
            .expect("sends text json");
        websocket
            .send(Message::Binary(br#"{"binary":true}"#.to_vec().into()))
            .await
            .expect("sends binary json");
    });

    let connection = NativeRelayTransport::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let mut transport = connection.into_transport();

    assert_eq!(
        transport.next_json().await.expect("reads text"),
        Some(json!({ "text": true }))
    );
    assert_eq!(
        transport.next_json().await.expect("reads binary"),
        Some(json!({ "binary": true }))
    );

    server.await.expect("server task joins");
}

#[tokio::test]
async fn native_transport_replies_to_ping_before_returning_json() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        websocket
            .send(Message::Ping(b"relay".to_vec().into()))
            .await
            .expect("sends ping");

        let message = timeout(Duration::from_secs(2), websocket.next())
            .await
            .expect("client sends pong before timeout")
            .expect("client sends pong")
            .expect("pong is readable");

        match message {
            Message::Pong(bytes) => assert_eq!(&bytes[..], b"relay"),
            other => panic!("expected pong, got {other:?}"),
        }

        websocket
            .send(Message::Text("{\"afterPing\":true}".into()))
            .await
            .expect("sends json after ping");
    });

    let connection = NativeRelayTransport::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let mut transport = connection.into_transport();

    assert_eq!(
        transport.next_json().await.expect("reads json after ping"),
        Some(json!({ "afterPing": true }))
    );

    server.await.expect("server task joins");
}

#[tokio::test]
async fn native_transport_acknowledges_subscription_push() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let message = websocket
            .next()
            .await
            .expect("client sends ack frame")
            .expect("frame is readable");

        match message {
            Message::Text(text) => {
                serde_json::from_str::<serde_json::Value>(&text).expect("ack frame is json")
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    });

    let connection = NativeRelayTransport::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let mut transport = connection.into_transport();

    let topic = RelayTopic::from_bytes([0x22; 32]);
    let request = RelayJsonRpcRequest {
        id: RelayRpcId::new(455_649_879_284_480),
        jsonrpc: "2.0".to_owned(),
        method: <IrnSubscription as RelayRequest>::METHOD.to_owned(),
        params: IrnSubscription {
            id: "subscription-id".to_owned(),
            data: IrnSubscriptionData {
                topic,
                message: "encrypted-payload".to_owned(),
                published_at: 1_779_882_524_426,
                tag: None,
            },
        },
    };

    transport
        .ack_subscription(&request)
        .await
        .expect("sends subscription ack");

    let value = server.await.expect("server task joins");
    assert_eq!(
        value,
        json!({
            "id": 455_649_879_284_480_u64,
            "jsonrpc": "2.0",
            "result": true,
        })
    );
}

#[tokio::test]
async fn native_transport_matches_expected_response_id() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        websocket
            .send(Message::Text(
                r#"{"id":7,"jsonrpc":"2.0","result":true}"#.into(),
            ))
            .await
            .expect("sends relay response");
    });

    let connection = NativeRelayTransport::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let mut transport = connection.into_transport();

    let response = transport
        .next_response::<bool>(RelayRpcId::new(7))
        .await
        .expect("reads expected response");

    match response {
        RelayJsonRpcResponse::Success(success) => assert!(success.result),
        RelayJsonRpcResponse::Error(error) => panic!("unexpected relay error: {error:?}"),
    }

    server.await.expect("server task joins");
}

#[tokio::test]
async fn native_transport_returns_unexpected_message_for_different_response_id() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        websocket
            .send(Message::Text(
                r#"{"id":8,"jsonrpc":"2.0","result":true}"#.into(),
            ))
            .await
            .expect("sends unrelated response");
    });

    let connection = NativeRelayTransport::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let mut transport = connection.into_transport();

    let error = transport
        .next_response::<bool>(RelayRpcId::new(7))
        .await
        .expect_err("response id mismatch is reported");

    match error {
        TransportError::UnexpectedMessage { expected_id, value } => {
            assert_eq!(expected_id, RelayRpcId::new(7));
            assert_eq!(value["id"], 8);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    server.await.expect("server task joins");
}

#[tokio::test]
async fn native_transport_reports_invalid_json_text_frame() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        websocket
            .send(Message::Text("{".into()))
            .await
            .expect("sends invalid json");
    });

    let connection = NativeRelayTransport::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let mut transport = connection.into_transport();

    let error = transport
        .next_json()
        .await
        .expect_err("invalid json is reported");

    assert!(matches!(error, TransportError::Json { .. }));
    server.await.expect("server task joins");
}

#[tokio::test]
async fn native_transport_reports_non_utf8_binary_frame() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        websocket
            .send(Message::Binary(vec![0xff].into()))
            .await
            .expect("sends non-utf8 binary");
    });

    let connection = NativeRelayTransport::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let mut transport = connection.into_transport();

    let error = transport
        .next_json()
        .await
        .expect_err("non-utf8 binary is reported");

    assert!(matches!(error, TransportError::Utf8 { .. }));
    server.await.expect("server task joins");
}

#[tokio::test]
async fn native_transport_reports_close_frame_metadata() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        websocket
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Away,
                reason: "server restart".into(),
            })))
            .await
            .expect("sends close frame");
    });

    let connection = NativeRelayTransport::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let mut transport = connection.into_transport();

    let error = transport
        .next_json()
        .await
        .expect_err("close frame is reported");

    match error {
        TransportError::Closed(close) => {
            assert_eq!(close.code, Some(1001));
            assert_eq!(close.reason, "server restart");
        }
        other => panic!("unexpected error: {other:?}"),
    }

    server.await.expect("server task joins");
}
