//! Local WebSocket tests for the relay client behavior layer.

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use wc_protocol::relay::{IrnPublish, IrnUnsubscribe, RelayTopic};
use wc_transport::{RelayClient, RelayClientError};

#[tokio::test]
async fn relay_client_subscribe_returns_subscription_id() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;
        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["method"], "irn_subscribe");
        assert_eq!(
            request["params"]["topic"],
            "1111111111111111111111111111111111111111111111111111111111111111"
        );

        websocket
            .send(Message::Text(
                json!({
                    "id": request["id"],
                    "jsonrpc": "2.0",
                    "result": "subscription-id",
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("sends subscribe response");
    });

    let mut client = RelayClient::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    assert_eq!(client.status(), 101);

    let subscription_id = client
        .subscribe(RelayTopic::from_bytes([0x11; 32]))
        .await
        .expect("subscribes");
    assert_eq!(subscription_id, "subscription-id");

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_publish_returns_relay_ack() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;
        assert_eq!(request["method"], "irn_publish");
        assert_eq!(request["params"]["message"], "encrypted");
        assert_eq!(request["params"]["ttl"], 30);
        assert_eq!(request["params"]["tag"], 1100);

        websocket
            .send(Message::Text(
                json!({
                    "id": request["id"],
                    "jsonrpc": "2.0",
                    "result": true,
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("sends publish response");
    });

    let mut client = RelayClient::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let ack = client
        .publish(IrnPublish::new(
            RelayTopic::from_bytes([0x22; 32]),
            "encrypted",
            30,
            1100,
        ))
        .await
        .expect("publishes");

    assert!(ack);
    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_next_message_acknowledges_subscription_push() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        websocket
            .send(Message::Text(
                subscription_push_json(9001).to_string().into(),
            ))
            .await
            .expect("sends subscription push");

        let ack = read_json_frame(&mut websocket).await;
        assert_eq!(ack["id"], 9001);
        assert_eq!(ack["result"], true);
    });

    let mut client = RelayClient::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let message = client
        .next_message()
        .await
        .expect("reads message")
        .expect("message is present");

    assert_eq!(message.id, "push-subscription-id");
    assert_eq!(message.data.message, "encrypted-payload");
    assert_eq!(message.data.topic, RelayTopic::from_bytes([0x33; 32]));

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_queues_subscription_push_while_waiting_for_response() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;

        websocket
            .send(Message::Text(
                subscription_push_json(9002).to_string().into(),
            ))
            .await
            .expect("sends subscription push before response");

        let ack = read_json_frame(&mut websocket).await;
        assert_eq!(ack["id"], 9002);
        assert_eq!(ack["result"], true);

        websocket
            .send(Message::Text(
                json!({
                    "id": request["id"],
                    "jsonrpc": "2.0",
                    "result": "subscription-id",
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("sends subscribe response");
    });

    let mut client = RelayClient::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let subscription_id = client
        .subscribe(RelayTopic::from_bytes([0x44; 32]))
        .await
        .expect("subscribes after queued push");
    assert_eq!(subscription_id, "subscription-id");

    let message = client
        .next_message()
        .await
        .expect("reads queued message")
        .expect("message is queued");
    assert_eq!(message.data.message, "encrypted-payload");

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_maps_relay_error_response() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;

        websocket
            .send(Message::Text(
                json!({
                    "id": request["id"],
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": "Invalid payload",
                        "data": "Serialization",
                    },
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("sends relay error response");
    });

    let mut client = RelayClient::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let error = client
        .publish(IrnPublish::new(
            RelayTopic::from_bytes([0x55; 32]),
            "encrypted",
            30,
            1100,
        ))
        .await
        .expect_err("relay error is mapped");

    match error {
        RelayClientError::Relay {
            code,
            message,
            data,
        } => {
            assert_eq!(code, -32600);
            assert_eq!(message, "Invalid payload");
            assert_eq!(data.as_deref(), Some("Serialization"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_batch_methods_use_relay_shapes() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");

        let batch_subscribe = read_json_frame(&mut websocket).await;
        assert_eq!(batch_subscribe["method"], "irn_batchSubscribe");
        assert_eq!(
            batch_subscribe["params"]["topics"]
                .as_array()
                .expect("topics array")
                .len(),
            2
        );
        send_result(&mut websocket, &batch_subscribe, json!(["sub-a", "sub-b"])).await;

        let batch_fetch = read_json_frame(&mut websocket).await;
        assert_eq!(batch_fetch["method"], "irn_batchFetchMessages");
        send_result(
            &mut websocket,
            &batch_fetch,
            json!({
                "messages": [{
                    "topic": "6666666666666666666666666666666666666666666666666666666666666666",
                    "message": "cached",
                    "publishedAt": 1_779_886_081_486_u64,
                }],
                "hasMore": false,
            }),
        )
        .await;

        let batch_unsubscribe = read_json_frame(&mut websocket).await;
        assert_eq!(batch_unsubscribe["method"], "irn_batchUnsubscribe");
        send_result(&mut websocket, &batch_unsubscribe, json!(true)).await;
    });

    let mut client = RelayClient::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let topic_a = RelayTopic::from_bytes([0x66; 32]);
    let topic_b = RelayTopic::from_bytes([0x77; 32]);

    let subscription_ids = client
        .batch_subscribe(vec![topic_a.clone(), topic_b.clone()])
        .await
        .expect("batch subscribes");
    assert_eq!(subscription_ids, ["sub-a", "sub-b"]);

    let fetched = client
        .batch_fetch_messages(vec![topic_a.clone(), topic_b.clone()])
        .await
        .expect("batch fetches");
    assert!(!fetched.has_more);
    assert_eq!(fetched.messages.len(), 1);
    assert_eq!(fetched.messages[0].message, "cached");

    let unsubscribed = client
        .batch_unsubscribe(vec![
            IrnUnsubscribe::new(topic_a, "sub-a"),
            IrnUnsubscribe::new(topic_b, "sub-b"),
        ])
        .await
        .expect("batch unsubscribes");
    assert!(unsubscribed);

    server.await.expect("server task joins");
}

async fn read_json_frame(
    websocket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
) -> Value {
    let message = websocket
        .next()
        .await
        .expect("peer sends frame")
        .expect("frame is readable");

    match message {
        Message::Text(text) => serde_json::from_str::<Value>(&text).expect("text frame is json"),
        other => panic!("unexpected frame: {other:?}"),
    }
}

async fn send_result(
    websocket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    request: &Value,
    result: Value,
) {
    websocket
        .send(Message::Text(
            json!({
                "id": request["id"],
                "jsonrpc": "2.0",
                "result": result,
            })
            .to_string()
            .into(),
        ))
        .await
        .expect("sends result");
}

fn subscription_push_json(id: u64) -> Value {
    json!({
        "id": id,
        "jsonrpc": "2.0",
        "method": "irn_subscription",
        "params": {
            "id": "push-subscription-id",
            "data": {
                "topic": "3333333333333333333333333333333333333333333333333333333333333333",
                "message": "encrypted-payload",
                "publishedAt": 1_779_882_524_426_u64,
            },
        },
    })
}
