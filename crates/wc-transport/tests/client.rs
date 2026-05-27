//! Local WebSocket tests for the relay client behavior layer.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use wc_protocol::relay::{IrnPublish, IrnUnsubscribe, RelayTopic};
use wc_transport::{RelayClient, RelayClientConfig, RelayClientError, TransportError};

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
async fn relay_client_applies_incoming_frame_limit() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;
        assert_eq!(request["method"], "irn_subscribe");

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
            .expect("sends oversized response");
    });

    let mut client = RelayClient::connect_with_config(
        &format!("ws://{address}"),
        RelayClientConfig {
            max_incoming_frame_bytes: 4,
            ..RelayClientConfig::default()
        },
    )
    .await
    .expect("connects to local websocket");

    let error = client
        .subscribe(RelayTopic::from_bytes([0x23; 32]))
        .await
        .expect_err("oversized response is rejected");

    match error {
        RelayClientError::Transport {
            source: TransportError::FrameTooLarge { actual, limit },
        } => {
            assert!(actual > limit);
            assert_eq!(limit, 4);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_next_message_acknowledges_subscription_push() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");
    let topic = RelayTopic::from_bytes([0x33; 32]);
    let server_topic = topic.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;
        assert_eq!(request["method"], "irn_subscribe");
        send_result(&mut websocket, &request, json!("push-subscription-id")).await;

        websocket
            .send(Message::Text(
                subscription_push_json(9001, &server_topic)
                    .to_string()
                    .into(),
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
    let subscription_id = client
        .subscribe(topic.clone())
        .await
        .expect("subscribes before reading pushes");
    assert_eq!(subscription_id, "push-subscription-id");

    let message = client
        .next_message()
        .await
        .expect("reads message")
        .expect("message is present");

    assert_eq!(message.id, "push-subscription-id");
    assert_eq!(message.data.message, "encrypted-payload");
    assert_eq!(message.data.topic, topic);

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_queues_subscription_push_while_waiting_for_response() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");
    let topic = RelayTopic::from_bytes([0x44; 32]);
    let server_topic = topic.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;

        websocket
            .send(Message::Text(
                subscription_push_json(9002, &server_topic)
                    .to_string()
                    .into(),
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
        .subscribe(topic)
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
async fn relay_client_failed_subscribe_prunes_pending_pushes() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");
    let topic = RelayTopic::from_bytes([0x5a; 32]);
    let server_topic = topic.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;
        assert_eq!(request["method"], "irn_subscribe");

        websocket
            .send(Message::Text(
                subscription_push_json(9003, &server_topic)
                    .to_string()
                    .into(),
            ))
            .await
            .expect("sends pending subscription push");

        let ack = read_json_frame(&mut websocket).await;
        assert_eq!(ack["id"], 9003);
        assert_eq!(ack["result"], true);

        websocket
            .send(Message::Text(
                json!({
                    "id": request["id"],
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": "Invalid payload",
                    },
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("sends relay error response");

        sleep(Duration::from_millis(120)).await;
    });

    let mut client = RelayClient::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let error = client
        .subscribe(topic)
        .await
        .expect_err("subscribe fails after pending push");

    assert!(matches!(error, RelayClientError::Relay { .. }));

    let no_queued_message = timeout(Duration::from_millis(30), client.next_message()).await;
    assert!(no_queued_message.is_err());

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
        .batch_fetch_messages(&[topic_a.clone(), topic_b.clone()])
        .await
        .expect("batch fetches");
    assert!(!fetched.has_more);
    assert_eq!(fetched.messages.len(), 1);
    assert_eq!(fetched.messages[0].message, "cached");

    let unsubscribed = client
        .batch_unsubscribe(&[
            IrnUnsubscribe::new(topic_a, "sub-a"),
            IrnUnsubscribe::new(topic_b, "sub-b"),
        ])
        .await
        .expect("batch unsubscribes");
    assert!(unsubscribed);

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_times_out_waiting_for_response() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;
        assert_eq!(request["method"], "irn_subscribe");
        sleep(Duration::from_millis(120)).await;
    });

    let mut client = RelayClient::connect_with_config(
        &format!("ws://{address}"),
        RelayClientConfig {
            request_timeout: Duration::from_millis(20),
            ..RelayClientConfig::default()
        },
    )
    .await
    .expect("connects to local websocket");

    let error = client
        .subscribe(RelayTopic::from_bytes([0x88; 32]))
        .await
        .expect_err("request times out");

    match error {
        RelayClientError::RequestTimedOut { timeout } => {
            assert_eq!(timeout, Duration::from_millis(20));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_pushes_do_not_extend_response_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");
    let topic = RelayTopic::from_bytes([0x89; 32]);
    let server_topic = topic.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;
        assert_eq!(request["method"], "irn_subscribe");

        for id in [9010_u64, 9011, 9012] {
            websocket
                .send(Message::Text(
                    subscription_push_json(id, &server_topic).to_string().into(),
                ))
                .await
                .expect("sends subscription push");

            let ack = read_json_frame(&mut websocket).await;
            assert_eq!(ack["id"], id);
            assert_eq!(ack["result"], true);
        }

        sleep(Duration::from_millis(120)).await;
    });

    let mut client = RelayClient::connect_with_config(
        &format!("ws://{address}"),
        RelayClientConfig {
            request_timeout: Duration::from_millis(40),
            ..RelayClientConfig::default()
        },
    )
    .await
    .expect("connects to local websocket");

    let error = client
        .subscribe(topic)
        .await
        .expect_err("request times out after queued pushes");

    match error {
        RelayClientError::RequestTimedOut { timeout } => {
            assert_eq!(timeout, Duration::from_millis(40));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_rejects_too_many_pushes_while_waiting() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");
    let topic = RelayTopic::from_bytes([0x8a; 32]);
    let server_topic = topic.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;
        assert_eq!(request["method"], "irn_subscribe");

        websocket
            .send(Message::Text(
                subscription_push_json(9020, &server_topic)
                    .to_string()
                    .into(),
            ))
            .await
            .expect("sends first push");
        websocket
            .send(Message::Text(
                subscription_push_json(9021, &server_topic)
                    .to_string()
                    .into(),
            ))
            .await
            .expect("sends second push");

        let ack = read_json_frame(&mut websocket).await;
        assert_eq!(ack["id"], 9020);
        assert_eq!(ack["result"], true);
    });

    let mut client = RelayClient::connect_with_config(
        &format!("ws://{address}"),
        RelayClientConfig {
            max_pushes_while_waiting: 1,
            ..RelayClientConfig::default()
        },
    )
    .await
    .expect("connects to local websocket");

    let error = client
        .subscribe(topic)
        .await
        .expect_err("second push exceeds per-request limit");

    match error {
        RelayClientError::PushLimitExceeded { limit } => assert_eq!(limit, 1),
        other => panic!("unexpected error: {other:?}"),
    }

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_rejects_queue_overflow() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");
    let topic = RelayTopic::from_bytes([0x8b; 32]);
    let server_topic = topic.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;
        assert_eq!(request["method"], "irn_subscribe");

        websocket
            .send(Message::Text(
                subscription_push_json(9030, &server_topic)
                    .to_string()
                    .into(),
            ))
            .await
            .expect("sends subscription push");

        let ack = read_json_frame(&mut websocket).await;
        assert_eq!(ack["id"], 9030);
        assert_eq!(ack["result"], true);
    });

    let mut client = RelayClient::connect_with_config(
        &format!("ws://{address}"),
        RelayClientConfig {
            max_queued_messages: 0,
            ..RelayClientConfig::default()
        },
    )
    .await
    .expect("connects to local websocket");

    let error = client
        .subscribe(topic)
        .await
        .expect_err("queue capacity rejects push");

    match error {
        RelayClientError::QueueFull { limit } => assert_eq!(limit, 0),
        other => panic!("unexpected error: {other:?}"),
    }

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_rejects_unexpected_subscription_topic() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");
    let expected_topic = RelayTopic::from_bytes([0x8c; 32]);
    let unexpected_topic = RelayTopic::from_bytes([0x8d; 32]);
    let server_topic = unexpected_topic.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;
        assert_eq!(request["method"], "irn_subscribe");

        websocket
            .send(Message::Text(
                subscription_push_json(9040, &server_topic)
                    .to_string()
                    .into(),
            ))
            .await
            .expect("sends subscription push");

        let ack = read_json_frame(&mut websocket).await;
        assert_eq!(ack["id"], 9040);
        assert_eq!(ack["result"], true);
    });

    let mut client = RelayClient::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");

    let error = client
        .subscribe(expected_topic)
        .await
        .expect_err("unexpected topic is rejected");

    match error {
        RelayClientError::UnexpectedSubscriptionTopic { topic } => {
            assert_eq!(topic, unexpected_topic);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_rejects_batch_subscribe_length_mismatch() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");
        let request = read_json_frame(&mut websocket).await;
        assert_eq!(request["method"], "irn_batchSubscribe");
        send_result(&mut websocket, &request, json!(["only-one-id"])).await;
    });

    let mut client = RelayClient::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let error = client
        .batch_subscribe(vec![
            RelayTopic::from_bytes([0x8e; 32]),
            RelayTopic::from_bytes([0x8f; 32]),
        ])
        .await
        .expect_err("batch response length mismatch is rejected");

    match error {
        RelayClientError::BatchSubscribeLength { expected, actual } => {
            assert_eq!(expected, 2);
            assert_eq!(actual, 1);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    server.await.expect("server task joins");
}

#[tokio::test]
async fn relay_client_unsubscribe_prunes_queued_topic_messages() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds local websocket listener");
    let address = listener.local_addr().expect("listener address");
    let topic = RelayTopic::from_bytes([0x90; 32]);
    let server_topic = topic.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts client");
        let mut websocket = accept_async(stream).await.expect("accepts websocket");

        let subscribe = read_json_frame(&mut websocket).await;
        assert_eq!(subscribe["method"], "irn_subscribe");
        send_result(&mut websocket, &subscribe, json!("sub-id")).await;

        let unsubscribe = read_json_frame(&mut websocket).await;
        assert_eq!(unsubscribe["method"], "irn_unsubscribe");
        websocket
            .send(Message::Text(
                subscription_push_json(9050, &server_topic)
                    .to_string()
                    .into(),
            ))
            .await
            .expect("sends push during unsubscribe");

        let ack = read_json_frame(&mut websocket).await;
        assert_eq!(ack["id"], 9050);
        assert_eq!(ack["result"], true);
        send_result(&mut websocket, &unsubscribe, json!(true)).await;
        sleep(Duration::from_millis(120)).await;
    });

    let mut client = RelayClient::connect(&format!("ws://{address}"))
        .await
        .expect("connects to local websocket");
    let subscription_id = client.subscribe(topic.clone()).await.expect("subscribes");
    assert_eq!(subscription_id, "sub-id");

    let unsubscribed = client
        .unsubscribe(&topic, &subscription_id)
        .await
        .expect("unsubscribes");
    assert!(unsubscribed);

    let no_queued_message = timeout(Duration::from_millis(30), client.next_message()).await;
    assert!(no_queued_message.is_err());

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

fn subscription_push_json(id: u64, topic: &RelayTopic) -> Value {
    json!({
        "id": id,
        "jsonrpc": "2.0",
        "method": "irn_subscription",
        "params": {
            "id": "push-subscription-id",
            "data": {
                "topic": topic.as_str(),
                "message": "encrypted-payload",
                "publishedAt": 1_779_882_524_426_u64,
            },
        },
    })
}
