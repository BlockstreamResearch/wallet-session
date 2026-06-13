use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde_json::Value;
use wc_protocol::session::{
    JsonRpcErrorResponse, JsonRpcRequest, JsonRpcResponse as SignJsonRpcResponse, Session,
    SessionAckResponse, SessionAuthenticateParams, SessionAuthenticateResult, SessionDeleteParams,
    SessionEventParams, SessionExtendParams, SessionPingParams, SessionProposeParams,
    SessionProposeResult, SessionRequestParams, SessionRequestResponse, SessionSettleParams,
    SessionUpdateParams, SignMethod,
};

use crate::{
    cli::JsonProbeInput,
    util::{json_kind, print_cacao_summary, sensitive_str_for_log, unix_timestamp},
};

pub fn run(input: JsonProbeInput) -> Result<()> {
    let json = match input {
        JsonProbeInput::Json(json) => json,
        JsonProbeInput::Sample => SAMPLE_SESSION_PROBE_JSON.to_owned(),
    };
    let value = serde_json::from_str::<Value>(&json).context("session probe input is not JSON")?;
    let values = match value {
        Value::Array(values) => values,
        value => vec![value],
    };
    let context = session_probe_context(&values);

    println!("session-probe items={} bytes={}", values.len(), json.len());

    for (index, value) in values.iter().enumerate() {
        let shape = session_probe_shape(value);
        println!("session-probe item={index} shape={shape}");
        session_probe_value(index, value, &context)?;
    }

    Ok(())
}

struct SessionProbeContext {
    proposal_ids: BTreeSet<u64>,
}

fn session_probe_context(values: &[Value]) -> SessionProbeContext {
    let proposal_ids = values
        .iter()
        .filter(|value| value.get("method").and_then(Value::as_str) == Some("wc_sessionPropose"))
        .filter_map(|value| {
            serde_json::from_value::<JsonRpcRequest<SessionProposeParams>>(value.clone()).ok()
        })
        .flat_map(|request| [request.id, request.params.effective_id(request.id)])
        .collect();

    SessionProbeContext { proposal_ids }
}

fn session_probe_shape(value: &Value) -> String {
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        return format!("{method}-request");
    }

    if value.get("error").is_some() {
        return "jsonrpc-error".to_owned();
    }

    if let Some(result) = value.get("result") {
        if result.get("cacaos").is_some() {
            return "wc_sessionAuthenticate-result".to_owned();
        }

        if result.get("responderPublicKey").is_some() {
            return "wc_sessionPropose-result".to_owned();
        }

        return format!("jsonrpc-result-{}", json_kind(result));
    }

    if value.get("topic").is_some()
        && value.get("pairingTopic").is_some()
        && value.get("namespaces").is_some()
    {
        return "stored-session".to_owned();
    }

    "unknown".to_owned()
}

fn session_probe_value(index: usize, value: &Value, context: &SessionProbeContext) -> Result<()> {
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        let method = SignMethod::from_wire(method)
            .with_context(|| format!("session-probe item={index} unknown Sign method {method}"))?;
        return session_probe_request(index, method, value);
    }

    if value.get("error").is_some() {
        return session_probe_error(index, value, context);
    }

    if let Some(result) = value.get("result") {
        return session_probe_result(index, value, result);
    }

    if value.get("topic").is_some()
        && value.get("pairingTopic").is_some()
        && value.get("namespaces").is_some()
    {
        return session_probe_stored_session(index, value);
    }

    bail!("session-probe item={index} unsupported JSON shape")
}

fn session_probe_error(index: usize, value: &Value, context: &SessionProbeContext) -> Result<()> {
    let response = serde_json::from_value::<JsonRpcErrorResponse>(value.clone())
        .with_context(|| format!("session-probe item={index} failed to parse error response"))?;
    let label = if context.proposal_ids.contains(&response.id) {
        "proposal_rejection"
    } else {
        "error"
    };
    println!(
        "session-probe item={index} {label} id={} code={} message={} data_present={} data_kind={}",
        response.id,
        response.error.code.as_i64(),
        response.error.message,
        response.error.data.is_some(),
        response.error.data.as_ref().map_or("<none>", json_kind)
    );
    Ok(())
}

fn session_probe_result(index: usize, value: &Value, result: &Value) -> Result<()> {
    if result.get("cacaos").is_some() {
        return session_probe_authenticate_result(index, value);
    }

    if result.get("responderPublicKey").is_some() {
        return session_probe_proposal_approval(index, value);
    }

    if result.is_boolean() {
        return session_probe_ack(index, value);
    }

    let response =
        serde_json::from_value::<SessionRequestResponse>(value.clone()).with_context(|| {
            format!("session-probe item={index} failed to parse session request result")
        })?;
    println!(
        "session-probe item={index} session_request_result id={} result_kind={}",
        response.id,
        json_kind(response.result.as_value())
    );
    Ok(())
}

fn session_probe_authenticate_result(index: usize, value: &Value) -> Result<()> {
    let response =
        serde_json::from_value::<SignJsonRpcResponse<SessionAuthenticateResult>>(value.clone())
            .with_context(|| {
                format!("session-probe item={index} failed to parse authenticate result")
            })?;
    println!(
        "session-probe item={index} authenticate_result id={} responder={} cacaos={}",
        response.id,
        sensitive_str_for_log(&response.result.responder.metadata.name),
        response.result.cacaos.len()
    );
    for (cacao_index, cacao) in response.result.cacaos.iter().enumerate() {
        print_cacao_summary("session-probe", cacao_index, cacao);
    }
    Ok(())
}

fn session_probe_proposal_approval(index: usize, value: &Value) -> Result<()> {
    let response =
        serde_json::from_value::<SignJsonRpcResponse<SessionProposeResult>>(value.clone())
            .with_context(|| {
                format!("session-probe item={index} failed to parse session propose result")
            })?;
    println!(
        "session-probe item={index} proposal_approval id={} relay={} responder_public_key={}",
        response.id, response.result.relay.protocol, response.result.responder_public_key
    );
    Ok(())
}

fn session_probe_ack(index: usize, value: &Value) -> Result<()> {
    let response =
        serde_json::from_value::<SessionAckResponse>(value.clone()).with_context(|| {
            format!("session-probe item={index} failed to parse session ack result")
        })?;
    println!(
        "session-probe item={index} session_ack id={} result=true",
        response.id
    );
    Ok(())
}

fn session_probe_stored_session(index: usize, value: &Value) -> Result<()> {
    let session = serde_json::from_value::<Session>(value.clone())
        .with_context(|| format!("session-probe item={index} failed to parse stored session"))?;
    println!(
        "session-probe item={index} stored_session topic={} pairing_topic={} self={} peer={} namespaces={} expiry={} expired_now={} transport={}",
        session.topic,
        session.pairing_topic,
        session.self_participant.metadata.name,
        session.peer.metadata.name,
        session.namespaces.len(),
        session.expiry,
        session.is_expired_at(unix_timestamp()),
        session
            .transport_type
            .as_ref()
            .map_or("<none>", wc_protocol::session::SessionTransportType::as_str)
    );
    Ok(())
}

fn session_probe_request(index: usize, method: SignMethod, value: &Value) -> Result<()> {
    match method {
        SignMethod::SessionPropose => print_session_propose_request(index, value),
        SignMethod::SessionSettle => print_session_settle_request(index, value),
        SignMethod::SessionUpdate => print_session_update_request(index, value),
        SignMethod::SessionExtend => print_session_extend_request(index, value),
        SignMethod::SessionDelete => print_session_delete_request(index, value),
        SignMethod::SessionPing => print_session_ping_request(index, value),
        SignMethod::SessionRequest => print_session_request_request(index, value),
        SignMethod::SessionEvent => print_session_event_request(index, value),
        SignMethod::SessionAuthenticate => print_session_authenticate_request(index, value),
    }
}

fn print_session_propose_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionProposeParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} proposer={} relays={} required_namespaces={} optional_namespaces={} expiry={:?} expired_now={}",
        request.method,
        request.id,
        request.params.proposer.metadata.name,
        request.params.relays.len(),
        request.params.required_namespaces.len(),
        request.params.optional_namespaces.len(),
        request.params.effective_expiry_timestamp(),
        request.params.is_expired_at(unix_timestamp())
    );
    Ok(())
}

fn print_session_settle_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionSettleParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} controller={} relay={} namespaces={} expiry={} expired_now={} session_config_present={} special_namespaces={}",
        request.method,
        request.id,
        request.params.controller.metadata.name,
        request.params.relay.protocol,
        request.params.namespaces.len(),
        request.params.expiry,
        request.params.is_expired_at(unix_timestamp()),
        request.params.session_config.is_some(),
        request
            .params
            .special_namespaces
            .as_ref()
            .map_or(0, std::collections::BTreeMap::len)
    );
    Ok(())
}

fn print_session_update_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionUpdateParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} namespaces={}",
        request.method,
        request.id,
        request.params.namespaces.len()
    );
    Ok(())
}

fn print_session_extend_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionExtendParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} expiry={:?} expired_now={}",
        request.method,
        request.id,
        request.params.expiry,
        request.params.is_expired_at(unix_timestamp())
    );
    Ok(())
}

fn print_session_delete_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionDeleteParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} code={} message={}",
        request.method, request.id, request.params.code, request.params.message
    );
    Ok(())
}

fn print_session_ping_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionPingParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} params=empty",
        request.method, request.id
    );
    Ok(())
}

fn print_session_request_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionRequestParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} chain={} routed_method={} params_kind={} expiry={:?} expired_now={}",
        request.method,
        request.id,
        request.params.chain_id,
        request.params.request.method,
        json_kind(&request.params.request.params),
        request.params.request.expiry_timestamp,
        request.params.is_expired_at(unix_timestamp())
    );
    Ok(())
}

fn print_session_event_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionEventParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} chain={} event={} data_kind={}",
        request.method,
        request.id,
        request.params.chain_id,
        request.params.event.name,
        json_kind(&request.params.event.data)
    );
    Ok(())
}

fn print_session_authenticate_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionAuthenticateParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} requester={} expiry={} expired_now={} chains=[{}] domain={} aud={} resources={}",
        request.method,
        request.id,
        sensitive_str_for_log(&request.params.requester.metadata.name),
        request.params.expiry_timestamp,
        request.params.is_expired_at(unix_timestamp()),
        sensitive_str_for_log(
            &request
                .params
                .auth_payload
                .chains
                .iter()
                .map(wc_protocol::caip::Caip2ChainId::as_str)
                .collect::<Vec<_>>()
                .join(",")
        ),
        sensitive_str_for_log(&request.params.auth_payload.domain),
        sensitive_str_for_log(&request.params.auth_payload.aud),
        request.params.auth_payload.resources.len()
    );
    Ok(())
}

fn typed_session_request<T>(index: usize, value: &Value) -> Result<JsonRpcRequest<T>>
where
    T: DeserializeOwned,
{
    serde_json::from_value::<JsonRpcRequest<T>>(value.clone())
        .with_context(|| format!("session-probe item={index} failed to parse typed request"))
}

const SAMPLE_SESSION_PROBE_JSON: &str = r#"[
  {
    "id": 1,
    "jsonrpc": "2.0",
    "method": "wc_sessionPropose",
    "params": {
      "id": 1,
      "pairingTopic": "1111111111111111111111111111111111111111111111111111111111111111",
      "expiryTimestamp": 4102444800,
      "relays": [{"protocol": "irn"}],
      "proposer": {
        "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
        "metadata": {
          "name": "Probe Dapp",
          "description": "Probe dapp",
          "url": "https://example.com/dapp",
          "icons": []
        }
      },
      "requiredNamespaces": {
        "eip155": {
          "chains": ["eip155:1"],
          "methods": ["personal_sign"],
          "events": ["accountsChanged"]
        }
      },
      "optionalNamespaces": {}
    }
  },
  {
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
      "relay": {"protocol": "irn"},
      "responderPublicKey": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337"
    }
  },
  {
    "id": 1,
    "jsonrpc": "2.0",
    "error": {"code": 5000, "message": "User rejected."}
  },
  {
    "id": 2,
    "jsonrpc": "2.0",
    "method": "wc_sessionSettle",
    "params": {
      "relay": {"protocol": "irn"},
      "namespaces": {
        "eip155": {
          "chains": ["eip155:1"],
          "accounts": ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"],
          "methods": ["personal_sign"],
          "events": ["accountsChanged"]
        }
      },
      "controller": {
        "publicKey": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
        "metadata": {
          "name": "Probe Wallet",
          "description": "Probe wallet",
          "url": "https://example.com/wallet",
          "icons": []
        }
      },
      "expiry": 4102444800,
      "sessionConfig": {"disableDeepLink": true}
    }
  },
  {
    "id": 3,
    "jsonrpc": "2.0",
    "method": "wc_sessionUpdate",
    "params": {
      "namespaces": {
        "eip155": {
          "chains": ["eip155:1"],
          "accounts": ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"],
          "methods": ["personal_sign", "eth_signTypedData"],
          "events": ["accountsChanged", "chainChanged"]
        }
      }
    }
  },
  {
    "id": 4,
    "jsonrpc": "2.0",
    "method": "wc_sessionExtend",
    "params": {"expiry": 4102444800}
  },
  {
    "id": 5,
    "jsonrpc": "2.0",
    "method": "wc_sessionDelete",
    "params": {"code": 6000, "message": "User disconnected."}
  },
  {
    "id": 6,
    "jsonrpc": "2.0",
    "method": "wc_sessionPing",
    "params": {}
  },
  {
    "id": 7,
    "jsonrpc": "2.0",
    "method": "wc_sessionRequest",
    "params": {
      "chainId": "eip155:1",
      "request": {
        "method": "personal_sign",
        "params": [
          "0x68656c6c6f",
          "0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"
        ],
        "expiryTimestamp": 4102444800
      }
    }
  },
  {
    "id": 8,
    "jsonrpc": "2.0",
    "method": "wc_sessionEvent",
    "params": {
      "chainId": "eip155:1",
      "event": {
        "name": "accountsChanged",
        "data": ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"]
      }
    }
  },
  {
    "id": 9,
    "jsonrpc": "2.0",
    "method": "wc_sessionAuthenticate",
    "params": {
      "requester": {
        "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
        "metadata": {
          "name": "Probe Dapp",
          "description": "Probe dapp",
          "url": "https://example.com/dapp",
          "icons": []
        }
      },
      "authPayload": {
        "type": "caip122",
        "chains": ["eip155:1"],
        "aud": "https://example.com/login",
        "domain": "example.com",
        "version": "1",
        "nonce": "1234567890",
        "iat": "2026-05-27T06:10:58.791Z",
        "resources": []
      },
      "expiryTimestamp": 4102444800
    }
  },
  {
    "id": 9,
    "jsonrpc": "2.0",
    "result": {
      "responder": {
        "publicKey": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
        "metadata": {
          "name": "Probe Wallet",
          "description": "Probe wallet",
          "url": "https://example.com/wallet",
          "icons": []
        }
      },
      "cacaos": [{
        "h": {"t": "caip122"},
        "p": {
          "iss": "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87",
          "domain": "example.com",
          "aud": "https://example.com/login",
          "version": "1",
          "nonce": "1234567890",
          "iat": "2026-05-27T06:10:58.791Z",
          "resources": []
        },
        "s": {"t": "eip191", "s": "0x00"}
      }]
    }
  },
  {
    "id": 10,
    "jsonrpc": "2.0",
    "result": true
  },
  {
    "id": 11,
    "jsonrpc": "2.0",
    "error": {"code": 5000, "message": "User rejected."}
  },
  {
    "topic": "2222222222222222222222222222222222222222222222222222222222222222",
    "pairingTopic": "1111111111111111111111111111111111111111111111111111111111111111",
    "relay": {"protocol": "irn"},
    "expiry": 4102444800,
    "acknowledged": true,
    "controller": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
    "namespaces": {
      "eip155": {
        "chains": ["eip155:1"],
        "accounts": ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"],
        "methods": ["personal_sign"],
        "events": ["accountsChanged"]
      }
    },
    "requiredNamespaces": {},
    "optionalNamespaces": {},
    "self": {
      "publicKey": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
      "metadata": {
        "name": "Probe Wallet",
        "description": "Probe wallet",
        "url": "https://example.com/wallet",
        "icons": []
      }
    },
    "peer": {
      "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
      "metadata": {
        "name": "Probe Dapp",
        "description": "Probe dapp",
        "url": "https://example.com/dapp",
        "icons": []
      }
    },
    "transportType": "relay"
  }
]"#;
