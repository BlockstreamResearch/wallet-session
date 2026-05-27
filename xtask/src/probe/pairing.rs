use anyhow::{Context, Result, bail};
use serde_json::Value;
use wc_protocol::{
    dto::pairing::{
        PairingDeleteParams, PairingJsonRpcRequest, PairingJsonRpcResponse, PairingMethod,
        PairingPingParams,
    },
    session::JsonRpcErrorResponse,
};

use crate::{cli::JsonProbeInput, util::json_kind};

pub fn run(input: JsonProbeInput) -> Result<()> {
    let json = match input {
        JsonProbeInput::Json(json) => json,
        JsonProbeInput::Sample => SAMPLE_PAIRING_PROBE_JSON.to_owned(),
    };
    let value = serde_json::from_str::<Value>(&json).context("pairing probe input is not JSON")?;
    let values = match value {
        Value::Array(values) => values,
        value => vec![value],
    };

    println!("pairing-probe items={} bytes={}", values.len(), json.len());

    for (index, value) in values.iter().enumerate() {
        let shape = pairing_probe_shape(value);
        println!("pairing-probe item={index} shape={shape}");
        pairing_probe_value(index, value)?;
    }

    Ok(())
}

fn pairing_probe_shape(value: &Value) -> String {
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        return format!("{method}-request");
    }

    if value.get("error").is_some() {
        return "jsonrpc-error".to_owned();
    }

    if let Some(result) = value.get("result") {
        return format!("pairing-result-{}", json_kind(result));
    }

    "unknown".to_owned()
}

fn pairing_probe_value(index: usize, value: &Value) -> Result<()> {
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        let method = PairingMethod::from_wire(method).with_context(|| {
            format!("pairing-probe item={index} unknown Pairing method {method}")
        })?;
        return pairing_probe_request(index, method, value);
    }

    if value.get("error").is_some() {
        let response =
            serde_json::from_value::<JsonRpcErrorResponse>(value.clone()).with_context(|| {
                format!("pairing-probe item={index} failed to parse error response")
            })?;
        println!(
            "pairing-probe item={index} error id={} code={} message={} data_present={} data_kind={}",
            response.id,
            response.error.code.as_i64(),
            response.error.message,
            response.error.data.is_some(),
            response.error.data.as_ref().map_or("<none>", json_kind)
        );
        return Ok(());
    }

    if value.get("result").is_some() {
        let response = serde_json::from_value::<PairingJsonRpcResponse<bool>>(value.clone())
            .with_context(|| {
                format!("pairing-probe item={index} failed to parse pairing result")
            })?;
        println!(
            "pairing-probe item={index} pairing_ack id={} result={}",
            response.id, response.result
        );
        return Ok(());
    }

    bail!("pairing-probe item={index} unsupported JSON shape")
}

fn pairing_probe_request(index: usize, method: PairingMethod, value: &Value) -> Result<()> {
    match method {
        PairingMethod::Ping => {
            let parsed =
                serde_json::from_value::<PairingJsonRpcRequest<PairingPingParams>>(value.clone());
            let request = parsed.with_context(|| {
                format!("pairing-probe item={index} failed to parse wc_pairingPing")
            })?;
            println!(
                "pairing-probe item={index} request method={} id={} params=empty",
                request.method, request.id
            );
        }
        PairingMethod::Delete => {
            let parsed =
                serde_json::from_value::<PairingJsonRpcRequest<PairingDeleteParams>>(value.clone());
            let request = parsed.with_context(|| {
                format!("pairing-probe item={index} failed to parse wc_pairingDelete")
            })?;
            println!(
                "pairing-probe item={index} request method={} id={} code={} message={}",
                request.method, request.id, request.params.code, request.params.message
            );
        }
    }

    Ok(())
}

const SAMPLE_PAIRING_PROBE_JSON: &str = r#"[
  {
    "id": 1779866795062281,
    "jsonrpc": "2.0",
    "method": "wc_pairingPing",
    "params": {}
  },
  {
    "id": 1779866795062281,
    "jsonrpc": "2.0",
    "result": true
  },
  {
    "id": 1779866796850380,
    "jsonrpc": "2.0",
    "method": "wc_pairingDelete",
    "params": {
      "message": "User disconnected.",
      "code": 6000
    }
  }
]"#;
