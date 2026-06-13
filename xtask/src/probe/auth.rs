use anyhow::{Context, Result, bail};
use serde_json::Value;
use wc_protocol::session::{
    Cacao, JsonRpcRequest, JsonRpcResponse as SignJsonRpcResponse, SessionAuthenticateParams,
    SessionAuthenticateResult,
};

use crate::{
    cli::JsonProbeInput,
    util::{print_cacao_summary, sensitive_str_for_log},
};

pub fn run(input: JsonProbeInput) -> Result<()> {
    let json = match input {
        JsonProbeInput::Json(json) => json,
        JsonProbeInput::Sample => SAMPLE_AUTH_RESULT_JSON.to_owned(),
    };
    let value = serde_json::from_str::<Value>(&json).context("auth probe input is not JSON")?;

    println!(
        "auth-probe shape={} bytes={}",
        auth_probe_shape(&value),
        json.len()
    );

    if let Some(method) = value.get("method").and_then(Value::as_str) {
        println!("auth-probe jsonrpc_method={method}");
    }

    if value.get("method").and_then(Value::as_str) == Some("wc_sessionAuthenticate") {
        let request = serde_json::from_value::<JsonRpcRequest<SessionAuthenticateParams>>(value)
            .context("failed to parse wc_sessionAuthenticate request")?;
        println!(
            "auth-probe authenticate_request id={} requester={} expiry={} chains=[{}] domain={} aud={} resources={}",
            request.id,
            sensitive_str_for_log(&request.params.requester.metadata.name),
            request.params.expiry_timestamp,
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
        return Ok(());
    }

    if value
        .get("result")
        .and_then(|result| result.get("cacaos"))
        .is_some()
    {
        let response =
            serde_json::from_value::<SignJsonRpcResponse<SessionAuthenticateResult>>(value)
                .context("failed to parse wc_sessionAuthenticate result")?;
        println!(
            "auth-probe authenticate_result id={} responder={} cacaos={}",
            response.id,
            sensitive_str_for_log(&response.result.responder.metadata.name),
            response.result.cacaos.len()
        );
        for (index, cacao) in response.result.cacaos.iter().enumerate() {
            print_cacao_summary("auth-probe", index, cacao);
        }
        return Ok(());
    }

    if value.get("h").is_some() && value.get("p").is_some() && value.get("s").is_some() {
        let cacao = serde_json::from_value::<Cacao>(value).context("failed to parse CACAO")?;
        print_cacao_summary("auth-probe", 0, &cacao);
        return Ok(());
    }

    bail!("unsupported auth probe JSON shape")
}

fn auth_probe_shape(value: &Value) -> &'static str {
    if value.get("method").and_then(Value::as_str) == Some("wc_sessionAuthenticate") {
        "wc_sessionAuthenticate-request"
    } else if value
        .get("result")
        .and_then(|result| result.get("cacaos"))
        .is_some()
    {
        "wc_sessionAuthenticate-result"
    } else if value.get("h").is_some() && value.get("p").is_some() && value.get("s").is_some() {
        "cacao"
    } else {
        "unknown"
    }
}

const SAMPLE_AUTH_RESULT_JSON: &str = r#"{
  "id": 1779862258791507,
  "jsonrpc": "2.0",
  "result": {
    "cacaos": [
      {
        "h": {
          "t": "caip122"
        },
        "p": {
          "iss": "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87",
          "domain": "example.com",
          "aud": "https://example.com/login",
          "version": "1",
          "nonce": "1234567890",
          "iat": "2026-05-27T06:10:58.791Z",
          "statement": "",
          "resources": [
            "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XX19fQ"
          ]
        },
        "s": {
          "t": "eip191",
          "s": "0x5851cc642b66ba30b0073bd3a46c141d46d426eb013465aead257597ca3282a5530db47176d8400e79ac6ed0f8e53ffe87f5d52df421d712be2cbeb02e4768011b"
        }
      }
    ],
    "responder": {
      "publicKey": "977b7da860028df30993e70f25cc6d4f8dd67c4c2e8bb7a84b091a0f9cc37809",
      "metadata": {
        "name": "wc-rs live auth wallet",
        "description": "Temporary live probe wallet",
        "url": "https://example.com/wallet",
        "icons": [
          ""
        ]
      }
    }
  }
}"#;
