use serde_json::{Value, json};
use wc_bitcoin::{
    BitcoinAccountAddresses, BitcoinAccountScope, BitcoinConnectedAccount, BitcoinRequest,
    BitcoinRequestReview, GET_ACCOUNT_ADDRESSES_SESSION_PROPERTY, SendTransferResult,
    SignMessageResult, SignPsbtResult,
};
use wc_protocol::caip::Caip2ChainId;

use crate::{
    error::WcUniFfiError,
    util::{invalid_error, invalid_input, json_string, parse_json_value},
};

#[uniffi::export]
/// Builds Bitcoin session properties JSON from wallet-owned account addresses.
pub fn wc_bitcoin_session_properties_json(addresses_json: String) -> Result<String, WcUniFfiError> {
    let addresses: BitcoinAccountAddresses = serde_json::from_str(&addresses_json)
        .map_err(|error| invalid_input(format!("invalid Bitcoin addresses JSON: {error}")))?;
    json_string(
        &addresses.session_properties().map_err(|error| {
            invalid_input(format!("invalid Bitcoin session properties: {error}"))
        })?,
    )
}

/// Builds `wc_sessionEvent` params JSON for `bip122_addressesChanged`.
#[uniffi::export]
pub fn wc_bitcoin_addresses_changed_event_params_json(
    chain_id: String,
    addresses_json: String,
) -> Result<String, WcUniFfiError> {
    let chain_id = Caip2ChainId::parse(chain_id).map_err(invalid_error)?;
    let addresses: BitcoinAccountAddresses = serde_json::from_str(&addresses_json)
        .map_err(|error| invalid_input(format!("invalid Bitcoin addresses JSON: {error}")))?;
    json_string(
        &addresses
            .addresses_changed_event_params(chain_id)
            .map_err(|error| invalid_input(format!("invalid Bitcoin event params: {error}")))?,
    )
}
pub fn bitcoin_review_json_value(review: &BitcoinRequestReview) -> Value {
    json!({
        "requestId": review.request_id(),
        "chainId": review.chain_id().to_string(),
        "method": review.request().method().as_str(),
        "account": review.request().account().to_string(),
        "authorization": format!("{:?}", review.authorization()),
        "request": bitcoin_request_json_value(review.request()),
        "display": bitcoin_request_display_json_value_for_chain(
            review.request(),
            Some(review.chain_id().reference()),
        ),
    })
}

fn bitcoin_request_json_value(request: &BitcoinRequest) -> Value {
    match request {
        BitcoinRequest::SendTransfer(params) => json!({
            "type": "sendTransfer",
            "account": params.account.to_string(),
            "recipientAddress": params.recipient_address.to_string(),
            "amountSats": params.amount.to_sat().to_string(),
            "changeAddress": params.change_address.as_ref().map(ToString::to_string),
            "memo": params.memo.as_ref().map(ToString::to_string),
            "memoByteLen": params.memo.as_ref().map(wc_bitcoin::BitcoinMemo::byte_len),
        }),
        BitcoinRequest::GetAccountAddresses(params) => json!({
            "type": "getAccountAddresses",
            "account": params.account.to_string(),
            "intentions": params.intentions,
        }),
        BitcoinRequest::SignPsbt(params) => json!({
            "type": "signPsbt",
            "account": params.account.to_string(),
            "psbt": params.psbt.as_str(),
            "psbtLen": params.psbt.as_str().len(),
            "signInputs": params.sign_inputs.iter().map(|input| json!({
                "address": input.address.to_string(),
                "index": input.index,
                "sighashTypes": input.sighash_types_or_default(),
            })).collect::<Vec<_>>(),
            "broadcast": params.broadcast,
        }),
        BitcoinRequest::SignMessage(params) => json!({
            "type": "signMessage",
            "account": params.account.to_string(),
            "message": params.message,
            "messageLength": params.message.chars().count(),
            "address": params.address.as_ref().map(ToString::to_string),
            "signingAddress": params.signing_address().to_string(),
            "protocol": params.protocol_or_default().as_str(),
        }),
    }
}

#[cfg(test)]
pub(crate) fn bitcoin_request_display_json_value(request: &BitcoinRequest) -> Value {
    bitcoin_request_display_json_value_for_chain(request, None)
}

fn bitcoin_request_display_json_value_for_chain(
    request: &BitcoinRequest,
    chain_reference: Option<&str>,
) -> Value {
    match request {
        BitcoinRequest::SendTransfer(params) => json!({
            "intent": "Send Bitcoin",
            "warnings": [
                "Approving will sign and broadcast a Bitcoin transaction that spends wallet funds."
            ],
            "details": compact_fields([
                display_field("Amount", format_sats(params.amount.to_sat())),
                display_field("Recipient", params.recipient_address.to_string()),
                display_field("Connected account", params.account.to_string()),
                display_field(
                    "Change address",
                    params.change_address.as_ref().map_or_else(
                        || "Wallet-selected".to_owned(),
                        ToString::to_string,
                    ),
                ),
                display_field(
                    "Memo",
                    params.memo.as_ref().map_or_else(|| "None".to_owned(), ToString::to_string),
                ),
            ]),
            "info": [
                "Compare the amount and recipient with what you intended before approving."
            ],
        }),
        BitcoinRequest::GetAccountAddresses(params) => json!({
            "intent": "Share Bitcoin addresses",
            "warnings": [
                "This shares wallet-owned addresses with the connected app."
            ],
            "details": compact_fields([
                display_field("Connected account", params.account.to_string()),
                display_field(
                    "Requested intentions",
                    if params.intentions.is_empty() {
                        "Not specified".to_owned()
                    } else {
                        params.intentions.join(", ")
                    },
                ),
            ]),
            "info": [
                "Only wallet-owned addresses in the connected account scope can be returned."
            ],
        }),
        BitcoinRequest::SignPsbt(params) => {
            let wallet_selected_inputs = params.sign_inputs.is_empty();
            let summary = params.psbt.summary(chain_reference).ok();
            json!({
                "intent": if params.broadcast { "Sign and broadcast PSBT" } else { "Sign PSBT" },
                "warnings": if params.broadcast {
                    vec![
                        "Approving will sign the PSBT and broadcast the final Bitcoin transaction.",
                        "Only approve if the PSBT matches the payment you intended.",
                    ]
                } else {
                    vec![
                        "Approving creates signatures for a partially signed Bitcoin transaction.",
                        "A signed PSBT may later be finalized and broadcast outside this wallet.",
                    ]
                },
                "details": sign_psbt_details(params, summary.as_ref()),
                "info": sign_psbt_info(wallet_selected_inputs, summary.as_ref()),
            })
        }
        BitcoinRequest::SignMessage(params) => json!({
            "intent": "Sign Bitcoin message",
            "warnings": [
                "A signature proves control of the signing address for this exact message."
            ],
            "details": compact_fields([
                display_field("Protocol", params.protocol_or_default().as_str().to_owned()),
                display_field("Connected account", params.account.to_string()),
                display_field("Signing address", params.signing_address().to_string()),
                display_field("Message", params.message.clone()),
                display_field("Message length", format!("{} chars", params.message.chars().count())),
            ]),
            "info": [
                "Only sign if the displayed message, app, and signing address match your intent."
            ],
        }),
    }
}

fn sign_psbt_details(
    params: &wc_bitcoin::SignPsbtParams,
    summary: Option<&wc_bitcoin::BitcoinPsbtSummary>,
) -> Vec<Value> {
    let wallet_selected_inputs = params.sign_inputs.is_empty();
    let mut fields = vec![
        display_field("Connected account", params.account.to_string()),
        display_field("PSBT size", format!("{} chars", params.psbt.as_str().len())),
        display_field("Broadcast after signing", yes_no(params.broadcast)),
        display_field(
            "Input selection",
            if wallet_selected_inputs {
                "Wallet-selected spendable inputs only".to_owned()
            } else {
                format!("{} requested input(s)", params.sign_inputs.len())
            },
        ),
        display_field("Requested signers", sign_psbt_signers_summary(params)),
    ];

    if let Some(summary) = summary {
        fields.extend([
            display_field("PSBT inputs", format!("{} input(s)", summary.input_count)),
            display_field(
                "PSBT outputs",
                format!("{} output(s)", summary.output_count),
            ),
            display_field(
                "Total output amount",
                format_optional_sats(summary.total_output_sats),
            ),
            display_field("Outputs", sign_psbt_outputs_summary(summary)),
            display_field(
                "OP_RETURN outputs",
                format!("{} output(s)", summary.op_return_output_count),
            ),
            display_field(
                "Known input amounts",
                format!(
                    "{} of {} input(s)",
                    summary.known_input_count, summary.input_count
                ),
            ),
            display_field("Estimated fee", format_optional_sats(summary.fee_sats)),
        ]);
    }

    compact_fields(fields)
}

fn sign_psbt_info(
    wallet_selected_inputs: bool,
    summary: Option<&wc_bitcoin::BitcoinPsbtSummary>,
) -> Vec<&'static str> {
    let mut info = if wallet_selected_inputs {
        vec![
            "The app did not name specific inputs. The wallet will only sign PSBT inputs that match this wallet's spendable UTXOs.",
        ]
    } else {
        vec!["Every requested input signer must belong to the connected Bitcoin account."]
    };

    match summary {
        Some(summary) if summary.fee_sats.is_some() => info.push(
            "The PSBT includes input amounts, so the displayed fee is derived from inputs minus outputs.",
        ),
        Some(_) => info.push(
            "The PSBT does not include enough input amount data to derive the fee; compare the displayed outputs with your intent before approving.",
        ),
        None => info.push(
            "The wallet could not summarize this PSBT; only approve if you independently verified the transaction.",
        ),
    }

    info
}

fn display_field(label: impl Into<String>, value: impl Into<String>) -> Value {
    json!({
        "label": label.into(),
        "value": value.into(),
    })
}

fn compact_fields(fields: impl IntoIterator<Item = Value>) -> Vec<Value> {
    fields
        .into_iter()
        .filter(|field| {
            field
                .get("value")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        })
        .collect()
}

fn format_sats(sats: u64) -> String {
    let btc = sats / 100_000_000;
    let fractional = sats % 100_000_000;
    let unit = if sats == 1 { "sat" } else { "sats" };
    format!("{sats} {unit} ({btc}.{fractional:08} BTC)")
}

fn format_optional_sats(sats: Option<u64>) -> String {
    sats.map_or_else(|| "Unavailable".to_owned(), format_sats)
}

fn sign_psbt_outputs_summary(summary: &wc_bitcoin::BitcoinPsbtSummary) -> String {
    if summary.outputs.is_empty() {
        return "None".to_owned();
    }

    let mut outputs = summary
        .outputs
        .iter()
        .take(4)
        .map(sign_psbt_output_summary)
        .collect::<Vec<_>>();
    if summary.outputs.len() > outputs.len() {
        outputs.push(format!("+{} more", summary.outputs.len() - outputs.len()));
    }
    outputs.join("; ")
}

fn sign_psbt_output_summary(output: &wc_bitcoin::BitcoinPsbtOutputSummary) -> String {
    match &output.destination {
        wc_bitcoin::BitcoinPsbtOutputDestination::Address(address) => format!(
            "#{}: {} to {}",
            output.index,
            format_sats(output.amount_sats),
            address
        ),
        wc_bitcoin::BitcoinPsbtOutputDestination::OpReturn => {
            format!(
                "#{}: {} OP_RETURN data",
                output.index,
                format_sats(output.amount_sats)
            )
        }
        wc_bitcoin::BitcoinPsbtOutputDestination::ScriptHex(script) => format!(
            "#{}: {} to script {}",
            output.index,
            format_sats(output.amount_sats),
            truncate_middle(script, 24)
        ),
    }
}

fn truncate_middle(value: &str, max_len: usize) -> String {
    if value.len() <= max_len || max_len < 5 {
        return value.to_owned();
    }

    let prefix_len = (max_len - 3) / 2;
    let suffix_len = max_len - 3 - prefix_len;
    format!(
        "{}...{}",
        &value[..prefix_len],
        &value[value.len() - suffix_len..]
    )
}

fn yes_no(value: bool) -> String {
    if value { "Yes" } else { "No" }.to_owned()
}

fn sign_psbt_signers_summary(params: &wc_bitcoin::SignPsbtParams) -> String {
    if params.sign_inputs.is_empty() {
        return "Not specified by app".to_owned();
    }

    let mut signers = params
        .sign_inputs
        .iter()
        .map(|input| input.address.to_string())
        .collect::<Vec<_>>();
    signers.sort();
    signers.dedup();
    signers.join(", ")
}
pub fn validated_bitcoin_result(
    request: &BitcoinRequest,
    result_json: &str,
    account_scope: Option<&BitcoinAccountScope>,
) -> Result<Value, WcUniFfiError> {
    let value = parse_json_value(result_json)?;
    match request {
        BitcoinRequest::SendTransfer(_) => {
            let _: SendTransferResult =
                serde_json::from_value(value.clone()).map_err(invalid_error)?;
        }
        BitcoinRequest::GetAccountAddresses(params) => {
            let account_scope = account_scope.ok_or_else(|| {
                invalid_input(
                    "getAccountAddresses result requires active Bitcoin account address scope",
                )
            })?;
            let addresses: BitcoinAccountAddresses =
                serde_json::from_value(value.clone()).map_err(invalid_error)?;
            addresses
                .validate_for_request_and_scope(params, account_scope)
                .map_err(invalid_error)?;
        }
        BitcoinRequest::SignPsbt(params) => {
            let result: SignPsbtResult =
                serde_json::from_value(value.clone()).map_err(invalid_error)?;
            result.validate_for_request(params).map_err(invalid_error)?;
        }
        BitcoinRequest::SignMessage(params) => {
            let result: SignMessageResult =
                serde_json::from_value(value.clone()).map_err(invalid_error)?;
            result.validate_for_request(params).map_err(invalid_error)?;
        }
    }
    Ok(value)
}

pub fn bitcoin_account_scope_from_session(
    session: Option<&wc_protocol::session::Session>,
    request: &BitcoinRequest,
) -> Result<Option<BitcoinAccountScope>, WcUniFfiError> {
    let BitcoinRequest::GetAccountAddresses(params) = request else {
        return Ok(None);
    };
    let session = session
        .ok_or_else(|| invalid_input("getAccountAddresses result requires an active session"))?;
    let properties = session
        .session_properties
        .as_ref()
        .ok_or_else(|| invalid_input("active session is missing Bitcoin session properties"))?;
    let value = properties
        .get(GET_ACCOUNT_ADDRESSES_SESSION_PROPERTY)
        .ok_or_else(|| {
            invalid_input("active session is missing bip122_getAccountAddresses scope")
        })?;
    let addresses = match value.as_str() {
        Some(serialized) => {
            serde_json::from_str::<BitcoinAccountAddresses>(serialized).map_err(invalid_error)?
        }
        None => serde_json::from_value::<BitcoinAccountAddresses>(value.clone())
            .map_err(invalid_error)?,
    };
    let account =
        BitcoinConnectedAccount::from_wallet_first_external_address(params.account.clone());
    let scope =
        BitcoinAccountScope::from_account_addresses(account, &addresses).map_err(invalid_error)?;
    Ok(Some(scope))
}
