use serde_json::{Value, json};
use wc_bitcoin::BitcoinRequestReview;
use wc_core::{SessionRequestMethodReview, SingleSessionClient, SingleSessionPendingApproval};
use wc_protocol::session::{ProposalNamespaces, Session};
use wc_protocol::verify::VerifyAttestationHash;

use crate::{
    bitcoin::bitcoin_review_json_value,
    error::WcUniFfiError,
    types::{WcJsonPayload, WcPendingApproval, WcPendingApprovalKind},
    util::{json_string, operation_error, u64_to_i64},
};

pub fn pending_approval_to_record(
    client: &SingleSessionClient,
    approval: &SingleSessionPendingApproval,
) -> Result<WcPendingApproval, WcUniFfiError> {
    match approval {
        SingleSessionPendingApproval::SessionProposal(proposal) => Ok(WcPendingApproval {
            kind: WcPendingApprovalKind::SessionProposal,
            topic: proposal.pairing_topic().to_string(),
            request_id: u64_to_i64(proposal.proposal_id())?,
            review: WcJsonPayload::new(proposal_review_json(proposal)?),
        }),
        SingleSessionPendingApproval::SessionAuthenticate(authenticate) => {
            let review = client
                .session_authenticate_review(authenticate)
                .map_err(operation_error)?;
            Ok(WcPendingApproval {
                kind: WcPendingApprovalKind::SessionAuthenticate,
                topic: authenticate.pairing_topic().to_string(),
                request_id: u64_to_i64(authenticate.request_id())?,
                review: WcJsonPayload::new(authenticate_review_json(&review)?),
            })
        }
        SingleSessionPendingApproval::SessionRequest(review) => Ok(WcPendingApproval {
            kind: WcPendingApprovalKind::SessionRequest,
            topic: review.topic().to_string(),
            request_id: u64_to_i64(review.request_id())?,
            review: WcJsonPayload::new(session_request_review_json(review)?),
        }),
        SingleSessionPendingApproval::SessionUpdate(review) => Ok(WcPendingApproval {
            kind: WcPendingApprovalKind::SessionUpdate,
            topic: review.topic().to_string(),
            request_id: u64_to_i64(review.request_id())?,
            review: WcJsonPayload::new(session_update_review_json(review)?),
        }),
    }
}

pub fn proposal_review_json(
    proposal: &wc_core::SingleSessionProposal,
) -> Result<String, WcUniFfiError> {
    let metadata = &proposal.request().params.proposer.metadata;
    let required_namespaces = &proposal.request().params.required_namespaces;
    let optional_namespaces = &proposal.request().params.optional_namespaces;
    let auth_request_count = proposal.authentication_requests().len();
    let verify_risk = format!("{:?}", proposal.verify_risk_review().risk());
    json_string(&json!({
        "kind": "sessionProposal",
        "topic": proposal.pairing_topic().to_string(),
        "requestId": proposal.proposal_id(),
        "expiryTimestamp": proposal.expiry_timestamp(),
        "proposer": proposal.request().params.proposer,
        "requiredNamespaces": proposal.request().params.required_namespaces,
        "optionalNamespaces": proposal.request().params.optional_namespaces,
        "sessionProperties": proposal.request().params.session_properties,
        "scopedProperties": proposal.request().params.scoped_properties,
        "authenticationRequestCount": proposal.authentication_requests().len(),
        "verify": verify_review_json_value(&proposal.verify_risk_review()),
        "redirect": redirect_review_json_value(proposal.redirect()),
        "display": {
            "intent": "Connect WalletConnect session",
            "warnings": [
                "Approving creates a persistent session with the displayed app until you disconnect or the session expires.",
                "The app will be allowed to request the listed methods for the approved account. Each signing or transfer request still needs its own approval.",
                "Reject if the app name, URL, chain, or requested methods do not match what you intended to connect."
            ],
            "details": compact_fields(vec![
                display_field("App", &metadata.name),
                display_field("App URL", &metadata.url),
                display_field("Verify risk", verify_risk),
                display_field("Required namespaces", proposal_namespaces_summary(required_namespaces)),
                display_field("Optional namespaces", proposal_namespaces_summary(optional_namespaces)),
                display_field("Authentication requests", auth_request_count.to_string()),
                display_field(
                    "Proposal expiry",
                    proposal
                        .expiry_timestamp()
                        .map_or_else(|| "Unknown".to_owned(), |expiry| expiry.to_string()),
                ),
                display_field("Pairing topic", proposal.pairing_topic().to_string()),
            ]),
            "info": [
                "WalletConnect sessions are permission grants, not one-time signatures. Check the requested methods and accounts before approving.",
                "A later request prompt must still show exact intent, account, chain, and payload details before the wallet signs or broadcasts anything."
            ],
        },
    }))
}

pub fn authenticate_review_json(
    review: &wc_core::SessionAuthenticateReview,
) -> Result<String, WcUniFfiError> {
    let metadata = &review.requester().metadata;
    let payload_review = review.auth_payload_review();
    let verify_risk = format!("{:?}", review.verify_risk_review().risk());
    json_string(&json!({
        "kind": "sessionAuthenticate",
        "topic": review.topic().to_string(),
        "requestId": review.request_id(),
        "requester": review.requester(),
        "authPayload": review.auth_payload(),
        "payloadReview": {
            "chains": review.auth_payload_review().chains(),
            "audience": review.auth_payload_review().audience(),
            "domain": review.auth_payload_review().domain(),
            "nonce": review.auth_payload_review().nonce(),
            "statement": review.auth_payload_review().statement(),
            "resources": review.auth_payload_review().resources(),
            "recapResources": review.auth_payload_review().recap_resources(),
        },
        "expiryTimestamp": review.expiry_timestamp(),
        "publishedAt": review.published_at(),
        "verify": verify_review_json_value(&review.verify_risk_review()),
        "redirect": redirect_review_json_value(review.redirect()),
        "display": {
            "intent": "Authenticate with WalletConnect",
            "approval": {
                "enabled": true
            },
            "warnings": [
                "This request asks the wallet to sign a CAIP-122/CACAO authentication message that proves control of an account.",
                "Only approve authentication after the exact domain, audience, nonce, statement, and account match your intent.",
                "Approving returns a CACAO authentication object to the requester. It does not move funds."
            ],
            "details": compact_fields(vec![
                display_field("Requester", &metadata.name),
                display_field("Requester URL", &metadata.url),
                display_field("Verify risk", verify_risk),
                display_field("Domain", payload_review.domain()),
                display_field("Audience", payload_review.audience()),
                display_field("Nonce", payload_review.nonce()),
                display_field("Statement", payload_review.statement().unwrap_or("")),
                display_field("Chains", join_display(payload_review.chains().iter().map(ToString::to_string))),
                display_field("Resources", join_display(payload_review.resources().iter().cloned())),
                display_field("Expiry", review.expiry_timestamp().to_string()),
                display_field("Pairing topic", review.topic().to_string()),
            ]),
            "info": [
                "Authentication signatures can be used as login proof. Treat them like account-control attestations, not a harmless connection step.",
                "If the domain, URL, statement, or selected account is unfamiliar, reject the request and reconnect from the intended app."
            ],
        },
    }))
}

pub fn session_request_review_json(
    review: &wc_core::SessionRequestReview,
) -> Result<String, WcUniFfiError> {
    let bitcoin_review = BitcoinRequestReview::from_session_request(review);
    let bitcoin = bitcoin_review.as_ref().ok().map(bitcoin_review_json_value);
    let display = bitcoin_review
        .as_ref()
        .err()
        .map(|error| unreviewed_session_request_display_json_value(review, error.to_string()));
    json_string(&json!({
        "kind": "sessionRequest",
        "topic": review.topic().to_string(),
        "requestId": review.request_id(),
        "chainId": review.chain_id().to_string(),
        "method": review.method().to_string(),
        "expiryTimestamp": review.expiry_timestamp(),
        "publishedAt": review.published_at(),
        "authorizedAccountCount": review.authorized_accounts().len(),
        "paramsSummary": params_summary_json_value(review.params()),
        "methodReview": method_review_json_value(review),
        "bitcoin": bitcoin,
        "display": display,
        "verify": verify_review_json_value(&review.verify_risk_review()),
        "redirect": redirect_review_json_value(review.redirect()),
    }))
}

fn unreviewed_session_request_display_json_value(
    review: &wc_core::SessionRequestReview,
    reason: String,
) -> Value {
    json!({
        "intent": "Unsupported WalletConnect request",
        "approval": {
            "enabled": false,
            "reason": "This request does not have a reviewed execution payload."
        },
        "warnings": [
            "This wallet cannot safely approve this request because the payload could not be converted into a reviewed Bitcoin action.",
            "Reject this request unless the app can send a supported request with complete, reviewable details."
        ],
        "details": compact_fields(vec![
            display_field("Chain", review.chain_id().to_string()),
            display_field("Method", review.method().to_string()),
            display_field("Review status", reason),
            display_field("Authorized accounts", review.authorized_accounts().len().to_string()),
            display_field("Parameters", params_summary_display(review.params())),
        ]),
        "info": [
            "Clear signing requires the wallet to show the exact action, account, and payload before approval.",
            "The wallet only enables approval after the request has been parsed into a supported action with reviewed details."
        ],
    })
}

pub fn session_update_review_json(
    review: &wc_core::SessionUpdateReview,
) -> Result<String, WcUniFfiError> {
    let added = namespace_permissions_summary(review.diff().added());
    let removed = namespace_permissions_summary(review.diff().removed());
    json_string(&json!({
        "kind": "sessionUpdate",
        "topic": review.topic().to_string(),
        "requestId": review.request_id(),
        "currentNamespaces": review.current_namespaces(),
        "requestedNamespaces": review.requested_namespaces(),
        "diff": {
            "hasAdditions": review.diff().has_additions(),
            "hasRemovals": review.diff().has_removals(),
            "added": namespace_permissions_json_value(review.diff().added()),
            "removed": namespace_permissions_json_value(review.diff().removed()),
        },
        "redirect": redirect_review_json_value(review.redirect()),
        "display": {
            "intent": "Update WalletConnect session permissions",
            "warnings": [
                "Approving replaces this session's current permissions with the requested permissions.",
                "Added accounts, chains, methods, or events let the connected app request more actions in future prompts.",
                "Reject if any added permission does not match what you intended to grant."
            ],
            "details": compact_fields(vec![
                display_field("Added permissions", added),
                display_field("Removed permissions", removed),
                display_field("Has additions", yes_no(review.diff().has_additions())),
                display_field("Has removals", yes_no(review.diff().has_removals())),
                display_field("Session topic", review.topic().to_string()),
            ]),
            "info": [
                "A session update changes what the app may ask for later. It does not by itself sign or broadcast a transaction.",
                "After approval, future requests must still be reviewed against the exact app, account, chain, method, and payload."
            ],
        },
    }))
}

pub fn active_session_review_json(
    session: &Session,
    connection_state: &str,
) -> Result<String, WcUniFfiError> {
    let peer_name = session.peer.metadata.name.as_str();
    let peer_url = session.peer.metadata.url.as_str();
    let chains = session_chains(session);
    let accounts = session_accounts(session);
    let methods = session_methods(session);
    let events = session_events(session);
    let app_label = if peer_name.is_empty() {
        "Connected app"
    } else {
        peer_name
    };

    json_string(&json!({
        "kind": "activeSession",
        "topic": session.topic.to_string(),
        "pairingTopic": session.pairing_topic.to_string(),
        "expiryTimestamp": session.expiry,
        "acknowledged": session.acknowledged,
        "connectionState": connection_state,
        "peer": session.peer,
        "self": session.self_participant,
        "namespaces": session.namespaces,
        "sessionProperties": session.session_properties,
        "scopedProperties": session.scoped_properties,
        "display": {
            "intent": "Manage WalletConnect session",
            "warnings": [
                "This app can send requests for the granted accounts and methods until you disconnect or the session expires.",
                "Keep this session only if the app name, URL, chain, account, and methods match what you intended to connect."
            ],
            "details": compact_fields(vec![
                display_field("Connected app", app_label),
                display_field("App URL", peer_url),
                display_field("Connection state", connection_state),
                display_field("Acknowledged", yes_no(session.acknowledged)),
                display_field("Expiry", format!("Unix {}", session.expiry)),
                display_field("Chains", join_or_none(&chains)),
                display_field("Accounts", join_or_none(&accounts)),
                display_field("Methods", join_or_none(&methods)),
                display_field("Events", join_or_none(&events)),
                display_field("Session topic", session.topic.to_string()),
            ]),
            "info": [
                "A connected app cannot spend by itself, but it can ask the wallet to sign messages, sign PSBTs, send transfers, or share addresses allowed by the session.",
                "Request prompts still require wallet approval and should be checked against the exact app, account, method, and displayed request details."
            ],
        },
        "actions": {
            "disconnect": {
                "intent": "Disconnect WalletConnect session",
                "warnings": [
                    "Disconnecting stops this app from sending future requests through this session.",
                    "Use disconnect if you do not recognize the app, URL, account, chain, or granted methods."
                ],
                "details": compact_fields(vec![
                    display_field("Connected app", app_label),
                    display_field("App URL", peer_url),
                    display_field("Accounts losing access", join_or_none(&accounts)),
                    display_field("Methods losing access", join_or_none(&methods)),
                    display_field("Session topic", session.topic.to_string()),
                ]),
                "info": [
                    "The app may ask you to reconnect later. Reconnecting creates a new approval prompt with fresh permissions.",
                    "Disconnect does not move funds and does not revoke signatures that were already approved."
                ],
            },
            "extend": {
                "intent": "Extend WalletConnect session",
                "warnings": [
                    "Extending keeps the current grants active for longer. It does not add new chains, accounts, methods, or events.",
                    "Only extend if you still trust this app and still want it to request actions for the displayed accounts."
                ],
                "details": compact_fields(vec![
                    display_field("Connected app", app_label),
                    display_field("App URL", peer_url),
                    display_field("Current expiry", format!("Unix {}", session.expiry)),
                    display_field("Accounts kept active", join_or_none(&accounts)),
                    display_field("Methods kept active", join_or_none(&methods)),
                ]),
                "info": [
                    "The dapp will still need a separate approval for every signing or transaction request.",
                    "If the session context no longer matches your intent, disconnect instead of extending."
                ],
            }
        },
    }))
}

fn session_chains(session: &Session) -> Vec<String> {
    let mut chains = session
        .namespaces
        .values()
        .flat_map(|namespace| namespace.chains.iter().flatten())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    chains.sort();
    chains.dedup();
    chains
}

fn session_accounts(session: &Session) -> Vec<String> {
    let mut accounts = session
        .namespaces
        .values()
        .flat_map(|namespace| namespace.accounts.iter())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    accounts.sort();
    accounts.dedup();
    accounts
}

fn session_methods(session: &Session) -> Vec<String> {
    let mut methods = session
        .namespaces
        .values()
        .flat_map(|namespace| namespace.methods.iter())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    methods.sort();
    methods.dedup();
    methods
}

fn session_events(session: &Session) -> Vec<String> {
    let mut events = session
        .namespaces
        .values()
        .flat_map(|namespace| namespace.events.iter())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    events.sort();
    events.dedup();
    events
}

fn proposal_namespaces_summary(namespaces: &ProposalNamespaces) -> String {
    if namespaces.is_empty() {
        return "None".to_owned();
    }

    namespaces
        .iter()
        .map(|(key, namespace)| {
            let chains = namespace.chains.as_ref().map_or_else(
                || "Any compatible chain".to_owned(),
                |chains| join_display(chains.iter().map(ToString::to_string)),
            );
            let methods = join_display(namespace.methods.iter().map(ToString::to_string));
            let events = join_display(namespace.events.iter().map(ToString::to_string));
            format!("{key}: chains {chains}; methods {methods}; events {events}")
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn namespace_permissions_summary(set: &wc_core::SessionNamespacePermissionSet) -> String {
    if set.is_empty() {
        return "None".to_owned();
    }

    set.namespaces()
        .iter()
        .map(|(key, permissions)| {
            let chains = join_display(permissions.chains().iter().map(ToString::to_string));
            let accounts = join_display(permissions.accounts().iter().map(ToString::to_string));
            let methods = join_display(permissions.methods().iter().map(ToString::to_string));
            let events = join_display(permissions.events().iter().map(ToString::to_string));
            format!(
                "{key}: chains {chains}; accounts {accounts}; methods {methods}; events {events}"
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "None".to_owned()
    } else {
        values.join(", ")
    }
}

fn join_display<I>(values: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let values = values.into_iter().collect::<Vec<_>>();
    if values.is_empty() {
        "None".to_owned()
    } else {
        values.join(", ")
    }
}

fn display_field(label: impl Into<String>, value: impl Into<String>) -> Value {
    json!({
        "label": label.into(),
        "value": value.into(),
    })
}

fn compact_fields(fields: Vec<Value>) -> Vec<Value> {
    fields
        .into_iter()
        .filter(|field| {
            field
                .get("value")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        })
        .collect()
}

const fn yes_no(value: bool) -> &'static str {
    if value { "Yes" } else { "No" }
}

fn namespace_permissions_json_value(set: &wc_core::SessionNamespacePermissionSet) -> Value {
    Value::Object(
        set.namespaces()
            .iter()
            .map(|(namespace, permissions)| {
                (
                    namespace.to_string(),
                    json!({
                        "chains": permissions.chains().iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "accounts": permissions.accounts().iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "methods": permissions.methods().iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "events": permissions.events().iter().map(ToString::to_string).collect::<Vec<_>>(),
                    }),
                )
            })
            .collect(),
    )
}

fn verify_review_json_value(review: &wc_core::VerifyRiskReview) -> Value {
    json!({
        "surface": format!("{:?}", review.surface()),
        "topic": review.topic().to_string(),
        "requestId": review.request_id(),
        "payloadHash": review.payload_hash().map(ToString::to_string),
        "risk": format!("{:?}", review.risk()),
        "requiresExplicitUserReview": review.requires_explicit_user_review(),
        "shouldRejectByDefault": review.should_reject_by_default(),
        "context": review.verify_context(),
    })
}

fn redirect_review_json_value(review: &wc_core::WalletRedirectReview) -> Value {
    json!({
        "origin": format!("{:?}", review.origin()),
        "native": review.native(),
        "universal": review.universal(),
        "linkModeRequested": review.link_mode_requested(),
        "hasMetadata": review.has_metadata(),
        "allowsAutomaticRedirect": review.allows_automatic_redirect(),
        "automaticTarget": review.automatic_target().map(|target| json!({
            "kind": format!("{:?}", target.kind()),
            "uri": target.uri(),
        })),
        "linkModeTarget": review.link_mode_target().map(|target| json!({
            "kind": format!("{:?}", target.kind()),
            "uri": target.uri(),
        })),
    })
}

fn params_summary_json_value(params: &Value) -> Value {
    match params {
        Value::Array(values) => json!({
            "shape": "array",
            "len": values.len(),
            "hash": VerifyAttestationHash::from_message(&params.to_string()).to_string(),
        }),
        Value::Object(object) => json!({
            "shape": "object",
            "keys": object.keys().cloned().collect::<Vec<_>>(),
            "hash": VerifyAttestationHash::from_message(&params.to_string()).to_string(),
        }),
        Value::String(value) => json!({
            "shape": "string",
            "charLen": value.chars().count(),
            "byteLen": value.len(),
            "hash": VerifyAttestationHash::from_message(value).to_string(),
        }),
        Value::Null => json!({ "shape": "null" }),
        Value::Bool(_) => json!({ "shape": "bool" }),
        Value::Number(_) => json!({ "shape": "number" }),
    }
}

fn params_summary_display(params: &Value) -> String {
    match params {
        Value::Array(values) => format!("array with {} item(s)", values.len()),
        Value::Object(object) => {
            let keys = object.keys().cloned().collect::<Vec<_>>();
            if keys.is_empty() {
                "object with no keys".to_owned()
            } else {
                format!("object keys: {}", keys.join(", "))
            }
        }
        Value::String(value) => format!("string, {} chars", value.chars().count()),
        Value::Null => "null".to_owned(),
        Value::Bool(_) => "boolean".to_owned(),
        Value::Number(_) => "number".to_owned(),
    }
}

fn method_review_json_value(review: &wc_core::SessionRequestReview) -> Value {
    match review.method_review() {
        Ok(SessionRequestMethodReview::Signing(signing)) => json!({
            "type": "signing",
            "kind": format!("{:?}", signing.kind()),
            "account": account_constraint_json_value(signing.account()),
            "chain": signing.chain().map(chain_constraint_json_value),
            "requiresUnsafeRawSigningWarning": signing.requires_unsafe_raw_signing_warning(),
            "message": signing.message().map(signing_message_json_value),
            "typedData": signing.typed_data().map(typed_data_json_value),
            "transaction": signing.transaction().map(transaction_summary_json_value),
        }),
        Ok(SessionRequestMethodReview::Transaction(transaction)) => json!({
            "type": "transaction",
            "account": account_constraint_json_value(transaction.account()),
            "chain": transaction.chain().map(chain_constraint_json_value),
            "summary": transaction_summary_json_value(transaction.summary()),
        }),
        Ok(SessionRequestMethodReview::WalletCall(wallet_call)) => {
            wallet_call_review_json_value(&wallet_call)
        }
        Ok(SessionRequestMethodReview::ExternalTyped(external)) => json!({
            "type": "externalTyped",
            "method": external.method().to_string(),
            "reviewer": external.reviewer(),
        }),
        Ok(SessionRequestMethodReview::Raw) => json!({
            "type": "raw",
            "status": "unsupportedByBinding",
        }),
        Err(error) => json!({
            "type": "invalid",
            "error": error.to_string(),
        }),
    }
}

fn account_constraint_json_value(account: &wc_core::SessionRequestAccountConstraint) -> Value {
    json!({
        "status": format!("{:?}", account.status()),
        "requestedAddress": account.requested_address(),
        "authorizedAccountCount": account.authorized_accounts().len(),
        "matched": account.matched_account().is_some(),
    })
}

fn chain_constraint_json_value(chain: &wc_core::SessionRequestChainConstraint) -> Value {
    json!({
        "status": format!("{:?}", chain.status()),
        "caip2ChainId": chain.caip2_chain_id().map(ToString::to_string),
    })
}

fn wallet_call_chain_json_value(chain: &wc_core::WalletCallChainConstraint) -> Value {
    json!({
        "status": format!("{:?}", chain.status()),
        "rawChainId": chain.raw_chain_id(),
        "caip2ChainId": chain.caip2_chain_id().map(ToString::to_string),
    })
}

fn signing_message_json_value(message: &wc_core::SigningMessageSummary) -> Value {
    json!({
        "status": format!("{:?}", message.status()),
        "byteLen": message.byte_len(),
        "characterLen": message.character_len(),
        "payloadHash": message.payload_hash().to_string(),
        "requiresUnsafeRawSigningWarning": message.requires_unsafe_raw_signing_warning(),
    })
}

fn typed_data_json_value(typed_data: &wc_core::Eip712TypedDataSummary) -> Value {
    json!({
        "status": format!("{:?}", typed_data.status()),
        "displayStatus": format!("{:?}", typed_data.display_status()),
        "primaryType": typed_data.primary_type(),
        "domain": {
            "name": typed_data.domain().name(),
            "version": typed_data.domain().version(),
            "chain": typed_data.domain().chain().map(chain_constraint_json_value),
            "verifyingContract": typed_data.domain().verifying_contract().map(evm_address_json_value),
            "keys": typed_data.domain().keys(),
        },
        "typeNames": typed_data.type_names(),
        "messageKeys": typed_data.message_keys(),
    })
}

fn transaction_summary_json_value(summary: &wc_core::EvmTransactionSummary) -> Value {
    json!({
        "status": format!("{:?}", summary.status()),
        "displayFieldCount": summary.display_field_count(),
        "to": summary.to().map(evm_address_json_value),
        "value": summary.value().map(evm_quantity_json_value),
        "data": summary.data().map(evm_calldata_json_value),
    })
}

fn evm_call_json_value(call: &wc_core::EvmCallSummary) -> Value {
    json!({
        "displayFieldCount": call.display_field_count(),
        "to": call.to().map(evm_address_json_value),
        "value": call.value().map(evm_quantity_json_value),
        "data": call.data().map(evm_calldata_json_value),
    })
}

fn evm_address_json_value(address: &wc_core::EvmAddressSummary) -> Value {
    json!({
        "status": format!("{:?}", address.status()),
        "address": address.address(),
    })
}

fn evm_quantity_json_value(quantity: &wc_core::EvmHexQuantity) -> Value {
    json!({
        "status": format!("{:?}", quantity.status()),
        "decimal": quantity.decimal(),
    })
}

fn evm_calldata_json_value(calldata: &wc_core::EvmCalldataSummary) -> Value {
    json!({
        "status": format!("{:?}", calldata.status()),
        "byteLen": calldata.byte_len(),
        "functionSelector": calldata.function_selector(),
    })
}

fn wallet_call_review_json_value(review: &wc_core::WalletCallReview) -> Value {
    match review {
        wc_core::WalletCallReview::GetCapabilities(capabilities) => json!({
            "type": "walletGetCapabilities",
            "address": account_constraint_json_value(capabilities.address()),
            "requestedChains": capabilities.requested_chains().iter().map(wallet_call_chain_json_value).collect::<Vec<_>>(),
        }),
        wc_core::WalletCallReview::SendCalls(send_calls) => json!({
            "type": "walletSendCalls",
            "from": account_constraint_json_value(send_calls.from()),
            "requestedChain": wallet_call_chain_json_value(send_calls.requested_chain()),
            "callCount": send_calls.call_count(),
            "atomicRequired": send_calls.atomic_required(),
            "capabilityKeys": send_calls.capability_keys(),
            "calls": send_calls.calls().iter().map(evm_call_json_value).collect::<Vec<_>>(),
        }),
        wc_core::WalletCallReview::GetCallsStatus(status) => json!({
            "type": "walletGetCallsStatus",
            "idHash": VerifyAttestationHash::from_message(status.id()).to_string(),
            "binding": wallet_call_status_binding_json_value(status.binding()),
        }),
        wc_core::WalletCallReview::ShowCallsStatus(status) => json!({
            "type": "walletShowCallsStatus",
            "idHash": VerifyAttestationHash::from_message(status.id()).to_string(),
            "binding": wallet_call_status_binding_json_value(status.binding()),
        }),
    }
}

fn wallet_call_status_binding_json_value(binding: &wc_core::WalletCallStatusIdBinding) -> Value {
    json!({
        "status": format!("{:?}", binding.status()),
        "matched": binding.matched_entry().is_some(),
    })
}
