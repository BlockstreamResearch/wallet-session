use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::timeout;
use wc_protocol::{
    key::X25519KeyPair,
    pairing::PairingUri,
    relay::{DEFAULT_RELAY_URL, RelayAuthToken, RelayConnectionUrl, relay_auth_audience},
    session::{
        JsonRpcError, JsonRpcRequest, Session, SessionDeleteParams, SessionEventParams,
        SessionNamespaces, SessionProposeParams, SignMethod,
    },
};
use wc_transport::{RelayClient, RelayClientConfig};

use super::{
    DEFAULT_PAIRING_RECEIVE_TIMEOUT, SESSION_DELETE_REQUEST_TAG, SESSION_DELETE_RESPONSE_TAG,
    SESSION_EVENT_REQUEST_TAG, SESSION_EVENT_RESPONSE_TAG, SESSION_EXTEND_REQUEST_TAG,
    SESSION_EXTEND_RESPONSE_TAG, SESSION_UPDATE_REQUEST_TAG, SESSION_UPDATE_RESPONSE_TAG,
    approval::{
        next_sign_rpc_id, session_proposal_approval_publishes, session_proposal_reject_publish,
    },
    codec::{
        decode_session_lifecycle_response_data, decode_session_message_data,
        decode_session_message_data_unchecked, decode_session_settle_response_data,
        decode_subscription_data, validate_session_message_payload,
    },
    error::PairingClientError,
    pairing_lifecycle::pairing_ping_response_publish,
    session_lifecycle::{
        session_delete_request_publish, session_delete_response_publish,
        session_event_request_publish, session_extend_request_publish,
        session_ping_response_publish, session_update_request_publish,
    },
    session_request::{
        session_request_error_publish, session_request_success_publish,
        session_request_validation_error,
    },
    types::{
        ApprovedSession, PairingReceivedMessage, PairingSubscription, SessionClientEvent,
        SessionLifecycleRequest, SessionLifecycleResponseMessage, SessionMessageOutcome,
        SessionPayload, SessionProposalApproval, SessionReceivedMessage, SessionRequestRejection,
        SessionSettleResponseMessage, SessionSubscription,
    },
};

/// Bounded same-topic deliveries inspected while waiting for a lifecycle ack.
///
/// A relay may deliver the locally published request back to the active
/// subscription before the peer response arrives. The bound keeps that skip path
/// finite while still accepting the common request-echo then response sequence.
const MAX_SESSION_LIFECYCLE_RESPONSE_DELIVERIES: usize = 4;

/// Configuration for a native pairing-topic relay client.
///
/// The pairing receive path uses Relay Auth query parameters before opening the
/// WebSocket connection.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth#overview>
///
/// > WalletConnect expects an `Authorization: Bearer <signed jwt>` header when establishing the Websocket connection.
/// > Where websocket headers are not supported i.e. browsers, use the URL query param `?auth=<signed jwt>`.
///
/// # Examples
///
/// ```
/// use wc_core::{PairingClientConfig, DEFAULT_PAIRING_RECEIVE_TIMEOUT};
///
/// let config = PairingClientConfig::new("project-id", [7; 32], "client-subject");
///
/// assert_eq!(config.project_id, "project-id");
/// assert_eq!(config.receive_timeout, DEFAULT_PAIRING_RECEIVE_TIMEOUT);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingClientConfig {
    /// Reown/WalletConnect Cloud project ID used by the public relay.
    pub project_id: String,
    /// Relay WebSocket endpoint.
    pub relay_url: String,
    /// User-agent value placed in the relay connection URL.
    pub user_agent: String,
    /// Ed25519 seed used to sign the Relay Auth JWT.
    pub auth_seed: [u8; 32],
    /// Relay Auth JWT `sub` claim.
    pub auth_subject: String,
    /// Relay Auth JWT lifetime in seconds.
    pub auth_ttl_seconds: u64,
    /// Maximum time spent waiting for one live pairing message.
    pub receive_timeout: Duration,
    /// Runtime limits for the underlying relay client.
    pub relay_client: RelayClientConfig,
}

impl PairingClientConfig {
    /// Builds a config with the public relay URL and conservative runtime defaults.
    #[must_use]
    pub fn new(
        project_id: impl Into<String>,
        auth_seed: [u8; 32],
        auth_subject: impl Into<String>,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            relay_url: DEFAULT_RELAY_URL.to_owned(),
            user_agent: "wc-2/rust-poc-0.1.0/macos/native".to_owned(),
            auth_seed,
            auth_subject: auth_subject.into(),
            auth_ttl_seconds: 86_400,
            receive_timeout: DEFAULT_PAIRING_RECEIVE_TIMEOUT,
            relay_client: RelayClientConfig::default(),
        }
    }
}

/// Native client for receiving encrypted messages on a pairing topic.
///
/// This is the first core behavior layer above the relay transport. It parses
/// and checks pairing metadata, fetches retained relay messages, subscribes to
/// the pairing topic, and decodes encrypted pairing-topic payloads.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionpropose>
///
/// > Used to propose a session through topic A. Requires a success response
/// > with associated data.
///
/// # Examples
///
/// ```no_run
/// use wc_core::{PairingClient, PairingClientConfig};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let mut client = PairingClient::connect(&PairingClientConfig::new(
///     "project-id",
///     [7; 32],
///     "client-subject",
/// ))
/// .await?;
///
/// assert_eq!(client.status(), 101);
/// # Ok(())
/// # }
/// ```
pub struct PairingClient {
    relay: RelayClient,
    receive_timeout: Duration,
}

impl PairingClient {
    /// Opens an authenticated relay connection for pairing-topic operations.
    pub async fn connect(config: &PairingClientConfig) -> Result<Self, PairingClientError> {
        let url = relay_connection_url(config, now_unix_seconds()?)?;
        let relay = RelayClient::connect_with_config(url.as_str(), config.relay_client.clone())
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(Self {
            relay,
            receive_timeout: config.receive_timeout,
        })
    }

    /// HTTP status returned during the relay WebSocket upgrade.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.relay.status()
    }

    /// Fetches retained messages for a parsed pairing URI.
    ///
    /// Relay clients fetch before subscribing so messages published while a
    /// wallet was offline are not skipped.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#fetch-messages>
    ///
    /// > Used when a client wants to fetch all undelivered messages matching a single topic before subscribing.
    pub async fn fetch_pairing_messages(
        &mut self,
        pairing: &PairingUri,
    ) -> Result<Vec<PairingReceivedMessage>, PairingClientError> {
        validate_pairing_not_expired(pairing, now_unix_seconds()?)?;
        let response = self
            .relay
            .fetch_messages(pairing.topic())
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        response
            .messages
            .into_iter()
            .map(|data| decode_subscription_data(data, pairing.sym_key()))
            .collect()
    }

    /// Subscribes to the relay topic carried by a parsed pairing URI.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscribe>
    ///
    /// > Used when a client subscribes a given topic.
    pub async fn subscribe_pairing(
        &mut self,
        pairing: &PairingUri,
    ) -> Result<PairingSubscription, PairingClientError> {
        validate_pairing_not_expired(pairing, now_unix_seconds()?)?;
        let subscription_id = self
            .relay
            .subscribe(pairing.topic().clone())
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(PairingSubscription {
            topic: pairing.topic().clone(),
            sym_key: pairing.sym_key().clone(),
            subscription_id,
        })
    }

    /// Waits for one live message for a pairing subscription.
    ///
    /// The underlying relay client acknowledges relay pushes before returning
    /// them. This method then checks the topic and decrypts the `WalletConnect`
    /// envelope with the pairing symmetric key.
    pub async fn next_pairing_message(
        &mut self,
        subscription: &PairingSubscription,
    ) -> Result<Option<PairingReceivedMessage>, PairingClientError> {
        let Some(subscription_data) = timeout(self.receive_timeout, self.relay.next_message())
            .await
            .map_err(|_| PairingClientError::ReceiveTimedOut {
                timeout: self.receive_timeout,
            })?
            .map_err(|source| PairingClientError::Relay { source })?
        else {
            return Ok(None);
        };

        if subscription_data.data.topic != subscription.topic {
            return Err(PairingClientError::UnexpectedTopic {
                expected: subscription.topic.clone(),
                actual: subscription_data.data.topic,
            });
        }

        decode_subscription_data(subscription_data.data, &subscription.sym_key).map(Some)
    }

    /// Unsubscribes the relay connection from a pairing topic.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#unsubscribe>
    ///
    /// > Used when a client unsubscribes a given topic.
    pub async fn unsubscribe_pairing(
        &mut self,
        subscription: &PairingSubscription,
    ) -> Result<bool, PairingClientError> {
        self.relay
            .unsubscribe(&subscription.topic, &subscription.subscription_id)
            .await
            .map_err(|source| PairingClientError::Relay { source })
    }

    /// Approves a `wc_sessionPropose` request and publishes the settlement request.
    ///
    /// The first approval primitive follows the maintained Sign Client order:
    /// derive the session topic, subscribe to it, publish the proposal success
    /// response on the pairing topic, then publish `wc_sessionSettle` on the
    /// derived session topic.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L475-L498>
    ///
    /// > const selfPublicKey = await this.client.core.crypto.generateKeyPair();
    /// > const sessionTopic = await this.client.core.crypto.generateSharedKey(
    /// > await this.client.core.relayer.subscribe(sessionTopic, {
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L528-L548>
    ///
    /// > await this.sendApproveSession({
    /// > sessionTopic,
    /// > proposal,
    pub async fn approve_session_proposal(
        &mut self,
        subscription: &PairingSubscription,
        proposal: &JsonRpcRequest<SessionProposeParams>,
        approval: SessionProposalApproval,
    ) -> Result<ApprovedSession, PairingClientError> {
        let responder =
            X25519KeyPair::generate().map_err(|source| PairingClientError::KeyPair { source })?;
        let settle_request_id = next_sign_rpc_id()?;
        let approval_messages = session_proposal_approval_publishes(
            subscription,
            proposal,
            approval,
            &responder,
            settle_request_id,
        )?;
        let session_subscription_id = self
            .relay
            .subscribe(approval_messages.session_topic.clone())
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        let proposal_response_ack = self
            .relay
            .publish(approval_messages.proposal_response)
            .await
            .map_err(|source| PairingClientError::Relay { source })?;
        let session_settle_ack = self
            .relay
            .publish(approval_messages.session_settle)
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(ApprovedSession {
            subscription: SessionSubscription {
                topic: approval_messages.session_topic,
                sym_key: approval_messages.session_sym_key,
                subscription_id: session_subscription_id,
            },
            responder_public_key: responder.public_key().clone(),
            session_settle_request_id: settle_request_id,
            session: approval_messages.session,
            proposal_response_ack,
            session_settle_ack,
        })
    }

    /// Waits for the peer response to the `wc_sessionSettle` request.
    ///
    /// The peer handles `wc_sessionSettle` on the derived session topic and
    /// responds with JSON-RPC `result: true` or a JSON-RPC error on the same
    /// topic.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2269-L2274>
    ///
    /// > await this.sendResult<"wc_sessionSettle">({
    /// > id: payload.id,
    /// > topic,
    /// > result: true,
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2278-L2283>
    ///
    /// > await this.sendError({
    /// > id,
    /// > topic,
    /// > error: err,
    pub async fn next_session_settle_response(
        &mut self,
        approved: &ApprovedSession,
    ) -> Result<Option<SessionSettleResponseMessage>, PairingClientError> {
        let Some(subscription_data) = timeout(
            self.receive_timeout,
            self.relay.next_message_for_topic(approved.session_topic()),
        )
        .await
        .map_err(|_| PairingClientError::ReceiveTimedOut {
            timeout: self.receive_timeout,
        })?
        .map_err(|source| PairingClientError::Relay { source })?
        else {
            return Ok(None);
        };

        decode_session_settle_response_data(
            subscription_data.data,
            approved.subscription(),
            approved.session_settle_request_id,
        )
        .map(Some)
    }

    /// Publishes a `wc_sessionUpdate` request for an acknowledged session.
    ///
    /// The wallet/controller sends replacement namespaces to the peer and waits
    /// for a separate JSON-RPC acknowledgement.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L638-L650>
    ///
    /// > method: "wc_sessionUpdate",
    /// > params: { namespaces },
    /// > await this.client.session.update(topic, { namespaces });
    pub async fn update_session(
        &mut self,
        subscription: &SessionSubscription,
        session: &Session,
        namespaces: &SessionNamespaces,
    ) -> Result<SessionLifecycleRequest, PairingClientError> {
        let request_id = next_sign_rpc_id()?;
        let publish = session_update_request_publish(
            subscription,
            session,
            namespaces,
            request_id,
            now_unix_seconds()?,
        )?;
        let publish_ack = self
            .relay
            .publish(publish)
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(SessionLifecycleRequest {
            topic: subscription.topic().clone(),
            request_id,
            method: SignMethod::SessionUpdate,
            request_tag: SESSION_UPDATE_REQUEST_TAG,
            response_tag: SESSION_UPDATE_RESPONSE_TAG,
            publish_ack,
        })
    }

    /// Publishes a `wc_sessionExtend` request for an acknowledged session.
    ///
    /// Current Sign Client traffic sends `{}` as params and expects
    /// `result: true` on the same session topic.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L678-L685>
    ///
    /// > method: "wc_sessionExtend",
    /// > params: {},
    /// > expiry: calcExpiry(SESSION_EXPIRY),
    pub async fn extend_session(
        &mut self,
        subscription: &SessionSubscription,
        session: &Session,
    ) -> Result<SessionLifecycleRequest, PairingClientError> {
        let request_id = next_sign_rpc_id()?;
        let publish =
            session_extend_request_publish(subscription, session, request_id, now_unix_seconds()?)?;
        let publish_ack = self
            .relay
            .publish(publish)
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(SessionLifecycleRequest {
            topic: subscription.topic().clone(),
            request_id,
            method: SignMethod::SessionExtend,
            request_tag: SESSION_EXTEND_REQUEST_TAG,
            response_tag: SESSION_EXTEND_RESPONSE_TAG,
            publish_ack,
        })
    }

    /// Publishes a `wc_sessionEvent` request for an acknowledged session.
    ///
    /// Current Sign Client traffic emits `session_event` to listeners and only
    /// sends a JSON-RPC error when validation fails; a success ack is not sent
    /// by that implementation.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L881-L896>
    ///
    /// > method: "wc_sessionEvent",
    /// > params: { event, chainId },
    /// > throwOnFailedPublish: true,
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2537-L2539>
    ///
    /// > this.isValidEmit({ topic, ...params });
    /// > this.client.events.emit("session_event", { id, topic, params });
    pub async fn emit_session_event(
        &mut self,
        subscription: &SessionSubscription,
        session: &Session,
        params: &SessionEventParams,
    ) -> Result<SessionLifecycleRequest, PairingClientError> {
        let request_id = next_sign_rpc_id()?;
        let publish = session_event_request_publish(
            subscription,
            session,
            params,
            request_id,
            now_unix_seconds()?,
        )?;
        let publish_ack = self
            .relay
            .publish(publish)
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(SessionLifecycleRequest {
            topic: subscription.topic().clone(),
            request_id,
            method: SignMethod::SessionEvent,
            request_tag: SESSION_EVENT_REQUEST_TAG,
            response_tag: SESSION_EVENT_RESPONSE_TAG,
            publish_ack,
        })
    }

    /// Publishes a `wc_sessionDelete` request for an acknowledged session.
    ///
    /// The maintained Sign Client deletes local session state after the relay
    /// accepts the publish. It does not wait for the peer's JSON-RPC response
    /// before removing the local session.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L897-L909>
    ///
    /// > await this.sendRequest({
    /// > topic,
    /// > method: "wc_sessionDelete",
    pub async fn disconnect_session(
        &mut self,
        subscription: &SessionSubscription,
        session: &Session,
        reason: SessionDeleteParams,
    ) -> Result<SessionLifecycleRequest, PairingClientError> {
        let request_id = next_sign_rpc_id()?;
        let publish = session_delete_request_publish(
            subscription,
            session,
            reason,
            request_id,
            now_unix_seconds()?,
        )?;
        let publish_ack = self
            .relay
            .publish(publish)
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(SessionLifecycleRequest {
            topic: subscription.topic().clone(),
            request_id,
            method: SignMethod::SessionDelete,
            request_tag: SESSION_DELETE_REQUEST_TAG,
            response_tag: SESSION_DELETE_RESPONSE_TAG,
            publish_ack,
        })
    }

    /// Waits for the peer response to a session lifecycle request.
    ///
    /// Same-topic deliveries with other tags are skipped with a fixed bound; in
    /// live relay testing the first skipped message can be the request echo.
    /// Maintained JS Sign Client sends success responses for update and extend,
    /// but currently does not send one for event.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2302-L2327>
    ///
    /// > await this.sendResult<"wc_sessionUpdate">({
    /// > id,
    /// > result: true,
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2363-L2375>
    ///
    /// > await this.sendResult<"wc_sessionExtend">({
    /// > id,
    /// > result: true,
    pub async fn next_session_lifecycle_response(
        &mut self,
        subscription: &SessionSubscription,
        request: &SessionLifecycleRequest,
    ) -> Result<Option<SessionLifecycleResponseMessage>, PairingClientError> {
        if request.topic() != subscription.topic() {
            return Err(PairingClientError::UnexpectedTopic {
                expected: subscription.topic().clone(),
                actual: request.topic().clone(),
            });
        }

        for _ in 0..MAX_SESSION_LIFECYCLE_RESPONSE_DELIVERIES {
            let Some(subscription_data) = timeout(
                self.receive_timeout,
                self.relay.next_message_for_topic(subscription.topic()),
            )
            .await
            .map_err(|_| PairingClientError::ReceiveTimedOut {
                timeout: self.receive_timeout,
            })?
            .map_err(|source| PairingClientError::Relay { source })?
            else {
                return Ok(None);
            };

            if subscription_data.data.tag != Some(request.response_tag()) {
                continue;
            }

            return decode_session_lifecycle_response_data(
                subscription_data.data,
                subscription,
                request.request_id(),
            )
            .map(Some);
        }

        Err(PairingClientError::SessionLifecycleResponseNotReceived {
            expected_tag: request.response_tag(),
            inspected: MAX_SESSION_LIFECYCLE_RESPONSE_DELIVERIES,
        })
    }

    /// Waits for one live message on an acknowledged session topic.
    ///
    /// Parses `wc_sessionRequest` when that method arrives; other session
    /// methods are classified by name until their behavior is implemented.
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionrequest>
    ///
    /// > Sends a CAIP-27 request to the peer client.
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionrequest>
    ///
    /// > The client should immediately reject the request and respond an error
    /// > if the target session permissions doesn't include the requested method
    /// > or chain ID.
    pub async fn next_session_message(
        &mut self,
        subscription: &SessionSubscription,
        session: &Session,
    ) -> Result<Option<SessionReceivedMessage>, PairingClientError> {
        let Some(subscription_data) = timeout(
            self.receive_timeout,
            self.relay.next_message_for_topic(subscription.topic()),
        )
        .await
        .map_err(|_| PairingClientError::ReceiveTimedOut {
            timeout: self.receive_timeout,
        })?
        .map_err(|source| PairingClientError::Relay { source })?
        else {
            return Ok(None);
        };

        decode_session_message_data(
            subscription_data.data,
            subscription,
            session,
            now_unix_seconds()?,
        )
        .map(Some)
    }

    /// Waits for one session-topic message and responds to invalid requests.
    ///
    /// Valid messages are returned for wallet handling. Parsed `wc_sessionRequest`
    /// messages that fail request-level validation are answered on the session
    /// topic with a JSON-RPC error and returned as `Rejected`.
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionrequest>
    ///
    /// > The client should immediately reject the request and respond an error
    /// > if the target session permissions doesn't include the requested method
    /// > or chain ID.
    pub async fn next_session_message_or_reject(
        &mut self,
        subscription: &SessionSubscription,
        session: &Session,
    ) -> Result<Option<SessionMessageOutcome>, PairingClientError> {
        let Some(subscription_data) = timeout(
            self.receive_timeout,
            self.relay.next_message_for_topic(subscription.topic()),
        )
        .await
        .map_err(|_| PairingClientError::ReceiveTimedOut {
            timeout: self.receive_timeout,
        })?
        .map_err(|source| PairingClientError::Relay { source })?
        else {
            return Ok(None);
        };

        let now_unix_seconds = now_unix_seconds()?;
        let message = decode_session_message_data_unchecked(
            subscription_data.data,
            subscription,
            session,
            now_unix_seconds,
        )?;

        match validate_session_message_payload(session, &message, now_unix_seconds) {
            Ok(()) => Ok(Some(SessionMessageOutcome::Received(message))),
            Err(error) => {
                let Some(response_error) = session_request_validation_error(&error) else {
                    return Err(error);
                };
                let SessionPayload::SessionRequest(request) = message.payload() else {
                    return Err(error);
                };
                let request_id = request.id;
                let response_ack = self
                    .respond_session_request_error(subscription, &message, response_error.clone())
                    .await?;

                Ok(Some(SessionMessageOutcome::Rejected(
                    SessionRequestRejection {
                        topic: message.topic().clone(),
                        request_id,
                        error: response_error,
                        response_ack,
                    },
                )))
            }
        }
    }

    /// Waits for one wallet-facing event on an acknowledged session topic.
    ///
    /// Valid decrypted deliveries become `SessionClientEvent` variants.
    /// Invalid `wc_sessionRequest` payloads are answered with a JSON-RPC error
    /// and returned as `RejectedSessionRequest`.
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/session-events.md#session_request>
    ///
    /// > Triggered when a session request is received and should be presented
    /// > to the user for approval or rejection.
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionrequest>
    ///
    /// > The client should immediately reject the request and respond an error
    /// > if the target session permissions doesn't include the requested method
    /// > or chain ID.
    pub async fn next_session_event(
        &mut self,
        subscription: &SessionSubscription,
        session: &Session,
    ) -> Result<Option<SessionClientEvent>, PairingClientError> {
        self.next_session_message_or_reject(subscription, session)
            .await
            .map(|outcome| outcome.map(SessionClientEvent::from_outcome))
    }

    /// Publishes a success response for a received `wc_sessionRequest`.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionrequest>
    ///
    /// > Response
    /// > // Success result
    /// > any
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L3694-L3708>
    ///
    /// > if (isJsonRpcResult(response)) {
    /// > await this.sendResult({
    /// > id,
    pub async fn respond_session_request_success(
        &mut self,
        subscription: &SessionSubscription,
        message: &SessionReceivedMessage,
        result: impl Into<serde_json::Value>,
    ) -> Result<bool, PairingClientError> {
        let publish = session_request_success_publish(subscription, message, result.into())?;
        self.relay
            .publish(publish)
            .await
            .map_err(|source| PairingClientError::Relay { source })
    }

    /// Publishes an error response for a received `wc_sessionRequest`.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionrequest>
    ///
    /// > The client should immediately reject the request and respond an error
    /// > if the target session permissions doesn't include the requested method
    /// > or chain ID.
    pub async fn respond_session_request_error(
        &mut self,
        subscription: &SessionSubscription,
        message: &SessionReceivedMessage,
        error: JsonRpcError,
    ) -> Result<bool, PairingClientError> {
        let publish = session_request_error_publish(subscription, message, error)?;
        self.relay
            .publish(publish)
            .await
            .map_err(|source| PairingClientError::Relay { source })
    }

    /// Publishes a success response for a received `wc_sessionPing`.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionping>
    ///
    /// > // Success result
    /// > true
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2401-L2411>
    ///
    /// > await this.sendResult<"wc_sessionPing">({
    /// > id,
    /// > topic,
    pub async fn respond_session_ping(
        &mut self,
        subscription: &SessionSubscription,
        message: &SessionReceivedMessage,
    ) -> Result<bool, PairingClientError> {
        let publish = session_ping_response_publish(subscription, message)?;
        self.relay
            .publish(publish)
            .await
            .map_err(|source| PairingClientError::Relay { source })
    }

    /// Publishes a success response for a received `wc_sessionDelete`.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessiondelete>
    ///
    /// > // Success result
    /// > true
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2442-L2454>
    ///
    /// > await this.isValidDisconnect({ topic, reason: payload.params });
    /// > await this.deleteSession({ topic, id });
    pub async fn respond_session_delete(
        &mut self,
        subscription: &SessionSubscription,
        message: &SessionReceivedMessage,
    ) -> Result<bool, PairingClientError> {
        let publish = session_delete_response_publish(subscription, message)?;
        self.relay
            .publish(publish)
            .await
            .map_err(|source| PairingClientError::Relay { source })
    }

    /// Publishes a success response for a received `wc_pairingPing`.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/pairing.ts#L377-L385>
    ///
    /// > await this.sendResult<"wc_pairingPing">(id, topic, true);
    /// > this.events.emit(PAIRING_EVENTS.ping, { id, topic });
    pub async fn respond_pairing_ping(
        &mut self,
        subscription: &PairingSubscription,
        message: &PairingReceivedMessage,
    ) -> Result<bool, PairingClientError> {
        let publish = pairing_ping_response_publish(subscription, message)?;
        self.relay
            .publish(publish)
            .await
            .map_err(|source| PairingClientError::Relay { source })
    }

    /// Publishes a `wc_sessionPropose` JSON-RPC error response.
    ///
    /// This rejects the proposal on the pairing topic. Approval is intentionally
    /// separate because it must create a responder key pair and then settle a
    /// session on the derived session topic.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L593-L599>
    ///
    /// > await this.sendError({
    /// > id,
    /// > topic: pairingTopic,
    /// > error: reason,
    pub async fn reject_session_proposal(
        &mut self,
        subscription: &PairingSubscription,
        proposal_id: u64,
        error: JsonRpcError,
    ) -> Result<bool, PairingClientError> {
        let publish = session_proposal_reject_publish(subscription, proposal_id, error)?;
        self.relay
            .publish(publish)
            .await
            .map_err(|source| PairingClientError::Relay { source })
    }
}

/// Builds the authenticated relay URL at a specific unix timestamp.
///
/// Keeping timestamp injection here makes Relay Auth testable without sleeping
/// or mocking the system clock.
pub(super) fn relay_connection_url(
    config: &PairingClientConfig,
    issued_at: u64,
) -> Result<RelayConnectionUrl, PairingClientError> {
    let audience = relay_auth_audience(&config.relay_url);
    let token = RelayAuthToken::sign_with_seed(
        &config.auth_seed,
        &config.auth_subject,
        audience,
        issued_at,
        config.auth_ttl_seconds,
    )
    .map_err(|source| PairingClientError::RelayAuth { source })?;

    Ok(RelayConnectionUrl::new(
        &config.relay_url,
        &config.project_id,
        token.as_str(),
        &config.user_agent,
    ))
}

/// Returns unix seconds for Relay Auth `iat` and pairing expiry comparisons.
///
/// Pairing URI expiry is defined as `expiryTimestamp`; Relay Auth JWTs also
/// carry unix-second `iat` and `exp` claims.
pub(super) fn now_unix_seconds() -> Result<u64, PairingClientError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| PairingClientError::Clock { source })?
        .as_secs())
}

/// Rejects pairing URIs that cannot receive valid proposals anymore.
pub(super) const fn validate_pairing_not_expired(
    pairing: &PairingUri,
    now_unix_seconds: u64,
) -> Result<(), PairingClientError> {
    if let Some(expiry_timestamp) = pairing.expiry_timestamp()
        && expiry_timestamp <= now_unix_seconds
    {
        return Err(PairingClientError::PairingExpired {
            expiry_timestamp,
            now_unix_seconds,
        });
    }

    Ok(())
}
