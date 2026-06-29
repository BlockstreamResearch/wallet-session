use std::{collections::BTreeMap, fmt};

use bitcoin::Amount;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wc_protocol::{
    caip::Caip2ChainId,
    session::{SessionEvent, SessionEventParams, SessionProperties},
};

use crate::{
    BitcoinAccountScope, BitcoinAddress, BitcoinDerivationPath, BitcoinEvent, BitcoinMemo,
    BitcoinPsbt, BitcoinPublicKey, BitcoinRequestError, BitcoinTxid, BitcoinWalletAddressRole,
    GET_ACCOUNT_ADDRESSES_SESSION_PROPERTY, HexBytes,
};

const DEFAULT_SIGHASH_TYPES: [u32; 1] = [1];

mod amount_sats {
    use bitcoin::Amount;
    use serde::{Deserialize, Deserializer, Serializer, de};

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde with functions serialize field values by reference"
    )]
    pub(super) fn serialize<S>(amount: &Amount, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&amount.to_sat().to_string())
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Amount, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        crate::value::parse_amount(&value).map_err(de::Error::custom)
    }
}

/// Parameters for `sendTransfer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendTransferParams {
    /// Connected account's first external address.
    pub account: BitcoinAddress,
    /// Recipient public address.
    pub recipient_address: BitcoinAddress,
    /// Amount to send, denominated in satoshis.
    #[serde(with = "amount_sats")]
    pub amount: Amount,
    /// Optional sender-owned change address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_address: Option<BitcoinAddress>,
    /// Optional `OP_RETURN` memo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<BitcoinMemo>,
}

/// Result for `sendTransfer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SendTransferResult {
    /// Broadcast transaction id.
    pub txid: BitcoinTxid,
}

/// Parameters for `getAccountAddresses`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetAccountAddressesParams {
    /// Connected account's first external address.
    pub account: BitcoinAddress,
    /// Optional dapp intentions such as `payment` or `ordinal`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intentions: Vec<String>,
}

/// Address metadata returned by `getAccountAddresses`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitcoinAccountAddress {
    /// Public address belonging to the connected account.
    pub address: BitcoinAddress,
    /// Optional public key hex for the derivation path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<BitcoinPublicKey>,
    /// Optional derivation path for this address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<BitcoinDerivationPath>,
    /// Optional address intention such as `payment` or `ordinal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intention: Option<String>,
}

/// `getAccountAddresses` result and `bip122_addressesChanged` event data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BitcoinAccountAddresses(Vec<BitcoinAccountAddress>);

impl BitcoinAccountAddresses {
    /// Builds address result data from wallet-owned address metadata.
    #[must_use]
    pub const fn new(addresses: Vec<BitcoinAccountAddress>) -> Self {
        Self(addresses)
    }

    /// Address entries.
    #[must_use]
    pub fn as_slice(&self) -> &[BitcoinAccountAddress] {
        &self.0
    }

    /// Number of address entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when there are no address entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Moves the address entries into caller-owned state.
    #[must_use]
    pub fn into_vec(self) -> Vec<BitcoinAccountAddress> {
        self.0
    }

    /// Serializes this address set as the recommended session property value.
    pub fn session_property_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_string(self).map(Value::String)
    }

    /// Builds a `sessionProperties` map containing `bip122_getAccountAddresses`.
    pub fn session_properties(&self) -> Result<SessionProperties, serde_json::Error> {
        let mut properties = BTreeMap::new();
        properties.insert(
            GET_ACCOUNT_ADDRESSES_SESSION_PROPERTY.to_owned(),
            self.session_property_value()?,
        );
        Ok(properties)
    }

    /// Builds `wc_sessionEvent` params for `bip122_addressesChanged`.
    pub fn addresses_changed_event_params(
        &self,
        chain_id: Caip2ChainId,
    ) -> Result<SessionEventParams, serde_json::Error> {
        Ok(SessionEventParams {
            event: SessionEvent {
                name: BitcoinEvent::AddressesChanged.session_event_name(),
                data: serde_json::to_value(self)?,
            },
            chain_id,
        })
    }

    /// Validates a `getAccountAddresses` result against the reviewed request
    /// and the wallet-owned account scope used to authorize the session.
    pub fn validate_for_request_and_scope(
        &self,
        request: &GetAccountAddressesParams,
        scope: &BitcoinAccountScope,
    ) -> Result<(), BitcoinRequestError> {
        if &request.account != scope.connected_account().address() {
            return Err(BitcoinRequestError::AccountScopeMismatch {
                requested_account: request.account.to_string(),
                connected_account: scope.connected_account().to_string(),
            });
        }
        if self.is_empty() {
            return Err(BitcoinRequestError::AccountAddressesResultEmpty);
        }

        let mut includes_connected_account = false;
        for entry in self.as_slice() {
            if &entry.address == scope.connected_account().address() {
                includes_connected_account = true;
            }
            if !scope.contains_address(&entry.address) {
                return Err(BitcoinRequestError::UnauthorizedWalletAddress {
                    role: BitcoinWalletAddressRole::AccountAddressResult,
                    address: entry.address.to_string(),
                });
            }
        }
        if !includes_connected_account {
            return Err(BitcoinRequestError::AccountAddressesResultMissingConnectedAccount);
        }

        Ok(())
    }
}

/// Parameters for `signPsbt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignPsbtParams {
    /// Connected account's first external address.
    pub account: BitcoinAddress,
    /// Base64 encoded PSBT to sign.
    pub psbt: BitcoinPsbt,
    /// Inputs and addresses the dapp asks the wallet to sign.
    pub sign_inputs: Vec<SignPsbtInput>,
    /// Whether the wallet should finalize and broadcast after signing.
    #[serde(default, skip_serializing_if = "is_false")]
    pub broadcast: bool,
}

/// One PSBT input signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignPsbtInput {
    /// Address whose private key should sign the input.
    pub address: BitcoinAddress,
    /// PSBT input index to sign.
    pub index: u32,
    /// Optional allowed sighash types. `WalletConnect` defaults this to `[1]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sighash_types: Option<Vec<u32>>,
}

impl SignPsbtInput {
    /// Returns explicit sighash types or the `WalletConnect` default `[1]`.
    #[must_use]
    pub fn sighash_types_or_default(&self) -> &[u32] {
        self.sighash_types
            .as_deref()
            .unwrap_or(&DEFAULT_SIGHASH_TYPES)
    }
}

/// Result for `signPsbt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignPsbtResult {
    /// Base64 encoded signed PSBT.
    pub psbt: BitcoinPsbt,
    /// Broadcast transaction id, required when the request used `broadcast`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<BitcoinTxid>,
}

impl SignPsbtResult {
    /// Builds a signed PSBT result without broadcasting.
    #[must_use]
    pub const fn signed(psbt: BitcoinPsbt) -> Self {
        Self { psbt, txid: None }
    }

    /// Builds a signed and broadcast PSBT result.
    #[must_use]
    pub const fn broadcast(psbt: BitcoinPsbt, txid: BitcoinTxid) -> Self {
        Self {
            psbt,
            txid: Some(txid),
        }
    }

    /// Validates that broadcast requests include a transaction id.
    pub const fn validate_for_request(
        &self,
        request: &SignPsbtParams,
    ) -> Result<(), BitcoinRequestError> {
        if request.broadcast && self.txid.is_none() {
            return Err(BitcoinRequestError::BroadcastResultMissingTxid);
        }
        Ok(())
    }
}

/// Signature protocol for `signMessage`.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum SignMessageProtocol {
    /// Legacy ECDSA message signing.
    #[serde(rename = "ecdsa")]
    #[default]
    Ecdsa,
    /// BIP-322 message signing.
    #[serde(rename = "bip322")]
    Bip322,
}

impl SignMessageProtocol {
    /// Wire protocol string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ecdsa => "ecdsa",
            Self::Bip322 => "bip322",
        }
    }
}

impl fmt::Display for SignMessageProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Parameters for `signMessage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignMessageParams {
    /// Connected account's first external address.
    pub account: BitcoinAddress,
    /// Message to sign.
    pub message: String,
    /// Optional address whose private key should sign the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<BitcoinAddress>,
    /// Optional preferred signature protocol. `WalletConnect` defaults to ECDSA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<SignMessageProtocol>,
}

impl SignMessageParams {
    /// Returns the requested protocol or the `WalletConnect` default.
    #[must_use]
    pub fn protocol_or_default(&self) -> SignMessageProtocol {
        self.protocol.unwrap_or_default()
    }

    /// Returns the explicit signing address or the connected account address.
    #[must_use]
    pub fn signing_address(&self) -> &BitcoinAddress {
        self.address.as_ref().unwrap_or(&self.account)
    }
}

/// Result for `signMessage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignMessageResult {
    /// Address used to sign the message.
    pub address: BitcoinAddress,
    /// Signature hex bytes.
    pub signature: HexBytes,
    /// Optional message hash hex bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_hash: Option<HexBytes>,
}

impl SignMessageResult {
    /// Validates that the result address is the exact reviewed signing address.
    pub fn validate_for_request(
        &self,
        request: &SignMessageParams,
    ) -> Result<(), BitcoinRequestError> {
        if &self.address != request.signing_address() {
            return Err(BitcoinRequestError::SignMessageResultAddressMismatch {
                expected_address: request.signing_address().to_string(),
                actual_address: self.address.to_string(),
            });
        }
        Ok(())
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}
