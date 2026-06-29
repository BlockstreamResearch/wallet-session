use std::fmt;

use bitcoin::psbt::PsbtSighashType;
use serde::Deserialize;
use serde_json::Value;
use wc_core::SessionRequestReview;
use wc_protocol::{
    caip::{Caip2ChainId, Caip10AccountId},
    session::SessionMethod,
};

use crate::{
    BitcoinAccountScope, BitcoinAddress, BitcoinMethod, BitcoinRequestError, BitcoinValueError,
    GetAccountAddressesParams, SendTransferParams, SignMessageParams, SignPsbtParams,
    is_bitcoin_chain_id,
};

/// Parsed `WalletConnect` Bitcoin request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitcoinRequest {
    /// `sendTransfer` request.
    SendTransfer(SendTransferParams),
    /// `getAccountAddresses` request.
    GetAccountAddresses(GetAccountAddressesParams),
    /// `signPsbt` request.
    SignPsbt(SignPsbtParams),
    /// `signMessage` request.
    SignMessage(SignMessageParams),
}

impl BitcoinRequest {
    /// Parses a request from a session method and raw JSON params.
    pub fn from_method_and_params(
        method: &SessionMethod,
        params: &Value,
    ) -> Result<Self, BitcoinRequestError> {
        let method = BitcoinMethod::try_from(method)?;
        Self::from_bitcoin_method_and_params(method, params)
    }

    /// Parses a request from a Bitcoin method and raw JSON params.
    pub fn from_bitcoin_method_and_params(
        method: BitcoinMethod,
        params: &Value,
    ) -> Result<Self, BitcoinRequestError> {
        match method {
            BitcoinMethod::SendTransfer => parse_params(method, params).map(Self::SendTransfer),
            BitcoinMethod::GetAccountAddresses => {
                let request: GetAccountAddressesParams = parse_params(method, params)?;
                validate_intentions(method, &request.intentions)?;
                Ok(Self::GetAccountAddresses(request))
            }
            BitcoinMethod::SignPsbt => {
                let request: SignPsbtParams = parse_params(method, params)?;
                for input in &request.sign_inputs {
                    if input.sighash_types.as_ref().is_some_and(Vec::is_empty) {
                        return Err(BitcoinRequestError::InvalidParams {
                            method,
                            source: BitcoinValueError::EmptySighashTypes,
                        });
                    }
                    if let Some(sighash_types) = &input.sighash_types {
                        for &value in sighash_types {
                            validate_sighash_type(method, value)?;
                        }
                    }
                }
                Ok(Self::SignPsbt(request))
            }
            BitcoinMethod::SignMessage => parse_params(method, params).map(Self::SignMessage),
        }
    }

    /// Request method.
    #[must_use]
    pub const fn method(&self) -> BitcoinMethod {
        match self {
            Self::SendTransfer(_) => BitcoinMethod::SendTransfer,
            Self::GetAccountAddresses(_) => BitcoinMethod::GetAccountAddresses,
            Self::SignPsbt(_) => BitcoinMethod::SignPsbt,
            Self::SignMessage(_) => BitcoinMethod::SignMessage,
        }
    }

    /// Connected account address requested by the dapp.
    #[must_use]
    pub const fn account(&self) -> &BitcoinAddress {
        match self {
            Self::SendTransfer(params) => &params.account,
            Self::GetAccountAddresses(params) => &params.account,
            Self::SignPsbt(params) => &params.account,
            Self::SignMessage(params) => &params.account,
        }
    }

    /// Validates that every wallet-owned address referenced by this request is in scope.
    ///
    /// This protects wallet signing backends from approving a request whose
    /// connected account is authorized but whose PSBT input signer, message
    /// signer, or change address belongs to a different account group.
    pub fn ensure_account_scope(
        &self,
        scope: &BitcoinAccountScope,
    ) -> Result<(), BitcoinRequestError> {
        if self.account() != scope.connected_account().address() {
            return Err(BitcoinRequestError::AccountScopeMismatch {
                requested_account: self.account().to_string(),
                connected_account: scope.connected_account().to_string(),
            });
        }

        match self {
            Self::SendTransfer(params) => {
                if let Some(change_address) = &params.change_address {
                    ensure_address_in_scope(
                        BitcoinWalletAddressRole::ChangeAddress,
                        change_address,
                        scope,
                    )?;
                }
            }
            Self::GetAccountAddresses(_) => {}
            Self::SignPsbt(params) => {
                for input in &params.sign_inputs {
                    ensure_address_in_scope(
                        BitcoinWalletAddressRole::PsbtInputSigner,
                        &input.address,
                        scope,
                    )?;
                }
            }
            Self::SignMessage(params) => {
                ensure_address_in_scope(
                    BitcoinWalletAddressRole::MessageSigner,
                    params.signing_address(),
                    scope,
                )?;
            }
        }

        Ok(())
    }
}

fn validate_sighash_type(method: BitcoinMethod, value: u32) -> Result<(), BitcoinRequestError> {
    let sighash_type = PsbtSighashType::from_u32(value);
    if sighash_type.ecdsa_hash_ty().is_ok() || sighash_type.taproot_hash_ty().is_ok() {
        return Ok(());
    }

    Err(BitcoinRequestError::InvalidParams {
        method,
        source: BitcoinValueError::InvalidSighashType { value },
    })
}

/// Wallet-facing Bitcoin request review built from a generic session request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinRequestReview {
    request_id: u64,
    chain_id: Caip2ChainId,
    request: BitcoinRequest,
    authorization: BitcoinAccountAuthorization,
}

impl BitcoinRequestReview {
    /// Builds a typed Bitcoin review from a generic `wc_sessionRequest` review.
    pub fn from_session_request(
        review: &SessionRequestReview,
    ) -> Result<Self, BitcoinRequestError> {
        if !is_bitcoin_chain_id(review.chain_id()) {
            return Err(BitcoinRequestError::UnsupportedChain {
                chain_id: review.chain_id().to_string(),
            });
        }
        let request = BitcoinRequest::from_method_and_params(review.method(), review.params())?;
        let authorization = BitcoinAccountAuthorization::for_account(
            request.account(),
            review.authorized_accounts(),
        );
        if authorization == BitcoinAccountAuthorization::Unauthorized {
            return Err(BitcoinRequestError::UnauthorizedAccount {
                account: request.account().to_string(),
            });
        }
        Ok(Self {
            request_id: review.request_id(),
            chain_id: review.chain_id().clone(),
            request,
            authorization,
        })
    }

    /// Validates this request against a wallet-owned Bitcoin account scope.
    pub fn ensure_account_scope(
        &self,
        scope: &BitcoinAccountScope,
    ) -> Result<(), BitcoinRequestError> {
        self.request.ensure_account_scope(scope)
    }

    /// Converts this review into an account-scoped review for wallet approval.
    pub fn into_account_scoped(
        self,
        scope: BitcoinAccountScope,
    ) -> Result<BitcoinAccountScopedReview, BitcoinRequestError> {
        self.ensure_account_scope(&scope)?;
        Ok(BitcoinAccountScopedReview {
            review: self,
            scope,
        })
    }

    /// JSON-RPC request id.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Requested BIP-122 chain id.
    #[must_use]
    pub const fn chain_id(&self) -> &Caip2ChainId {
        &self.chain_id
    }

    /// Typed Bitcoin request.
    #[must_use]
    pub const fn request(&self) -> &BitcoinRequest {
        &self.request
    }

    /// Account authorization status relative to the active session.
    #[must_use]
    pub const fn authorization(&self) -> BitcoinAccountAuthorization {
        self.authorization
    }
}

/// Bitcoin request review proven against the wallet's account address scope.
#[derive(Clone, PartialEq, Eq)]
pub struct BitcoinAccountScopedReview {
    review: BitcoinRequestReview,
    scope: BitcoinAccountScope,
}

impl BitcoinAccountScopedReview {
    /// The original typed request review.
    #[must_use]
    pub const fn review(&self) -> &BitcoinRequestReview {
        &self.review
    }

    /// Wallet-owned account scope used for authorization.
    #[must_use]
    pub const fn scope(&self) -> &BitcoinAccountScope {
        &self.scope
    }

    /// Moves this value into the underlying typed request review.
    #[must_use]
    pub fn into_review(self) -> BitcoinRequestReview {
        self.review
    }
}

impl fmt::Debug for BitcoinAccountScopedReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitcoinAccountScopedReview")
            .field("request_id", &self.review.request_id)
            .field("chain_id", &self.review.chain_id)
            .field("method", &self.review.request.method())
            .field("authorization", &self.review.authorization)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Authorization status for the request account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinAccountAuthorization {
    /// No active-session account context was available.
    NotChecked,
    /// Requested account matches a CAIP-10 account authorized for the chain.
    Authorized,
    /// Requested account does not match authorized accounts for the chain.
    Unauthorized,
}

impl BitcoinAccountAuthorization {
    /// Computes account authorization status.
    #[must_use]
    pub fn for_account(account: &BitcoinAddress, authorized_accounts: &[Caip10AccountId]) -> Self {
        if authorized_accounts.is_empty() {
            return Self::NotChecked;
        }
        if authorized_accounts
            .iter()
            .any(|authorized| authorized.address() == account.as_str())
        {
            Self::Authorized
        } else {
            Self::Unauthorized
        }
    }
}

/// Wallet-owned address role referenced by a Bitcoin request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinWalletAddressRole {
    /// `sendTransfer.changeAddress`.
    ChangeAddress,
    /// `getAccountAddresses` result address.
    AccountAddressResult,
    /// `signPsbt.signInputs[].address`.
    PsbtInputSigner,
    /// `signMessage.address`, or the connected account when omitted.
    MessageSigner,
}

impl BitcoinWalletAddressRole {
    /// Role label for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChangeAddress => "change address",
            Self::AccountAddressResult => "account address result",
            Self::PsbtInputSigner => "PSBT input signer",
            Self::MessageSigner => "message signer",
        }
    }
}

impl fmt::Display for BitcoinWalletAddressRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn ensure_address_in_scope(
    role: BitcoinWalletAddressRole,
    address: &BitcoinAddress,
    scope: &BitcoinAccountScope,
) -> Result<(), BitcoinRequestError> {
    if scope.contains_address(address) {
        return Ok(());
    }

    Err(BitcoinRequestError::UnauthorizedWalletAddress {
        role,
        address: address.to_string(),
    })
}

fn parse_params<T>(method: BitcoinMethod, params: &Value) -> Result<T, BitcoinRequestError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(params.clone())
        .map_err(|source| BitcoinRequestError::MalformedParams { method, source })
}

fn validate_intentions(
    method: BitcoinMethod,
    intentions: &[String],
) -> Result<(), BitcoinRequestError> {
    if intentions
        .iter()
        .any(|intention| intention.trim().is_empty())
    {
        return Err(BitcoinRequestError::InvalidParams {
            method,
            source: BitcoinValueError::EmptyIntention,
        });
    }
    Ok(())
}
