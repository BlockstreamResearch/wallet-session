use crate::{BitcoinMethod, BitcoinWalletAddressRole};

/// Error while building a wallet-owned Bitcoin account scope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BitcoinAccountScopeError {
    /// The provided address set did not include the connected account address.
    #[error("Bitcoin account scope is missing the connected account address")]
    MissingConnectedAccount,
    /// The address entry path is not the default first external account path.
    #[error("Bitcoin connected account path is not the default first external path")]
    InvalidConnectedAccountPath,
}

/// Validation error for Bitcoin value newtypes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BitcoinValueError {
    /// Address was empty.
    #[error("Bitcoin address is empty")]
    EmptyAddress,
    /// Address is longer than the CAIP-10 limit.
    #[error("Bitcoin address is too long: {len}")]
    AddressTooLong {
        /// Observed string length.
        len: usize,
    },
    /// Address contains a character not allowed by CAIP-10.
    #[error("Bitcoin address contains an invalid character")]
    InvalidAddress,
    /// Amount was empty.
    #[error("Bitcoin amount is empty")]
    EmptyAmount,
    /// Amount contains a non-decimal digit.
    #[error("Bitcoin amount must be ASCII decimal digits")]
    InvalidAmount,
    /// Amount is outside the representable Bitcoin amount range.
    #[error("Bitcoin amount is out of range")]
    AmountOutOfRange,
    /// Hex value was empty.
    #[error("hex value is empty")]
    EmptyHex,
    /// Hex value used a `0x` prefix.
    #[error("hex value must not use a 0x prefix")]
    HexPrefix,
    /// Hex value had an odd number of characters.
    #[error("hex value has odd length: {len}")]
    OddHexLength {
        /// Observed string length.
        len: usize,
    },
    /// Hex value contains a non-hex character.
    #[error("hex value contains an invalid character")]
    InvalidHex,
    /// Public key was empty.
    #[error("Bitcoin public key is empty")]
    EmptyPublicKey,
    /// Public key is not a valid Bitcoin ECDSA public key encoding.
    #[error("Bitcoin public key is invalid")]
    InvalidPublicKey,
    /// Memo exceeds the `WalletConnect` 80-byte limit.
    #[error("Bitcoin memo is too long: {byte_len} bytes")]
    MemoTooLong {
        /// Observed decoded byte length.
        byte_len: usize,
    },
    /// Transaction id is not 64 hex characters.
    #[error("Bitcoin txid must be 64 hex characters, got {len}")]
    InvalidTxidLength {
        /// Observed string length.
        len: usize,
    },
    /// PSBT string was empty.
    #[error("Bitcoin PSBT is empty")]
    EmptyPsbt,
    /// PSBT string contains characters outside standard base64.
    #[error("Bitcoin PSBT must be standard base64")]
    InvalidPsbt,
    /// PSBT base64 padding appeared before the end of the string.
    #[error("Bitcoin PSBT base64 padding must be trailing")]
    InvalidPsbtPadding,
    /// Derivation path was empty.
    #[error("Bitcoin derivation path is empty")]
    EmptyDerivationPath,
    /// Derivation path must start with `m/`.
    #[error("Bitcoin derivation path must start with m/")]
    InvalidDerivationPath,
    /// Derivation path contains whitespace or control characters.
    #[error("Bitcoin derivation path contains invalid characters")]
    InvalidDerivationPathCharacters,
    /// `signPsbt` did not include any `signInputs`.
    #[error("signPsbt requires at least one signInputs entry")]
    EmptySignInputs,
    /// A `signPsbt` input provided an empty `sighashTypes` list.
    #[error("signPsbt sighashTypes must not be empty when present")]
    EmptySighashTypes,
    /// A `signPsbt` input provided a sighash type that is neither standard ECDSA nor valid Taproot.
    #[error("signPsbt sighashTypes contains an invalid value: {value}")]
    InvalidSighashType {
        /// Observed sighash type value.
        value: u32,
    },
    /// An intention string was empty.
    #[error("getAccountAddresses intentions must be non-empty")]
    EmptyIntention,
}

/// Error while building a typed Bitcoin request review.
#[derive(Debug, thiserror::Error)]
pub enum BitcoinRequestError {
    /// Session request did not target a `bip122` chain.
    #[error("unsupported Bitcoin chain id: {chain_id}")]
    UnsupportedChain {
        /// Requested chain id.
        chain_id: String,
    },
    /// Method is not a `WalletConnect` Bitcoin method.
    #[error("unsupported Bitcoin method: {method}")]
    UnsupportedMethod {
        /// Requested method name.
        method: String,
    },
    /// Params failed serde shape validation.
    #[error("malformed {method} params")]
    MalformedParams {
        /// Requested Bitcoin method.
        method: BitcoinMethod,
        /// Underlying serde error.
        source: serde_json::Error,
    },
    /// Params failed semantic validation.
    #[error("invalid {method} params")]
    InvalidParams {
        /// Requested Bitcoin method.
        method: BitcoinMethod,
        /// Underlying value validation error.
        source: BitcoinValueError,
    },
    /// Requested account is not authorized in the active session.
    #[error("unauthorized Bitcoin account")]
    UnauthorizedAccount {
        /// Requested account address.
        account: String,
    },
    /// Request account does not match the wallet-owned account scope.
    #[error("Bitcoin request account does not match wallet account scope")]
    AccountScopeMismatch {
        /// Requested account address.
        requested_account: String,
        /// Connected wallet account address.
        connected_account: String,
    },
    /// Request references a wallet-owned address outside the connected account scope.
    #[error("Bitcoin request references an unauthorized {role}")]
    UnauthorizedWalletAddress {
        /// Address role in the request.
        role: BitcoinWalletAddressRole,
        /// Requested wallet-owned address.
        address: String,
    },
    /// A broadcast `signPsbt` result omitted the required `txid`.
    #[error("broadcast signPsbt result must include txid")]
    BroadcastResultMissingTxid,
    /// A `getAccountAddresses` result did not include any addresses.
    #[error("getAccountAddresses result must not be empty")]
    AccountAddressesResultEmpty,
    /// A `getAccountAddresses` result omitted the connected account address.
    #[error("getAccountAddresses result must include the connected account address")]
    AccountAddressesResultMissingConnectedAccount,
    /// A `signMessage` result reported a different signing address than the reviewed request.
    #[error("signMessage result address does not match requested signer")]
    SignMessageResultAddressMismatch {
        /// Address the request allowed the wallet to sign with.
        expected_address: String,
        /// Address reported in the result.
        actual_address: String,
    },
}
