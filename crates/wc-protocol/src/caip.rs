//! CAIP identifier primitives.

use std::{
    borrow::Borrow,
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// CAIP namespace component.
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/ebacdb90283ded501350bd0011db4362734f9c4b/CAIPs/caip-2.md#syntax>
///
/// > namespace:   [-a-z0-9]{3,8}
///
/// The maintained `WalletConnect` utilities split CAIP identifiers before
/// higher-level namespace validation.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/caip.ts#L14-L17>
///
/// > const [namespace, reference] = chain.split(CAIP_DELIMITER);
/// > return { namespace, reference };
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CaipNamespace(String);

impl CaipNamespace {
    /// Validates a CAIP namespace component.
    pub fn parse(value: impl Into<String>) -> Result<Self, CaipParseError> {
        let value = value.into();
        validate_namespace(&value)?;
        Ok(Self(value))
    }

    /// Namespace string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Moves the namespace into caller-owned state.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl FromStr for CaipNamespace {
    type Err = CaipParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for CaipNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for CaipNamespace {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for CaipNamespace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CaipNamespace {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// CAIP-2 blockchain identifier.
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/ebacdb90283ded501350bd0011db4362734f9c4b/CAIPs/caip-2.md#syntax>
///
/// > chain_id:    namespace + ":" + reference
/// > namespace:   [-a-z0-9]{3,8}
/// > reference:   [-_a-zA-Z0-9]{1,32}
///
/// # Examples
///
/// ```
/// use wc_protocol::caip::Caip2ChainId;
///
/// let chain = Caip2ChainId::parse("eip155:1")?;
/// assert_eq!(chain.namespace(), "eip155");
/// assert_eq!(chain.reference(), "1");
/// assert_eq!(chain.as_str(), "eip155:1");
/// # Ok::<(), wc_protocol::caip::CaipParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Caip2ChainId {
    value: String,
    namespace_end: usize,
}

impl Caip2ChainId {
    /// Validates a CAIP-2 chain ID.
    pub fn parse(value: impl Into<String>) -> Result<Self, CaipParseError> {
        let value = value.into();
        let (namespace, reference) = value
            .split_once(':')
            .ok_or(CaipParseError::InvalidChainIdFormat)?;
        if reference.contains(':') {
            return Err(CaipParseError::InvalidChainIdFormat);
        }

        validate_namespace(namespace)?;
        validate_reference(reference)?;

        Ok(Self {
            namespace_end: namespace.len(),
            value,
        })
    }

    /// Builds a CAIP-2 chain ID from its components.
    pub fn from_parts(namespace: &str, reference: &str) -> Result<Self, CaipParseError> {
        validate_namespace(namespace)?;
        validate_reference(reference)?;
        Self::parse(format!("{namespace}:{reference}"))
    }

    /// Full `namespace:reference` string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Namespace component.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.value[..self.namespace_end]
    }

    /// Reference component.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.value[self.namespace_end + 1..]
    }

    /// Moves the chain ID into caller-owned state.
    #[must_use]
    pub fn into_string(self) -> String {
        self.value
    }
}

impl FromStr for Caip2ChainId {
    type Err = CaipParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for Caip2ChainId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for Caip2ChainId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for Caip2ChainId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Caip2ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// CAIP-10 account identifier.
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/ebacdb90283ded501350bd0011db4362734f9c4b/CAIPs/caip-10.md#syntax>
///
/// > account_id:        chain_id + ":" + account_address
/// > chain_id:          [-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32} (See [CAIP-2][])
/// > account_address:   [-.%a-zA-Z0-9]{1,128}
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/ebacdb90283ded501350bd0011db4362734f9c4b/CAIPs/caip-10.md#canonicalization>
///
/// > this specification does NOT require canonicalization
///
/// # Examples
///
/// ```
/// use wc_protocol::caip::Caip10AccountId;
///
/// let account = Caip10AccountId::parse(
///     "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
/// )?;
/// assert_eq!(account.chain_id_str(), "eip155:1");
/// assert_eq!(account.address(), "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");
/// # Ok::<(), wc_protocol::caip::CaipParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Caip10AccountId {
    value: String,
    namespace_end: usize,
    reference_end: usize,
}

impl Caip10AccountId {
    /// Validates a CAIP-10 account ID.
    pub fn parse(value: impl Into<String>) -> Result<Self, CaipParseError> {
        let value = value.into();
        let mut parts = value.split(':');
        let namespace = parts.next().ok_or(CaipParseError::InvalidAccountIdFormat)?;
        let reference = parts.next().ok_or(CaipParseError::InvalidAccountIdFormat)?;
        let address = parts.next().ok_or(CaipParseError::InvalidAccountIdFormat)?;
        if parts.next().is_some() {
            return Err(CaipParseError::InvalidAccountIdFormat);
        }

        validate_namespace(namespace)?;
        validate_reference(reference)?;
        validate_address(address)?;

        let namespace_end = namespace.len();
        let reference_end = namespace_end + 1 + reference.len();

        Ok(Self {
            value,
            namespace_end,
            reference_end,
        })
    }

    /// Builds a CAIP-10 account ID from a validated chain ID and address.
    pub fn from_parts(chain_id: &Caip2ChainId, address: &str) -> Result<Self, CaipParseError> {
        validate_address(address)?;
        Self::parse(format!("{chain_id}:{address}"))
    }

    /// Full `namespace:reference:account_address` string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Full chain ID prefix.
    #[must_use]
    pub fn chain_id_str(&self) -> &str {
        &self.value[..self.reference_end]
    }

    /// Chain ID prefix as a typed CAIP-2 value.
    #[must_use]
    pub fn chain_id(&self) -> Caip2ChainId {
        Caip2ChainId::parse(self.chain_id_str())
            .expect("Caip10AccountId validates its CAIP-2 prefix")
    }

    /// Namespace component.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.value[..self.namespace_end]
    }

    /// Reference component.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.value[self.namespace_end + 1..self.reference_end]
    }

    /// Account address component.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.value[self.reference_end + 1..]
    }

    /// Moves the account ID into caller-owned state.
    #[must_use]
    pub fn into_string(self) -> String {
        self.value
    }
}

impl FromStr for Caip10AccountId {
    type Err = CaipParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for Caip10AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for Caip10AccountId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for Caip10AccountId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Caip10AccountId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// `WalletConnect` namespace map key.
///
/// Proposal and session namespace maps use either a bare CAIP namespace, such as
/// `eip155`, or a full CAIP-2 chain ID, such as `eip155:1`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/caip.ts#L107-L113>
///
/// > // check if chainId is provided in the key as `eip155:1` or in the namespace as chains[]
/// > return namespace.includes(":") ? [namespace] : namespaceProps.chains || [];
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceKey {
    /// Bare CAIP namespace key.
    Namespace(CaipNamespace),
    /// CAIP-2 chain ID key.
    ChainId(Caip2ChainId),
}

impl NamespaceKey {
    /// Parses a `WalletConnect` namespace map key.
    pub fn parse(value: &str) -> Result<Self, CaipParseError> {
        if value.contains(':') {
            Caip2ChainId::parse(value).map(Self::ChainId)
        } else {
            CaipNamespace::parse(value).map(Self::Namespace)
        }
    }

    /// Original key string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Namespace(namespace) => namespace.as_str(),
            Self::ChainId(chain_id) => chain_id.as_str(),
        }
    }

    /// Namespace component.
    #[must_use]
    pub fn namespace(&self) -> &str {
        match self {
            Self::Namespace(namespace) => namespace.as_str(),
            Self::ChainId(chain_id) => chain_id.namespace(),
        }
    }

    /// Chain ID when the key is chain-specific.
    #[must_use]
    pub const fn chain_id(&self) -> Option<&Caip2ChainId> {
        match self {
            Self::Namespace(_) => None,
            Self::ChainId(chain_id) => Some(chain_id),
        }
    }
}

impl FromStr for NamespaceKey {
    type Err = CaipParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for NamespaceKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for NamespaceKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for NamespaceKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl PartialOrd for NamespaceKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NamespaceKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl Hash for NamespaceKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl Serialize for NamespaceKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NamespaceKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

/// CAIP identifier parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaipParseError {
    /// CAIP-2 chain IDs must contain exactly one colon.
    #[error("CAIP-2 chain ID must be namespace:reference")]
    InvalidChainIdFormat,

    /// CAIP-10 account IDs must contain exactly two colons.
    #[error("CAIP-10 account ID must be namespace:reference:account_address")]
    InvalidAccountIdFormat,

    /// CAIP namespace length is outside `3..=8`.
    #[error("CAIP namespace must be 3 to 8 bytes, got {actual}")]
    InvalidNamespaceLength {
        /// Namespace length in bytes.
        actual: usize,
    },

    /// CAIP namespace contains a character outside `[-a-z0-9]`.
    #[error("CAIP namespace contains invalid character {character:?} at byte index {index}")]
    InvalidNamespaceCharacter {
        /// Byte index in the original input.
        index: usize,
        /// Character rejected by namespace validation.
        character: char,
    },

    /// CAIP-2 reference length is outside `1..=32`.
    #[error("CAIP reference must be 1 to 32 bytes, got {actual}")]
    InvalidReferenceLength {
        /// Reference length in bytes.
        actual: usize,
    },

    /// CAIP-2 reference contains a character outside `[-_a-zA-Z0-9]`.
    #[error("CAIP reference contains invalid character {character:?} at byte index {index}")]
    InvalidReferenceCharacter {
        /// Byte index in the original input.
        index: usize,
        /// Character rejected by reference validation.
        character: char,
    },

    /// CAIP-10 account address length is outside `1..=128`.
    #[error("CAIP account address must be 1 to 128 bytes, got {actual}")]
    InvalidAddressLength {
        /// Account address length in bytes.
        actual: usize,
    },

    /// CAIP-10 account address contains a character outside `[-.%a-zA-Z0-9]`.
    #[error("CAIP account address contains invalid character {character:?} at byte index {index}")]
    InvalidAddressCharacter {
        /// Byte index in the original input.
        index: usize,
        /// Character rejected by account address validation.
        character: char,
    },
}

fn validate_namespace(value: &str) -> Result<(), CaipParseError> {
    validate_len(value, 3, 8)
        .map_err(|actual| CaipParseError::InvalidNamespaceLength { actual })?;
    validate_chars(value, is_namespace_char).map_err(|(index, character)| {
        CaipParseError::InvalidNamespaceCharacter { index, character }
    })
}

fn validate_reference(value: &str) -> Result<(), CaipParseError> {
    validate_len(value, 1, 32)
        .map_err(|actual| CaipParseError::InvalidReferenceLength { actual })?;
    validate_chars(value, is_reference_char).map_err(|(index, character)| {
        CaipParseError::InvalidReferenceCharacter { index, character }
    })
}

fn validate_address(value: &str) -> Result<(), CaipParseError> {
    validate_len(value, 1, 128)
        .map_err(|actual| CaipParseError::InvalidAddressLength { actual })?;
    validate_chars(value, is_account_address_char)
        .map_err(|(index, character)| CaipParseError::InvalidAddressCharacter { index, character })
}

const fn validate_len(value: &str, min: usize, max: usize) -> Result<(), usize> {
    let actual = value.len();
    if actual < min || actual > max {
        Err(actual)
    } else {
        Ok(())
    }
}

fn validate_chars(value: &str, allowed: fn(char) -> bool) -> Result<(), (usize, char)> {
    value
        .char_indices()
        .find(|(_, character)| !allowed(*character))
        .map_or(Ok(()), |(index, character)| Err((index, character)))
}

const fn is_namespace_char(character: char) -> bool {
    matches!(character, 'a'..='z' | '0'..='9' | '-')
}

const fn is_reference_char(character: char) -> bool {
    matches!(character, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_')
}

const fn is_account_address_char(character: char) -> bool {
    matches!(
        character,
        'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' | '%'
    )
}
