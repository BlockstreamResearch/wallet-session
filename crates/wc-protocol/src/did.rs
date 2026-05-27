//! DID primitives.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::caip::{Caip2ChainId, Caip10AccountId, CaipParseError};

const DID_PKH_PREFIX: &str = "did:pkh:";

/// DID PKH identifier.
///
/// <https://github.com/w3c-ccg/did-pkh/blob/90b28ad3c18d63822a8aab3c752302aa64fc9382/did-pkh-method-draft.md#syntax-and-interpretation>
///
/// > pkh-did    = "did:pkh:" address
/// > address    = account_id according to [CAIP-10]
///
/// # Examples
///
/// ```
/// use wc_protocol::did::DidPkh;
///
/// let did = DidPkh::parse(
///     "did:pkh:eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
/// )?;
/// assert_eq!(did.account_id_str(), "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");
/// assert_eq!(did.chain_id().as_str(), "eip155:1");
/// # Ok::<(), wc_protocol::did::DidPkhParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DidPkh {
    value: String,
}

impl DidPkh {
    /// Validates a DID PKH identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, DidPkhParseError> {
        let value = value.into();
        let account_id = value
            .strip_prefix(DID_PKH_PREFIX)
            .ok_or(DidPkhParseError::InvalidPrefix)?;
        Caip10AccountId::parse(account_id)
            .map_err(|source| DidPkhParseError::InvalidAccount { source })?;
        Ok(Self { value })
    }

    /// Builds a DID PKH identifier from a validated CAIP-10 account ID.
    #[must_use]
    pub fn from_account_id(account_id: &Caip10AccountId) -> Self {
        Self {
            value: format!("{DID_PKH_PREFIX}{account_id}"),
        }
    }

    /// Full `did:pkh:<account_id>` string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// CAIP-10 account ID suffix.
    #[must_use]
    pub fn account_id_str(&self) -> &str {
        &self.value[DID_PKH_PREFIX.len()..]
    }

    /// CAIP-10 account ID suffix as a typed value.
    #[must_use]
    pub fn account_id(&self) -> Caip10AccountId {
        Caip10AccountId::parse(self.account_id_str())
            .expect("DidPkh validates its CAIP-10 account suffix")
    }

    /// CAIP-2 chain ID from the account suffix.
    #[must_use]
    pub fn chain_id(&self) -> Caip2ChainId {
        self.account_id().chain_id()
    }

    /// Account address component from the account suffix.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.value[DID_PKH_PREFIX.len() + self.account_id().chain_id_str().len() + 1..]
    }

    /// Moves the DID into caller-owned state.
    #[must_use]
    pub fn into_string(self) -> String {
        self.value
    }
}

impl FromStr for DidPkh {
    type Err = DidPkhParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for DidPkh {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for DidPkh {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for DidPkh {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DidPkh {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// DID PKH parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DidPkhParseError {
    /// DID PKH strings must start with `did:pkh:`.
    #[error("DID PKH must start with did:pkh:")]
    InvalidPrefix,

    /// DID PKH account suffix must be a valid CAIP-10 account ID.
    #[error("DID PKH account suffix is invalid")]
    InvalidAccount {
        /// CAIP-10 parse failure.
        #[source]
        source: CaipParseError,
    },
}
