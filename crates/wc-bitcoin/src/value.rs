use std::{borrow::Borrow, fmt, str::FromStr};

use base64::prelude::{BASE64_STANDARD, Engine as _};
use bitcoin::{
    Amount, Denomination, Network, PublicKey, Txid,
    address::{Address, NetworkUnchecked},
    bip32::{ChildNumber, DerivationPath},
    psbt::Psbt,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::BitcoinValueError;

/// Bitcoin address string used by `WalletConnect` Bitcoin methods.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinAddress(String);

impl BitcoinAddress {
    /// Parses a CAIP-compatible Bitcoin account address.
    pub fn parse(value: impl Into<String>) -> Result<Self, BitcoinValueError> {
        let value = value.into();
        validate_address(&value)?;
        Ok(Self(value))
    }

    /// Borrows the address string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Moves the address into caller-owned state.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl Borrow<str> for BitcoinAddress {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for BitcoinAddress {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for BitcoinAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for BitcoinAddress {
    type Err = BitcoinValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for BitcoinAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BitcoinAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// Bitcoin amount encoded on the wire as a decimal satoshi string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinAmountSats(Amount);

impl BitcoinAmountSats {
    /// Parses a non-empty ASCII decimal satoshi amount.
    pub fn parse(value: impl Into<String>) -> Result<Self, BitcoinValueError> {
        let value = value.into();
        let amount = parse_amount(&value)?;
        Ok(Self(amount))
    }

    /// Amount in satoshis.
    #[must_use]
    pub fn to_sat(&self) -> u64 {
        self.0.to_sat()
    }

    /// Converts the amount to the `WalletConnect` decimal satoshi string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.to_sat().to_string()
    }
}

impl fmt::Display for BitcoinAmountSats {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.to_sat())
    }
}

impl FromStr for BitcoinAmountSats {
    type Err = BitcoinValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for BitcoinAmountSats {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_sat().to_string())
    }
}

impl<'de> Deserialize<'de> for BitcoinAmountSats {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// Non-empty hex bytes without a `0x` prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexBytes(String);

impl HexBytes {
    /// Parses non-empty even-length hex bytes without a prefix.
    pub fn parse(value: impl Into<String>) -> Result<Self, BitcoinValueError> {
        let value = value.into();
        validate_hex_bytes(&value, HexPolicy::NonEmpty)?;
        Ok(Self(value))
    }

    /// Borrows the hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Length in decoded bytes.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len() / 2
    }

    /// Moves the hex string into caller-owned state.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for HexBytes {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for HexBytes {
    type Err = BitcoinValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for HexBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// Bitcoin ECDSA public key encoded on the wire as hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinPublicKey(PublicKey);

impl BitcoinPublicKey {
    /// Parses a compressed or uncompressed Bitcoin ECDSA public key.
    pub fn parse(value: impl Into<String>) -> Result<Self, BitcoinValueError> {
        let value = value.into();
        let public_key = parse_public_key(&value)?;
        Ok(Self(public_key))
    }

    /// Converts the public key to its hex wire string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.to_string()
    }
}

impl fmt::Display for BitcoinPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl FromStr for BitcoinPublicKey {
    type Err = BitcoinValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for BitcoinPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BitcoinPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// `OP_RETURN` memo hex without `0x`, capped at 80 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinMemo(String);

impl BitcoinMemo {
    /// Parses memo hex with the `WalletConnect` 80-byte limit.
    pub fn parse(value: impl Into<String>) -> Result<Self, BitcoinValueError> {
        let value = value.into();
        validate_hex_bytes(&value, HexPolicy::AllowEmpty)?;
        if value.len() / 2 > 80 {
            return Err(BitcoinValueError::MemoTooLong {
                byte_len: value.len() / 2,
            });
        }
        Ok(Self(value))
    }

    /// Borrows the memo hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Length in decoded bytes.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len() / 2
    }
}

impl AsRef<str> for BitcoinMemo {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for BitcoinMemo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for BitcoinMemo {
    type Err = BitcoinValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for BitcoinMemo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BitcoinMemo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// Bitcoin transaction id encoded on the wire as hex without a `0x` prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTxid(Txid);

impl BitcoinTxid {
    /// Parses a 32-byte transaction id encoded as 64 hex characters.
    pub fn parse(value: impl Into<String>) -> Result<Self, BitcoinValueError> {
        let value = value.into();
        let txid = parse_txid(&value)?;
        Ok(Self(txid))
    }
}

impl fmt::Display for BitcoinTxid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl FromStr for BitcoinTxid {
    type Err = BitcoinValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for BitcoinTxid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BitcoinTxid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// Base64 encoded PSBT string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinPsbt(String);

impl BitcoinPsbt {
    /// Parses a non-empty base64-looking PSBT string.
    pub fn parse(value: impl Into<String>) -> Result<Self, BitcoinValueError> {
        let value = value.into();
        validate_base64(&value)?;
        Ok(Self(value))
    }

    /// Borrows the base64 string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for BitcoinPsbt {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for BitcoinPsbt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for BitcoinPsbt {
    type Err = BitcoinValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for BitcoinPsbt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BitcoinPsbt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// Bitcoin derivation path encoded on the wire as a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinDerivationPath(DerivationPath);

impl BitcoinDerivationPath {
    /// Parses a non-empty derivation path beginning with `m/`.
    pub fn parse(value: impl Into<String>) -> Result<Self, BitcoinValueError> {
        let value = value.into();
        let path = parse_derivation_path(&value)?;
        Ok(Self(path))
    }

    /// Returns true for the default Bitcoin account identifier path.
    ///
    /// The `WalletConnect` Bitcoin docs use the first external Native `SegWit`
    /// address, `m/84'/0'/account'/0/0`, as the account identifier.
    #[must_use]
    pub fn is_default_account_identifier_path(&self) -> bool {
        let Some(levels) = bip44_levels(&self.0) else {
            return false;
        };
        is_hardened(levels[0], 84)
            && is_hardened(levels[1], 0)
            && is_any_hardened(levels[2])
            && is_normal(levels[3], 0)
            && is_normal(levels[4], 0)
    }

    /// Returns true for derivation paths belonging to the supported account group.
    ///
    /// This accepts BIP44, BIP49, BIP84, and BIP86 Bitcoin paths with the same
    /// account level, matching the address families described by the
    /// `WalletConnect` Bitcoin docs.
    #[must_use]
    pub fn is_supported_account_group_path(&self) -> bool {
        let Some(levels) = bip44_levels(&self.0) else {
            return false;
        };
        matches!(child_index(levels[0]), 44 | 49 | 84 | 86)
            && is_any_hardened(levels[0])
            && is_hardened(levels[1], 0)
            && is_any_hardened(levels[2])
            && is_any_normal(levels[3])
            && is_any_normal(levels[4])
    }
    /// Converts the derivation path to its wire string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.to_string()
    }
}

impl fmt::Display for BitcoinDerivationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl FromStr for BitcoinDerivationPath {
    type Err = BitcoinValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for BitcoinDerivationPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BitcoinDerivationPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

fn validate_address(value: &str) -> Result<(), BitcoinValueError> {
    if value.is_empty() {
        return Err(BitcoinValueError::EmptyAddress);
    }
    if value.len() > 128 {
        return Err(BitcoinValueError::AddressTooLong { len: value.len() });
    }
    value
        .parse::<Address<NetworkUnchecked>>()
        .and_then(|address| address.require_network(Network::Bitcoin))
        .map(|_| ())
        .map_err(|_| BitcoinValueError::InvalidAddress)
}

fn parse_amount(value: &str) -> Result<Amount, BitcoinValueError> {
    if value.is_empty() {
        return Err(BitcoinValueError::EmptyAmount);
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BitcoinValueError::InvalidAmount);
    }
    let amount = Amount::from_str_in(value, Denomination::Satoshi)
        .map_err(|_| BitcoinValueError::AmountOutOfRange)?;
    if amount > Amount::MAX_MONEY {
        return Err(BitcoinValueError::AmountOutOfRange);
    }
    Ok(amount)
}

#[derive(Debug, Clone, Copy)]
enum HexPolicy {
    AllowEmpty,
    NonEmpty,
}

fn validate_hex_bytes(value: &str, policy: HexPolicy) -> Result<(), BitcoinValueError> {
    if value.is_empty() && matches!(policy, HexPolicy::NonEmpty) {
        return Err(BitcoinValueError::EmptyHex);
    }
    if value.starts_with("0x") || value.starts_with("0X") {
        return Err(BitcoinValueError::HexPrefix);
    }
    if value.len() % 2 != 0 {
        return Err(BitcoinValueError::OddHexLength { len: value.len() });
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BitcoinValueError::InvalidHex);
    }
    Ok(())
}

fn validate_base64(value: &str) -> Result<(), BitcoinValueError> {
    if value.is_empty() {
        return Err(BitcoinValueError::EmptyPsbt);
    }
    let bytes = BASE64_STANDARD
        .decode(value)
        .map_err(|_| BitcoinValueError::InvalidPsbt)?;
    Psbt::deserialize(&bytes)
        .map(|_| ())
        .map_err(|_| BitcoinValueError::InvalidPsbt)
}

fn parse_derivation_path(value: &str) -> Result<DerivationPath, BitcoinValueError> {
    if value.is_empty() {
        return Err(BitcoinValueError::EmptyDerivationPath);
    }
    if !value.starts_with("m/") {
        return Err(BitcoinValueError::InvalidDerivationPath);
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(BitcoinValueError::InvalidDerivationPathCharacters);
    }
    value
        .parse::<DerivationPath>()
        .map_err(|_| BitcoinValueError::InvalidDerivationPath)
}

fn parse_public_key(value: &str) -> Result<PublicKey, BitcoinValueError> {
    if value.is_empty() {
        return Err(BitcoinValueError::EmptyPublicKey);
    }
    value
        .parse::<PublicKey>()
        .map_err(|_| BitcoinValueError::InvalidPublicKey)
}

fn parse_txid(value: &str) -> Result<Txid, BitcoinValueError> {
    value
        .parse::<Txid>()
        .map_err(|_| BitcoinValueError::InvalidTxidLength { len: value.len() })
}

fn bip44_levels(path: &DerivationPath) -> Option<Vec<ChildNumber>> {
    let levels = path.as_ref().to_vec();
    (levels.len() == 5).then_some(levels)
}

const fn is_hardened(level: ChildNumber, value: u32) -> bool {
    matches!(level, ChildNumber::Hardened { index } if index == value)
}

const fn is_normal(level: ChildNumber, value: u32) -> bool {
    matches!(level, ChildNumber::Normal { index } if index == value)
}

const fn is_any_hardened(level: ChildNumber) -> bool {
    matches!(level, ChildNumber::Hardened { .. })
}

const fn is_any_normal(level: ChildNumber) -> bool {
    matches!(level, ChildNumber::Normal { .. })
}

const fn child_index(level: ChildNumber) -> u32 {
    match level {
        ChildNumber::Hardened { index } | ChildNumber::Normal { index } => index,
    }
}
