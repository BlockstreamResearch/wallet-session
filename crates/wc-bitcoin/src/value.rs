use std::{borrow::Borrow, fmt, str::FromStr};

use base64::prelude::{BASE64_STANDARD, Engine as _};
use bitcoin::{
    Network, PublicKey, Txid,
    address::{Address, NetworkUnchecked},
    amount::{Amount, Denomination},
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

    /// Summarizes the unsigned transaction embedded in the PSBT for user review.
    pub fn summary(
        &self,
        chain_reference: Option<&str>,
    ) -> Result<BitcoinPsbtSummary, BitcoinValueError> {
        BitcoinPsbtSummary::from_psbt(&parse_base64_psbt(self.as_str())?, chain_reference)
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

/// Wallet-facing summary of the unsigned transaction embedded in a PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinPsbtSummary {
    /// Number of transaction inputs in the unsigned transaction.
    pub input_count: usize,
    /// Number of transaction outputs in the unsigned transaction.
    pub output_count: usize,
    /// Total amount across all outputs, when it fits in a `u64`.
    pub total_output_sats: Option<u64>,
    /// Number of inputs that include UTXO data in the PSBT.
    pub known_input_count: usize,
    /// Total amount across inputs only when every input includes UTXO data.
    pub total_input_sats: Option<u64>,
    /// Implied fee only when every input amount is known and covers the outputs.
    pub fee_sats: Option<u64>,
    /// Number of outputs whose script starts with `OP_RETURN`.
    pub op_return_output_count: usize,
    /// Per-output summaries in transaction output order.
    pub outputs: Vec<BitcoinPsbtOutputSummary>,
}

impl BitcoinPsbtSummary {
    fn from_psbt(psbt: &Psbt, chain_reference: Option<&str>) -> Result<Self, BitcoinValueError> {
        let network = bitcoin_network_for_chain_reference(chain_reference);
        let outputs = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .map(|(index, output)| BitcoinPsbtOutputSummary {
                index,
                amount_sats: output.value.to_sat(),
                destination: psbt_output_destination(output, network),
            })
            .collect::<Vec<_>>();
        let total_output_sats = outputs
            .iter()
            .try_fold(0_u64, |total, output| total.checked_add(output.amount_sats));
        let op_return_output_count = outputs
            .iter()
            .filter(|output| matches!(output.destination, BitcoinPsbtOutputDestination::OpReturn))
            .count();

        let mut known_input_count = 0_usize;
        let mut known_input_total = Some(0_u64);
        for funding_utxo in psbt.iter_funding_utxos() {
            match funding_utxo {
                Ok(utxo) => {
                    known_input_count += 1;
                    if let Some(total) = known_input_total {
                        known_input_total = total.checked_add(utxo.value.to_sat());
                    }
                }
                Err(_) => known_input_total = None,
            }
        }

        let all_input_amounts_known = known_input_count == psbt.unsigned_tx.input.len();
        let total_input_sats = all_input_amounts_known
            .then_some(known_input_total)
            .flatten();
        let fee_sats = total_input_sats
            .zip(total_output_sats)
            .and_then(|(input, output)| input.checked_sub(output));

        Ok(Self {
            input_count: psbt.unsigned_tx.input.len(),
            output_count: outputs.len(),
            total_output_sats,
            known_input_count,
            total_input_sats,
            fee_sats,
            op_return_output_count,
            outputs,
        })
    }
}

/// One output in a wallet-facing PSBT summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinPsbtOutputSummary {
    /// Zero-based output index.
    pub index: usize,
    /// Output amount in satoshis.
    pub amount_sats: u64,
    /// Destination decoded from the output script.
    pub destination: BitcoinPsbtOutputDestination,
}

/// User-reviewable destination for a PSBT output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitcoinPsbtOutputDestination {
    /// Standard Bitcoin address decoded with the request chain.
    Address(String),
    /// Data-carrying `OP_RETURN` output.
    OpReturn,
    /// Non-standard or chain-unknown script, encoded as hex.
    ScriptHex(String),
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

    fn wire_string(&self) -> String {
        format!("m/{}", self.0)
    }
}

impl fmt::Display for BitcoinDerivationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.wire_string())
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
        serializer.serialize_str(&self.wire_string())
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
        .map(|_| ())
        .map_err(|_| BitcoinValueError::InvalidAddress)
}

pub fn parse_amount(value: &str) -> Result<Amount, BitcoinValueError> {
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
    parse_base64_psbt(value).map(|_| ())
}

fn parse_base64_psbt(value: &str) -> Result<Psbt, BitcoinValueError> {
    if value.is_empty() {
        return Err(BitcoinValueError::EmptyPsbt);
    }
    let bytes = BASE64_STANDARD
        .decode(value)
        .map_err(|_| BitcoinValueError::InvalidPsbt)?;
    Psbt::deserialize(&bytes).map_err(|_| BitcoinValueError::InvalidPsbt)
}

fn bitcoin_network_for_chain_reference(chain_reference: Option<&str>) -> Option<Network> {
    match chain_reference {
        Some("000000000019d6689c085ae165831e93") => Some(Network::Bitcoin),
        Some("000000000933ea01ad0ee984209779ba") => Some(Network::Testnet),
        Some("00000008819873e925422c1ff0f99f7c") => Some(Network::Signet),
        Some("0f9188f13cb7b2c71f2a335e3a4fc328") => Some(Network::Regtest),
        _ => None,
    }
}

fn psbt_output_destination(
    output: &bitcoin::TxOut,
    network: Option<Network>,
) -> BitcoinPsbtOutputDestination {
    if output.script_pubkey.is_op_return() {
        return BitcoinPsbtOutputDestination::OpReturn;
    }

    if let Some(network) = network {
        if let Ok(address) = Address::from_script(&output.script_pubkey, network) {
            return BitcoinPsbtOutputDestination::Address(address.to_string());
        }
    }

    BitcoinPsbtOutputDestination::ScriptHex(output.script_pubkey.to_hex_string())
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
