use std::{collections::BTreeSet, fmt};

use crate::{
    BitcoinAccountAddress, BitcoinAccountAddresses, BitcoinAccountScopeError, BitcoinAddress,
    BitcoinDerivationPath, BitcoinValueError,
};

/// Wallet-verified Bitcoin account identifier.
///
/// The `WalletConnect` Bitcoin account identifier is the account's first
/// external Native `SegWit` address, not an arbitrary address from the wallet.
/// Use [`Self::from_first_external_entry`] when path metadata is available, or
/// [`Self::from_wallet_first_external_address`] only after local wallet state
/// has already verified the address role.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinConnectedAccount(BitcoinAddress);

impl BitcoinConnectedAccount {
    /// Builds a connected account from a wallet-verified first external address.
    #[must_use]
    pub const fn from_wallet_first_external_address(address: BitcoinAddress) -> Self {
        Self(address)
    }

    /// Parses a wallet-verified first external address.
    pub fn parse_wallet_first_external_address(
        value: impl Into<String>,
    ) -> Result<Self, BitcoinValueError> {
        BitcoinAddress::parse(value).map(Self::from_wallet_first_external_address)
    }

    /// Builds a connected account from an address entry with a default account path.
    pub fn from_first_external_entry(
        entry: &BitcoinAccountAddress,
    ) -> Result<Self, BitcoinAccountScopeError> {
        if !entry
            .path
            .as_ref()
            .is_some_and(BitcoinDerivationPath::is_default_account_identifier_path)
        {
            return Err(BitcoinAccountScopeError::InvalidConnectedAccountPath);
        }
        Ok(Self(entry.address.clone()))
    }

    /// Borrows the account identifier address.
    #[must_use]
    pub const fn address(&self) -> &BitcoinAddress {
        &self.0
    }

    /// Borrows the account identifier address string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Moves the identifier into its address.
    #[must_use]
    pub fn into_address(self) -> BitcoinAddress {
        self.0
    }
}

impl fmt::Debug for BitcoinConnectedAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BitcoinConnectedAccount")
            .field(&RedactedStringDebug(self.as_str()))
            .finish()
    }
}

impl AsRef<BitcoinAddress> for BitcoinConnectedAccount {
    fn as_ref(&self) -> &BitcoinAddress {
        self.address()
    }
}

impl AsRef<str> for BitcoinConnectedAccount {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for BitcoinConnectedAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Wallet-owned Bitcoin address scope for one connected account.
///
/// This is the wallet-side boundary for requests that can refer to secondary
/// addresses. `account` is the first external address shown as the connected
/// account; `addresses` contains every wallet-owned address that may be used
/// for signing or change within that account group.
#[derive(Clone, PartialEq, Eq)]
pub struct BitcoinAccountScope {
    account: BitcoinConnectedAccount,
    addresses: BTreeSet<BitcoinAddress>,
}

impl BitcoinAccountScope {
    /// Builds an account scope from wallet-owned addresses.
    pub fn new<I>(
        account: BitcoinConnectedAccount,
        addresses: I,
    ) -> Result<Self, BitcoinAccountScopeError>
    where
        I: IntoIterator<Item = BitcoinAddress>,
    {
        let addresses = addresses.into_iter().collect::<BTreeSet<_>>();
        if !addresses.contains(account.address()) {
            return Err(BitcoinAccountScopeError::MissingConnectedAccount);
        }
        Ok(Self { account, addresses })
    }

    /// Builds a scope from `getAccountAddresses` result data.
    pub fn from_account_addresses(
        account: BitcoinConnectedAccount,
        addresses: &BitcoinAccountAddresses,
    ) -> Result<Self, BitcoinAccountScopeError> {
        Self::new(
            account,
            addresses
                .as_slice()
                .iter()
                .map(|entry| entry.address.clone()),
        )
    }

    /// Connected account identifier for this scope.
    #[must_use]
    pub const fn connected_account(&self) -> &BitcoinConnectedAccount {
        &self.account
    }

    /// Wallet-owned addresses in this account group.
    #[must_use]
    pub const fn addresses(&self) -> &BTreeSet<BitcoinAddress> {
        &self.addresses
    }

    /// Returns whether the address is wallet-owned within this account group.
    #[must_use]
    pub fn contains_address(&self, address: &BitcoinAddress) -> bool {
        self.addresses.contains(address)
    }

    /// Number of wallet-owned addresses in this account group.
    #[must_use]
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Returns true when no wallet-owned addresses are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

impl fmt::Debug for BitcoinAccountScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitcoinAccountScope")
            .field("account", &self.account)
            .field("address_count", &self.addresses.len())
            .finish()
    }
}

struct RedactedStringDebug<'a>(&'a str);

impl fmt::Debug for RedactedStringDebug<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<redacted len={}>", self.0.len())
    }
}
