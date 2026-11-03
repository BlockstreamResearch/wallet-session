//! The address a connection's inbound bytes are accounted to.
//!
//! Identities cost nothing to mint, so the identity share alone cannot stop
//! one client from spending the relay-wide budget under many names. An address
//! is harder to multiply. It is the TCP peer's, unless that peer is a proxy
//! listed in `application.trusted_proxies`: then it is the client address the
//! proxy writes into `X-Real-IP`. The header is ignored from every other peer,
//! so a client that reaches the relay directly cannot choose its own source.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::atomic::{AtomicBool, Ordering},
};

use serde::{Deserialize, Deserializer};
use thiserror::Error;
use tokio_tungstenite::tungstenite::http::HeaderMap;

/// Header in which a trusted proxy names the client it forwards.
pub const REAL_IP_HEADER: &str = "x-real-ip";

/// Leading bits of an IPv6 address that make up one source. A subscriber is
/// normally assigned a whole /64, so keying on the full address would give one
/// client as many shares as it has addresses.
pub const IPV6_SOURCE_PREFIX: u8 = 64;

/// Whether an ignored `X-Real-IP` has been reported, so that clients sending
/// one cannot fill the log with the warning.
static IGNORED_HEADER_REPORTED: AtomicBool = AtomicBool::new(false);

/// A range of addresses, written `address/length` or as a single address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPrefix {
    network: IpAddr,
    length: u8,
}

/// A range that is not an address or an `address/length` pair.
#[derive(Debug, Error)]
#[error("invalid address range {0:?}: expected an IP address or address/length")]
pub struct InvalidPrefix(String);

impl IpPrefix {
    /// The addresses sharing the first `length` bits of `address`, or `None`
    /// if `length` is longer than the address.
    ///
    /// An IPv4-mapped IPv6 range is stored as the IPv4 range it maps, since
    /// addresses are compared in their canonical form.
    pub fn new(address: IpAddr, length: u8) -> Option<Self> {
        let (address, length) = match address {
            IpAddr::V6(v6) if length >= 96 => match v6.to_ipv4_mapped() {
                Some(v4) => (IpAddr::V4(v4), length - 96),
                None => (address, length),
            },
            _ => (address, length),
        };
        if length > bits(address) {
            return None;
        }
        Some(Self {
            network: mask(address, length),
            length,
        })
    }

    /// Number of leading bits the range fixes.
    pub fn length(&self) -> u8 {
        self.length
    }

    /// Whether `address` lies in this range.
    pub fn contains(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        address.is_ipv4() == self.network.is_ipv4() && mask(address, self.length) == self.network
    }

    /// The first and last address of the range, as integers.
    fn span(&self) -> (u128, u128) {
        let (first, host_bits) = match self.network {
            IpAddr::V4(v4) => (
                u128::from(u32::from(v4)),
                32u32.saturating_sub(u32::from(self.length)),
            ),
            IpAddr::V6(v6) => (
                u128::from(v6),
                128u32.saturating_sub(u32::from(self.length)),
            ),
        };
        let hosts = u128::MAX.checked_shr(128 - host_bits).unwrap_or(0);
        (first, first | hosts)
    }
}

/// The whole of an address family, as a range, if `ranges` together hold
/// every address a peer of that family can connect from. Trusting them would
/// let every such peer name its own source, as trusting `0.0.0.0/0` would.
///
/// Peers are compared in canonical form, so an IPv6 list need not hold the
/// IPv4-mapped block to take in every IPv6 peer.
pub fn covered_family(ranges: &[IpPrefix]) -> Option<IpPrefix> {
    let v4 = ranges
        .iter()
        .filter(|range| range.network.is_ipv4())
        .map(IpPrefix::span);
    if covers_all(v4, u128::from(u32::MAX)) {
        return IpPrefix::new(Ipv4Addr::UNSPECIFIED.into(), 0);
    }

    let mapped = u128::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0));
    let v6 = ranges
        .iter()
        .filter(|range| range.network.is_ipv6())
        .map(IpPrefix::span)
        .chain([(mapped, mapped | u128::from(u32::MAX))]);
    if covers_all(v6, u128::MAX) {
        return IpPrefix::new(Ipv6Addr::UNSPECIFIED.into(), 0);
    }
    None
}

/// Whether `spans`, inclusive, together hold every integer up to `last`.
fn covers_all(spans: impl Iterator<Item = (u128, u128)>, last: u128) -> bool {
    let mut spans: Vec<_> = spans.collect();
    spans.sort_unstable();
    // The lowest integer none of the spans seen so far holds.
    let mut next = 0u128;
    for (first, end) in spans {
        if first > next {
            return false;
        }
        match end.checked_add(1) {
            Some(after) if after <= last => next = next.max(after),
            _ => return true,
        }
    }
    false
}

impl FromStr for IpPrefix {
    type Err = InvalidPrefix;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidPrefix(text.to_owned());
        let (address, length) = match text.trim().split_once('/') {
            Some((address, length)) => (address, Some(length)),
            None => (text.trim(), None),
        };
        let address: IpAddr = address.parse().map_err(|_| invalid())?;
        let length = match length {
            Some(length) => length.parse().map_err(|_| invalid())?,
            None => bits(address),
        };
        Self::new(address, length).ok_or_else(invalid)
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.length)
    }
}

impl<'de> Deserialize<'de> for IpPrefix {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Bits in an address of `address`'s family.
fn bits(address: IpAddr) -> u8 {
    if address.is_ipv4() { 32 } else { 128 }
}

/// `address` with every bit after the first `length` cleared.
fn mask(address: IpAddr, length: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let kept = u32::MAX
                .checked_shl(32u32.saturating_sub(u32::from(length)))
                .unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & kept))
        }
        IpAddr::V6(v6) => {
            let kept = u128::MAX
                .checked_shl(128u32.saturating_sub(u32::from(length)))
                .unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & kept))
        }
    }
}

/// What a connection's inbound bytes are accounted to: an IPv4 address, or
/// the /64 holding an IPv6 one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Source(IpAddr);

impl Source {
    /// The source `address` belongs to.
    pub fn of(address: IpAddr) -> Self {
        match address.to_canonical() {
            v4 @ IpAddr::V4(_) => Self(v4),
            v6 @ IpAddr::V6(_) => Self(mask(v6, IPV6_SOURCE_PREFIX)),
        }
    }

    /// The source of a connection from `peer` that sent `headers` with its
    /// handshake.
    ///
    /// Only a peer in `trusted_proxies` may name the client in `X-Real-IP`.
    /// From any other peer the header is ignored and the peer is the source.
    /// A trusted proxy that does not name exactly one address is the source
    /// itself, so the clients it forwards that way share one share rather
    /// than escape it.
    pub fn resolve(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpPrefix]) -> Self {
        if !trusted_proxies.iter().any(|proxy| proxy.contains(peer)) {
            if headers.contains_key(REAL_IP_HEADER)
                && !IGNORED_HEADER_REPORTED.swap(true, Ordering::Relaxed)
            {
                log::warn!(
                    "ignoring X-Real-IP from a peer outside application.trusted_proxies; \
                     if a proxy fronts the relay, list it there, or every client it \
                     forwards shares one source budget"
                );
            }
            return Self::of(peer);
        }
        match real_ip(headers) {
            Some(client) => Self::of(client),
            None => {
                log::debug!("trusted proxy named no single client address; accounting the proxy");
                Self::of(peer)
            }
        }
    }
}

/// The address in `X-Real-IP`, if the header appears once and holds nothing
/// but an address.
fn real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let mut values = headers.get_all(REAL_IP_HEADER).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio_tungstenite::tungstenite::http::HeaderValue;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    fn headers(real_ips: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for real_ip in real_ips {
            headers.append(
                REAL_IP_HEADER,
                HeaderValue::from_str(real_ip).expect("header value"),
            );
        }
        headers
    }

    fn proxies(ranges: &[&str]) -> Vec<IpPrefix> {
        ranges
            .iter()
            .map(|range| range.parse().expect("test range"))
            .collect()
    }

    #[test]
    fn ranges_parse_as_addresses_or_prefixes() -> TestResult {
        let range: IpPrefix = "10.1.2.3/8".parse()?;
        assert_eq!(range.to_string(), "10.0.0.0/8", "host bits are cleared");
        assert!(range.contains(ip("10.200.0.1")));
        assert!(!range.contains(ip("11.0.0.1")));

        let single: IpPrefix = " 192.0.2.7 ".parse()?;
        assert_eq!(single.length(), 32);
        assert!(single.contains(ip("192.0.2.7")));
        assert!(!single.contains(ip("192.0.2.8")));

        let v6: IpPrefix = "fd00::/8".parse()?;
        assert!(v6.contains(ip("fd12::1")));
        assert!(!v6.contains(ip("fe80::1")));
        assert!(
            !v6.contains(ip("10.0.0.1")),
            "an IPv6 range holds no IPv4 address"
        );

        let mapped: IpPrefix = "::ffff:10.0.0.0/104".parse()?;
        assert_eq!(mapped.to_string(), "10.0.0.0/8");

        for invalid in ["", "proxy", "10.0.0.0/33", "fd00::/129", "10.0.0.0/", "/8"] {
            assert!(
                invalid.parse::<IpPrefix>().is_err(),
                "{invalid:?} must be rejected"
            );
        }
        Ok(())
    }

    #[test]
    fn ranges_that_together_hold_every_peer_are_found() -> TestResult {
        let every_v4: IpPrefix = "0.0.0.0/0".parse()?;
        let every_v6: IpPrefix = "::/0".parse()?;
        assert_eq!(covered_family(&proxies(&["0.0.0.0/0"])), Some(every_v4));
        assert_eq!(
            covered_family(&proxies(&["128.0.0.0/1", "fd00::/8", "0.0.0.0/1"])),
            Some(every_v4),
            "two halves trust every IPv4 peer as /0 does"
        );
        assert_eq!(
            covered_family(&proxies(&["::ffff:0.0.0.0/97", "128.0.0.0/1"])),
            Some(every_v4),
            "an IPv4-mapped range is its IPv4 range"
        );
        assert_eq!(
            covered_family(&proxies(&["8000::/1", "::/1"])),
            Some(every_v6)
        );

        // Every range beside the IPv4-mapped block: no IPv6 peer is left out.
        let mapped = u128::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0));
        let around = (0..96u8)
            .map(|bit| {
                let differs = Ipv6Addr::from(mapped ^ (1u128 << (127 - bit)));
                IpPrefix::new(IpAddr::V6(differs), bit + 1)
            })
            .collect::<Option<Vec<_>>>()
            .ok_or("ranges around the mapped block")?;
        assert_eq!(covered_family(&around), Some(every_v6));
        assert_eq!(covered_family(&around[1..]), None);

        let partial: [&[&str]; 4] = [
            &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
            &["0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "::/1"],
            &["127.0.0.1", "::1"],
            &[],
        ];
        for ranges in partial {
            assert_eq!(covered_family(&proxies(ranges)), None, "{ranges:?}");
        }
        Ok(())
    }

    #[test]
    fn mapped_peers_match_their_ipv4_range() -> TestResult {
        let range: IpPrefix = "172.16.0.0/12".parse()?;
        assert!(range.contains(ip("::ffff:172.18.0.2")));
        Ok(())
    }

    #[test]
    fn ipv6_sources_are_their_64() {
        assert_eq!(
            Source::of(ip("2001:db8:1:2::1")),
            Source::of(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")),
            "addresses in one /64 are one source"
        );
        assert_ne!(
            Source::of(ip("2001:db8:1:2::1")),
            Source::of(ip("2001:db8:1:3::1")),
            "neighbouring /64s are different sources"
        );
        assert_eq!(Source::of(ip("2001:db8:1:2::1")).0, ip("2001:db8:1:2::"));
    }

    #[test]
    fn ipv4_sources_are_the_address() {
        assert_ne!(Source::of(ip("192.0.2.1")), Source::of(ip("192.0.2.2")));
        assert_eq!(
            Source::of(ip("::ffff:192.0.2.1")),
            Source::of(ip("192.0.2.1")),
            "an IPv4-mapped peer is its IPv4 source, not a /64"
        );
    }

    #[test]
    fn real_ip_from_a_direct_peer_is_ignored() {
        let peer = ip("198.51.100.20");
        let spoofed = headers(&["203.0.113.9"]);

        assert_eq!(Source::resolve(peer, &spoofed, &[]), Source::of(peer));
        assert_eq!(
            Source::resolve(peer, &spoofed, &proxies(&["10.0.0.0/8", "fd00::/8"])),
            Source::of(peer),
            "a peer outside the trusted ranges names no one but itself"
        );
    }

    #[test]
    fn real_ip_from_a_trusted_proxy_names_the_source() {
        let trusted = proxies(&["172.16.0.0/12"]);
        let proxy = ip("172.18.0.3");

        assert_eq!(
            Source::resolve(proxy, &headers(&["203.0.113.9"]), &trusted),
            Source::of(ip("203.0.113.9"))
        );
        assert_eq!(
            Source::resolve(proxy, &headers(&["2001:db8:5:6::77"]), &trusted),
            Source::of(ip("2001:db8:5:6::1")),
            "a proxied IPv6 client is its /64 too"
        );
        assert_eq!(
            Source::resolve(
                ip("::ffff:172.18.0.3"),
                &headers(&["203.0.113.9"]),
                &trusted
            ),
            Source::of(ip("203.0.113.9")),
            "a dual-stack listener sees the proxy as an IPv4-mapped peer"
        );
    }

    #[test]
    fn a_trusted_proxy_naming_no_single_address_is_the_source() {
        let trusted = proxies(&["127.0.0.1"]);
        let proxy = ip("127.0.0.1");

        for named in [
            headers(&[]),
            headers(&["not-an-address"]),
            headers(&["203.0.113.9, 198.51.100.1"]),
            headers(&["203.0.113.9:443"]),
            headers(&["203.0.113.9", "198.51.100.1"]),
        ] {
            assert_eq!(
                Source::resolve(proxy, &named, &trusted),
                Source::of(proxy),
                "{named:?} must not name a source"
            );
        }
    }
}
