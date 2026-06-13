//! Wallet-facing redirect and link-mode review primitives.

use wc_protocol::session::DappRedirect;

/// How the wallet received the pairing request.
///
/// `WalletConnect` redirect guidance treats dapp-provided redirect metadata as
/// safe for automatic return only when the wallet was opened from a dapp link.
/// QR-scanned pairings still expose the raw metadata for UI, but do not produce
/// an automatic return target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletRedirectOrigin {
    /// The wallet cannot prove the pairing was opened by the dapp.
    Unknown,
    /// The pairing came from a scanned/copied URI, not an app switch.
    QrCode,
    /// The wallet was opened by the dapp through a native or universal link.
    DeepLink,
}

impl WalletRedirectOrigin {
    /// Whether this origin can use dapp redirect metadata for automatic return.
    #[must_use]
    pub const fn allows_automatic_redirect(self) -> bool {
        matches!(self, Self::DeepLink)
    }
}

/// Validated redirect target kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletRedirectTargetKind {
    /// Native custom-scheme app URI.
    Native,
    /// HTTPS universal link.
    Universal,
}

/// Validated redirect target that a wallet may pass to its platform layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRedirectTarget {
    kind: WalletRedirectTargetKind,
    uri: String,
}

impl WalletRedirectTarget {
    const fn new(kind: WalletRedirectTargetKind, uri: String) -> Self {
        Self { kind, uri }
    }

    /// Target kind.
    #[must_use]
    pub const fn kind(&self) -> WalletRedirectTargetKind {
        self.kind
    }

    /// Validated target URI.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }
}

/// Wallet-facing review of dapp redirect and link-mode metadata.
///
/// This type separates raw protocol metadata from the stricter recommendation a
/// wallet should use for automatic app return. Callers can still render the raw
/// `native` and `universal` strings, but should only launch
/// `automatic_target`/`link_mode_target` when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRedirectReview {
    origin: WalletRedirectOrigin,
    native: Option<String>,
    universal: Option<String>,
    link_mode: bool,
}

impl WalletRedirectReview {
    /// Builds redirect review data from optional dapp metadata.
    #[must_use]
    pub fn from_redirect(redirect: Option<&DappRedirect>, origin: WalletRedirectOrigin) -> Self {
        let (native, universal, link_mode) = redirect.map_or((None, None, false), |redirect| {
            (
                redirect.native.clone(),
                redirect.universal.clone(),
                redirect.link_mode.unwrap_or(false),
            )
        });

        Self {
            origin,
            native,
            universal,
            link_mode,
        }
    }

    /// Empty QR-safe review for lower-level constructors without dapp metadata.
    #[must_use]
    pub const fn empty(origin: WalletRedirectOrigin) -> Self {
        Self {
            origin,
            native: None,
            universal: None,
            link_mode: false,
        }
    }

    /// How the wallet received the pairing that advertised this metadata.
    #[must_use]
    pub const fn origin(&self) -> WalletRedirectOrigin {
        self.origin
    }

    /// Native redirect URI exactly as advertised by the dapp.
    #[must_use]
    pub fn native(&self) -> Option<&str> {
        self.native.as_deref()
    }

    /// Universal redirect URL exactly as advertised by the dapp.
    #[must_use]
    pub fn universal(&self) -> Option<&str> {
        self.universal.as_deref()
    }

    /// Whether the dapp advertised link-mode support.
    #[must_use]
    pub const fn link_mode_requested(&self) -> bool {
        self.link_mode
    }

    /// Whether any redirect metadata was present.
    #[must_use]
    pub const fn has_metadata(&self) -> bool {
        self.native.is_some() || self.universal.is_some() || self.link_mode
    }

    /// Whether automatic platform return is allowed for this origin.
    #[must_use]
    pub const fn allows_automatic_redirect(&self) -> bool {
        self.origin.allows_automatic_redirect()
    }

    /// Preferred validated automatic return target, if one is safe to launch.
    ///
    /// Native custom-scheme redirects are preferred over universal links for
    /// automatic return, matching current `WalletConnect` mobile-linking
    /// guidance. QR and unknown origins intentionally return `None`.
    #[must_use]
    pub fn automatic_target(&self) -> Option<WalletRedirectTarget> {
        if !self.allows_automatic_redirect() {
            return None;
        }

        self.native
            .as_deref()
            .filter(|uri| is_safe_native_uri(uri))
            .map(|uri| WalletRedirectTarget::new(WalletRedirectTargetKind::Native, uri.to_owned()))
            .or_else(|| {
                self.universal
                    .as_deref()
                    .filter(|uri| is_safe_universal_link(uri))
                    .map(|uri| {
                        WalletRedirectTarget::new(
                            WalletRedirectTargetKind::Universal,
                            uri.to_owned(),
                        )
                    })
            })
    }

    /// Validated link-mode universal-link target, if advertised and safe.
    ///
    /// Core exposes this as review data only; it does not open platform URLs or
    /// dispatch plaintext link-mode envelopes.
    #[must_use]
    pub fn link_mode_target(&self) -> Option<WalletRedirectTarget> {
        if !self.link_mode_requested() || !self.allows_automatic_redirect() {
            return None;
        }

        self.universal
            .as_deref()
            .filter(|uri| is_safe_universal_link(uri))
            .map(|uri| {
                WalletRedirectTarget::new(WalletRedirectTargetKind::Universal, uri.to_owned())
            })
    }
}

fn is_safe_native_uri(uri: &str) -> bool {
    if has_ascii_whitespace(uri) {
        return false;
    }

    let Some((scheme, rest)) = uri.split_once(':') else {
        return false;
    };
    if rest.is_empty() || !is_valid_uri_scheme(scheme) {
        return false;
    }

    !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "about"
            | "blob"
            | "data"
            | "file"
            | "ftp"
            | "http"
            | "https"
            | "javascript"
            | "mailto"
            | "tel"
            | "wc"
    )
}

fn is_safe_universal_link(uri: &str) -> bool {
    if has_ascii_whitespace(uri) {
        return false;
    }

    let Some(rest) = uri.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();

    !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn is_valid_uri_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn has_ascii_whitespace(value: &str) -> bool {
    value.bytes().any(|byte| byte.is_ascii_whitespace())
}

#[cfg(test)]
mod tests {
    use wc_protocol::session::DappRedirect;

    use super::{WalletRedirectOrigin, WalletRedirectReview, WalletRedirectTargetKind};

    fn redirect(native: Option<&str>, universal: Option<&str>, link_mode: bool) -> DappRedirect {
        DappRedirect {
            native: native.map(str::to_owned),
            universal: universal.map(str::to_owned),
            link_mode: Some(link_mode),
        }
    }

    #[test]
    fn qr_origin_preserves_metadata_without_automatic_target() {
        let redirect = redirect(
            Some("examplewallet://wc"),
            Some("https://example.com/wc"),
            true,
        );
        let review =
            WalletRedirectReview::from_redirect(Some(&redirect), WalletRedirectOrigin::QrCode);

        assert_eq!(review.native(), Some("examplewallet://wc"));
        assert_eq!(review.universal(), Some("https://example.com/wc"));
        assert!(review.link_mode_requested());
        assert!(review.has_metadata());
        assert!(review.automatic_target().is_none());
        assert!(review.link_mode_target().is_none());
    }

    #[test]
    fn deep_link_origin_prefers_valid_native_target() {
        let redirect = redirect(
            Some("examplewallet://wc?request=1"),
            Some("https://example.com/wc"),
            true,
        );
        let review =
            WalletRedirectReview::from_redirect(Some(&redirect), WalletRedirectOrigin::DeepLink);

        let target = review.automatic_target().expect("native target");
        assert_eq!(target.kind(), WalletRedirectTargetKind::Native);
        assert_eq!(target.uri(), "examplewallet://wc?request=1");

        let link_mode = review.link_mode_target().expect("link-mode target");
        assert_eq!(link_mode.kind(), WalletRedirectTargetKind::Universal);
        assert_eq!(link_mode.uri(), "https://example.com/wc");
    }

    #[test]
    fn deep_link_origin_falls_back_to_valid_universal_target() {
        let redirect = redirect(
            Some("javascript:alert(1)"),
            Some("https://example.com/wc"),
            false,
        );
        let review =
            WalletRedirectReview::from_redirect(Some(&redirect), WalletRedirectOrigin::DeepLink);

        let target = review.automatic_target().expect("universal target");
        assert_eq!(target.kind(), WalletRedirectTargetKind::Universal);
        assert_eq!(target.uri(), "https://example.com/wc");
    }

    #[test]
    fn invalid_redirects_do_not_become_targets() {
        let cases = [
            redirect(Some("https://example.com/native"), None, false),
            redirect(Some("wc:pairing"), None, false),
            redirect(Some("data:text/plain,secret"), None, false),
            redirect(Some("example wallet://wc"), None, false),
            redirect(None, Some("http://example.com/wc"), true),
            redirect(None, Some("https://exa mple.com/wc"), true),
            redirect(None, Some("https:///missing-host"), true),
        ];

        for redirect in cases {
            let review = WalletRedirectReview::from_redirect(
                Some(&redirect),
                WalletRedirectOrigin::DeepLink,
            );
            assert!(review.automatic_target().is_none());
            assert!(review.link_mode_target().is_none());
        }
    }

    #[test]
    fn link_mode_requires_flag_universal_link_and_deep_link_origin() {
        let without_flag = redirect(None, Some("https://example.com/wc"), false);
        let no_origin = redirect(None, Some("https://example.com/wc"), true);
        let non_https = redirect(None, Some("examplewallet://wc"), true);

        assert!(
            WalletRedirectReview::from_redirect(
                Some(&without_flag),
                WalletRedirectOrigin::DeepLink,
            )
            .link_mode_target()
            .is_none()
        );
        assert!(
            WalletRedirectReview::from_redirect(Some(&no_origin), WalletRedirectOrigin::Unknown)
                .link_mode_target()
                .is_none()
        );
        assert!(
            WalletRedirectReview::from_redirect(Some(&non_https), WalletRedirectOrigin::DeepLink)
                .link_mode_target()
                .is_none()
        );
    }
}
