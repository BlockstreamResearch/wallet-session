#![no_main]

use libfuzzer_sys::fuzz_target;
use wc_protocol::{
    caip::{Caip2ChainId, Caip10AccountId, CaipNamespace, NamespaceKey},
    did::DidPkh,
    relay::RelayTopic,
    session::{SessionEventName, SessionMethod},
    verify::VerifyAttestationHash,
};

const MAX_INPUT_BYTES: usize = 512;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(namespace) = CaipNamespace::parse(input) {
        assert_eq!(
            CaipNamespace::parse(namespace.as_str()),
            Ok(namespace.clone())
        );
        assert_eq!(namespace.to_string(), namespace.as_str());
    }

    if let Ok(chain_id) = Caip2ChainId::parse(input) {
        assert_eq!(Caip2ChainId::parse(chain_id.as_str()), Ok(chain_id.clone()));
        assert_eq!(chain_id.to_string(), chain_id.as_str());
        assert!(!chain_id.namespace().is_empty());
        assert!(!chain_id.reference().is_empty());
    }

    if let Ok(account_id) = Caip10AccountId::parse(input) {
        assert_eq!(
            Caip10AccountId::parse(account_id.as_str()),
            Ok(account_id.clone())
        );
        assert_eq!(account_id.to_string(), account_id.as_str());
        assert_eq!(account_id.chain_id().as_str(), account_id.chain_id_str());
        assert!(!account_id.address().is_empty());
    }

    if let Ok(namespace_key) = NamespaceKey::parse(input) {
        assert_eq!(
            NamespaceKey::parse(namespace_key.as_str()),
            Ok(namespace_key)
        );
    }

    if let Ok(topic) = RelayTopic::from_hex(input) {
        assert_eq!(RelayTopic::from_hex(topic.as_str()), Ok(topic));
    }

    if let Ok(method) = SessionMethod::parse(input) {
        assert_eq!(SessionMethod::parse(method.as_str()), Ok(method));
    }

    if let Ok(event) = SessionEventName::parse(input) {
        assert_eq!(SessionEventName::parse(event.as_str()), Ok(event));
    }

    if let Ok(did) = DidPkh::parse(input) {
        assert_eq!(DidPkh::parse(did.as_str()), Ok(did));
    }

    if let Ok(hash) = VerifyAttestationHash::parse(input) {
        assert_eq!(VerifyAttestationHash::parse(hash.as_str()), Ok(hash));
    }
});
