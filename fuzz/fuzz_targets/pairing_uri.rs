#![no_main]

use libfuzzer_sys::fuzz_target;
use wc_protocol::pairing::PairingUri;

const MAX_INPUT_BYTES: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(uri) = PairingUri::parse(input) {
        assert_eq!(uri.version().as_u32(), 2);
        assert_eq!(uri.topic().as_str().len(), 64);
        assert_eq!(uri.sym_key().as_str().len(), 64);
        assert_eq!(uri.relay().protocol(), "irn");

        let sym_key_bytes = uri.sym_key().to_bytes();
        assert_eq!(
            wc_protocol::pairing::PairingSymKey::from_bytes(sym_key_bytes),
            *uri.sym_key()
        );

        if let Some(methods) = uri.methods() {
            assert!(methods.iter().all(|method| !method.is_empty()));
        }
    }
});
