#![no_main]

use libfuzzer_sys::fuzz_target;
use wc_protocol::{
    envelope::{Envelope, EnvelopeEncoding, EnvelopeType},
    pairing::PairingSymKey,
};

const MAX_INPUT_BYTES: usize = 8192;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    for encoding in [EnvelopeEncoding::Base64, EnvelopeEncoding::Base64Url] {
        let Ok(envelope) = Envelope::decode(input, encoding) else {
            continue;
        };

        let encoded = envelope.encode(encoding);
        let reparsed = Envelope::decode(&encoded, encoding)
            .expect("encoded envelope should decode with the same encoding");
        assert_eq!(reparsed.envelope_type(), envelope.envelope_type());
        assert_eq!(reparsed.iv(), envelope.iv());
        assert_eq!(reparsed.sealed(), envelope.sealed());
        assert_eq!(reparsed.sender_public_key(), envelope.sender_public_key());

        match envelope.envelope_type() {
            EnvelopeType::Type0 | EnvelopeType::Type1 => {
                let key = PairingSymKey::from_bytes([0x42; 32]);
                let _ = envelope.decrypt(&key);
            }
            EnvelopeType::Type2 => {
                let _ = envelope.plaintext();
            }
        }
    }
});
