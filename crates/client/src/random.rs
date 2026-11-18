use wallet_session_core::message::MessageId;

use crate::error::Result;

pub(crate) fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn id() -> Result<MessageId> {
    Ok(MessageId::from_bytes(bytes()?))
}
