#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("packet too short")]
    Truncated,
    #[error("authentication failed")]
    Auth,
    #[error("malformed frame")]
    MalformedFrame,
    #[error("unknown frame type {0:#04x}")]
    UnknownFrame(u8),
    #[error("malformed ip packet")]
    MalformedIp,
    #[error("malformed fragment")]
    MalformedFragment,
    #[error("invalid key encoding")]
    InvalidKey,
    #[error("malformed handshake payload")]
    MalformedHello,
    #[error("unsupported protocol version {0}")]
    Version(u8),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
}
