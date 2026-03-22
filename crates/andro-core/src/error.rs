use thiserror::Error;

#[derive(Debug, Error)]
pub enum AndroError {
    #[error("no devices connected")]
    NoDevices,

    #[error("device not found: {0}")]
    DeviceNotFound(String),

    #[error("multiple devices connected, specify --device")]
    MultipleDevices,

    #[error("adb error: {0}")]
    Adb(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AndroError>;
