use thiserror::Error;

#[derive(Error, Debug)]
pub enum CapError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("toml serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("cbor encode error: {0}")]
    CborEncode(String),

    #[error("cbor decode error: {0}")]
    CborDecode(String),

    #[error("signature error: {0}")]
    Signature(String),

    #[error("invalid cap: {0}")]
    Invalid(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("missing entrypoint: {0}")]
    MissingEntrypoint(String),
}

pub type Result<T> = std::result::Result<T, CapError>;
