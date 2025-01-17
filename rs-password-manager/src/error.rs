use thiserror::Error;

#[derive(Error, Debug)]
pub enum PasswordError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Service not found")]
    ServiceNotFound,

    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),

    #[error("Export error: {0}")]
    ExportError(String),

    #[error("Import error: {0}")]
    ImportError(String),

    #[error("Invalid master key")]
    InvalidMasterKey,
}

impl From<serde_json::Error> for PasswordError {
    fn from(error: serde_json::Error) -> Self {
        PasswordError::SerializationError(error.to_string())
    }
}

impl From<base64::DecodeError> for PasswordError {
    fn from(error: base64::DecodeError) -> Self {
        PasswordError::ImportError(error.to_string())
    }
}

impl From<argon2::Error> for PasswordError {
    fn from(error: argon2::Error) -> Self {
        PasswordError::KeyDerivationError(error.to_string())
    }
} 