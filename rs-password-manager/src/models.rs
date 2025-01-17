use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceCredential {
    pub service_name: String,
    pub encrypted_password: Vec<u8>,
    pub salt: Vec<u8>,
    pub tags: Vec<String>,
    #[serde(default)]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Drop for ServiceCredential {
    fn drop(&mut self) {
        self.encrypted_password.zeroize();
        self.salt.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct PasswordConfig {
    pub length: usize,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_numbers: bool,
    pub use_symbols: bool,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        PasswordConfig {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ExportData {
    pub version: u8,
    pub credentials: Vec<ServiceCredential>,
    pub checksum: String,
}

impl Drop for ExportData {
    fn drop(&mut self) {
        self.credentials.clear();
        self.checksum.zeroize();
    }
}
