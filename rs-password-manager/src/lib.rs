mod crypto;
mod error;
mod models;
mod storage;
mod validation;

pub use crypto::KeyDerivation;
pub use error::PasswordError;
pub use models::{PasswordConfig, ServiceCredential};
pub use validation::PasswordValidator;

use storage::CredentialStorage;
use zeroize::Zeroizing;

/// The main password manager struct that provides all password management functionality.
pub struct PasswordManager {
    storage: CredentialStorage,
    validator: PasswordValidator,
}

impl PasswordManager {
    /// Creates a new password manager instance.
    ///
    /// # Arguments
    /// * `storage_path` - Path to the file where passwords will be stored
    pub fn new(storage_path: String) -> Self {
        PasswordManager {
            storage: CredentialStorage::new(storage_path),
            validator: PasswordValidator::new(),
        }
    }

    /// Adds or updates a password for a service.
    ///
    /// # Arguments
    /// * `service` - Name of the service
    /// * `password` - Password to store
    /// * `master_key` - Master key used for encryption
    /// * `tags` - Optional tags for organizing passwords
    ///
    /// # Returns
    /// * `Ok(())` if successful
    /// * `Err(PasswordError)` if validation or storage fails
    pub fn add_password(
        &self,
        service: &str,
        password: &str,
        master_key: &[u8],
        tags: Vec<String>,
    ) -> Result<(), PasswordError> {
        // Validate the password
        self.validator.validate_password(password)?;

        // Store the password
        self.storage.add_credential(service, password, master_key, tags)
    }

    /// Retrieves a password for a service.
    ///
    /// # Arguments
    /// * `service` - Name of the service
    /// * `master_key` - Master key used for decryption
    ///
    /// # Returns
    /// * `Ok(String)` containing the password if successful
    /// * `Err(PasswordError)` if retrieval fails
    pub fn get_password(&self, service: &str, master_key: &[u8]) -> Result<Zeroizing<String>, PasswordError> {
        self.storage.get_credential(service, master_key)
    }

    /// Lists all stored services and their tags.
    pub fn list_services(&self) -> Result<Vec<(String, Vec<String>)>, PasswordError> {
        self.storage.list_services()
    }

    /// Searches for services by name or tags.
    ///
    /// # Arguments
    /// * `query` - Search query to match against service names or tags
    pub fn search_services(&self, query: &str) -> Result<Vec<(String, Vec<String>)>, PasswordError> {
        self.storage.search_services(query)
    }

    /// Generates a secure random password.
    ///
    /// # Arguments
    /// * `config` - Configuration for password generation
    pub fn generate_password(&self, config: PasswordConfig) -> Zeroizing<String> {
        self.validator.generate_password(config)
    }

    /// Exports all passwords in an encrypted format.
    ///
    /// # Arguments
    /// * `master_key` - Master key used for encryption
    pub fn export_passwords(&self, master_key: &[u8]) -> Result<String, PasswordError> {
        self.storage.export_credentials(master_key)
    }

    /// Imports passwords from an encrypted export.
    ///
    /// # Arguments
    /// * `export_data` - Exported data string
    /// * `master_key` - Master key used for decryption
    pub fn import_passwords(&self, export_data: &str, master_key: &[u8]) -> Result<(), PasswordError> {
        self.storage.import_credentials(export_data, master_key)
    }
} 