use std::fs::{OpenOptions, File};
use std::io::{Write, BufReader, BufRead};
use std::path::Path;
use std::fmt;

use serde::{Serialize, Deserialize};
use aes::{Aes256, cipher::generic_array::GenericArray, NewBlockCipher, BlockEncrypt, BlockDecrypt};
use rand::{Rng, distributions::{Alphanumeric, Distribution}};
use rand::seq::SliceRandom;
use rand::prelude::IteratorRandom;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ServiceCredential {
    pub service_name: String,
    pub encrypted_password: Vec<u8>,
    pub salt: Vec<u8>,
    pub tags: Vec<String>,
}

#[derive(Debug)]
pub enum PasswordError {
    IoError(std::io::Error),
    SerializationError(String),
    DecryptionError(String),
    EncryptionError(String),
    ServiceNotFound,
    InvalidPassword(String),
}

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

impl From<std::io::Error> for PasswordError {
    fn from(error: std::io::Error) -> Self {
        PasswordError::IoError(error)
    }
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordError::IoError(e) => write!(f, "IO error: {}", e),
            PasswordError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            PasswordError::DecryptionError(e) => write!(f, "Decryption error: {}", e),
            PasswordError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            PasswordError::ServiceNotFound => write!(f, "Service not found"),
            PasswordError::InvalidPassword(e) => write!(f, "Invalid password: {}", e),
        }
    }
}

pub struct PasswordManager {
    storage_path: String,
}

impl PasswordManager {
    pub fn new(storage_path: String) -> Self {
        PasswordManager { storage_path }
    }

    pub fn add_password(&self, service: &str, password: &str, master_key: &[u8], tags: Vec<String>) -> Result<(), PasswordError> {
        self.validate_password(password)?;

        let salt = self.generate_salt();
        
        let encryption_key = self.derive_key(master_key, &salt);

        let encrypted_password = self.encrypt_password(password, &encryption_key)
            .map_err(|e| PasswordError::EncryptionError(e.to_string()))?;

        let credential = ServiceCredential {
            service_name: service.to_string(),
            encrypted_password,
            salt,
            tags,
        };

        let mut credentials = self.load_credentials()?;
        credentials.retain(|c| c.service_name != service);
        credentials.push(credential);

        self.save_credentials(&credentials)?;
        Ok(())
    }

    pub fn get_password(&self, service: &str, master_key: &[u8]) -> Result<String, PasswordError> {
        let credentials = self.load_credentials()?;
        
        let credential = credentials
            .iter()
            .find(|c| c.service_name == service)
            .ok_or(PasswordError::ServiceNotFound)?;

        let encryption_key = self.derive_key(master_key, &credential.salt);

        self.decrypt_password(&credential.encrypted_password, &encryption_key)
            .map_err(|e| PasswordError::DecryptionError(e.to_string()))
    }

    pub fn list_services(&self) -> Result<Vec<(String, Vec<String>)>, PasswordError> {
        let credentials = self.load_credentials()?;
        Ok(credentials.iter()
            .map(|c| (c.service_name.clone(), c.tags.clone()))
            .collect())
    }

    pub fn search_services(&self, query: &str) -> Result<Vec<(String, Vec<String>)>, PasswordError> {
        let credentials = self.load_credentials()?;
        Ok(credentials.iter()
            .filter(|c| c.service_name.to_lowercase().contains(&query.to_lowercase()) ||
                       c.tags.iter().any(|t| t.to_lowercase().contains(&query.to_lowercase())))
            .map(|c| (c.service_name.clone(), c.tags.clone()))
            .collect())
    }

    pub fn generate_password(&self, config: PasswordConfig) -> String {
        let mut rng = rand::thread_rng();
        let mut password = String::new();
        
        // Ensure at least one character of each required type
        if config.use_uppercase {
            password.push(('A'..='Z').choose(&mut rng).unwrap());
        }
        if config.use_lowercase {
            password.push(('a'..='z').choose(&mut rng).unwrap());
        }
        if config.use_numbers {
            password.push(('0'..='9').choose(&mut rng).unwrap());
        }
        if config.use_symbols {
            password.push("!@#$%^&*()_+-=[]{}|;:,.<>?".chars().choose(&mut rng).unwrap());
        }

        // Build character set for remaining characters
        let mut chars: Vec<char> = Vec::new();
        if config.use_uppercase {
            chars.extend('A'..='Z');
        }
        if config.use_lowercase {
            chars.extend('a'..='z');
        }
        if config.use_numbers {
            chars.extend('0'..='9');
        }
        if config.use_symbols {
            chars.extend("!@#$%^&*()_+-=[]{}|;:,.<>?".chars());
        }

        // If no character types selected, use alphanumeric
        if chars.is_empty() {
            for _ in 0..config.length {
                password.push(char::from(Alphanumeric.sample(&mut rng)));
            }
        } else {
            // Fill remaining length with random characters
            while password.len() < config.length {
                password.push(chars[rng.gen_range(0..chars.len())]);
            }

            // Shuffle the password to randomize character positions
            let mut chars: Vec<char> = password.chars().collect();
            chars.shuffle(&mut rng);
            password = chars.into_iter().collect();
        }

        password
    }

    fn validate_password(&self, password: &str) -> Result<(), PasswordError> {
        if password.len() < 8 {
            return Err(PasswordError::InvalidPassword("Password must be at least 8 characters long".to_string()));
        }

        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_number = password.chars().any(|c| c.is_numeric());

        if !(has_uppercase && has_lowercase && has_number) {
            return Err(PasswordError::InvalidPassword(
                "Password must contain uppercase, lowercase, and numbers".to_string()
            ));
        }

        Ok(())
    }

    fn generate_salt(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut salt = vec![0u8; 16];
        rng.fill(&mut salt[..]);
        salt
    }

    fn derive_key(&self, master_key: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut key = master_key.to_vec();
        key.extend_from_slice(salt);
        key[..32].to_vec()
    }

    fn encrypt_password(&self, password: &str, key: &[u8]) -> Result<Vec<u8>, PasswordError> {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(&pad_password(password));
        cipher.encrypt_block(&mut block);
        Ok(block.to_vec())
    }

    fn decrypt_password(&self, encrypted_password: &[u8], key: &[u8]) -> Result<String, PasswordError> {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(encrypted_password);
        cipher.decrypt_block(&mut block);
        
        String::from_utf8(block.to_vec())
            .map(|s| s.trim_end_matches('\0').to_string())
            .map_err(|e| PasswordError::DecryptionError(e.to_string()))
    }

    fn load_credentials(&self) -> Result<Vec<ServiceCredential>, PasswordError> {
        if !Path::new(&self.storage_path).exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.storage_path)?;
        let reader = BufReader::new(file);
        let mut credentials = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                let credential: ServiceCredential = serde_json::from_str(&line)
                    .map_err(|e| PasswordError::SerializationError(e.to_string()))?;
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }

    fn save_credentials(&self, credentials: &[ServiceCredential]) -> Result<(), PasswordError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.storage_path)?;

        for credential in credentials {
            let json = serde_json::to_string(credential)
                .map_err(|e| PasswordError::SerializationError(e.to_string()))?;
            writeln!(file, "{}", json)?;
        }

        Ok(())
    }
}

fn pad_password(password: &str) -> [u8; 16] {
    let mut padded = [0u8; 16];
    let bytes = password.as_bytes();
    let len = bytes.len().min(16);
    padded[..len].copy_from_slice(&bytes[..len]);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_manager() -> (PasswordManager, NamedTempFile) {
        let temp_file = NamedTempFile::new().unwrap();
        let manager = PasswordManager::new(temp_file.path().to_str().unwrap().to_string());
        (manager, temp_file)
    }

    #[test]
    fn test_add_and_get_password() {
        let (manager, _temp_file) = create_test_manager();
        let master_key = b"0123456789abcdef0123456789abcdef";
        
        manager.add_password("test_service", "TestPass123!", master_key, vec![]).unwrap();
        let retrieved = manager.get_password("test_service", master_key).unwrap();
        
        assert_eq!(retrieved, "TestPass123!");
    }

    #[test]
    fn test_service_not_found() {
        let (manager, _temp_file) = create_test_manager();
        let master_key = b"0123456789abcdef0123456789abcdef";
        
        let result = manager.get_password("nonexistent", master_key);
        assert!(matches!(result, Err(PasswordError::ServiceNotFound)));
    }

    #[test]
    fn test_update_existing_password() {
        let (manager, _temp_file) = create_test_manager();
        let master_key = b"0123456789abcdef0123456789abcdef";
        
        manager.add_password("test_service", "OldPass123!", master_key, vec![]).unwrap();
        manager.add_password("test_service", "NewPass123!", master_key, vec![]).unwrap();
        
        let retrieved = manager.get_password("test_service", master_key).unwrap();
        assert_eq!(retrieved, "NewPass123!");
    }

    #[test]
    fn test_multiple_passwords() {
        let (manager, _temp_file) = create_test_manager();
        let master_key = b"0123456789abcdef0123456789abcdef";
        
        manager.add_password("service1", "Pass123One!", master_key, vec![]).unwrap();
        manager.add_password("service2", "Pass123Two!", master_key, vec![]).unwrap();
        
        assert_eq!(manager.get_password("service1", master_key).unwrap(), "Pass123One!");
        assert_eq!(manager.get_password("service2", master_key).unwrap(), "Pass123Two!");
    }

    #[test]
    fn test_password_generation() {
        let (manager, _) = create_test_manager();
        let config = PasswordConfig {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
        };

        let password = manager.generate_password(config);
        assert_eq!(password.len(), 16);
        assert!(password.chars().any(|c| c.is_uppercase()));
        assert!(password.chars().any(|c| c.is_lowercase()));
        assert!(password.chars().any(|c| c.is_numeric()));
        assert!(password.chars().any(|c| !c.is_alphanumeric()));
    }

    #[test]
    fn test_password_validation() {
        let (manager, _) = create_test_manager();
        
        // Test weak password
        assert!(matches!(
            manager.validate_password("weak"),
            Err(PasswordError::InvalidPassword(_))
        ));

        // Test strong password
        assert!(manager.validate_password("StrongP@ssw0rd").is_ok());
    }

    #[test]
    fn test_search_services() {
        let (manager, _) = create_test_manager();
        let master_key = b"0123456789abcdef0123456789abcdef";
        
        manager.add_password("gmail.com", "GmailPass123!", master_key, vec!["email".to_string()]).unwrap();
        manager.add_password("github.com", "GitHubPass123!", master_key, vec!["dev".to_string()]).unwrap();
        
        let results = manager.search_services("mail").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "gmail.com");
        
        let results = manager.search_services("dev").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "github.com");
    }
} 