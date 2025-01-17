use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use chrono::Utc;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use zeroize::Zeroizing;

use crate::crypto::KeyDerivation;
use crate::error::PasswordError;
use crate::models::{ServiceCredential, ExportData};

pub struct CredentialStorage {
    storage_path: String,
}

impl CredentialStorage {
    pub fn new(storage_path: String) -> Self {
        CredentialStorage { storage_path }
    }

    pub fn add_credential(
        &self,
        service: &str,
        password: &str,
        master_key: &[u8],
        tags: Vec<String>,
    ) -> Result<(), PasswordError> {
        let mut credentials = self.load_credentials()?;
        let salt = KeyDerivation::generate_salt();
        let key = KeyDerivation::derive_key(master_key, &salt)?;
        
        let encrypted_password = KeyDerivation::encrypt_password(password, &key)?;
        
        let now = Utc::now();
        let credential = ServiceCredential {
            service_name: service.to_string(),
            encrypted_password,
            salt,
            tags,
            created_at: Some(now),
            updated_at: Some(now),
        };

        // Update or add new credential
        if let Some(pos) = credentials.iter().position(|c| c.service_name == service) {
            credentials[pos] = credential;
        } else {
            credentials.push(credential);
        }

        self.save_credentials(&credentials)
    }

    pub fn get_credential(&self, service: &str, master_key: &[u8]) -> Result<Zeroizing<String>, PasswordError> {
        let credentials = self.load_credentials()?;
        
        let credential = credentials
            .iter()
            .find(|c| c.service_name == service)
            .ok_or(PasswordError::ServiceNotFound)?;

        let key = KeyDerivation::derive_key(master_key, &credential.salt)?;
        KeyDerivation::decrypt_password(&credential.encrypted_password, &key)
    }

    pub fn list_services(&self) -> Result<Vec<(String, Vec<String>)>, PasswordError> {
        let credentials = self.load_credentials()?;
        Ok(credentials
            .into_iter()
            .map(|c| (c.service_name.clone(), c.tags.clone()))
            .collect())
    }

    pub fn search_services(&self, query: &str) -> Result<Vec<(String, Vec<String>)>, PasswordError> {
        let credentials = self.load_credentials()?;
        let query = query.to_lowercase();
        
        Ok(credentials
            .into_iter()
            .filter(|c| {
                c.service_name.to_lowercase().contains(&query) ||
                c.tags.iter().any(|t| t.to_lowercase().contains(&query))
            })
            .map(|c| (c.service_name.clone(), c.tags.clone()))
            .collect())
    }

    pub fn export_credentials(&self, _master_key: &[u8]) -> Result<String, PasswordError> {
        let credentials = self.load_credentials()?;
        let export_data = ExportData {
            version: 1,
            credentials,
            checksum: "".to_string(), // TODO: Implement checksum
        };

        let json = serde_json::to_string(&export_data)?;
        Ok(BASE64.encode(json))
    }

    pub fn import_credentials(&self, export_data: &str, _master_key: &[u8]) -> Result<(), PasswordError> {
        let json = BASE64.decode(export_data)?;
        let json = String::from_utf8(json)
            .map_err(|e| PasswordError::ImportError(e.to_string()))?;
        
        let data: ExportData = serde_json::from_str(&json)?;
        
        // TODO: Verify checksum
        
        self.save_credentials(&data.credentials)
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
                let credential: ServiceCredential = serde_json::from_str(&line)?;
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
            let json = serde_json::to_string(credential)?;
            writeln!(file, "{}", json)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_storage() -> (CredentialStorage, NamedTempFile) {
        let temp_file = NamedTempFile::new().unwrap();
        let storage = CredentialStorage::new(temp_file.path().to_str().unwrap().to_string());
        (storage, temp_file)
    }

    #[test]
    fn test_add_and_get_credential() {
        let (storage, _temp_file) = create_test_storage();
        let master_key = b"test_master_key";
        let password = "TestPass123!";
        
        storage.add_credential("test_service", password, master_key, vec![])
            .unwrap();
            
        let retrieved = storage.get_credential("test_service", master_key).unwrap();
        assert_eq!(&*retrieved, password);
    }

    #[test]
    fn test_update_credential() {
        let (storage, _temp_file) = create_test_storage();
        let master_key = b"test_master_key";
        
        storage.add_credential("test_service", "OldPass123!", master_key, vec![])
            .unwrap();
        storage.add_credential("test_service", "NewPass123!", master_key, vec![])
            .unwrap();
            
        let retrieved = storage.get_credential("test_service", master_key).unwrap();
        assert_eq!(&*retrieved, "NewPass123!");
    }

    #[test]
    fn test_export_import() {
        let (storage, _temp_file) = create_test_storage();
        let master_key = b"test_master_key";
        let password = "TestPass123!";
        
        storage.add_credential("test_service", password, master_key, vec!["tag1".to_string()])
            .unwrap();
            
        let export_data = storage.export_credentials(master_key).unwrap();
        
        // Create new storage
        let (new_storage, _temp_file) = create_test_storage();
        new_storage.import_credentials(&export_data, master_key).unwrap();
        
        let retrieved = new_storage.get_credential("test_service", master_key).unwrap();
        assert_eq!(&*retrieved, password);
    }

    #[test]
    fn test_search_with_tags() {
        let (storage, _temp_file) = create_test_storage();
        let master_key = b"test_master_key";
        
        storage.add_credential("email1", "Pass123!", master_key, vec!["email".to_string()])
            .unwrap();
        storage.add_credential("email2", "Pass123!", master_key, vec!["email".to_string()])
            .unwrap();
        storage.add_credential("other", "Pass123!", master_key, vec!["other".to_string()])
            .unwrap();
            
        let results = storage.search_services("email").unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, tags)| tags.contains(&"email".to_string())));
    }
} 