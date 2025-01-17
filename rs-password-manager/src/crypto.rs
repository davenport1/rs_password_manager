use aes::{Aes256, BlockEncrypt, BlockDecrypt, NewBlockCipher};
use aes::cipher::generic_array::GenericArray;
use argon2::Argon2;
use rand::{Rng, thread_rng};
use zeroize::Zeroizing;

use crate::error::PasswordError;

const SALT_LENGTH: usize = 16;
const KEY_LENGTH: usize = 32;

pub struct KeyDerivation;

impl KeyDerivation {
    pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, PasswordError> {
        let argon2 = Argon2::default();
        let mut output_key_material = Zeroizing::new(vec![0u8; KEY_LENGTH]);
        
        argon2
            .hash_password_into(password, salt, &mut output_key_material)
            .map_err(|e| PasswordError::KeyDerivationError(e.to_string()))?;

        Ok(output_key_material)
    }

    pub fn generate_salt() -> Vec<u8> {
        let mut rng = thread_rng();
        let mut salt = vec![0u8; SALT_LENGTH];
        rng.fill(&mut salt[..]);
        salt
    }

    pub fn encrypt_password(password: &str, key: &[u8]) -> Result<Vec<u8>, PasswordError> {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(&pad_password(password));
        cipher.encrypt_block(&mut block);
        Ok(block.to_vec())
    }

    pub fn decrypt_password(encrypted: &[u8], key: &[u8]) -> Result<Zeroizing<String>, PasswordError> {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(encrypted);
        cipher.decrypt_block(&mut block);
        
        String::from_utf8(block.to_vec())
            .map(|s| Zeroizing::new(s.trim_end_matches('\0').to_string()))
            .map_err(|e| PasswordError::DecryptionError(e.to_string()))
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

    #[test]
    fn test_key_derivation() {
        let password = b"test_password";
        let salt = KeyDerivation::generate_salt();
        let key = KeyDerivation::derive_key(password, &salt).unwrap();
        assert_eq!(key.len(), KEY_LENGTH);
    }

    #[test]
    fn test_encryption_decryption() {
        let password = "test_password";
        let key = vec![0u8; KEY_LENGTH];
        
        let encrypted = KeyDerivation::encrypt_password(password, &key).unwrap();
        let decrypted = KeyDerivation::decrypt_password(&encrypted, &key).unwrap();
        
        assert_eq!(&*decrypted, password);
    }

    #[test]
    fn test_salt_generation() {
        let salt1 = KeyDerivation::generate_salt();
        let salt2 = KeyDerivation::generate_salt();
        
        assert_eq!(salt1.len(), SALT_LENGTH);
        assert_eq!(salt2.len(), SALT_LENGTH);
        assert_ne!(salt1, salt2);
    }
} 