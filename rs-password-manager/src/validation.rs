use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use rand::prelude::IteratorRandom;
use zeroize::Zeroizing;

use crate::error::PasswordError;
use crate::models::PasswordConfig;

pub struct PasswordValidator {
    min_length: usize,
    require_uppercase: bool,
    require_lowercase: bool,
    require_numbers: bool,
    require_symbols: bool,
}

impl Default for PasswordValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordValidator {
    pub fn new() -> Self {
        PasswordValidator {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_symbols: false,
        }
    }

    pub fn validate_password(&self, password: &str) -> Result<(), PasswordError> {
        if password.len() < self.min_length {
            return Err(PasswordError::InvalidPassword(
                format!("Password must be at least {} characters long", self.min_length)
            ));
        }

        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_number = password.chars().any(|c| c.is_numeric());
        let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

        let mut requirements = Vec::new();

        if self.require_uppercase && !has_uppercase {
            requirements.push("uppercase letter");
        }
        if self.require_lowercase && !has_lowercase {
            requirements.push("lowercase letter");
        }
        if self.require_numbers && !has_number {
            requirements.push("number");
        }
        if self.require_symbols && !has_symbol {
            requirements.push("special character");
        }

        if !requirements.is_empty() {
            return Err(PasswordError::InvalidPassword(
                format!("Password must contain: {}", requirements.join(", "))
            ));
        }

        Ok(())
    }

    pub fn generate_password(&self, config: PasswordConfig) -> Zeroizing<String> {
        let mut rng = thread_rng();
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
        let mut chars = Vec::new();
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

        // Fill remaining length with random characters
        while password.len() < config.length {
            password.push(chars[rng.gen_range(0..chars.len())]);
        }

        // Shuffle the password to randomize character positions
        let mut chars: Vec<char> = password.chars().collect();
        chars.shuffle(&mut rng);
        Zeroizing::new(chars.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_validation() {
        let validator = PasswordValidator::new();

        // Test weak passwords
        assert!(validator.validate_password("weak").is_err());
        assert!(validator.validate_password("password").is_err());
        assert!(validator.validate_password("12345678").is_err());
        assert!(validator.validate_password("UPPERCASE").is_err());

        // Test strong passwords
        assert!(validator.validate_password("StrongP@ssw0rd").is_ok());
        assert!(validator.validate_password("C0mpl3x!Pass").is_ok());
    }

    #[test]
    fn test_password_generation() {
        let validator = PasswordValidator::new();
        let config = PasswordConfig {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
        };

        let password = validator.generate_password(config);
        
        assert_eq!(password.len(), 16);
        assert!(password.chars().any(|c| c.is_uppercase()));
        assert!(password.chars().any(|c| c.is_lowercase()));
        assert!(password.chars().any(|c| c.is_numeric()));
        assert!(password.chars().any(|c| !c.is_alphanumeric()));
    }

    #[test]
    fn test_generated_password_validation() {
        let validator = PasswordValidator::new();
        let config = PasswordConfig::default();

        let password = validator.generate_password(config);
        assert!(validator.validate_password(&password).is_ok());
    }
} 