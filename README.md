# rs_password_manager

[![CI](https://github.com/yourusername/rs_password_manager/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/rs_password_manager/actions/workflows/ci.yml)
[![Security Audit](https://github.com/yourusername/rs_password_manager/actions/workflows/audit.yml/badge.svg)](https://github.com/yourusername/rs_password_manager/actions/workflows/audit.yml)
[![codecov](https://codecov.io/gh/yourusername/rs_password_manager/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/rs_password_manager)

A secure command-line password manager written in Rust. This project provides both a library for password management and a CLI tool for easy interaction.

## Features

- Secure password encryption using AES-256
- Command-line interface for easy password management
- Simple JSON-based storage
- Configurable storage location
- Library crate for integration into other Rust projects
- Password generation with configurable options
- Tag-based organization
- Export/import functionality
- Secure memory handling with automatic wiping

## Security Features

- AES-256 encryption for passwords
- Argon2 key derivation
- Per-password salts
- Secure memory wiping using zeroize
- Regular security audits
- Password strength validation

## Installation

### From Release

Download the latest release for your platform from the [releases page](https://github.com/yourusername/rs_password_manager/releases).

### From Source

```bash
git clone https://github.com/yourusername/rs_password_manager.git
cd rs_password_manager
cargo install --path rs-password-manager-cli
```

## Usage

### CLI Tool

The password manager provides several commands:

1. Adding a password:
```bash
password_manager add --service <service_name> [--tags <tag1,tag2>] [--generate]
```

2. Retrieving a password:
```bash
password_manager get --service <service_name>
```

3. Listing all services:
```bash
password_manager list
```

4. Searching services:
```bash
password_manager search --query <search_term>
```

5. Generating a password:
```bash
password_manager generate [--length <length>] [--no-uppercase] [--no-lowercase] [--no-numbers] [--no-symbols]
```

6. Export/Import:
```bash
password_manager export --output passwords.export
password_manager import --input passwords.export
```

### Configuration

The application uses a `Settings.toml` file for configuration:

```toml
storage_path = "passwords.json"  # Path where passwords will be stored
```

You can also use environment variables with the `APP_` prefix:
```bash
export APP_STORAGE_PATH="/path/to/passwords.json"
```

### Library Usage

To use rs_password_manager as a library in your Rust project:

```toml
[dependencies]
rs-password-manager = "0.1.0"
```

Example code:

```rust
use rs_password_manager::{PasswordManager, PasswordConfig, KeyDerivation};

fn main() {
    let manager = PasswordManager::new("passwords.json".to_string());
    
    // Generate a password
    let config = PasswordConfig::default();
    let password = manager.generate_password(config);
    
    // Add a password
    let master_key = KeyDerivation::derive_key(b"master_password", &KeyDerivation::generate_salt())
        .expect("Failed to derive key");
    
    manager.add_password(
        "example.com",
        &password,
        &master_key,
        vec!["email".to_string()]
    ).expect("Failed to add password");
}
```

## Development

### Running Tests

```bash
cargo test --workspace
```

### Security Audit

```bash
cargo audit
```

### Code Coverage

```bash
cargo llvm-cov --workspace --lcov --output-path lcov.info
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate and adhere to the existing code style.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
