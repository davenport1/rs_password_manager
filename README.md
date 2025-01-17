# rs_password_manager

A secure command-line password manager written in Rust. This project provides both a library for password management and a CLI tool for easy interaction.

## Features

- Secure password encryption using AES-256
- Command-line interface for easy password management
- Simple JSON-based storage
- Configurable storage location
- Library crate for integration into other Rust projects

## Installation

### From Source

```bash
git clone https://github.com/yourusername/rs_password_manager.git
cd rs_password_manager
cargo install --path .
```

## Usage

### CLI Tool

The password manager provides two main commands:

1. Adding a password:
```bash
password_manager add --service <service_name>
```

2. Retrieving a password:
```bash
password_manager get --service <service_name>
```

For both commands, you'll be prompted to enter your master password. This master password is used to encrypt and decrypt your stored passwords.

### Configuration

The application uses a `Settings.toml` file for configuration. You can specify:

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
rs_password_manager = "0.1.0"
```

Example code:

```rust
use rs_password_manager::PasswordManager;

fn main() {
    let manager = PasswordManager::new("passwords.json".to_string());
    
    // Add a password
    let master_key = [0u8; 32]; // Replace with your key derivation
    manager.add_password("example.com", "mypassword", &master_key).unwrap();
    
    // Retrieve a password
    let password = manager.get_password("example.com", &master_key).unwrap();
    println!("Password: {}", password);
}
```

## Security Notes

- The master password is used to derive the encryption key
- Passwords are encrypted using AES-256
- The storage file contains encrypted passwords only
- It's recommended to use a strong master password

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
