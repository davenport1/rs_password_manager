use std::fs::OpenOptions;
use std::io::Write;

use serde::{Serialize, Deserialize};
use config::{Config, ConfigError};
use aes::{Aes256, cipher::generic_array::GenericArray, NewBlockCipher, BlockEncrypt, BlockDecrypt};
use clap::{Parser, Subcommand, error::Result};
use rpassword::read_password;

#[derive(Parser)]
#[command(name = "Password Manager")]
#[command(about = "A simple password manager CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Serialize, Deserialize, Debug)]
struct ServiceModel {
    service_name: String,
    encrypted_password: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AppSettings {
    file_name: String,
}

#[derive(Subcommand)]
enum Commands {
    Add {
        #[arg(short, long)]
        service: String,
    },
    Get {
        #[arg(short, long)]
        service: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let settings: AppSettings = config().expect("Failed to retrieve appsettings");

    match &cli.command {
        Commands::Add { service } => {
            add_password(service, settings);
        }
        Commands::Get { service } => {
            println!("Retrieving password for service: {}", service);
            get_password(service, settings);
        }
    }
}

fn add_password(service: &str, settings: AppSettings) {
    println!("Enter your master password");
    let master_password = read_password().expect("Failed to read master password");

    let key: [u8; 32] = master_password
        .as_bytes()
        .iter()
        .cloned()
        .collect::<Vec<u8>>()[0..32]
        .try_into()
        .unwrap();

    println!("Enter the password for {}: ", service);
    let password = read_password().expect("Failed to read password");

    let encrypted_password = encrypt_password(&password, &key);

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("passwords.json")
        .expect("Failed to open file");

    writeln!(file, "{}: {:?}", service, encrypted_password).expect("Failed to write to file");

    println!("Password for {} saved.", service)
}

fn get_password(service: &str, settings: AppSettings) {
    println!("Enter your master password");
    let master_password = read_password().expect("Failed to read master password");

    let key: [u8; 32] = master_password
        .as_bytes()
        .iter()
        .cloned()
        .collect::<Vec<u8>>()[0..32]
        .try_into()
        .unwrap();

    let encrypted_password = vec![];

    let password = decrypt_password(encrypted_password, &key);

    println!("Password for {}: {}", service, password);
}

fn decrypt_password(encrypted_password: Vec<u8>, key: &[u8]) -> String {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(&encrypted_password);

    cipher.decrypt_block(&mut block);

    String::from_utf8(block.to_vec()).unwrap()
}

fn encrypt_password(password: &str, key: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(password.as_bytes());

    cipher.encrypt_block(&mut block);

    block.to_vec()
}

fn config() -> Result<AppSettings, ConfigError> {
    let settings = Config::builder()
        .add_source(config::File::with_name("./Settings.toml"))
        .add_source(config::Environment::with_prefix("APP"))
        .build()?;

    let config = settings.try_deserialize::<AppSettings>()?;
    Ok(config)
}
