use clap::{Parser, Subcommand};
use config::{Config, ConfigError};
use rpassword::read_password;
use rs_password_manager::{KeyDerivation, PasswordConfig, PasswordManager};
use serde::Deserialize;
use std::process;

#[derive(Parser)]
#[command(name = "Password Manager")]
#[command(about = "A secure password manager CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Deserialize, Debug)]
struct AppSettings {
    storage_path: String,
}

#[derive(Subcommand)]
enum Commands {
    Add {
        #[arg(short, long)]
        service: String,
        #[arg(short, long)]
        tags: Vec<String>,
        #[arg(short, long)]
        generate: bool,
    },
    Get {
        #[arg(short, long)]
        service: String,
    },
    List,
    Search {
        #[arg(short, long)]
        query: String,
    },
    Generate {
        #[arg(short, long, default_value = "16")]
        length: usize,
        #[arg(long, default_value = "true")]
        uppercase: bool,
        #[arg(long, default_value = "true")]
        lowercase: bool,
        #[arg(long, default_value = "true")]
        numbers: bool,
        #[arg(long, default_value = "true")]
        symbols: bool,
    },
    Export {
        #[arg(short, long)]
        output: String,
    },
    Import {
        #[arg(short, long)]
        input: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let settings: AppSettings = config().expect("Failed to retrieve appsettings");
    let password_manager = PasswordManager::new(settings.storage_path);

    match &cli.command {
        Commands::Add {
            service,
            tags,
            generate,
        } => {
            println!("Enter your master password:");
            let master_password = read_password().expect("Failed to read master password");
            let key = derive_key(&master_password);

            let password = if *generate {
                let generated = password_manager.generate_password(PasswordConfig::default());
                println!("Generated password: {}", &*generated);
                generated.to_string()
            } else {
                println!("Enter the password for {}: ", service);
                read_password().expect("Failed to read password")
            };

            match password_manager.add_password(service, &password, &key, tags.clone()) {
                Ok(_) => println!("Password for {} saved successfully.", service),
                Err(e) => {
                    eprintln!("Failed to save password: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Get { service } => {
            println!("Enter your master password:");
            let master_password = read_password().expect("Failed to read master password");
            let key = derive_key(&master_password);

            match password_manager.get_password(service, &key) {
                Ok(password) => println!("Password for {}: {}", service, &*password),
                Err(e) => {
                    eprintln!("Failed to retrieve password: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::List => match password_manager.list_services() {
            Ok(services) => {
                if services.is_empty() {
                    println!("No passwords stored.");
                } else {
                    println!("Stored passwords:");
                    for (service, tags) in services {
                        if tags.is_empty() {
                            println!("- {}", service);
                        } else {
                            println!("- {} (tags: {})", service, tags.join(", "));
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to list services: {}", e);
                process::exit(1);
            }
        },
        Commands::Search { query } => match password_manager.search_services(query) {
            Ok(services) => {
                if services.is_empty() {
                    println!("No matching services found.");
                } else {
                    println!("Matching services:");
                    for (service, tags) in services {
                        if tags.is_empty() {
                            println!("- {}", service);
                        } else {
                            println!("- {} (tags: {})", service, tags.join(", "));
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to search services: {}", e);
                process::exit(1);
            }
        },
        Commands::Generate {
            length,
            uppercase,
            lowercase,
            numbers,
            symbols,
        } => {
            let config = PasswordConfig {
                length: *length,
                use_uppercase: *uppercase,
                use_lowercase: *lowercase,
                use_numbers: *numbers,
                use_symbols: *symbols,
            };
            let password = password_manager.generate_password(config);
            println!("Generated password: {}", &*password);
        }
        Commands::Export { output } => {
            println!("Enter your master password:");
            let master_password = read_password().expect("Failed to read master password");
            let key = derive_key(&master_password);

            match password_manager.export_passwords(&key) {
                Ok(data) => {
                    std::fs::write(output, data).unwrap_or_else(|e| {
                        eprintln!("Failed to write export file: {}", e);
                        process::exit(1);
                    });
                    println!("Passwords exported successfully to {}", output);
                }
                Err(e) => {
                    eprintln!("Failed to export passwords: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Import { input } => {
            println!("Enter your master password:");
            let master_password = read_password().expect("Failed to read master password");
            let key = derive_key(&master_password);

            let data = std::fs::read_to_string(input).unwrap_or_else(|e| {
                eprintln!("Failed to read import file: {}", e);
                process::exit(1);
            });

            match password_manager.import_passwords(&data, &key) {
                Ok(_) => println!("Passwords imported successfully."),
                Err(e) => {
                    eprintln!("Failed to import passwords: {}", e);
                    process::exit(1);
                }
            }
        }
    }
}

fn derive_key(master_password: &str) -> Vec<u8> {
    let salt = KeyDerivation::generate_salt();
    KeyDerivation::derive_key(master_password.as_bytes(), &salt)
        .expect("Failed to derive key")
        .to_vec()
}

fn config() -> Result<AppSettings, ConfigError> {
    let settings = Config::builder()
        .add_source(config::File::with_name("Settings.toml"))
        .add_source(config::Environment::with_prefix("APP"))
        .build()?;

    settings.try_deserialize()
}
