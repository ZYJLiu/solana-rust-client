use solana_sdk::{bs58, signer::keypair::Keypair};
use spl_token_client::client::RpcClientResponse;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;

// Get or create a keypair from an .env file
pub fn get_or_create_keypair(variable_name: &str) -> Result<Keypair, Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    match env::var(variable_name) {
        Ok(secret_key_string) => {
            // Try to decode base58 first
            if let Ok(decoded_secret_key) = bs58::decode(&secret_key_string).into_vec() {
                Ok(Keypair::from_bytes(&decoded_secret_key)?)
            } else {
                // Fallback to JSON format
                let decoded_secret_key: Vec<u8> = serde_json::from_str(&secret_key_string)?;
                Ok(Keypair::from_bytes(&decoded_secret_key)?)
            }
        }
        Err(_) => {
            // Create a new keypair if the environment variable is not found
            let keypair = Keypair::new();

            // Convert secret key to Vec<u8> and then to JSON, append to .env file
            let secret_key_bytes = Vec::from(keypair.to_bytes());
            let json_secret_key = serde_json::to_string(&secret_key_bytes)?;

            // Open .env file, create it if it does not exist
            let mut file = OpenOptions::new().append(true).create(true).open(".env")?;

            writeln!(file, "{}={}", variable_name, json_secret_key)?;

            Ok(keypair)
        }
    }
}

pub fn print_transaction_link(response: RpcClientResponse, message: &str) {
    match response {
        RpcClientResponse::Signature(signature) => {
            println!(
                "\n{}: https://solana.fm/tx/{}?cluster=localnet-solana",
                message, signature
            );
        }
        _ => println!("Signature not found in response"),
    }
}
