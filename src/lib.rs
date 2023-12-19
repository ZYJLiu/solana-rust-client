use solana_sdk::signer::keypair::Keypair;
use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;

// Get or create a keypair from an .env file
pub fn get_or_create_keypair(variable_name: &str) -> Result<Keypair, Box<dyn Error>> {
    dotenv::dotenv().ok();

    match env::var(variable_name) {
        Ok(secret_key_string) => {
            // Fallback to JSON format
            let decoded_secret_key: Vec<u8> = serde_json::from_str(&secret_key_string)?;
            Ok(Keypair::from_bytes(&decoded_secret_key)?)
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
