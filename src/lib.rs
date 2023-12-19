use solana_sdk::signer::keypair::Keypair;
use std::env;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

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

// pub fn save_keypair(keypair: &Keypair, variable_name: &str) -> Result<(), Box<dyn Error>> {
//     let secret_key_bytes = Vec::from(keypair.to_bytes());
//     let json_secret_key = serde_json::to_string(&secret_key_bytes)?;

//     let mut contents = String::new();
//     let file_path = ".env";

//     // Read the current .env file if it exists
//     if let Ok(mut file) = File::open(file_path) {
//         file.read_to_string(&mut contents)?;
//     }

//     // Split the contents into lines and process them
//     let lines: Vec<String> = contents
//         .split('\n')
//         .map(|line| {
//             if line.starts_with(&format!("{}=", variable_name)) {
//                 format!("{}={}", variable_name, json_secret_key)
//             } else {
//                 line.to_string()
//             }
//         })
//         .collect();

//     // Rejoin the lines and add the new variable if it wasn't found
//     let new_contents = if lines
//         .iter()
//         .any(|line| line.starts_with(&format!("{}=", variable_name)))
//     {
//         lines.join("\n")
//     } else {
//         format!(
//             "{}\n{}={}",
//             lines.join("\n"),
//             variable_name,
//             json_secret_key
//         )
//     };

//     // Write the updated contents back to the .env file
//     let mut file = OpenOptions::new()
//         .write(true)
//         .truncate(true)
//         .open(file_path)?;
//     file.write_all(new_contents.as_bytes())?;

//     Ok(())
// }
