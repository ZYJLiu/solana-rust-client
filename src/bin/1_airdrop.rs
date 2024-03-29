// cargo run --bin 1_airdrop
use keypair_utils::get_or_create_keypair;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, native_token::LAMPORTS_PER_SOL, signer::Signer,
};
use std::error::Error;

// Create two keypairs saved to .env file (wallet_1 and wallet_2) and airdrop 1 SOL to each
fn main() -> Result<(), Box<dyn Error>> {
    let wallet_1 = get_or_create_keypair("wallet_1")?;
    let wallet_2 = get_or_create_keypair("wallet_2")?;

    let client = RpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    client.request_airdrop(&wallet_1.pubkey(), LAMPORTS_PER_SOL)?;
    client.request_airdrop(&wallet_2.pubkey(), LAMPORTS_PER_SOL)?;
    Ok(())
}
